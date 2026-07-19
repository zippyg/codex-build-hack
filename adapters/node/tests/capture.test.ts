import { describe, expect, test } from "bun:test";

import {
  CaptureCallbackError,
  CaptureConfigurationError,
  captureResponses,
  verifyCallsiteRegistry,
  type CaptureObservation,
  type ResponsesCallables,
} from "../src/index";

const CALLSITE_ID = `cs_${"a".repeat(64)}`;
const OTHER_CALLSITE_ID = `cs_${"b".repeat(64)}`;
const CONTENT_CANARY = "CAPTURE_BODY_CANARY_MUST_NOT_PERSIST";
const LABEL_CANARY = "CAPTURE_LABEL_CANARY_MUST_NOT_PERSIST";

function response(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    model: LABEL_CANARY,
    output: CONTENT_CANARY,
    usage: { input_tokens: 13, output_tokens: 8 },
    ...overrides,
  };
}

function callables(
  create: ResponsesCallables["create"],
  parse: ResponsesCallables["parse"] = create,
): ResponsesCallables {
  return { create, parse };
}

function registry() {
  return verifyCallsiteRegistry([{ callsiteId: CALLSITE_ID, enabled: true }]);
}

describe("metadata-only Responses capture", () => {
  test("wraps Promise create and parse calls without monkeypatching", async () => {
    const observations: CaptureObservation[] = [];
    const calls: Array<readonly [string, readonly unknown[]]> = [];
    const resource = callables(
      async (...args) => {
        calls.push(["create", args]);
        return response({ retriesTaken: 2 });
      },
      async (...args) => {
        calls.push(["parse", args]);
        return response();
      },
    );
    const originalCreate = resource.create;
    const captured = captureResponses(resource, {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    });

    await captured.create({ model: LABEL_CANARY, input: CONTENT_CANARY, tools: [{ name: LABEL_CANARY }] });
    await captured.parse({ model: LABEL_CANARY, input: CONTENT_CANARY, text_format: { type: "json_schema" } });

    expect(resource.create).toBe(originalCreate);
    expect(calls.map(([name]) => name)).toEqual(["create", "parse"]);
    expect(observations).toHaveLength(2);
    expect(observations[0]).toMatchObject({
      callsiteId: CALLSITE_ID,
      operation: "responses.create",
      status: "ok",
      inputTokens: 13,
      outputTokens: 8,
      flags: ["asynchronous", "retry", "tools"],
    });
    expect(observations[1]).toMatchObject({
      operation: "responses.parse",
      flags: ["asynchronous", "structured_output"],
    });
    const serialized = JSON.stringify(observations);
    expect(serialized).not.toContain(CONTENT_CANARY);
    expect(serialized).not.toContain(LABEL_CANARY);
  });

  test("rejects unverified, disabled, forged, and duplicate callsites before calling the SDK", async () => {
    let calls = 0;
    const resource = callables(async () => {
      calls += 1;
      return response();
    });
    expect(() =>
      captureResponses(resource, {
        callsiteId: OTHER_CALLSITE_ID,
        registry: registry(),
        sink: () => {},
      }),
    ).toThrow(CaptureConfigurationError);
    expect(() =>
      captureResponses(resource, {
        callsiteId: CALLSITE_ID,
        registry: verifyCallsiteRegistry([{ callsiteId: CALLSITE_ID, enabled: false }]),
        sink: () => {},
      }),
    ).toThrow(CaptureConfigurationError);
    expect(() =>
      captureResponses(resource, {
        callsiteId: CALLSITE_ID,
        registry: {
          schemaVersion: "promptectomy-callsite-registry-1",
          digest: "sha256:forged",
          entries: [{ callsiteId: CALLSITE_ID, enabled: true }],
        },
        sink: () => {},
      }),
    ).toThrow(CaptureConfigurationError);
    expect(() =>
      verifyCallsiteRegistry([
        { callsiteId: CALLSITE_ID, enabled: true },
        { callsiteId: CALLSITE_ID, enabled: true },
      ]),
    ).toThrow(CaptureConfigurationError);
    expect(calls).toBe(0);
  });

  test("preserves application error identity and never persists exception text", async () => {
    const observations: CaptureObservation[] = [];
    const error = new Error(CONTENT_CANARY);
    const captured = captureResponses(callables(async () => Promise.reject(error)), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    });

    await expect(captured.create({ model: LABEL_CANARY, input: CONTENT_CANARY })).rejects.toBe(error);
    expect(observations).toHaveLength(1);
    expect(observations[0]?.status).toBe("error");
    expect(observations[0]?.flags).toEqual(["asynchronous", "error"]);
    expect(JSON.stringify(observations)).not.toContain(CONTENT_CANARY);
    expect(JSON.stringify(observations)).not.toContain(LABEL_CANARY);
  });

  test("records abort cancellation without replacing the AbortError", async () => {
    const observations: CaptureObservation[] = [];
    const controller = new AbortController();
    const error = new DOMException(CONTENT_CANARY, "AbortError");
    const captured = captureResponses(callables(async () => Promise.reject(error)), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    });
    controller.abort();

    await expect(
      captured.create({ model: "gpt", input: CONTENT_CANARY, signal: controller.signal }),
    ).rejects.toBe(error);
    expect(observations[0]?.status).toBe("cancelled");
    expect(observations[0]?.flags).toEqual(["asynchronous", "cancellation"]);
  });

  test("an aborted request signal classifies a provider-specific error as cancellation", async () => {
    const observations: CaptureObservation[] = [];
    const controller = new AbortController();
    const error = new Error(CONTENT_CANARY);
    const captured = captureResponses(callables(async () => Promise.reject(error)), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    });
    controller.abort();

    await expect(captured.create({ signal: controller.signal })).rejects.toBe(error);
    expect(observations[0]?.status).toBe("cancelled");
    expect(JSON.stringify(observations)).not.toContain(CONTENT_CANARY);
  });

  test("tracks stream completion, error, and early return exactly once", async () => {
    const observations: CaptureObservation[] = [];
    async function* complete() {
      yield { delta: CONTENT_CANARY };
      yield { delta: CONTENT_CANARY };
    }
    const completed = (await captureResponses(callables(async () => complete()), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    }).create({ model: LABEL_CANARY, input: CONTENT_CANARY, stream: true })) as AsyncIterable<unknown>;
    expect(await Array.fromAsync(completed)).toHaveLength(2);

    const streamError = new Error(CONTENT_CANARY);
    async function* failing() {
      yield 1;
      throw streamError;
    }
    const failed = (await captureResponses(callables(async () => failing()), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    }).create({ model: "gpt", input: CONTENT_CANARY, stream: true })) as AsyncIterableIterator<unknown>;
    expect((await failed.next()).value).toBe(1);
    await expect(failed.next()).rejects.toBe(streamError);

    let closed = false;
    async function* early() {
      try {
        yield 1;
        yield 2;
      } finally {
        closed = true;
      }
    }
    const returned = (await captureResponses(callables(async () => early()), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    }).create({ model: "gpt", input: CONTENT_CANARY, stream: true })) as AsyncIterableIterator<unknown>;
    expect((await returned.next()).value).toBe(1);
    if (returned.return === undefined) {
      throw new Error("captured stream must expose return");
    }
    const closeReturned = returned.return.bind(returned);
    await closeReturned();
    await closeReturned();

    expect(closed).toBeTrue();
    expect(observations.map((item) => item.status)).toEqual(["ok", "error", "cancelled"]);
    expect(observations.map((item) => item.streamEventCount)).toEqual([2, 1, 1]);
    expect(observations[0]?.flags).toEqual(["asynchronous", "streaming"]);
    expect(observations[1]?.flags).toEqual(["asynchronous", "error", "streaming"]);
    expect(observations[2]?.flags).toEqual(["asynchronous", "cancellation", "streaming"]);
    expect(JSON.stringify(observations)).not.toContain(CONTENT_CANARY);
  });

  test("a successful call reports callback failure without leaking callback details", async () => {
    const captured = captureResponses(callables(async () => response()), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: () => {
        throw new Error(CONTENT_CANARY);
      },
    });
    const caught = await captured.create({ model: "gpt", input: CONTENT_CANARY }).catch((error) => error);
    expect(caught).toBeInstanceOf(CaptureCallbackError);
    expect(String(caught)).not.toContain(CONTENT_CANARY);
  });

  test("sink must be synchronous and return within its declared post-call budget", async () => {
    const asyncSink = captureResponses(callables(async () => response()), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (() => Promise.resolve()) as unknown as (observation: CaptureObservation) => void,
    });
    await expect(asyncSink.create({ model: "gpt" })).rejects.toBeInstanceOf(CaptureCallbackError);

    const slowSink = captureResponses(callables(async () => response()), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      maxSinkMilliseconds: 1,
      sink: () => {
        const end = performance.now() + 3;
        while (performance.now() < end) {}
      },
    });
    await expect(slowSink.create({ model: "gpt" })).rejects.toBeInstanceOf(CaptureCallbackError);
  });

  test("oversized and getter-backed values fail without reading protected properties", async () => {
    let getterReads = 0;
    const protectedRequest = {
      model: "gpt",
      get input() {
        getterReads += 1;
        return CONTENT_CANARY;
      },
    };
    const observations: CaptureObservation[] = [];
    await captureResponses(callables(async () => response()), {
      callsiteId: CALLSITE_ID,
      registry: registry(),
      sink: (observation) => observations.push(observation),
    }).create(protectedRequest);
    expect(getterReads).toBe(0);
    expect(JSON.stringify(observations)).not.toContain(CONTENT_CANARY);

    const oversized = Array.from({ length: 257 }, () => CONTENT_CANARY);
    await expect(
      captureResponses(callables(async () => response()), {
        callsiteId: CALLSITE_ID,
        registry: registry(),
        sink: () => {},
      }).create({ input: oversized }),
    ).rejects.toThrow("Capture array exceeds the item bound");
  });
});
