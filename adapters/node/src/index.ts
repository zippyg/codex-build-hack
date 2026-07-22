import { createHash, randomUUID } from "node:crypto";

const ADAPTER_VERSION = "node-openai-responses-capture-0.1.0";
const CALLSITE_ID = /^(?:cs_|callsite_sha256_)[0-9a-f]{64}$/;
const MAX_FIELDS = 256;
const MAX_ARRAY_ITEMS = 256;
const SHAPE_SAMPLE_ITEMS = 16;
const MAX_DEPTH = 8;
const MAX_MODEL_LENGTH = 256;
const MAX_SINK_MILLISECONDS = 100;

const SAFE_FIELDS = new Set([
  "background",
  "context_management",
  "conversation",
  "error",
  "include",
  "input",
  "input_tokens",
  "instructions",
  "max_output_tokens",
  "max_tool_calls",
  "metadata",
  "model",
  "moderation",
  "output",
  "output_tokens",
  "parallel_tool_calls",
  "previous_response_id",
  "prompt",
  "prompt_cache_key",
  "prompt_cache_options",
  "prompt_cache_retention",
  "reasoning",
  "response",
  "safety_identifier",
  "service_tier",
  "store",
  "stream",
  "stream_options",
  "temperature",
  "text",
  "text_format",
  "tool_choice",
  "tools",
  "top_logprobs",
  "top_p",
  "truncation",
  "usage",
  "user",
  "verbosity",
]);

const verifiedRegistries = new WeakSet<object>();

export type CaptureStatus = "ok" | "error" | "cancelled";
export type ResponsesOperation = "responses.create" | "responses.parse";

export interface CallsiteRegistryEntry {
  readonly callsiteId: string;
  readonly enabled: boolean;
}

export interface VerifiedCallsiteRegistry {
  readonly schemaVersion: "promptectomy-callsite-registry-1";
  readonly digest: string;
  readonly entries: readonly CallsiteRegistryEntry[];
}

export interface CaptureObservation {
  readonly schemaVersion: "promptectomy-node-capture-1";
  readonly adapterVersion: typeof ADAPTER_VERSION;
  readonly runtime: "node";
  readonly observationId: string;
  readonly attemptId: string;
  readonly callsiteId: string;
  readonly registryDigest: string;
  readonly provider: "openai";
  readonly modelDigest: string;
  readonly operation: ResponsesOperation;
  readonly startedAtUnixNano: string;
  readonly endedAtUnixNano: string;
  readonly durationMicroseconds: number;
  readonly status: CaptureStatus;
  readonly inputTokens: number | null;
  readonly outputTokens: number | null;
  readonly requestShapeDigest: string;
  readonly responseShapeDigest: string;
  readonly flags: readonly CaptureFlag[];
  readonly streamEventCount: number | null;
}

export type CaptureFlag =
  | "asynchronous"
  | "cancellation"
  | "error"
  | "retry"
  | "streaming"
  | "structured_output"
  | "tools";

export type ObservationSink = (observation: CaptureObservation) => void;

export interface ResponsesCallables {
  create: (...args: any[]) => Promise<unknown>;
  parse: (...args: any[]) => Promise<unknown>;
}

export type CapturedResponses = ResponsesCallables;

export interface CaptureOptions {
  readonly callsiteId: string;
  readonly registry: VerifiedCallsiteRegistry;
  readonly sink: ObservationSink;
  readonly maxSinkMilliseconds?: number;
}

export class CaptureConfigurationError extends Error {
  readonly code = "capture_configuration_error";
}

export class CaptureCallbackError extends Error {
  readonly code = "capture_callback_error";
}

export class CaptureShapeError extends Error {
  readonly code = "capture_shape_error";
}

type Shape =
  | "null"
  | "boolean"
  | "integer"
  | "number"
  | "string"
  | "bytes"
  | "object"
  | { readonly array: readonly Shape[]; readonly count: number }
  | {
      readonly fields: readonly (readonly [string, Shape])[];
      readonly unknownFieldCount: number;
    };

interface SafeFields {
  readonly descriptors: Readonly<Record<string, PropertyDescriptor>>;
  readonly count: number;
}

function sha256(domain: string, value: string): string {
  return `sha256:${createHash("sha256").update(domain).update("\0").update(value).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`).join(",")}}`;
}

function plainFields(value: unknown): SafeFields | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return null;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const count = Object.keys(descriptors).length;
  if (count > MAX_FIELDS) {
    throw new CaptureShapeError("Capture object exceeds the member bound");
  }
  return { descriptors, count };
}

function dataField(value: unknown, name: string): unknown {
  const fields = plainFields(value);
  const descriptor = fields?.descriptors[name];
  return descriptor && "value" in descriptor ? descriptor.value : undefined;
}

function shape(value: unknown, depth = 0): Shape {
  if (depth > MAX_DEPTH) {
    throw new CaptureShapeError("Capture shape exceeds the depth bound");
  }
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "bigint") return "integer";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  if (typeof value === "string") return "string";
  if (value instanceof Uint8Array || value instanceof ArrayBuffer) return "bytes";
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) {
      throw new CaptureShapeError("Capture array exceeds the item bound");
    }
    return {
      array: value.slice(0, SHAPE_SAMPLE_ITEMS).map((item) => shape(item, depth + 1)),
      count: value.length,
    };
  }
  const fields = plainFields(value);
  if (!fields) return "object";
  const safe: Array<readonly [string, Shape]> = [];
  let unknownFieldCount = 0;
  for (const [key, descriptor] of Object.entries(fields.descriptors)) {
    if (!SAFE_FIELDS.has(key) || !("value" in descriptor)) {
      unknownFieldCount += 1;
      continue;
    }
    safe.push([sha256("capture-field", key), shape(descriptor.value, depth + 1)]);
  }
  safe.sort(([left], [right]) => left.localeCompare(right));
  return { fields: safe, unknownFieldCount };
}

function shapeDigest(domain: string, value: unknown): string {
  try {
    return sha256(domain, stableJson(shape(value)));
  } catch (error) {
    if (error instanceof CaptureShapeError) throw error;
    return sha256(domain, stableJson("object"));
  }
}

function boundedToken(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function usage(value: unknown): readonly [number | null, number | null] {
  const usageValue = dataField(value, "usage");
  return [boundedToken(dataField(usageValue, "input_tokens")), boundedToken(dataField(usageValue, "output_tokens"))];
}

function retryCount(value: unknown): number {
  for (const field of ["retries_taken", "_retries_taken", "retriesTaken", "_retriesTaken"]) {
    const count = dataField(value, field);
    if (typeof count === "number" && Number.isSafeInteger(count) && count > 0) return count;
  }
  return 0;
}

function requestFromArgs(args: readonly unknown[]): Readonly<Record<string, unknown>> {
  const request = args[0];
  const fields = plainFields(request);
  if (!fields) return {};
  const values: Record<string, unknown> = {};
  for (const [key, descriptor] of Object.entries(fields.descriptors)) {
    if ("value" in descriptor) values[key] = descriptor.value;
  }
  return values;
}

function cancellation(error: unknown, request: Readonly<Record<string, unknown>>): boolean {
  if (request.signal instanceof AbortSignal && request.signal.aborted) return true;
  if (error instanceof DOMException && error.name === "AbortError") return true;
  return error instanceof Error && error.name === "AbortError";
}

function asyncIteratorFactory(value: unknown): (() => AsyncIterator<unknown>) | null {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return null;
  let current: object | null = value;
  for (let depth = 0; current !== null && depth <= MAX_DEPTH; depth += 1) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(current, Symbol.asyncIterator);
      current = Object.getPrototypeOf(current);
    } catch {
      return null;
    }
    if (descriptor) {
      return "value" in descriptor && typeof descriptor.value === "function"
        ? (descriptor.value as () => AsyncIterator<unknown>)
        : null;
    }
  }
  return null;
}

function validateRegistry(entries: readonly CallsiteRegistryEntry[]): VerifiedCallsiteRegistry {
  if (entries.length === 0 || entries.length > 100_000) {
    throw new CaptureConfigurationError("Callsite registry entry count is invalid");
  }
  const normalized = entries.map((entry) => {
    if (!CALLSITE_ID.test(entry.callsiteId) || typeof entry.enabled !== "boolean") {
      throw new CaptureConfigurationError("Callsite registry contains an invalid entry");
    }
    return { callsiteId: entry.callsiteId, enabled: entry.enabled } as const;
  });
  const ids = new Set(normalized.map((entry) => entry.callsiteId));
  if (ids.size !== normalized.length) {
    throw new CaptureConfigurationError("Callsite registry contains a duplicate ID");
  }
  normalized.sort((left, right) => left.callsiteId.localeCompare(right.callsiteId));
  const registry = Object.freeze({
    schemaVersion: "promptectomy-callsite-registry-1" as const,
    digest: sha256("callsite-registry", stableJson(normalized)),
    entries: Object.freeze(normalized),
  });
  verifiedRegistries.add(registry);
  return registry;
}

export function verifyCallsiteRegistry(entries: readonly CallsiteRegistryEntry[]): VerifiedCallsiteRegistry {
  return validateRegistry(entries);
}

class Attempt {
  readonly #attemptId = randomUUID();
  readonly #startedAtUnixNano = BigInt(Date.now()) * 1_000_000n;
  readonly #started = performance.now();
  #finished = false;

  constructor(
    readonly operation: ResponsesOperation,
    readonly callsiteId: string,
    readonly registry: VerifiedCallsiteRegistry,
    readonly request: Readonly<Record<string, unknown>>,
    readonly sink: ObservationSink,
    readonly maxSinkMilliseconds: number,
  ) {}

  get finished(): boolean {
    return this.#finished;
  }

  finish(status: CaptureStatus, response?: unknown, streamEventCount: number | null = null): void {
    if (this.#finished) return;
    this.#finished = true;
    const endedAtUnixNano = BigInt(Date.now()) * 1_000_000n;
    const model = dataField(response, "model") ?? this.request.model;
    const safeModel = typeof model === "string" && model.length <= MAX_MODEL_LENGTH ? model : "unknown";
    const [inputTokens, outputTokens] = usage(response);
    const flags = new Set<CaptureFlag>(["asynchronous"]);
    if (this.request.stream === true) flags.add("streaming");
    if (Object.hasOwn(this.request, "tools")) flags.add("tools");
    if (
      this.operation === "responses.parse" ||
      Object.hasOwn(this.request, "text") ||
      Object.hasOwn(this.request, "text_format") ||
      Object.hasOwn(this.request, "response_format")
    ) {
      flags.add("structured_output");
    }
    if (status === "error") flags.add("error");
    if (status === "cancelled") flags.add("cancellation");
    if (retryCount(response) > 0) flags.add("retry");
    const observation: CaptureObservation = Object.freeze({
      schemaVersion: "promptectomy-node-capture-1",
      adapterVersion: ADAPTER_VERSION,
      runtime: "node",
      observationId: sha256("capture-observation", `${this.#attemptId}\0${this.#startedAtUnixNano}`),
      attemptId: sha256("capture-attempt", this.#attemptId),
      callsiteId: this.callsiteId,
      registryDigest: this.registry.digest,
      provider: "openai",
      modelDigest: sha256("model", safeModel),
      operation: this.operation,
      startedAtUnixNano: this.#startedAtUnixNano.toString(),
      endedAtUnixNano: endedAtUnixNano.toString(),
      durationMicroseconds: Math.max(0, Math.round((performance.now() - this.#started) * 1_000)),
      status,
      inputTokens,
      outputTokens,
      requestShapeDigest: shapeDigest("capture-request-shape", this.request),
      responseShapeDigest: shapeDigest("capture-response-shape", response),
      flags: Object.freeze([...flags].sort()),
      streamEventCount,
    });
    const callbackStarted = performance.now();
    let result: unknown;
    try {
      result = this.sink(observation);
    } catch {
      throw new CaptureCallbackError("The capture observation callback failed");
    }
    const callbackDuration = performance.now() - callbackStarted;
    if (
      (result !== null && (typeof result === "object" || typeof result === "function")) ||
      callbackDuration > this.maxSinkMilliseconds
    ) {
      throw new CaptureCallbackError("The capture observation callback exceeded its contract");
    }
  }

  finishPreserving(error: unknown, streamEventCount: number | null = null): void {
    try {
      this.finish(cancellation(error, this.request) ? "cancelled" : "error", undefined, streamEventCount);
    } catch {
      // The original application error has priority over capture failure.
    }
  }
}

class CapturedAsyncStream implements AsyncIterableIterator<unknown> {
  readonly #iterator: AsyncIterator<unknown>;
  #events = 0;

  constructor(
    stream: object,
    iteratorFactory: () => AsyncIterator<unknown>,
    readonly attempt: Attempt,
  ) {
    this.#iterator = iteratorFactory.call(stream);
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<unknown> {
    return this;
  }

  async next(...args: [] | [undefined]): Promise<IteratorResult<unknown>> {
    try {
      const result = await this.#iterator.next(...args);
      if (result.done) {
        this.attempt.finish("ok", { stream: { events: this.#events } }, this.#events);
      } else {
        this.#events += 1;
      }
      return result;
    } catch (error) {
      this.attempt.finishPreserving(error, this.#events);
      throw error;
    }
  }

  async return(value?: unknown): Promise<IteratorResult<unknown>> {
    try {
      const result = this.#iterator.return
        ? await this.#iterator.return(value)
        : ({ done: true, value } as IteratorResult<unknown>);
      if (!this.attempt.finished) {
        this.attempt.finish("cancelled", { stream: { events: this.#events } }, this.#events);
      }
      return result;
    } catch (error) {
      this.attempt.finishPreserving(error, this.#events);
      throw error;
    }
  }

  async throw(error?: unknown): Promise<IteratorResult<unknown>> {
    try {
      if (!this.#iterator.throw) throw error;
      const result = await this.#iterator.throw(error);
      this.attempt.finish(
        cancellation(error, this.attempt.request) ? "cancelled" : "error",
        undefined,
        this.#events,
      );
      return result;
    } catch (caught) {
      this.attempt.finishPreserving(caught, this.#events);
      throw caught;
    }
  }
}

function validateOptions(options: CaptureOptions): number {
  if (!verifiedRegistries.has(options.registry)) {
    throw new CaptureConfigurationError("Capture requires a verified callsite registry");
  }
  const matches = options.registry.entries.filter(
    (entry) => entry.callsiteId === options.callsiteId && entry.enabled,
  );
  if (!CALLSITE_ID.test(options.callsiteId) || matches.length !== 1) {
    throw new CaptureConfigurationError("Capture requires one enabled registry-verified callsite ID");
  }
  if (typeof options.sink !== "function") {
    throw new CaptureConfigurationError("Capture requires a synchronous observation callback");
  }
  const maximum = options.maxSinkMilliseconds ?? MAX_SINK_MILLISECONDS;
  if (!Number.isFinite(maximum) || maximum <= 0 || maximum > 1_000) {
    throw new CaptureConfigurationError("Capture callback budget is invalid");
  }
  return maximum;
}

export function captureResponses(responses: ResponsesCallables, options: CaptureOptions): CapturedResponses {
  const maxSinkMilliseconds = validateOptions(options);

  async function call(operation: ResponsesOperation, args: readonly unknown[]): Promise<unknown> {
    const request = requestFromArgs(args);
    const attempt = new Attempt(
      operation,
      options.callsiteId,
      options.registry,
      request,
      options.sink,
      maxSinkMilliseconds,
    );
    try {
      const method = operation === "responses.create" ? responses.create : responses.parse;
      const result = await method(...args);
      if (request.stream === true) {
        const iteratorFactory = asyncIteratorFactory(result);
        if (iteratorFactory === null || result === null || typeof result !== "object") {
          const error = new TypeError("A streaming Responses call returned a non-stream value");
          attempt.finishPreserving(error);
          throw error;
        }
        return new CapturedAsyncStream(result, iteratorFactory, attempt);
      }
      attempt.finish("ok", result);
      return result;
    } catch (error) {
      attempt.finishPreserving(error);
      throw error;
    }
  }

  return Object.freeze({
    create: (...args: unknown[]) => call("responses.create", args),
    parse: (...args: unknown[]) => call("responses.parse", args),
  });
}
