import type { CallsiteAudit, PipelineEvent, Verdict } from "./contracts";

export type Stage =
  | "feed"
  | "audit"
  | "stream"
  | "diffs"
  | "judgment"
  | "swap"
  | "guard";

export type Beat = 1 | 2 | 3 | 4 | 5 | 6;

const STAGE_BEAT: Record<Stage, Beat> = {
  feed: 1,
  audit: 2,
  stream: 3,
  diffs: 3,
  judgment: 4,
  swap: 5,
  guard: 6,
};

export interface TrafficSample {
  callsiteId: string;
  latencyMs: number;
  costUsd: number;
  source: "llm" | "compiled";
  seq: number;
}

export interface SynthLine {
  text: string;
  kind: "reasoning" | "code" | "tool";
}

export interface CallsiteState {
  audit: CallsiteAudit;
  status: "queued" | "synthesizing" | "replaying" | "iterating" | "done";
  round: number | null;
  replayPassed: number;
  replayTotal: number;
  verdict: Verdict | null;
  synth: SynthLine[];
}

export interface SwapInfo {
  callsiteId: string;
  beforeMs: number;
  afterMs: number;
  beforeCost: number;
  samples: { input?: unknown; llm_output?: unknown; compiled_output?: unknown }[];
}

export interface DashState {
  stage: Stage;
  beat: Beat;
  traffic: TrafficSample[];
  cumulativeCost: number;
  frozenCost: number | null;
  recordedCalls: number | null;
  order: string[];
  callsites: Record<string, CallsiteState>;
  activeCallsite: string | null;
  diffVerdict: Verdict | null;
  keepVerdict: Verdict | null;
  swap: SwapInfo | null;
  swapped: boolean;
  totals: {
    callsites: number;
    compiled: number;
    kept: number;
    est_monthly_savings_usd: number;
    pipeline_cost_reduction_pct: number;
  } | null;
  seq: number;
}

export const initialState: DashState = {
  stage: "feed",
  beat: 1,
  traffic: [],
  cumulativeCost: 12.63,
  frozenCost: null,
  recordedCalls: null,
  order: [],
  callsites: {},
  activeCallsite: null,
  diffVerdict: null,
  keepVerdict: null,
  swap: null,
  swapped: false,
  totals: null,
  seq: 0,
};

const RING = 60;

function withStage(s: DashState, stage: Stage): DashState {
  return { ...s, stage, beat: STAGE_BEAT[stage] };
}

export function reduce(s: DashState, e: PipelineEvent): DashState {
  const seq = s.seq + 1;
  switch (e.type) {
    case "traffic": {
      const sample: TrafficSample = {
        callsiteId: e.callsite_id,
        latencyMs: e.latency_ms,
        costUsd: e.cost_usd,
        source: e.source,
        seq,
      };
      const swapped = s.swapped || e.source === "compiled";
      return {
        ...s,
        seq,
        swapped,
        traffic: [...s.traffic.slice(-(RING - 1)), sample],
        cumulativeCost: swapped ? s.cumulativeCost : s.cumulativeCost + e.cost_usd,
        frozenCost: swapped && s.frozenCost === null ? s.cumulativeCost : s.frozenCost,
      };
    }
    case "scan": {
      const callsites: Record<string, CallsiteState> = {};
      const order: string[] = [];
      for (const a of e.audit) {
        order.push(a.callsite_id);
        callsites[a.callsite_id] = {
          audit: a,
          status: "queued",
          round: null,
          replayPassed: 0,
          replayTotal: 0,
          verdict: null,
          synth: [],
        };
      }
      return withStage(
        { ...s, seq, recordedCalls: e.recorded_calls, order, callsites },
        "audit",
      );
    }
    case "callsiteStatus": {
      const cs = s.callsites[e.callsite_id];
      if (!cs) return { ...s, seq };
      const next = {
        ...s,
        seq,
        activeCallsite: e.status === "done" ? s.activeCallsite : e.callsite_id,
        callsites: {
          ...s.callsites,
          [e.callsite_id]: { ...cs, status: e.status, round: e.round ?? cs.round },
        },
      };
      // First synthesis flip moves the stage to the codex stream.
      if (s.stage === "audit" && e.status === "synthesizing") return withStage(next, "stream");
      return next;
    }
    case "synthToken": {
      const cs = s.callsites[e.callsite_id];
      if (!cs) return { ...s, seq };
      return {
        ...s,
        seq,
        activeCallsite: e.callsite_id,
        callsites: {
          ...s.callsites,
          [e.callsite_id]: {
            ...cs,
            synth: [...cs.synth, { text: e.text, kind: e.kind ?? "reasoning" }],
          },
        },
      };
    }
    case "replay": {
      const cs = s.callsites[e.callsite_id];
      if (!cs) return { ...s, seq };
      return {
        ...s,
        seq,
        callsites: {
          ...s.callsites,
          [e.callsite_id]: { ...cs, replayPassed: e.passed, replayTotal: e.total },
        },
      };
    }
    case "verdict": {
      const v = e.verdict;
      const cs = s.callsites[v.callsite_id];
      const base = cs
        ? {
            ...s,
            seq,
            callsites: { ...s.callsites, [v.callsite_id]: { ...cs, verdict: v, status: "done" as const } },
          }
        : { ...s, seq };
      if (v.status === "COMPILED_WITH_DIFFS")
        return withStage({ ...base, diffVerdict: v }, "diffs");
      if (v.status === "NOT_COMPILABLE")
        return withStage({ ...base, keepVerdict: v }, "judgment");
      return base;
    }
    case "swap": {
      return withStage(
        {
          ...s,
          seq,
          swapped: true,
          frozenCost: s.frozenCost ?? s.cumulativeCost,
          swap: {
            callsiteId: e.callsite_id,
            beforeMs: e.before_ms,
            afterMs: e.after_ms,
            beforeCost: e.before_cost,
            samples: e.samples,
          },
        },
        "swap",
      );
    }
    case "done": {
      return withStage({ ...s, seq, totals: e.totals }, "guard");
    }
  }
}

export function p50(samples: TrafficSample[], source: "llm" | "compiled"): number | null {
  const xs = samples.filter((t) => t.source === source).map((t) => t.latencyMs);
  if (xs.length === 0) return null;
  const sorted = [...xs].sort((a, b) => a - b);
  return sorted[Math.floor((sorted.length - 1) / 2)];
}

export function lastCostPerReq(s: DashState): number | null {
  const last = s.traffic[s.traffic.length - 1];
  return last ? last.costUsd : null;
}
