// Frozen contracts for the PROMPTECTOMY dashboard. Mirror of engine/promptectomy/contracts.py.
// Same NDJSON wire shape, two validators (Pydantic on the engine, Zod here). The engine emits
// PipelineEvents to NDJSON; the Next route validates each line against these schemas and forwards.
// Do not change without the integrator (main owner).

import { z } from "zod";

export const CallKind = z.enum(["structured", "classifier", "freeform"]);

export const CallsiteAudit = z.object({
  callsite_id: z.string(),
  file: z.string(),
  line: z.number().int().min(1),
  symbol: z.string().default(""),
  kind: CallKind,
  eligibility: z.enum(["candidate", "keep_model", "unsupported"]),
  sample_count: z.number().int().min(0),
});
export type CallsiteAudit = z.infer<typeof CallsiteAudit>;

export const Diff = z.object({
  event_id: z.string().default(""),
  input: z.unknown(),
  expected: z.unknown(),
  got: z.unknown(),
  summary: z.string().default(""),
});

export const Verdict = z.object({
  callsite_id: z.string(),
  status: z.enum(["COMPILED", "COMPILED_WITH_DIFFS", "NOT_COMPILABLE", "ERROR"]),
  reason: z.string().default(""),
  agreement: z.number().min(0).max(1).nullable().default(null),
  holdout_n: z.number().int().min(0).default(0),
  diffs: z.array(Diff).default([]),
  module_path: z.string().nullable().default(null),
  median_latency_ms: z.number().nullable().default(null),
});
export type Verdict = z.infer<typeof Verdict>;

const Scan = z.object({
  type: z.literal("scan"),
  audit: z.array(CallsiteAudit),
  recorded_calls: z.number().int(),
});
const Traffic = z.object({
  type: z.literal("traffic"),
  callsite_id: z.string(),
  latency_ms: z.number(),
  cost_usd: z.number(),
  source: z.enum(["llm", "compiled"]),
});
const CallsiteStatus = z.object({
  type: z.literal("callsiteStatus"),
  callsite_id: z.string(),
  status: z.enum(["queued", "synthesizing", "replaying", "iterating", "done"]),
  round: z.number().int().nullable().optional(),
});
const SynthToken = z.object({
  type: z.literal("synthToken"),
  callsite_id: z.string(),
  text: z.string(),
  kind: z.enum(["reasoning", "code", "tool"]).nullable().optional(),
});
const Replay = z.object({
  type: z.literal("replay"),
  callsite_id: z.string(),
  passed: z.number().int(),
  total: z.number().int(),
});
const VerdictEvent = z.object({ type: z.literal("verdict"), verdict: Verdict });
const SwapSample = z.object({
  input: z.unknown(),
  llm_output: z.unknown(),
  compiled_output: z.unknown(),
});
const Swap = z.object({
  type: z.literal("swap"),
  callsite_id: z.string(),
  before_ms: z.number(),
  after_ms: z.number(),
  before_cost: z.number(),
  samples: z.array(SwapSample).default([]),
});
const Done = z.object({
  type: z.literal("done"),
  totals: z.object({
    callsites: z.number().int(),
    compiled: z.number().int(),
    kept: z.number().int(),
    est_monthly_savings_usd: z.number(),
    pipeline_cost_reduction_pct: z.number(),
  }),
});

export const PipelineEvent = z.discriminatedUnion("type", [
  Scan,
  Traffic,
  CallsiteStatus,
  SynthToken,
  Replay,
  VerdictEvent,
  Swap,
  Done,
]);
export type PipelineEvent = z.infer<typeof PipelineEvent>;

// Recorder/replayer wrapper (NOT the wire shape): one NDJSON line per recorded event.
export const RecordedLine = z.object({ at_ms: z.number(), event: PipelineEvent });
export type RecordedLine = z.infer<typeof RecordedLine>;
