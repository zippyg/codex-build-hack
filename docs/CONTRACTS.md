# Frozen contracts (the interface every lane builds against)

Do not change these without the integrator (owner of `main`). Any change is a re-freeze + a note here.

## The two sources of truth
- `engine/promptectomy/contracts.py` - Pydantic. Engine emits, validates, and records against these.
- `ui/lib/contracts.ts` - Zod. Dashboard validates every NDJSON line against the same wire shape.

They MUST stay byte-compatible on the JSON wire shape. Field names are snake_case on the wire.

## The pieces
- `LedgerEventV1` - one recorded LLM call (prompt/response/usage/latency/cost). Never records secrets.
- `AuditReport` / `CallsiteAudit` - what Codex emits under `--output-schema` when it scans a repo.
  Codex identifies candidates; it does NOT decide a verdict.
- `Verdict` - emitted by the PARENT verifier after the sealed holdout, never by Codex.
  Status: COMPILED | COMPILED_WITH_DIFFS | NOT_COMPILABLE | ERROR.
- `PipelineEvent` - the NDJSON stream the dashboard consumes (scan, traffic, callsiteStatus,
  synthToken, replay, verdict, swap, done). Engine writes it; Next route validates + forwards.
- Recorder wrapper: each line of a recording is `{ at_ms, event }` (see `ui/fixtures/demo-run.ndjson`).

## Non-negotiable honesty rules (baked into scoring, do not soften)
- train/dev/holdout = 60/20/20, grouped by canonical request hash. Codex sees train+dev, NEVER holdout.
- Holdout runs ONCE, by the parent verifier. Any miss is final for that run.
- Agreement measures preservation of recorded MODEL behaviour, not objective correctness. Say so.
- Claim per-callsite cost -> ~0 and a MEASURED whole-pipeline reduction %. Never "the bill went to zero"
  (one callsite stays a model + 1% shadow traffic).
- Only claim "the LLM contradicted itself" if the ledger actually has repeated identical requests with
  divergent outputs. Otherwise a diff is just a diff.

## The engine module contract (what Codex generates per callsite)
`engine/promptectomy/generated/<callsite_id>.py` exposing:
`def run(input: JsonValue, params: dict) -> JsonValue` - pure, deterministic, stdlib only, < 100ms,
no network/fs/env/clock/random. Output must satisfy the callsite's normalized-output schema.
