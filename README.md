# PROMPTECTOMY

**Live demo (recorded replay, clickable): https://ui-cyan-eight.vercel.app**


**Point Codex at your app. It finds the LLM calls that should be code, writes the deterministic
replacement, and proves it works by replaying traffic the model never saw. The calls it can't
compile, it keeps.**

> Codex turned two prompts into code, proved them against traffic it never saw, and kept the third
> because it still earned its tokens.

Every app shipped since 2023 has LLM calls doing jobs a parser or a classifier should do. Teams
prototype with a model because it is fast, then never go back and harden it. They pay the token tax,
the latency, and the nondeterminism forever. PROMPTECTOMY is the going-back, as an agent.

## What it does

1. A one-line shim records every real LLM call your app makes (input, output, latency, cost) to a
   local ledger. This recorded traffic becomes an executable spec.
2. `promptectomy run` scans the repo for LLM callsites and, for each candidate, launches Codex in an
   isolated git worktree to synthesize a pure, deterministic replacement.
3. The recorded traffic is split train / dev / holdout (60 / 20 / 20). Codex iterates against train
   and dev. It never sees the holdout.
4. A parent verifier runs the holdout once and issues a verdict:
   - COMPILED: agreement on every held-out case.
   - COMPILED_WITH_DIFFS: high agreement, every disagreement shown as a receipt.
   - NOT_COMPILABLE: freeform generation with no deterministic equivalent. This stays a model.
5. Compiled callsites hot-swap in behind the shim; a 1% shadow guard keeps checking against the model
   and re-opens a callsite on drift.

The result: per-callsite cost and latency collapse toward zero, whole-pipeline cost drops by a
measured percentage, and the one call that genuinely needs a model still uses one.

## Why it's honest (not a magic trick)

- Agreement measures preservation of the recorded model's behaviour, not objective correctness.
- The holdout is sealed: Codex cannot see it, and it runs exactly once. No iterating to a green number.
- We claim per-callsite cost toward zero and a measured whole-pipeline reduction, never "the bill went
  to zero."
- Every disagreement is shown, not hidden.

## How Codex is central

Codex is the compiler and the surgeon, not a chat box:
- It audits the repository under a JSON output schema to find candidate callsites.
- It writes each deterministic replacement in an isolated git worktree.
- It repairs its own code against the train/dev tests, iterating to green.
- It produces a committed code artifact with a diff and a saved activity trace.
- A verifier Codex cannot game then grades that artifact against traffic Codex never saw.

## Architecture

- Engine: Python 3.12 (uv). Shim, ledger, scanner, worktree synthesis, replay, scoring, verifier,
  Typer CLI. Emits a `PipelineEvent` NDJSON stream.
- Dashboard: Next.js (bun). A live cockpit that renders the run: latency/cost meters, the replay wall,
  the Codex activity stream, verdicts, and the hot-swap. Reads the same NDJSON.
- Contracts frozen in `engine/promptectomy/contracts.py` (Pydantic) and `ui/lib/contracts.ts` (Zod).

## Run it

```bash
# engine: install, capture traffic, then compile + verify
cd engine && uv sync
uv run python -m demo.triager.capture 240     # keyless synthetic ledger (or run your own app under the shim)
uv run promptectomy run .. --events jsonl     # scan -> synthesize in worktrees -> sealed-holdout verify
uv run promptectomy scan <any-repo>           # audit-only: find LLM callsites in any repo (no traffic)

# dashboard (plays the recorded run)
cd ui && bun install && bun dev               # http://localhost:4319
```

## Status

Built at the Codex Community Hackathon, London, 18 July 2026. On a real run: `extract_ticket_facts`
and `route_ticket` both COMPILED at 100% agreement on sealed holdouts (52 and 60 cases) that Codex
never saw, latency ~900ms -> ~0.006ms, whole-pipeline cost -44.8%; the freeform reply was correctly
kept as a model. The scanner was also run on microsoft/markitdown and found its 3 vision/LLM callsites,
correctly keeping all three. Generated modules, receipts, and the full story are in docs/SUBMISSION.md.
