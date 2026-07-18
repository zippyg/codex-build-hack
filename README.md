# PROMPTECTOMY

**Live demo (recorded replay, clickable): https://promptectomy.vercel.app**


**Point Codex at your app. It finds the LLM calls that should be code, writes the deterministic
replacement, and proves it works by replaying traffic the model never saw. The calls it can't
compile, it keeps.**

> Codex turned two prompts into code, proved them against traffic it never saw, and kept the third
> because it still earned its tokens.

Every app shipped since 2023 has LLM calls doing jobs a parser or a classifier should do. Teams
prototype with a model because it is fast, then never go back and harden it. They pay the token tax,
the latency, and the nondeterminism forever. PROMPTECTOMY is the going-back, as an agent.

## What it does

1. The prototype shim can record OpenAI Responses calls (input, output, latency, cost) to a local
   ledger. This recorded traffic becomes an executable spec. Turnkey installation into another app
   is not packaged yet.
2. `promptectomy run` scans the repo for LLM callsites and, for each candidate, launches Codex in an
   isolated git worktree to synthesize a pure, deterministic replacement.
3. The recorded traffic is split train / dev / holdout (60 / 20 / 20). Codex iterates against train
   and dev. It never sees the holdout.
4. A parent verifier runs the holdout once and issues a verdict:
   - COMPILED: agreement on every held-out case.
   - COMPILED_WITH_DIFFS: high agreement, every disagreement shown as a receipt.
   - NOT_COMPILABLE: freeform generation with no deterministic equivalent. This stays a model.
5. Compiled callsites can be enabled through the shim registry when a captured Response envelope is
   available. The current 1% shadow path records original-model calls, but automatic comparison,
   disabling on drift, and re-opening synthesis are not implemented yet.

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
- Dashboard: Next.js (bun). A cockpit that renders latency/cost meters, the replay wall, the Codex
  activity stream, verdicts, and replacement registration from the same NDJSON contract.
- Contracts frozen in `engine/promptectomy/contracts.py` (Pydantic) and `ui/lib/contracts.ts` (Zod).

## Current prototype boundary

The deployed site is a real renderer of the engine's `PipelineEvent` stream, but the public Vercel
deployment replays a frozen verified run. It does not run Codex or accept a repository. The scanner
can inspect any local checkout, while the full compile-and-verify command currently assumes this
repository's demo layout and recorded ledger. There is no TUI, GitHub import flow, or bundled
CLI-to-dashboard server yet.

The intended product loop is: install the local CLI and capture shim, point it at a local checkout
(cloning an online repository first), run synthesis and sealed verification, then open the dashboard
as the report for that run. Wiring and packaging that end-to-end loop is the next engineering step.

## Run this prototype

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
