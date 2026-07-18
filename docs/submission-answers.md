# Pasteable submission answers (fill the form the moment the link is up)

Repo: https://github.com/zippyg/codex-build-hack (private; add judges, or flip to public at submit).
LIVE DEMO (public, shareable): https://promptectomy.vercel.app  (auto-plays; use the bottom bar to
play/pause and jump to any beat). Local: `cd ui && bun install && bun dev` then http://localhost:4319.

## Project name
PROMPTECTOMY

## Tagline (one line)
Codex removes the LLM calls that should be code, proves it against traffic the model never saw, and keeps the ones that still need a model.

## Elevator pitch (2-3 sentences)
Every app shipped since 2023 has LLM calls doing a parser's or a classifier's job: fast to prototype, never hardened, paying the token tax, the latency, and the nondeterminism forever. PROMPTECTOMY is the going-back, as an agent: Codex audits a repo, synthesizes deterministic replacements for low-entropy callsites, proves equivalence by replaying recorded traffic on a sealed holdout it never saw, and refuses the callsites that genuinely need a model. The first AI tool whose lifetime token count goes negative.

## The problem
Teams reach for a model because it is the fastest way to ship, then never revisit it. Low-entropy callsites (extract these fields, classify this ticket) stay as model calls: slow, costly, nondeterministic, and impossible to test. Going back by hand is tedious and risky, so nobody does it.

## What it does
1. A prototype shim records OpenAI Responses calls (input, output, latency, cost) to a local ledger. That recorded traffic becomes an executable spec. Turnkey installation into another app is not packaged yet.
2. `promptectomy run` scans the repo for LLM callsites (Codex audits it under a strict output schema).
3. For each candidate, Codex synthesizes a pure, deterministic replacement in an isolated git worktree.
4. Traffic is split train/dev/holdout (60/20/20). Codex iterates against train+dev and NEVER sees the holdout. A parent verifier runs the sealed holdout once and issues a verdict: COMPILED / COMPILED_WITH_DIFFS (every disagreement shown) / NOT_COMPILABLE (freeform, stays a model).
5. Compiled callsites are written into a registry-backed replacement path. The prototype records 1% shadow calls, but automatic comparison, drift disabling, and synthesis reopening remain future work.

## How we used Codex (this is the point)
Codex is the compiler and the surgeon, not a chat box. It audits the repository, writes each replacement in an isolated worktree, repairs its own code against the train/dev tests, and produces a committed code artifact with a diff and a saved activity trace. A verifier Codex cannot game then grades that artifact against traffic Codex never saw. We also built the project itself with Codex (terra for the engine) plus a Fable-model UI lane, orchestrated in parallel from a frozen contract.

## Results (real run, frozen as the demo dataset)
- extract_ticket_facts: COMPILED, 100% agreement on a 52-case sealed holdout, ~900ms -> 0.006ms.
- route_ticket: COMPILED, 100% on a 60-case sealed holdout (a negation-aware rule classifier, not a toy regex).
- draft_empathetic_reply: NOT_COMPILABLE, correctly kept as a model.
- Whole-pipeline cost -44.8% (honest: the kept freeform call is why it is not higher).
- Ran the scanner on microsoft/markitdown: found its 3 vision/LLM callsites and correctly kept all three.

## How we built it
Python 3.12 (uv) engine: SDK shim, ledger, scanner, worktree synthesis via `codex exec`, replay, scoring, sealed-holdout verifier, Typer CLI. Next.js (bun) dashboard: a live cockpit reading an NDJSON event stream. Contracts frozen in Pydantic + Zod. An AST purity guard enforces that generated code is stdlib-only with no IO before it is ever imported.

## Challenges
Making the proof ungameable (train/dev/holdout by canonical-request hash, holdout run once), getting Codex's `--output-schema` OpenAI-strict-valid so synthesis did not 400, and pacing a real ~108s run into an honest 90-second demo.

## What's next
Package the real local product loop: install the shim, point the CLI at a checkout, serve its event stream to the dashboard, and open the finished run as a report. Then add automatic shadow comparison, out-of-process sandboxing with rlimits, streaming and async callsite support, real production-traffic capture, and a shared registry of verified replacements.

## Honest boundaries (state them; they are strengths)
Agreement measures preservation of the recorded model's behaviour, not objective correctness. Generated code currently runs in-process (statically guarded); production would sandbox it out-of-process. Demo traffic is synthetic-but-realistic (keyless); real capture uses the shim with an API key. The public dashboard is a recorded replay, not a hosted repository runner.

## Try it
See README.md "Run it". The dashboard replays the real recorded run deterministically, so the demo cannot stall.
