# PROMPTECTOMY - full handoff

Everything a human or a fresh agent needs to take this over. Written 18 July 2026, ~14:40 BST.
Repo: github.com/zippyg/codex-build-hack (private). Latest pushed: run `git log --oneline -5`.

## What it is
PROMPTECTOMY: point Codex at a repo, it finds the LLM calls that should be deterministic code, writes
the replacement, and PROVES equivalence by replaying recorded traffic on a sealed holdout the model
never saw; hot-swaps it in; keeps the calls that genuinely need a model. "The AI that writes the code
that makes the AI unnecessary." Built for the Codex Community Hackathon, London, 18 July 2026.

## Repo layout
- `engine/` - Python 3.12 (uv). The tool.
  - `promptectomy/contracts.py` - FROZEN Pydantic contracts (ledger, audit, verdict, PipelineEvent).
  - `promptectomy/shim.py` - monkeypatches `Responses.create`; records to the ledger; hot-swaps to a
    compiled engine when the registry enables it; 1% shadow guard. Callsite-id resolution is cached.
  - `promptectomy/ledger.py` - JSONL ledger, key-based secret redaction.
  - `promptectomy/scan.py` - Codex audit (`codex exec --output-schema`) + a static tag fallback.
  - `promptectomy/synthesize.py` - builds the `codex exec` synthesis call in a worktree; parses --json.
  - `promptectomy/worktrees.py` - git worktree per callsite (`pt/<id>`), staging, cleanup.
  - `promptectomy/splitting.py` - train/dev/holdout 60/20/20 by canonical-request hash (no leakage).
  - `promptectomy/scoring.py` - structured (canonical-JSON exact) + classifier (label agreement + macro-F1).
  - `promptectomy/replay.py` - runs a generated module under a 100ms SIGALRM timeout; scores it.
  - `promptectomy/guard.py` - AST purity guard: rejects forbidden imports/IO/eval BEFORE a generated
    module is imported. Wired into replay.load_engine and shim._engine (+ path confinement).
  - `promptectomy/verify.py` - parent-owned sealed-holdout verifier (runs once), emits the Verdict.
  - `promptectomy/schemas.py` - generates OpenAI-strict `--output-schema` JSON from the contracts.
  - `promptectomy/cli.py` - Typer: `run`, `scan`, `accept`, `disable`.
  - `promptectomy/generated/*.py` - the modules CODEX WROTE (committed as evidence).
  - `demo/triager/pipeline.py` - the demo app (3 tagged callsites). `traffic.py` + `capture.py` build
    a keyless synthetic ledger with text-derivable ground truth.
  - `tests/test_engine.py` - 7 pytest (scoring, split no-leakage, replay, ledger redaction, guard).
- `ui/` - Next.js (bun). The dashboard.
  - `lib/contracts.ts` - FROZEN Zod mirror of the PipelineEvent wire shape.
  - `lib/useEventStream.ts` - plays a fixture NDJSON with at_ms pacing (`?speed=`, `?until=`) OR a live
    EventSource. `lib/state.ts` - event reducer + beat derivation.
  - `fixtures/demo-run.ndjson` - the HONEST re-paced ~88s demo (real verdicts/numbers). THIS is what
    the stage plays. `fixtures/real-run.ndjson` - the raw real run it was built from.
  - `app/page.tsx`, `components/*` - the cockpit (MeterStrip, CallsiteWall, MainStage + stages/).
  - `tests/beats.spec.ts` - Playwright 8/8 (asserts the 6 beat states render + verdict colors).
- `docs/` - SUBMISSION.md (pitch, demo script, Q&A, boundaries, numbers), submission-answers.md
  (pasteable form fields), CONTRACTS.md, HANDOFF.md (this), specs/, source/ (the builder guide).
- `.agent/` - plans (DECISION-promptectomy.md, BUILD-PLAN.md, MASTER-PLAN.md), logs, memory, receipts.
  Ideation trail: `.claude/agent-logs/fable-*.md` and `.agent/artifacts/cx-*.md`.

## How to run
```bash
# engine
cd engine && uv sync
uv run python -m demo.triager.capture 240     # keyless synthetic ledger -> .promptectomy/ledger.jsonl
uv run promptectomy run .. --events jsonl     # scan -> synthesize in worktrees -> sealed-holdout verify (needs codex CLI logged in)
uv run promptectomy scan <any-repo>           # audit-only: find LLM callsites in any repo
uv run pytest -q                              # 7 green
# dashboard
cd ui && bun install && bun dev               # http://localhost:4319 (auto-plays fixtures/demo-run.ndjson)
```
No OPENAI_API_KEY needed (synthetic traffic). Codex synthesis uses the local `codex` CLI (logged in).

## Verified results (frozen demo dataset, real run)
extract_ticket_facts COMPILED 100% (52-case sealed holdout, ~900ms->0.006ms); route_ticket COMPILED
100% (60-case holdout, a negation-aware rule classifier); draft_empathetic_reply NOT_COMPILABLE.
Whole-pipeline cost -44.8%. Scanner on microsoft/markitdown @ e144e0a found its 3 vision/LLM callsites,
all correctly kept. Receipts in `.agent/artifacts/receipts/`.

## The demo (2 min, recorded replay = cannot stall)
Open the dashboard; it auto-plays the 6 beats (~88s). Retellable line: "Codex turned two prompts into
code, proved them against traffic it never saw, and kept the third because it still earned its tokens."
Full beat-by-beat + Q&A answers in docs/SUBMISSION.md. Live-run is a Q&A bonus, never the stage plan.

## State: 12 of 13 tasks done (see the session task list)
Done: contracts, engine, dashboard, tests, kill-gate, full pipeline, UI-real-run, security, perf,
public receipt, native render check, measured numbers. Open: #13 submit.

## What's LEFT (priority order)
1. DASHBOARD CLARITY + DE-AI (in progress, do this by direct edits, NOT a subagent - usage is tight):
   - CLARITY: add a plain-language NARRATOR line that changes per beat so a viewer with no context
     understands it (script drafted in SUBMISSION/chat). This is the top fix - "value obvious in 2 min".
   - IDENTITY: the dark+neon-green+mono look reads as generic-AI. Give it a distinctive, opinionated
     identity (candidate direction: clean surgical/clinical-editorial, on-theme with "-ectomy").
2. DEPLOY TO VERCEL: deploy `ui/` (Next) as a static recorded-replay so judges get a live shareable URL.
   The engine CANNOT run on Vercel (Python + codex + worktrees); the dashboard + bundled fixture can.
   `vercel` CLI 54.18.7 is installed and available. Deploy the FINAL (post-redesign) version.
3. SUBMIT (#13, human/day-of): get the organiser's London submission link (announced ~10:40); optional
   60-90s backup screen recording; fresh-start rehearsal; submit by 16:30 (buffer to 17:00). Paste from
   docs/submission-answers.md.

## Known boundaries (state them in the pitch; they are strengths)
- Generated code runs in-process (statically guarded by guard.py); production = out-of-process sandbox + rlimits.
- Agreement = preservation of recorded MODEL behaviour, not objective correctness.
- Traffic is synthetic-but-realistic (keyless); real capture uses the shim with an API key.
- Live shim hot-swap needs a captured real Response envelope; the demo shows the swap via the recording.
- Both compiled callsites are 100% (no diffs), so the demo shows clean COMPILED, not a forced diff beat.

## Usage / fleet notes
Conserve subagent usage (esp. Fable). Do remaining UI work by direct edits. Codex CLI is fine for
synthesis/scan. The security audit is in .claude/agent-logs/security-audit-20260718.md (semgrep clean;
keys scrubbed; holdout isolated; headline: in-process exec is a stated boundary).
