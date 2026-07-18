# Submission pack (fill measured numbers after the first clean run)

## Logistics (CONFIRM ON THE DAY)
- [ ] The exact London submission flow/link (announced ~10:40). THIS IS THE ONLY EXTERNAL BLOCKER.
- [ ] Team name + every member individually registered/approved.
- [ ] Repo link (private, add judges; or a clean public mirror if allowed).
- [ ] Submit by 16:30, buffer to 17:00. Do not code in the final window.

## One-liner
Point Codex at your app; it turns the LLM calls that should be code into tested deterministic code,
proves them against traffic the model never saw, and keeps the ones that still need a model.

## 90-second demo script (recorded-replay by default; live holdout replay is real)
- 0:00-0:10  Terminal: `promptectomy run`. Triager processing a ticket through 3 model callsites.
             Meters show baseline: p50 ~912ms, cost ticking per request.
- 0:10-0:20  The ledger + 3 audited callsite cards (1,240 recorded calls).
- 0:20-0:38  Real Codex activity trace: worktree lanes, the generated diff streaming in.
- 0:38-0:58  Sealed holdout runs LIVE: extract=COMPILED (green flood), route=COMPILED_WITH_DIFFS
             (one honest diff shown), reply=NOT_COMPILABLE (violet KEEP MODEL, the judgment beat).
- 0:58-1:13  Enable engines, rerun a fixed batch: latency crashes 912ms to ~3ms, per-callsite cost
             to $0.00, whole-pipeline cost down [MEASURED]%.
- 1:13-1:23  Force one shadow comparison; show the 1% runtime guard.
- 1:23-1:30  Close: "Codex turned two prompts into code, proved them against traffic it never saw,
             and kept the third because it still earned its tokens."

## Judge Q&A (rehearse)
Isn't this a strawman? We only compile low-entropy callsites. Codex never saw the sealed holdout,
every disagreement is exposed, and a real public-repo vision call was correctly refused. This proves
behavioural preservation against recorded traffic, not that the model was ground truth.

How is Codex central? Codex audits the repo, writes each replacement in an isolated worktree, repairs
it against train/dev tests, and produces a committed artifact. A verifier it cannot game then grades
that artifact against traffic Codex never saw.

Deleting OpenAI calls at an OpenAI event, good look? We spend powerful inference once on engineering,
then reserve recurring inference for the callsites where it earns its keep. The freeform reply still
uses OpenAI. Better allocation of inference, not anti-model theatre.

## Public receipt (kills the strawman)
- [ ] Scan a pinned commit of microsoft/markitdown; its OpenAI-assisted vision path should be marked
      keep-model. Label: "public repo audit, no traffic" (no recorded traffic = no equivalence verdict).

## Reliability checklist
- [ ] Cached synthetic ledger; saved real Codex event stream + generated commit + diff.
- [ ] Pre-warm python/next/import. Recorded real Codex trace for the demo; holdout replay + meters live.
- [ ] Full backup screen recording. Static verdict fixtures. Live model never on the 90s critical path.

## Measured numbers (fill after the clean run)
- Recorded calls: [ ] · Holdout N per compiled callsite: [ ] · Agreement: extract [ ], route [ ]
- Latency before/after: [ ]ms to [ ]ms · Whole-pipeline cost reduction: [ ]%
- Est. monthly savings shown: $[ ]
