# Submission pack

## Logistics (CONFIRM ON THE DAY)
- [ ] The exact London submission flow/link (announced ~10:40). THIS IS THE ONLY EXTERNAL BLOCKER.
- [ ] Team name + every member individually registered/approved.
- [ ] Repo link (private, add judges; or a clean public mirror if allowed).
- [ ] Submit by 16:30, buffer to 17:00. Do not code in the final window.

## One-liner
Point Codex at your app; it turns the LLM calls that should be code into tested deterministic code,
proves them against traffic the model never saw, and keeps the ones that still need a model.

## 90-second demo script (recorded replay of the verified run)
- 0:00-0:12  Establish the problem and baseline: 720 recorded calls across three callsites, about
             900ms per replaceable model call.
- 0:12-0:27  Show the three audited callsites and explain that the ledger is the executable spec.
- 0:27-0:48  Show the saved real Codex activity trace: isolated worktrees and generated modules.
- 0:48-1:08  Show the sealed-holdout receipts: extract 52/52 COMPILED, route 60/60 COMPILED, and
             freeform reply NOT_COMPILABLE. Codex never saw those holdout inputs.
- 1:08-1:23  Show measured replay results: compiled latency about 0.006ms and 0.0005ms, with
             whole-pipeline cost down 44.79%. State that this screen is a recorded run.
- 1:23-1:30  Close: "Codex turned two prompts into code, proved them against traffic it never saw,
             and kept the third because it still earned its tokens."

Do not claim that the public site runs Codex, performs a live SDK hot-swap, or automatically compares
shadow outputs. Those are product-direction screens around a recorded verified engine run.

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

## Public receipt (kills the strawman) - DONE
- Ran `promptectomy scan` on microsoft/markitdown @ e144e0a (public repo, no traffic). Codex found 3
  real LLM callsites and correctly marked ALL THREE keep_model: image-caption (_llm_caption.py),
  image-description (_image_converter.py), and vision OCR (_ocr_service.py). The tool refused to
  compile code it did not write, because those are genuinely multimodal. Receipt in
  .agent/artifacts/receipts/markitdown-audit.json (+ meta with the SHA).
- Judgment demonstrated on someone else's code. Offer a live scan of any public repo in Q&A.

## Reliability checklist
- [ ] Cached synthetic ledger; saved real Codex event stream + generated commit + diff.
- [ ] Pre-warm python/next/import. Recorded real Codex trace for the demo; holdout replay + meters live.
- [ ] Full backup screen recording. Static verdict fixtures. Live model never on the 90s critical path.

## Measured numbers (from the frozen demo run 0269a16, 720 recorded calls)
- Recorded calls: 720 (240 tickets x 3 callsites), synthetic-but-realistic (keyless).
- extract_ticket_facts: COMPILED, 100% agreement on a 52-case SEALED holdout, ~900ms -> 0.006ms.
- route_ticket: COMPILED, 100% agreement on a 60-case SEALED holdout, ~900ms -> 0.0005ms.
- draft_empathetic_reply: NOT_COMPILABLE (freeform, correctly kept as a model call).
- Whole-pipeline cost reduction: 44.79% (the kept freeform call is why it is not higher; honest).
- Real capture via the shim needs an OPENAI_API_KEY; the demo uses synthetic recorded traffic by design.
- The generated modules (regex parser + negation-aware rule classifier) are committed as evidence.

## Security posture (we threat-modeled our own tool; full audit in .claude/agent-logs/security-audit-20260718.md)
- API keys never reach the ledger: the shim drops extra_headers, never captures the client key, and
  redacts Authorization/api_key/secret/password/bearer. Verified by test.
- The Codex synthesis child runs with OPENAI_API_KEY scrubbed from its environment.
- The sealed holdout is never staged into the synthesis worktree; Codex cannot see it, and it runs once.
- Generated code is gated by a static purity guard (AST): forbidden imports (os/sys/subprocess/socket/
  importlib/...) and IO/eval builtins are rejected BEFORE the module is imported. Enforced, not prompted.
- The compiled module path is confined to the generated directory (no traversal / arbitrary load).
- Subprocess calls are argv-form (no shell); semgrep clean; no unsafe deserialization.
- Stated boundary (say it in the pitch): generated code still executes in-process; production would run
  it in an out-of-process sandbox with rlimits. Demo uses synthetic data, single user, no real PII.
