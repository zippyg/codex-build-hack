# London submission form pack

Source checked live: 2026-07-18 16:13 BST.

Submission form: <https://demo-queue-tau.vercel.app/e/codex-community-hackathon-18th-july-2026-b29005>

Deadline: 17:00 BST sharp.

Status: **DO NOT SUBMIT FROM THIS FILE. Required human details and repository publication remain.**

## Required blockers

1. `https://github.com/zippyg/codex-build-hack` is currently **PRIVATE**. The form requires a public repository.

Also confirm the phone number, email, and at least one Twitter/X or LinkedIn profile. Do not guess them.

## Exact form-ready values

### Team name, maximum 80

`PROMPTECTOMY`

### Other team members

Leave blank if solo. The live guide explicitly encourages solo submissions. Otherwise list only registered and approved teammates, one per line, with no more than four total team members.

### Presenter and primary contact, maximum 60

`Zain Mughal`

### Project name, maximum 64

`PROMPTECTOMY`

### Project description, maximum 240

232 characters:

> PROMPTECTOMY uses Codex to find low-entropy LLM calls, write deterministic replacements, and verify them against unseen recorded traffic. The demo compiled two calls at 100% holdout agreement and kept the freeform call on the model.

### Public GitHub repository

`https://github.com/zippyg/codex-build-hack`

Do not use this value until GitHub confirms the repository is public. It was created during the event at 11:17 BST, which the Git history and GitHub creation timestamp prove.

### Phone number

`NEEDS ZAIN`

### Email

`NEEDS ZAIN`

### Category, optional, maximum 10

`devtools`

### Demo video

Primary local upload: `ui/output/submission/promptectomy-demo-elevenlabs.webm`

Verified locally: WebM, 82.52 seconds, 800x450 VP8 video, normalized ElevenLabs British voiceover in Opus, 4.6 MB, working product, no slides. The silent source remains at `ui/output/submission/promptectomy-demo-clean.webm`. The form stores the uploaded file for six months.

### Twitter/X or LinkedIn

`NEEDS ZAIN`

At least one is required.

## README-facing pitch

### Tagline

Codex removes the LLM calls that should be code, proves the replacements against traffic it never saw, and keeps the calls that still need a model.

### What genuinely works

1. A prototype shim can record synchronous, non-streaming OpenAI Responses calls to a local ledger.
2. In the event demo, Codex audits tagged callsites, receives train/dev fixtures in isolated Git worktrees, and writes deterministic Python replacements.
3. A parent process verifies each replacement against a holdout that was not staged into the synthesis worktree.
4. The demonstrated run compiled two low-entropy callsites at 100% holdout agreement and kept the freeform reply on the model.
5. The dashboard can replay that verified run or consume a local run's validated SSE event stream.
6. The supported shim compares sampled compiled and original outputs, then atomically disables a replacement on normalized drift.

### Results from the frozen event run

- `extract_ticket_facts`: COMPILED, 52/52 holdout cases, about 900 ms to 0.006 ms.
- `route_ticket`: COMPILED, 60/60 holdout cases, about 900 ms to 0.0005 ms.
- `draft_empathetic_reply`: NOT_COMPILABLE, correctly kept on the model.
- Whole-pipeline cost reduction: 44.79 percent.
- A scan of `microsoft/markitdown` found three vision/LLM callsites and kept all three.

### Honest boundary

The public dashboard is a recorded replay, not a hosted repository runner. Audit-only scanning works from an installed wheel against local checkouts and public Git URLs. General compilation still requires captured traffic and the supported synchronous OpenAI Responses adapter. There is no full-screen TUI or production sandbox. Generated code currently runs in-process and must not be used with untrusted repositories or real traffic.

## Judge Q&A

### Is the result a hardcoded animation?

The dashboard is a deterministic replay, but its evidence comes from a real engine run. Codex created two Python modules in isolated worktrees, and the parent process graded them on holdout fixtures that were not available during synthesis. The replay makes the 90-second video reliable; it does not fabricate the receipts.

### Is this a strawman?

The product targets only low-entropy extraction and classification callsites. It deliberately kept the freeform reply and all three multimodal callsites found in `microsoft/markitdown`. Agreement proves preservation of recorded model behaviour, not objective correctness.

### How is Codex central?

Codex is both the build tool and the prototype compiler. The repository was created during the event. In the product loop, Codex audits the target code, reads only train/dev fixtures, and writes each deterministic replacement in an isolated worktree. The parent verifier, not Codex, issues the holdout verdict.

### Why remove OpenAI calls at an OpenAI event?

The point is better allocation of inference. Spend powerful inference once on engineering, then reserve recurring model calls for tasks where generation is still valuable. The freeform call remains on OpenAI.

## Before Zain submits manually

- [ ] Make the GitHub repository public and verify it in a logged-out browser.
- [ ] Ensure the latest honest README and dashboard changes are committed and pushed.
- [x] An ElevenLabs-narrated upload-ready video exists at 82.52 seconds and 4.6 MB.
- [ ] Watch the uploaded file end to end before submission.
- [ ] Fill phone, email, and at least one social profile.
- [ ] Confirm team membership and registration.
- [ ] Open the public repo and live demo in a private browser window.
- [ ] Submit once and save the private status link.
