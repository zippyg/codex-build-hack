# London submission readiness

Live sources checked at 16:15 BST on 18 July 2026:

- form: <https://demo-queue-tau.vercel.app/e/codex-community-hackathon-18th-july-2026-b29005>
- guide: <https://warp-peach-ef6.notion.site/Builder-Guide-Codex-Community-Hackathon-39fbb741601b815ca33be80ba66fefd8>

Deadline: **17:00 BST sharp**.

Instruction: **do not submit automatically**.

## Current hard blockers

- [ ] GitHub repository is public. It was confirmed PRIVATE at 16:16 BST.
- [x] An ElevenLabs-narrated WebM exists at `ui/output/submission/promptectomy-demo-elevenlabs.webm`: 82.52 seconds, 4.6 MB, 800x450 VP8 video plus normalized Opus audio.
- [ ] Zain supplies phone, email, and at least one Twitter/X or LinkedIn profile.
- [ ] Zain confirms solo/team details and every teammate is registered and approved.

The form has no live-demo URL field. The public README must keep the demo link at the top.

## Form values

Use the exact field pack in `docs/submission-answers.md`. Its project description is 232 of the allowed 240 characters and `devtools` fits the 10-character category limit.

## 90-second recorded demo

Use the working dashboard, not slides. The verified narrated file is `ui/output/submission/promptectomy-demo-elevenlabs.webm`. The silent source is `ui/output/submission/promptectomy-demo-clean.webm`. The public site may lag behind the honest local copy.

### Voiceover and screen plan

- **0:00-0:08**: Open the dashboard. "Every app has model calls doing a parser's job. PROMPTECTOMY uses Codex to turn those calls into tested deterministic code."
- **0:08-0:20**: Show the request feed and baseline meters. "This verified run recorded 720 calls across extraction, routing, and freeform reply."
- **0:20-0:32**: Jump to Scan. "Codex audits the repository. It marks low-entropy extraction and classification as candidates and keeps freeform generation on the model."
- **0:32-0:47**: Jump to Compile. "Codex receives only train and dev fixtures in an isolated worktree, writes the replacement, and repairs it against visible cases."
- **0:47-1:03**: Jump to Judge. "The parent process now grades holdout traffic that was never staged into Codex's worktree: 52 of 52 and 60 of 60. The freeform reply is correctly refused."
- **1:03-1:18**: Jump to Swap. "Verified replay drops the two replaceable calls from about 900 milliseconds to microseconds and cuts whole-pipeline model cost by 44.79 percent."
- **1:18-1:26**: Jump to Guard. "Sampled shadow calls compare normalized outputs and atomically disable a replacement on drift. Out-of-process sandboxing is still required for production."
- **1:26-1:30**: Close. "Codex turned two prompts into code, proved them against traffic it never saw, and kept the third because it still earned its tokens."

### Recording checklist

- [ ] Capture 1920x1080 or 1440x900 with readable browser zoom.
- [ ] Show the actual interactive dashboard and controls.
- [ ] Do not show terminal secrets, notifications, unrelated tabs, or slides.
- [ ] Keep the final encoded duration below 90.0 seconds, not exactly on the boundary.
- [ ] Watch the exported file with sound from start to finish.
- [ ] Verify the file type and size before opening the form.

## Two-minute finalist version

If shortlisted, finalists get two minutes plus up to one minute of questions.

1. Problem and thesis, 15 seconds.
2. Baseline request feed and candidate audit, 25 seconds.
3. Codex worktree synthesis, 30 seconds.
4. Sealed-holdout verdicts, 25 seconds.
5. Cost and latency result, 15 seconds.
6. `microsoft/markitdown` negative control and honest boundary, 10 seconds.

## Judge Q&A

### Is the dashboard hardcoded?

It is a deterministic replay of a real engine event stream so the short video cannot stall. The engine produced the audit, worktree synthesis activity, generated modules, replay scores, and verdicts. The public site does not execute Codex or accept a repository.

### Did Codex see the answers?

Codex received train and dev fixtures only. The demonstrated holdout was not copied into its worktree. The current one-use guard is process-local, so the accurate claim is that the parent graded it once in the demonstrated run, not that the data can never be replayed again.

### Why did you keep one model call?

The freeform reply has open-ended generative value. PROMPTECTOMY targets low-entropy extraction and classification, not every use of AI. The external `microsoft/markitdown` scan also kept all three multimodal callsites.

### Why is Codex central?

Codex built the event project and acts as its prototype compiler. It audits target code, reads the visible executable specification, writes deterministic replacements in isolated Git worktrees, and repairs them against train/dev fixtures. The parent process owns the final demonstrated verdict.

### Is it safe for production?

No. The current event build is a single-user prototype using synthetic traffic. Production requires out-of-process generated-code execution, an allowlisted environment, artifact hash binding, durable holdout receipts, wider SDK coverage, and explicit activation controls.

## Verified receipts

- 720 synthetic-but-realistic ledger events, 240 tickets across three callsites.
- `extract_ticket_facts`: COMPILED, 52/52 demonstrated holdout cases.
- `route_ticket`: COMPILED, 60/60 demonstrated holdout cases.
- `draft_empathetic_reply`: NOT_COMPILABLE and kept on the model.
- Whole-pipeline cost reduction: 44.79 percent.
- `microsoft/markitdown` at `e144e0a`: three LLM/vision callsites found, all kept.
- Repository created on GitHub at 10:17 UTC during the event; first commit at 11:17 BST.

## Final manual sequence

1. Finish and verify the local changes.
2. Commit and push the honest implementation and README.
3. Deliberately make the repository public.
4. Verify README, clone command, demo link, and repository visibility in a logged-out browser.
5. Record or select the final video and verify duration, sound, and size.
6. Enter the form fields manually.
7. Review every value before submission.
8. Submit once, then save the private status link.
