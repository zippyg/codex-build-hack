# Active Plan
## Goal
Ship PROMPTECTOMY: a Codex agent that removes LLM calls from a codebase and proves equivalence by
replaying real recorded traffic. Win the local London competition (2-min demo, 17:00 BST).

## Idea (LOCKED)
PROMPTECTOMY - see .agent/artifacts/plans/DECISION-promptectomy.md. Backup: UNDERSTUDY.

## Phases
- [x] Phase 1 - recover organiser constraints.
- [x] Phase 2 - select the idea (PROMPTECTOMY, confirmed 18 Jul).
- [ ] Phase 3 - build the critical loop: SDK shim + ledger, one callsite synthesized to GREEN on a
      withheld holdout via codex exec. Exit: one end-to-end callsite compiled + verified from a clean run.
- [ ] Phase 4 - full demo: 3 callsites (COMPILED / DIFFS / NOT COMPILABLE), hot-swap + latency/cost
      meters, shadow guard, streaming --json UI. Pre-run on a real public repo for receipts.
- [ ] Phase 5 - reliability + submission: rehearse 90s script, record backup run, prep submission links.
## Strategy
Parallel fleet: Codex (synthesis/replay backend in worktrees), Fable (streaming compare UI), Claude
(orchestrate + CLI + integration). Freeze the ledger + callsite + verdict schemas FIRST. Build demo +
submission assets in parallel, not at the end. Lean on OSS (Vercel AI SDK/AI Elements, openai SDK shim).
## Notes
Only live-AI moment is the synthesis stream (cacheable fallback); the equivalence proof is deterministic.
Kill-gate: if one callsite cannot compile+verify to green from a clean run early on, pivot to UNDERSTUDY.
