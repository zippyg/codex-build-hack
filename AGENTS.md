# codex-build-hack - Agent Guide (portable)

Cross-tool guidance (Claude Code + Codex both read this).

## Tooling
- Package manager: none yet. Choose only after the team selects an implementation stack, then respect its lockfile.
- Build/test/lint: no application exists yet. Record exact commands here when the stack is created.

## Working agreement
- Brutal honesty, evidence-backed, state confidence. No scope creep.
- Comments explain WHY not WHAT. Secrets via env only. No destructive commands.
- Match the planning tier to the change (tiny → just do it; feature → plan first).

## Memory & logs
- Curated memory: .agent/memory/  · raw logs: .agent/logs/YYYY-MM-DD/
- Active work: .agent/state/ACTIVE_PLAN.md, CURRENT_TASK.md
- Hackathon source of truth: docs/source/2026-07-18-builder-guide.md.
