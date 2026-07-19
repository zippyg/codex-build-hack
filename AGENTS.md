# codex-build-hack - Agent Guide (portable)

Cross-tool guidance (Claude Code + Codex both read this).

## Tooling
- Engine: Python 3.12 with `uv`; run commands from `engine/`.
- Dashboard: Next.js 15 with `bun`; run commands from `ui/`.
- Engine install/test: `uv sync`, then `uv run pytest -q`.
- Dashboard install/build/test: `bun install`, `bun run build`, then `bunx playwright test`.
- Live dashboard: https://promptectomy.vercel.app. This is a recorded replay, not a hosted engine.

## Working agreement
- Brutal honesty, evidence-backed, state confidence. No scope creep.
- Comments explain WHY not WHAT. Secrets via env only. No destructive commands.
- Match the planning tier to the change (tiny → just do it; feature → plan first).

## Memory & logs
- Curated memory: .agent/memory/  · raw logs: .agent/logs/YYYY-MM-DD/
- Active work: .agent/state/ACTIVE_PLAN.md, CURRENT_TASK.md
- Current takeover truth: .agent/state/STATUS_2026-07-19.md
- Hackathon source of truth: docs/source/2026-07-18-builder-guide.md.
