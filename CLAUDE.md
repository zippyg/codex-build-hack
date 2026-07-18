# codex-build-hack

Claude-specific entry point. Shared rules live in [AGENTS.md](AGENTS.md); read it too.

## Overview

PROMPTECTOMY, a Codex Community Hackathon prototype. The Python engine audits LLM callsites, asks Codex to synthesize deterministic replacements, and verifies them against sealed holdouts. The Next.js dashboard renders the engine event contract; the public deployment replays a frozen verified run.

## Stack
- Engine: Python 3.12, `uv`, Pydantic, Typer, pytest.
- Dashboard: Next.js 15, TypeScript, Zod, `bun`, Playwright.

## Key commands
- engine install: `cd engine && uv sync`
- engine test: `cd engine && uv run pytest -q`
- dashboard install: `cd ui && bun install`
- dashboard build/typecheck: `cd ui && bun run build`
- dashboard browser test: `cd ui && bunx playwright test`

## Architecture
The engine lives in `engine/promptectomy/`, the demo pipeline in `engine/demo/triager/`, and the dashboard in `ui/`. Contracts are mirrored between Pydantic and Zod. Read `.agent/state/STATUS_2026-07-18.md` for the current honest boundary before making product claims. The public dashboard is https://promptectomy.vercel.app and is a recorded replay, not a repository runner.

## Discipline
- Read before edit; surgical edits; no unrequested refactors.
- Tests around changed behavior. No decorative comments.
- Honesty: flag fatal flaws before implementing; state confidence.
