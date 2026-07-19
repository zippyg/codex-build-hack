# Contributor and coding-agent guide

This file gives human contributors and repository-aware coding agents the same operating contract.

## Toolchains

- Engine: Python 3.12, `uv`, Pydantic, Typer, and pytest.
- Dashboard: Next.js, TypeScript, `bun`, and Playwright.
- Local isolation: an accepted OCI-compatible runtime. OrbStack is the primary macOS backend.

Use the repository lockfiles. Do not mix Python or JavaScript package managers.

## Verified commands

```bash
cd engine
uv sync --frozen
uv run pytest -q

cd ../ui
bun install --frozen-lockfile
bun run typecheck
bun run build
bunx playwright test
```

## Safety invariants

- Inspect, Audit, and Draft must not mutate or execute target repositories.
- Repository, generated, candidate, dependency, and test code must not run in the trusted core or clients.
- Draft output belongs in private tool-owned storage, never inside the target repository.
- Do not add a weaker fallback when isolation, policy, evidence, or freshness checks fail.
- Never expose credentials, protected content, raw exceptions, or host paths in events and reports.
- Apply must remain explicit, stale-checked, recoverable, and unable to target a default branch.
- Do not track generated replacements, local agent state, runtime data, screenshots, secrets, or submission artifacts.

## Change discipline

Read a file fully before editing it. Prefer the smallest change that closes a tested behavior. Add targeted tests for non-trivial logic. Security-sensitive changes require an explicit threat-boundary review. Public claims must map to current tests or evidence under `docs/architecture/`.

The accepted product boundaries are in [docs/product/vision-and-scope.md](docs/product/vision-and-scope.md). Architecture decisions live in [docs/adr/](docs/adr/).
