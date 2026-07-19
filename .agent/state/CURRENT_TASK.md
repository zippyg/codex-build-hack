# Current Task

## Phase 1A: honest non-mutating Python reference

Implement `docs/architecture/phase-1a-handoff.md` against the existing Python package.

Required outcome:

- explicit `doctor`, `inspect`, `audit`, `draft`, `status`, and JSON/Markdown report semantics;
- Inspect, Audit, and Draft preserve target tree and Git state across all terminal paths;
- no repository/generated/test/dependency code executes on these general paths;
- direct no-tool OpenAI Responses connector with schema-constrained output and fail-closed unavailable behavior;
- unverified patch/test artifacts only in private tool-owned storage;
- typed terminal states/errors, safe append-only events, support/unsupported accounting, receipt/retention/cleanup metadata;
- clean installed-wheel, privacy-canary, path-confinement, zero-work, cancellation, and legacy-path reachability tests.

Do not start Phase 1B executor work. Preserve `engine/promptectomy/generated/route_ticket.py` exactly.
