# Phase 1A implementation handoff

Status: ready for a separate implementation goal, not started
Prepared: 18 July 2026
Boundary: safe non-mutating Python reference behavior and unverified patch artifacts only

## Outcome

Phase 1A turns the current hackathon CLI into an honest reference implementation of the accepted authority model. A user can inspect and audit a supported repository, request an explicitly unverified candidate patch, inspect durable safe artifacts, and receive a typed terminal outcome. The target checkout remains byte-for-byte unchanged.

Phase 1A does not make PROMPTECTOMY safe for generated-code execution or production use. It creates the behavioral oracle that later isolation, Rust, TUI, and GUI phases must match.

## Required reading

Read in this order before editing:

1. `AGENTS.md`
2. `.agent/state/STATUS_2026-07-18.md`
3. `docs/product/vision-and-scope.md`
4. `docs/adr/0001-authority-and-non-mutation.md`
5. `docs/adr/0002-supported-v1-matrix.md`
6. `docs/adr/0004-git-acquisition.md`
7. `docs/adr/0005-state-artifacts-and-receipts.md`
8. `docs/adr/0006-executors-and-agent-authority.md`
9. `docs/architecture/system-design.md`
10. `docs/architecture/adapters-and-support.md`
11. `docs/architecture/privacy-and-data-egress.md`
12. `docs/architecture/contracts-v2.md`
13. `docs/architecture/threat-model.md`
14. `docs/architecture/testing-and-benchmarks.md`
15. `docs/architecture/ux-contracts.md`

Treat the tracked Phase 0 documents as target behavior and the current source as migration input. If they conflict, do not silently preserve the prototype behavior.

## Immutable entry boundary

- Expected entry commit: `8bab7bba966030e9c84af86352dc4a70e8462d4f` unless the branch has deliberately advanced with Phase 0 documentation.
- `engine/promptectomy/generated/route_ticket.py` is pre-existing user/live-demo work. Its Phase 0 entry SHA-256 is `a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c`.
- Never stage, restore, overwrite, commit, regenerate, format, or decide the disposition of that file. Recheck its digest before and after every implementation batch.
- Preserve unrelated user changes. Use a dedicated `zc/` branch or an isolated worktree only after confirming that doing so cannot absorb the generated-file change.

## In scope

### 1. Explicit command semantics

Expose the Phase 1A subset through the existing Python/Typer package:

```text
promptectomy doctor [source] [--json]
promptectomy inspect <source> [--json]
promptectomy audit <source> [--policy <file>] [--json]
promptectomy draft <source> [--policy <file>] [--json]
promptectomy status [run-id] [--json]
promptectomy report <run-id> --format json|md
```

Aliases for the hackathon `scan` command may remain temporarily, but machine output must identify the canonical operation. The legacy `run` command must not claim general success or silently retain unsafe synthesis semantics. Either map it to a clearly named compatibility path limited to the synthetic demo or fail with a typed migration message.

### 2. Inspect and Audit

- Inspect inventories source identity, revision, language/provider surfaces, evidence availability, support levels, exclusions, and unsupported areas.
- Audit performs supported static reasoning and may use the trusted model connector only under an explicit egress manifest.
- Neither mode writes the target checkout, Git index, refs, config, hooks, worktrees, untracked set, or nested repositories.
- Neither mode imports repository modules, runs repository commands, resolves dependencies, executes hooks/filters, or launches generated code.
- Local path handling is the Phase 1A acceptance path. Public remote Git may remain explicitly unsupported until the acquisition boundary is refactored to meet ADR 0004.

### 3. Draft-unverified

- Draft starts only after explicit command intent and a recorded authority manifest.
- Snapshot and candidate work live under private tool-owned storage outside the target checkout and its `.git` directory.
- The accepted Phase 1A transport is a direct OpenAI Responses request to an API-available Codex coding model from the trusted connector. It receives only egress-manifest-approved source slices, omits all tools, and returns strict schema-constrained candidate data.
- `codex exec`, Codex SDK threads, MCP, shell, filesystem, web, hosted-shell, apply-patch, and computer-use tools are forbidden on the general Phase 1A Draft path. The current `workspace-write` synthesis subprocess cannot be reused.
- Record the configured/returned model, reasoning setting, prompt/schema/content-manifest digests, response ID, usage, budget, and policy outcome without persisting credentials or raw protected content in safe state.
- If no direct no-tool Codex Responses transport is configured, the model lacks required structured output, the egress manifest is absent, or the request cannot meet the budget, return `safe_agent_transport_unavailable` or a more specific typed policy error and create no candidate patch.
- Generated code, patch code, repository code, tests, dependency installers, and build tools do not execute.
- Output is a patch plus proposed tests, evidence, limitations, and a Candidate state of `unverified`.
- Any path outside the immutable snapshot, unexpected patch target, malformed agent output, missing policy, or unavailable authority fails closed.
- No compatibility fallback may invoke the current in-process synthesis/replay path.

### 4. State, artifacts, and reports

Phase 1A may use a narrow Python store before Contract v2 and SQLite land, but it must provide the same observable invariants:

- tool-owned run directory with owner-only permissions;
- immutable source/snapshot digest and recorded authority manifest digest;
- append-only safe NDJSON events with run-local sequence starting at 1;
- terminal status from the accepted set;
- typed errors and stable machine output;
- content-addressed candidate patch and report artifacts;
- explicit support coverage, unsupported areas, evidence grade, and limitations;
- digest-bound local receipt language, never `signed` or `attested` identity language;
- deletion/retention metadata and deterministic cleanup status.

Do not persist raw credentials, full environment values, arbitrary exception strings, unredacted remote locators, raw prompt content, source bodies in safe events, or captured request/response bodies without a separate protected-content policy.

## Out of scope

- OCI, WASI, microVM, or any generated/repository code execution.
- Verified Draft, candidate evaluation, sealed holdout replay, or performance/cost replacement verdicts.
- Phase 1B isolation, Phase 1C hostile installed-wheel acceptance, Apply, Integrate, hot-swap, or runtime interception.
- Private Git credential brokering, recursive submodules, LFS/filter execution, archive import, or hosted repositories.
- Rust workspace, daemon, SQLite/event-store migration, local HTTP API, TUI, Tauri GUI, hosted runner, deployment, or package publishing.
- Expansion beyond Python and TypeScript/JavaScript OpenAI Responses support definitions.
- Public-repository, license, trademark, release, or production-readiness claims.

## Implementation sequence

1. Capture the baseline: Git state, route-ticket digest, current CLI paths, write sites, execution sites, event contracts, and tests.
2. Add failing authority/non-mutation tests around local fixture repositories before changing commands.
3. Introduce the minimum explicit mode, terminal-status, typed-error, support-summary, and authority-manifest models needed by Phase 1A.
4. Separate source inspection from acquisition, synthesis, execution, and target-repository output paths.
5. Implement `doctor` and `inspect` with complete supported/unsupported accounting.
6. Implement `audit` without repository execution or mutation. Make zero performed work a typed no-findings/unsupported/failure outcome, never generic success.
7. Implement the direct no-tool Responses connector and `draft` parser. Prove with an injected HTTP/client test double that no tool field, ambient environment, unapproved content, or uncontrolled destination enters the request. Parse schema-constrained output into a patch artifact without applying or executing it. Any live synthetic connector probe is optional and requires explicit user approval and egress consent.
8. Implement safe event persistence, status, JSON/Markdown report projection, receipt digest, retention metadata, and cleanup state.
9. Quarantine or explicitly gate legacy demo-only synthesis so it cannot be reached by general commands.
10. Run the focused fixtures, installed-wheel checks relevant to changed behavior, non-mutation digest tests, privacy canaries, and a final diff/security review.

Do not introduce broad abstractions merely because the target architecture later uses Rust. Phase 1A is a small, testable Python conformance oracle.

## Required acceptance fixtures

Use synthetic fixture repositories only. At minimum:

1. clean supported Python/OpenAI Responses callsite;
2. clean supported TypeScript/OpenAI Responses callsite for inspect/support accounting, even if Draft generation remains adapter-limited;
3. mixed supported and unsupported SDK surfaces;
4. no LLM callsites;
5. malformed source and permission-denied source;
6. dirty Git checkout with staged, unstaged, and untracked files;
7. symlink/path-traversal and nested repository cases;
8. prompt-injection strings in filenames, comments, source, and captured metadata;
9. privacy canaries in source, environment names, locator credentials, exceptions, and fixture payloads;
10. Codex timeout, invalid JSON, unknown schema version, over-budget output, and cancellation.

For every fixture, hash the target files, index, refs, config, hooks, worktree list, and untracked inventory before and after. Inspect, Audit, and Draft pass only when these are unchanged.

## Required tests and gates

The implementation must leave runnable tests for these Phase 0 IDs:

- `INV-AUTH-01..04` and `INV-NM-01..03` for Inspect/Audit/Draft-unverified, cancellation, and explicit unsupported/zero-work behavior;
- `GIT-*` cases applicable to local-path non-mutation and path confinement;
- `AGENT-*` for schema-constrained output, offline tools, credentials, prompt injection, budgets, cancellation, and holdout absence;
- `CONNECTOR-01..10` for exact endpoint/model/schema, omitted tools, content minimization, credential/log isolation, budget, timeout/cancel, and fail-closed unsupported transport;
- `STATE-*`, `CONTRACT-*`, `RECEIPT-*`, `CLI-*`, `REPORT-*`, and `PRIV-*` applicable to the Phase 1A store;
- explicit regression for no false zero-work success;
- build/install a clean wheel in a disposable environment and prove its Phase 1A schemas/assets load.

No test may require a real private repository, real customer trace, production endpoint, secret, or host execution of untrusted code. A human-readable demo is useful but is not acceptance evidence.

## Evidence required at handoff

- exact before/after Git state and route-ticket digest;
- changed-file inventory grouped by behavior, tests, and docs;
- command/test receipts with pass, fail, and skipped counts;
- mutation-digest receipt for every fixture and mode;
- safe sample JSON output for each terminal status exercised;
- installed-wheel result from a fresh disposable environment;
- privacy-canary result;
- architecture and security review findings with every P0/P1 resolved;
- explicit list of deferred Phase 1B/1C/Rust/client work.

## Rollback

Phase 1A must be reversible as one documentation-referenced implementation change. It must not migrate user data, edit external repositories, deploy, or make irreversible state. If the new general commands cannot meet non-mutation and no-execution gates, retain them as failing/unsupported and keep the hackathon demo path separately labelled. Never regain functionality by falling back to in-process generated-code execution.

## Definition of done

- General `inspect`, `audit`, and `draft` semantics match the authority table.
- Draft creates only an `unverified` patch artifact in tool-owned storage.
- Target repositories are byte-for-byte and Git-state unchanged across all three modes.
- Unsupported and insufficient-evidence outcomes are typed and visible.
- Machine output, terminal state, event sequence, receipt wording, report projection, and exit classes are deterministic.
- Privacy canaries and agent credential/tool-isolation tests pass.
- A clean installed wheel works for the Phase 1A surface.
- No isolation, evaluation, Apply, Rust, TUI, GUI, deploy, publish, or public-release work has started.
- The pre-existing `route_ticket.py` change is exactly preserved.
- Fresh architecture, security, and diff reviews have no unresolved P0/P1.

The bounded, copyable implementation input is [phase-1a-goal.txt](phase-1a-goal.txt). It is an instruction artifact only and was not executed during Phase 0.
