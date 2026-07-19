# PROMPTECTOMY Phase 0 forward plan

Date: 2026-07-18
Status: complete; closure evidence in `docs/architecture/phase-0-review-resolution.md`
Execution boundary: architecture, decisions, schemas, threats, tests, governance, and handoff only
Product implementation: prohibited in this goal

## Objective

Convert the winning PROMPTECTOMY prototype and the post-hackathon design into an accepted, tracked, testable Phase 0 foundation for a safe open-source product. Completion means the product promise, authority model, supported matrix, target architecture, trust boundaries, contracts, evidence rules, UX contracts, testing strategy, open-source policy, and Phase 1A handoff are explicit enough that implementation no longer depends on hidden assumptions.

## Current truth

- Repository: `/Users/zain/Documents/codex-build-hack`.
- `HEAD` and `origin/main` were `8bab7bb` when this plan was prepared.
- The only visible working-tree change was `engine/promptectomy/generated/route_ticket.py`. It is user/live-demo work. Preserve it exactly and do not stage, restore, overwrite, commit, or infer its intended disposition.
- The Python engine is real but Python/OpenAI-specific. It captures a ledger, uses Codex for audit/synthesis, creates target-repository worktrees, self-checks train/development fixtures, and has the parent replay a sealed holdout.
- Generated Python still executes in-process. The AST guard is not a sandbox. The current product is no-go for untrusted or production workloads.
- The public Vercel dashboard is a recorded fixture replay. The local UI can consume a real local SSE stream, but there is no hosted repository runner or TUI.
- Current `.agent/artifacts/` drafts are ignored by Git. Accepted Phase 0 decisions must be promoted into tracked `docs/` files.
- Existing status files contain some stale statements. Direct Git/source inspection plus the post-hackathon audit are authoritative.

## Required read order

Read each item before writing decisions:

1. `AGENTS.md`
2. `.agent/state/STATUS_2026-07-18.md`
3. `.agent/artifacts/audits/repo-audit-2026-07-18-post-hackathon.md`
4. `.agent/artifacts/plans/design-promptectomy-open-source.md`
5. `.agent/artifacts/plans/ROADMAP-promptectomy-open-source.md`
6. `.agent/artifacts/reviews/architecture-pressure-test-2026-07-18.md`
7. `.agent/artifacts/audits/sec-promptectomy-generated-code.md`
8. `README.md`, `engine/pyproject.toml`, `ui/package.json`, and all current engine contracts/CLI/security/execution paths needed to verify factual claims

## Scope

### In scope

- Reconfirm exact Git and repository state without mutating it.
- Preserve the hackathon baseline as an identified commit and document the uncommitted generated-file boundary.
- Decide and document the product vision, users, use cases, non-goals, and L0-L5 capability ladder.
- Decide Inspect, Audit, Draft, Apply, and Integrate authority semantics.
- Decide the target architecture: Rust local control plane, language/provider adapters, SQLite/event store, content-addressed artifacts, CLI, TUI, Tauri GUI, static reports, executor interface, and Codex adapter.
- Decide stable v1 support and the rules by which future languages/providers become supported.
- Specify local/private/public Git acquisition and snapshot security.
- Specify telemetry, evidence, evaluation, privacy, protected content, source-code egress, storage, retention, deletion, and local-only behavior.
- Specify contract v2 entities, state machine, event envelope, compatibility, error taxonomy, receipt semantics, and type-generation strategy.
- Specify sandbox tiers, dependency acquisition, model-transport versus agent-tool authority, and fail-closed behavior.
- Specify prompt/versioning policy and bounded Codex agent roles.
- Specify GUI, TUI, CLI, report, review, and consent information architecture at a functional level.
- Specify the golden repository/trace corpus, hostile tests, performance budgets, SLO candidates, release gates, and manual acceptance.
- Decide the license recommendation, DCO/CLA path, governance, support policy, naming checks, and release/supply-chain policy.
- Run a disposable schema-generation proof using tool-owned examples only.
- Obtain independent architecture and security pressure tests, resolve findings, and prepare the Phase 1A goal.

### Out of scope

- Any product-code or runtime-behavior change.
- Any change to `engine/promptectomy/generated/route_ticket.py`.
- Running PROMPTECTOMY, generated code, builds, tests, Codex synthesis, or capture against a non-fixture repository.
- Creating the Rust workspace or implementing Rust/Python/TypeScript product code.
- Implementing the TUI, Tauri GUI, local daemon, SQLite store, executor, capture adapters, safe apply, hosted runner, CI integration, or runtime shadow/deployment lane.
- Deploying, submitting, publishing packages, changing Vercel, making repositories public, or writing to external services.
- Claiming trademark clearance or legal approval from a web search.

## Success criteria

- Every current-state claim is traceable to the repository, a direct command, or a primary source.
- No product source or existing user change is modified.
- Tracked documents define exactly what Inspect, Audit, Draft, Apply, and Integrate may read, write, execute, transmit, and persist.
- Stable v1 support is explicitly Python and TypeScript/JavaScript plus OpenAI Responses, with sync, async, streaming, tools, structured output, retry/error, and OTLP/OpenInference evidence expectations.
- Unsupported behavior is a typed outcome, never silent zero-work success.
- Remote Git acquisition has an explicit protocol, credential, config, submodule, LFS/filter, hook, redirect, quota, and cleanup policy.
- Source and trace egress require an explicit manifest and consent. Metadata-only is default; local-only mode is defined.
- Generated/repository code can never execute in the trusted core by design. Supported verified Draft requires an accepted executor and fails closed without one.
- V1 receipts are digest-bound, not falsely described as signed identity attestations.
- Contract examples validate through a disposable Rust/Python/TypeScript schema proof without creating product infrastructure.
- Every safety invariant maps to at least one automated or manual acceptance test.
- Architecture and security reviewers report no unresolved P0/P1 issue in the Phase 0 documents.
- A bounded Phase 1A goal exists and does not include executor isolation, hostile acceptance, Rust, TUI, or GUI work.

## Deliverable layout

Create tracked documents under these paths unless repo inspection reveals a stronger existing convention:

```text
docs/product/vision-and-scope.md
docs/architecture/system-design.md
docs/architecture/threat-model.md
docs/architecture/privacy-and-data-egress.md
docs/architecture/contracts-v2.md
docs/architecture/adapters-and-support.md
docs/architecture/testing-and-benchmarks.md
docs/architecture/ux-contracts.md
docs/architecture/phase-1a-handoff.md
docs/adr/0001-authority-and-non-mutation.md
docs/adr/0002-supported-v1-matrix.md
docs/adr/0003-control-plane-and-clients.md
docs/adr/0004-git-acquisition.md
docs/adr/0005-state-artifacts-and-receipts.md
docs/adr/0006-executors-and-agent-authority.md
docs/adr/0007-contract-v2.md
docs/adr/0008-open-source-governance.md
```

Avoid duplicating the 1,000-line draft verbatim. Tracked documents should be authoritative, navigable, cross-linked, and precise. Record rejected alternatives and consequences in ADRs.

## Phase 0.1: establish the immutable baseline

### Tasks

1. Run read-only Git status, log, branch/upstream, tracked-file, and diff summaries.
2. Confirm `HEAD`, `origin/main`, repository visibility where safely discoverable, lockfiles, current stacks, tests declared, and CI absence/presence.
3. Inspect but do not alter the `route_ticket.py` diff. Record that the baseline commit and working state differ.
4. Reconcile stale status statements in the new tracked current-state section. Do not rewrite historical logs just to make them look current.
5. Record what was verified now versus inherited from prior test receipts. Do not rerun product tests in Phase 0.

### Exit criterion

A reviewer can reproduce the exact starting state, and no file except Phase 0 planning/documentation artifacts has changed.

## Phase 0.2: freeze product and authority decisions

### Tasks

1. Define the product thesis: repository-to-evidence-to-patch, not a generic autonomous code fixer.
2. Define personas, core jobs, explicit non-goals, and the L0-L5 support ladder.
3. Define terminal run states: completed, completed-no-findings, completed-with-unsupported, failed, cancelled, and interrupted.
4. Define Inspect, Audit, Draft, Apply, and Integrate as separate capability grants.
5. State the invariants:
   - Inspect/Audit never write target repositories.
   - Draft writes only tool-owned storage.
   - Apply is explicit, branch-based, receipt-checked, previewed, and recoverable.
   - Untrusted code never runs in the core/UI process.
   - Agents never grant themselves authority.
6. Define the consent/preflight manifest: source, commit, paths, commands, executor, network, environment names, model, budget, egress, retention, cancellation, and cleanup.
7. Define honest product language and claims for the README/UI.

### Exit criterion

Every user action has a named authority level and a testable read/write/execute/transmit boundary.

## Phase 0.3: freeze the technical architecture

### Tasks

1. Specify the Rust core boundaries without creating the workspace:
   - durable orchestrator and policy engine;
   - SQLite job/event state;
   - content-addressed artifacts;
   - repository acquisition/snapshots;
   - executor and AgentRuntime interfaces;
   - versioned local API;
   - CLI and Ratatui clients;
   - Tauri/React desktop client;
   - static report renderer.
2. Specify what remains in Python and TypeScript during migration and how the Python prototype acts as a conformance oracle.
3. Specify the target stable v1 matrix and adapter conformance levels.
4. Specify repository ingestion:
   - explicit HTTPS/SSH/local/archive inputs;
   - no external helpers or file/ext protocols by default;
   - neutral system/global Git config;
   - no submodule recursion or LFS/smudge/filter execution by default;
   - isolated credential broker;
   - path/symlink/archive/redirect/size/time/output controls.
5. Specify stable callsite fingerprints and cross-commit relocation confidence.
6. Specify OTLP/OpenInference ingestion, Python/Node capture, metadata-only defaults, protected content, and source minimization.
7. Specify evidence grades, duplicate grouping, temporal/group holdouts, behavior/contracts/domain-truth evaluation, sample thresholds, and price versioning.
8. Specify executor tiers: Audit-only without isolation, OCI for native builds, WASI for compatible pure functions, stronger hosted isolation later.
9. Separate Codex model transport from agent tools. Model credentials cannot enter child environments; repository tools stay offline.
10. Specify Codex roles, typed outputs, budgets, attempts, cancellation, prompt registry, untrusted-context delimiters, and hidden-holdout separation.

### Exit criterion

All major components have one owner, interface, input/output contract, failure behavior, trust zone, and migration boundary. Rejected alternatives are recorded.

## Phase 0.4: freeze contracts, UX, threats, and verification

### Tasks

1. Define contract v2 entities and invariants for repository, snapshot, authority, run, event, callsite, observation, finding, candidate, evaluation, patch, artifact, receipt, and error.
2. Define state transitions, idempotency, sequence/cursor rules, recovery, cancellation, and compatibility/versioning.
3. Define V1 receipt limits: digest-bound local consistency, not identity signature. Defer signed evaluation receipts until key identity/storage/rotation/revocation policy exists.
4. Build a disposable schema proof outside product code. Validate representative examples from Rust, Python, and TypeScript and retain only the decision/results needed for the ADR.
5. Define CLI commands and stable JSON/exit-code behavior.
6. Define TUI screens and keyboard/plain-mode requirements.
7. Define GUI import, preflight, run, inventory, finding, candidate, agent-office, apply, history, and settings flows.
8. Define report contents and JSON, Markdown, HTML, NDJSON, SARIF, JUnit, patch, and receipt exports.
9. Complete the threat model for malicious repositories, prompt injection, generated-code escape, Git/archive import, secrets, local API/Tauri, trace privacy, terminal output, supply chain, resource exhaustion, holdout leakage, stale apply, and artifact tampering.
10. Define the golden fixtures, malicious corpus, privacy canaries, property/contract/integration/E2E/chaos/security tests, performance budgets, SLO candidates, and release blockers.
11. Define license recommendation, dependency-license review, DCO/CLA decision process, governance, support window, vulnerability reporting, naming checks, signed releases, SBOM, SLSA provenance, and attestations.

### Exit criterion

Representative contracts validate, every threat maps to controls and tests, every client maps to the same core contract, and every release claim has an acceptance gate.

## Phase 0.5: pressure-test, decide, and hand off

### Tasks

1. Run a fresh architecture review focused on contradictions, unnecessary complexity, sequencing, cross-platform assumptions, and migration risk.
2. Run a security review focused on authority, Git acquisition, data egress, model/tool credentials, local IPC, executor design, apply integrity, protected storage, and supply chain.
3. Resolve every P0/P1 finding. Record accepted P2/P3 debt with an owner and phase.
4. Make a final consistency pass across diagrams, ADRs, terminology, capability levels, phase names, and supported claims.
5. Confirm no product code or pre-existing user change was modified.
6. Write `docs/architecture/phase-1a-handoff.md` and a separate Phase 1A `/goal` input. Phase 1A covers only non-mutating command semantics and unverified patch artifacts. It must not start Phase 1B isolation or Phase 1C hostile acceptance.
7. Update the authoritative project status to point to the accepted tracked documents and clearly mark historical hackathon statements as historical.

### Exit criterion

Phase 0 is independently reviewable, tracked, internally consistent, free of unresolved P0/P1 findings, and ready for a separate Phase 1A implementation decision.

## Risks and blockers

| Risk or decision | Handling |
|---|---|
| The `route_ticket.py` change has no declared disposition | Preserve it untouched. Record the boundary. Ask Zain only if a tag/commit decision truly requires it |
| Architecture expands into premature implementation | Enforce the out-of-scope list and inspect the diff before every phase exit |
| “Any codebase” becomes an unsupported marketing claim | Use the L0-L5 ladder and target stable v1 matrix everywhere |
| OCI availability varies | Define fail-closed Audit/unverified-Draft behavior; do not implement the backend in Phase 0 |
| Codex needs network but agent tools must not have it | Specify a trusted model connector and separate offline tool executor; reject runtimes that cannot separate credentials |
| Protected data encryption design becomes homemade crypto | Specify reviewed envelope/AEAD and OS credential storage requirements; defer implementation |
| Apache-2.0 or the name is not legally cleared | Recommend with explicit legal/namespace gates; do not assert clearance |
| Tauri is mistaken for a sandbox | State that capabilities limit IPC but untrusted execution belongs in the executor |
| Phase 0 produces duplicate, ignored prose | Promote concise accepted truth to tracked docs and link to historical drafts |
| A schema spike turns into the Rust rewrite | Run it in disposable tool-owned storage, retain conclusions only, and verify no workspace was created |

## Manual decisions needed

These decisions should be presented with a recommendation and tradeoffs. Continue with the documented default if Zain does not respond and the choice is reversible and does not widen authority. Stop if a decision changes legal commitment, data egress, execution authority, or supported release claims.

1. Stable v1 support: recommend Python and TypeScript/JavaScript plus OpenAI Responses.
2. License: recommend Apache-2.0 subject to legal and dependency review.
3. Contributions: recommend DCO initially unless legal/governance requires CLA.
4. Protected content: recommend metadata-only default and fail-closed capture without secure key storage.
5. Executor: recommend OCI for local native verification, WASI for compatible pure functions, and Audit-only fallback.
6. Product name: retain PROMPTECTOMY during development, but require legal and package-namespace clearance before release.
7. Existing generated-file diff: do not decide or alter without Zain’s explicit instruction.

## Definition of done

- [x] Exact repository baseline and working-tree boundary recorded.
- [x] All required tracked product, architecture, threat, privacy, contract, adapter, UX, testing, and ADR documents exist.
- [x] Product modes and L0-L5 support are unambiguous.
- [x] Stable v1 matrix and future adapter conformance rules are explicit.
- [x] Remote Git, source/trace egress, protected storage, executor, and Codex authority policies are explicit.
- [x] Contract v2 entities, state machine, errors, receipts, and compatibility are specified.
- [x] Disposable Rust/Python/TypeScript schema proof is recorded without creating product code.
- [x] GUI, TUI, CLI, report, apply, agent-office, and consent UX contracts are specified.
- [x] Threats, controls, acceptance tests, SLOs, benchmarks, and release blockers are traceable.
- [x] OSS license/governance/name/supply-chain gates are documented honestly.
- [x] Architecture and security reviews have no unresolved P0/P1 issue.
- [x] `route_ticket.py` and all product source remain untouched by Phase 0.
- [x] Authoritative status points to tracked Phase 0 documents.
- [x] Separate Phase 1A plan and goal input are ready but not executed.
