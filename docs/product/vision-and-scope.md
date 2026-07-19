# PROMPTECTOMY product vision and scope

Status: accepted Phase 0 decision
Decision date: 18 July 2026
Baseline: `8bab7bba966030e9c84af86352dc4a70e8462d4f`

## Product contract

PROMPTECTOMY is a local-first, proof-first laboratory for finding LLM callsites that can be made cheaper, faster, safer, or more deterministic without silently changing required behavior.

The stable product promise is:

> Give PROMPTECTOMY a repository and optional evidence. It inventories supported LLM callsites without modifying the repository, grades the evidence, develops candidates only in tool-owned isolated storage, evaluates them against explicit contracts and holdouts, and returns a reviewable patch, tests, report, and digest-bound receipt. It does not apply or deploy anything without a separate explicit action.

PROMPTECTOMY is repository-to-evidence-to-patch infrastructure. It is not a generic coding-agent IDE, a universal optimizer, an observability backend, or an automatic deployment system.

## Current baseline

Phase 0 was designed against these directly verified facts:

- `HEAD` and `origin/main` both resolve to `8bab7bb` on branch `main`.
- GitHub reports `zippyg/codex-build-hack` as private. Open-sourcing is a future release action, not a current fact.
- The only modified product file at Phase 0 entry is `engine/promptectomy/generated/route_ticket.py`. Its entry SHA-256 is `a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c`. It is preserved as user/live-demo work and is outside Phase 0.
- The Python prototype captures a JSONL ledger, invokes Codex for audit and synthesis, creates Git worktrees in the target repository, lets Codex self-check train/development fixtures, and lets the parent process replay the sealed holdout.
- The prototype writes fixtures, events, a registry, and generated Python inside the target checkout. It imports generated Python into the parent process. The AST guard is defense in depth, not isolation.
- The Next.js application can replay an event fixture or consume a local SSE stream. The public Vercel application is a recorded replay, not a hosted repository runner.
- There is a Typer CLI and human event output. There is no full-screen TUI, Rust control plane, durable run database, private-repository broker, or safe general-purpose executor.
- Python uses `uv` with `engine/uv.lock`; the dashboard uses Bun with `ui/bun.lock`. There is no tracked Rust workspace or CI workflow.

No Phase 0 document upgrades those prototype capabilities. Target behavior becomes real only after its acceptance tests pass in the implementation phase named by the roadmap.

## Users and jobs

| User | Primary job | Required outcome |
|---|---|---|
| Individual developer | Understand LLM use in a local repository | Honest inventory, support limits, evidence gaps, no source mutation |
| Application team | Reduce cost or latency safely | Candidate patch, tests, evaluation detail, quantified uncertainty |
| Platform engineer | Migrate models/providers or standardize usage | Stable callsite identities, comparable evidence, provider-neutral reports |
| Security/reliability engineer | Review agent and LLM changes | Authority record, provenance, threats, isolated results, reproducible receipt |
| Maintainer/reviewer | Evaluate an optimization contribution | Small reviewable diff, explicit evaluators, limitations, replayable evidence |

The core jobs are inventory, evidence correlation, opportunity classification, isolated candidate development, rigorous evaluation, report/export, explicit branch-based apply, and later re-evaluation under drift.

## Capability ladder

Support is reported per snapshot, callsite, language, provider, operation, and adapter version. A repository never receives one vague supported/unsupported label.

| Level | Name | Required proof |
|---|---|---|
| L0 | Inventory | Languages, manifests, provider dependencies, exclusions, and coverage are reported without executing the repository |
| L1 | Static discovery | A stable adapter identifies callsites and symbols with a coverage report |
| L2 | Evidence-linked analysis | Normalized observations are correlated to callsites with confidence and privacy policy |
| L3 | Isolated evaluation | Candidate and applicable repository checks execute in an accepted executor under a declared manifest |
| L4 | Reviewable remediation | Patch, tests, evaluation, limitations, and digest-bound receipt are complete |
| L5 | Integration | An explicitly installed CI, shadow, or deployment integration monitors an accepted change |

Rules:

1. A run displays the highest level actually reached and a reason code for every blocked higher level.
2. L0 on an unsupported language is valid. It cannot be presented as successful optimization.
3. Codex understanding a language does not grant adapter support.
4. Stable means the declared conformance matrix passes on every claimed platform. Experimental means useful but not release-blocking. Unsupported is a typed outcome.

## Operating modes and terminal states

Modes are separate authority grants, not UI stages:

- Inspect: deterministic inventory and support report. No target writes or repository execution.
- Audit: read-only analysis and evidence gaps. No target writes or repository execution by default.
- Draft: patch and test artifacts in tool-owned storage. Repository/generated code may execute only in an accepted isolated executor. Until that exists, output is explicitly unverified.
- Apply: a new, explicit action that checks snapshot/receipt integrity, previews the diff, targets a named non-default branch, creates a recovery reference, and runs only approved checks in isolation.
- Integrate: a separately installed and separately threat-modeled CI, shadow, or deployment connection.

Terminal run states are `completed`, `completed_no_findings`, `completed_with_unsupported`, `failed`, `cancelled`, and `interrupted`. Silent success with zero work is forbidden. Each terminal state carries performed work, skipped/unsupported work, cleanup state, and retained artifact references.

The complete read/write/execute/transmit/persist matrix is authoritative in [ADR 0001](../adr/0001-authority-and-non-mutation.md).

## Stable v1 promise

Stable v1 is intentionally narrow:

- Languages: Python and TypeScript/JavaScript.
- Provider surface: OpenAI Responses.
- Operation coverage: synchronous, asynchronous, streaming, structured output, tool calls, retries, and errors.
- Evidence: OTLP import plus OpenTelemetry GenAI/OpenInference normalization when callsite correlation exists; metadata-only capture by default.
- Product surfaces: one shared local core exposed through CLI, TUI, Tauri desktop GUI, and static reports. These clients arrive in phases and cannot diverge in authority semantics.
- Default remediation: a patch artifact. Runtime hot-swap is not part of the stable v1 default path.
- Hosting: no hosted private-repository execution in v1.

The detailed support and conformance contract is in [adapters and support](../architecture/adapters-and-support.md) and [ADR 0002](../adr/0002-supported-v1-matrix.md).

## Non-goals and forbidden claims

Version 1 does not claim:

- any-repository or any-language L1-L4 support;
- semantic truth from agreement with prior model output alone;
- a production sandbox from AST filtering, Tauri capabilities, a Git worktree, or an ordinary subprocess;
- private-repository confidentiality without the documented acquisition and egress controls;
- zero cost, automatic deployment, automatic default-branch writes, or automatic production hot-swap;
- cryptographic identity from a digest-bound local receipt;
- signed evaluation receipts before signer identity, key lifecycle, verification, and revocation are designed;
- legal clearance for the PROMPTECTOMY name or Apache-2.0 until the named gates are complete.

Approved public wording uses "supported Python and TypeScript/JavaScript OpenAI Responses callsites" and always shows the L0-L5 result. "Any repo" is prohibited except as an input claim qualified by an honest L0 inventory result.

## Success measures

The product is successful when it can prove all of the following on the declared acceptance corpus:

1. Inspect, Audit, and Draft do not change the source checkout.
2. Untrusted/generated code never executes in the core or client process.
3. Every supported claim has a source snapshot, policy, evidence grade, evaluator manifest, tool version, and artifact digest.
4. Every unsupported or insufficient-evidence area is visible and machine-readable.
5. Identical declared inputs produce equivalent safe projections across CLI, TUI, GUI, JSON, Markdown, HTML, SARIF, and JUnit.
6. Cancellation, interruption, and cleanup are coherent and leave no orphan workers.
7. Source, trace, credentials, protected content, and model transport follow explicit least-authority grants.
8. A user can review and export without granting Apply.

Actual thresholds and test IDs are defined in [testing and benchmarks](../architecture/testing-and-benchmarks.md). Product language follows evidence, not aspiration.

## Decision map

- System ownership and migration: [system design](../architecture/system-design.md)
- Authority and non-mutation: [ADR 0001](../adr/0001-authority-and-non-mutation.md)
- Stable support: [ADR 0002](../adr/0002-supported-v1-matrix.md)
- Privacy and egress: [privacy and data egress](../architecture/privacy-and-data-egress.md)
- Security: [threat model](../architecture/threat-model.md)
- Contracts: [contract v2](../architecture/contracts-v2.md)
- User surfaces: [UX contracts](../architecture/ux-contracts.md)
- Next implementation boundary: [Phase 1A handoff](../architecture/phase-1a-handoff.md)
