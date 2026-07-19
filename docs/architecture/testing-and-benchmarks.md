# Testing, fixtures, benchmarks, and release evidence

Status: accepted Phase 0 verification plan
Date: 18 July 2026

## Principle

PROMPTECTOMY is proof-first. A test is evidence only for the exact invariant, adapter cell, platform, backend, and artifact it exercises. Narrow unit success cannot support broad repository/security/product claims.

Every test result records commit/tree digest, product/adapter/executor/toolchain versions, OS/architecture, relevant hardware/runtime, fixture/corpus version, command, duration, and result. Manual acceptance is labelled manual. Existing hackathon test counts are historical and do not certify the target design.

## Invariant traceability

| Security/product invariant | Mandatory test families | Release evidence |
|---|---|---|
| SEC-01 non-mutation | `INV-NM-*`, `APPLY-*`, `GIT-*` | Before/after source, index, refs, config, hooks, worktrees, untracked digests for success/failure/cancel/crash |
| SEC-02 no core/client untrusted execution | `EXEC-01..12`, `PARENT-01..06` | Instrumented parent/core proves no import/invoke/child outside broker |
| SEC-03 executor fail-closed | `EXEC-29..34`, `POLICY-01..08` | Verified Draft refused without every required control; no weaker fallback |
| SEC-04 empty environment/offline tools | `CRED-01..09`, `EXEC-06..12` | Canary variables/sockets/files/network unreachable |
| SEC-05 credential connector isolation | `CRED-*`, `GIT-06..10` | Git/model/provider credentials visible only to selected broker/connector |
| SEC-06 agent cannot grant authority | `AGENT-01..18`, `HOLD-*` | Injection corpus denied and bounded; no holdout/Apply/Integrate access |
| SEC-07 egress manifest | `EGRESS-01..12` | Undeclared file/field/destination/budget change blocks before transmission |
| SEC-08 protected content isolation | `PRIV-01..18`, `REPORT-*`, `BACKUP-*` | Unique canaries absent from every safe surface; protected paths encrypted/access-controlled |
| SEC-09 path/archive/artifact confinement | `PATH-*`, `ARCH-*`, `ART-*` | Hostile normalization/symlink/device/quota corpus cannot escape roots |
| SEC-10 cancellation | `CANCEL-01..10`, `AGENT-17..18` | Process-tree absence and revoked capabilities within budget |
| SEC-11 state/integrity | `STATE-*`, `ART-*`, `RECEIPT-*`, `MIG-*` | Crash injection never creates false completion; tamper detected |
| SEC-12 safe Apply | `APPLY-01..16` | Stale/dirty/default/invalid-refused; success affects named branch only with recovery ref |
| SEC-13 API/Tauri/report boundary | `API-*`, `GUI-*`, `REPORT-*`, `TUI-SEC-*` | Unapproved origin/window/content cannot invoke/read privileged surface |
| SEC-14 evidence-bound claims | `SUP-*`, `RELEASE-*`, documentation claim audit | Every stable claim maps to a passing matrix cell and no open critical/high finding |

## Test layers

| Layer | Scope |
|---|---|
| Domain unit | State transitions, capabilities, IDs, digests/JCS, split/evidence grades, price decimal math, error/exit mapping |
| Property/fuzz | Path/archive normalization, event replay/dedup, state transitions, artifact round trips, schema inputs, callsite identity |
| Contract | Draft 2020-12 schemas, Rust/Python/TypeScript bindings, positive/negative examples, prior-minor and unknown-major compatibility |
| Adapter | Python/Node OpenAI Responses and OTLP/OpenInference mappings across all declared feature cells |
| Repository fixture | Hermetic supported, ambiguous, unsupported, dirty, monorepo, and malicious repositories |
| Executor | Isolation, environment/network/filesystem/resource/process/cancellation/output controls per backend/platform |
| Agent/prompt | Injection, schema invalidity, hallucinated paths, budget/attempt stop, context minimization, hidden-holdout separation |
| Evaluation | Duplicates, grouping, temporal holdout, rare cases, baseline wrongness, evaluator disagreement/failure, evidence grades |
| Storage/recovery | SQLite/lease/event/artifact/migration/backup/disk-full/corruption/crash behavior |
| Client/export | CLI JSON/exit, TUI PTY, GUI/Tauri, browser/static reports, accessibility, reconnect/gaps/cancel, sanitizer |
| Installer/release | Clean install/upgrade/export/uninstall, packages/adapters, signatures/checksums/SBOM/provenance, secret/license/vulnerability scans |
| Manual physical | Claimed terminals, screen readers, macOS/Linux/Windows packages, runtime/backend setup, two fresh-user workflows |

Tests use the repository lockfile/toolchain. Network tests point to local controlled canaries except explicit acquisition/model connector tests. No test targets an unrelated real repository.

## Golden repository and evidence corpus

All fixtures are synthetic, hermetic, small enough to audit, and separately versioned.

### Supported Python fixture

- OpenAI Responses sync/async/streaming;
- structured output and schema failure;
- single/parallel tool calls and tool error;
- retries, timeout, cancellation, provider error, partial stream;
- direct client, alias, supported wrapper, multiple callsites;
- deterministic/extraction/routing/freeform/cache/batching/prompt-reduction opportunities;
- tests and domain labels containing baseline-right and baseline-wrong cases.

### Supported TypeScript/JavaScript fixture

The same operation matrix under Bun/Node-supported project layouts, ESM/CommonJS declarations where claimed, promise/cancellation/stream semantics, and lockfile-respecting toolchain behavior.

### Coverage/unsupported fixtures

- SDK imported but never called;
- unsupported SDK version/operation/provider;
- dynamic client selection, reflection/eval, generated/vendor code, opaque wrappers;
- Go/Rust/Java callsites inventoried at L0 only;
- mixed monorepo with nested manifests and package managers, nested `.git`, submodules, LFS pointers;
- spaces, Unicode, long paths, symlinks, case conflicts, staged/unstaged/untracked data.

### Malicious repository/archive fixture

- prompt injection in every text-bearing location;
- path traversal, absolute/device/reserved names, duplicate normalized members, symlink/hardlink escape, decompression bomb;
- Git remote helper/config/filter/LFS/submodule/redirect/credential attacks;
- environment/file/network/socket probes, fork/grandchild bombs, CPU/memory/disk/PID/output floods, infinite loop;
- terminal ANSI/OSC/hyperlink/bidi/Unicode/path attacks;
- dependency scripts and patches that add binary, symlink, workflow, hook, credential, out-of-scope path, or undeclared dependency.

### Evidence/privacy fixture

- OTLP HTTP/gRPC valid, duplicate, out-of-order, retry, partial-success, malformed, unknown-field, oversize batches;
- OpenInference and OpenTelemetry GenAI pinned mapping examples;
- unique canaries in source, prompt, output, tool/retrieval content, attributes, labels, IDs, errors, environment, Git URL, filename, terminal/dependency output;
- personal-data-like values, API key formats, nested/binary/large content, HTML/Markdown/SVG/URLs;
- synthetic/human-labelled/domain truth and intentionally wrong baseline outputs.

## Named test families

### Authority and non-mutation

- `INV-AUTH-01..07`: each mode permits exactly the ADR 0001 matrix; escalation/expiry/revocation/idempotency are enforced.
- `INV-NM-01..05`: Inspect, Audit, unverified Draft, verified Draft, cancel/fail/crash preserve target tree, index, refs, config, hooks, worktrees, and untracked-set digests.
- `PARENT-01..06`: generated/repository code is never imported/invoked in core/clients; candidate bytes are data until brokered execution.
- `APPLY-01..16`: dirty/stale/default/path/receipt/conflict refusal and one successful named-branch/recovery-reference case.

### Acquisition and confinement

- `GIT-01..17`: protocol/config/helper/redirect/credential/submodule/LFS/filter/hook/bundle/quota cases.
- `PATH-01..10`, `ARCH-01..08`: paths, modes, symlinks/hardlinks/devices/case/Unicode/duplicates/expansion.
- `ART-01..12`: atomic write, digest/class/path/size tamper, quarantine, reference/pin/GC behavior.

### Execution, credentials, agents, holdout

- `EXEC-01..34`: backend manifest, parent boundary, mount/device/socket/network/env, non-root, resource/process/output, dependency, fail-closed cases.
- `POLICY-01..08`: missing, expired, widened, revoked, or backend-incompatible authority fails closed without host or weaker-executor fallback.
- `CONNECTOR-01..10`: exact allowed model endpoint and request schema, no tools, minimal approved content, credential/log isolation, response metadata, budget, timeout/cancel, and fail-closed unavailable transport.
- `CRED-01..09`: canary model/Git/provider/cloud/database credentials absent from every non-connector boundary.
- `AGENT-01..18`: injection/tool/path/network/env/authority/dependency/Apply attempts, schema errors, budgets, repeated failure, cancellation.
- `HOLD-01..08`: no candidate/agent access, group-key irreversibility, mount timing, receipt binding.
- `CANCEL-01..10`: agent/acquisition/dependency/build/test/evaluator/daemon cancellation and orphan checks.

### Evidence, privacy, evaluation

- `DISC-01..12`: true/false positives, wrappers, generated exclusions, coverage, callsite relocation confidence.
- `CAP-01..20`: Python/Node operation matrix and normalized semantics.
- `OTLP-01..12`: transport/mapping/dedup/order/partial/malformed/unknown/limit behavior.
- `PRIV-01..18`: canaries absent from events, stdout/stderr, API, clients, exports, receipts, analytics, diagnostics, agent prompts, executor output.
- `PRIV-GIT-01..08`: credentials and private locators absent from Git arguments, config, process output, events, diagnostics, artifacts, exports, and crash recovery.
- `PRIV-DEL-01..08`: protected-object expiry, reference deletion, key destruction, interrupted deletion, backup interaction, and verifiable tombstone/GC behavior.
- `EGRESS-01..12`: preview/manifest/minimization/destination/budget/local-only/re-consent behavior.
- `BACKUP-01..10`: encryption envelope, wrong/lost/rotated key, tamper, interrupted write, backup/restore, secure-store-unavailable.
- `EVAL-01..14`: grouping/leakage/temporal/rare/baseline-wrong/domain/evaluator-failure/evidence-grade cases.

### State, contracts, clients, release

- `CONTRACT-01..12`: schema/meta-schema, all-language positive/negative validation, safe/protected separation, JCS/digest fixtures.
- `COMPAT-01..10`: prior minor, additive field, unknown major, database/export/adapter negotiation.
- `STATE-01..16`: valid/invalid transitions, event+projection atomicity, sequence/dedup/gap, lease/restart, concurrent readers, busy/checkpoint/recovery.
- `MIG-01..10`: backup/verify, migration fail/crash/disk-full, restore/export, patched SQLite version gate.
- `API-01..12`: socket permissions, capability, Host/Origin/CORS, body/rate/artifact authorization, cursor/idempotency.
- `CLI-01..12`: JSON schema, exit codes, no prompt, human sanitization, unsupported/empty/failure/cancel states.
- `TUI-01..12`, `TUI-SEC-01..06`: PTY navigation/resize/reconnect/gap/cancel/plain mode/untrusted control data.
- `GUI-01..10`: authority/run/error flows, reconnect/cancel, capability/origin/window restrictions, no privileged remote/report content.
- `REPORT-01..12`: equivalent frozen projections, sanitizer/CSP/URL/HTML/SVG/Markdown/path/terminal attacks, deterministic digest.
- `SUPPLY-01..16`, `RELEASE-01..16`: dependency/license/secret/SBOM/provenance/signing/install/upgrade/uninstall/version/advisory gates.

## Phase 1A acceptance subset

Phase 1A is intentionally smaller than the final corpus. It must pass:

1. `INV-AUTH-01..04` for Inspect, Audit, Draft-unverified, and explicit unsupported/zero-work behavior.
2. `INV-NM-01..03` across success, failure, cancellation, dirty and unsupported fixtures.
3. `PARENT-01..06` proving no generated/repository parent import/invoke.
4. `CONNECTOR-01..10` proving the direct Codex Responses request omits tools and unapproved context, isolates credentials/logs, enforces schema/budget/cancel, and fails closed when unavailable.
5. minimal `PATH-*` and artifact-root confinement for patch/test/report artifacts.
6. `PRIV-01..10` proving protected canaries stay out of safe events, CLI stdout/stderr, stored diagnostics, agent context, and the JSON/Markdown outputs that Phase 1A exposes. Local API and additional export formats remain later-phase gates.
7. typed terminal/exit cases for no callsites, unsupported, missing ledger/evidence, unavailable safe connector, agent failure, cancel, and internal failure.
8. regression tests for retained safe prototype scan/ledger/split/scoring/event behavior, without executing the unsafe full `run` path as acceptance.

Phase 1A cannot mark a candidate verified or run candidate/repository code. Executor/hostile installed-wheel certification belongs to 1B/1C.

## SLO candidates and design budgets

These are pre-release budgets to benchmark, not current promises. A stable release publishes measured thresholds and hardware/tool metadata.

| Area | Candidate objective |
|---|---|
| Safety | 100% target non-mutation across acceptance corpus; 0 canary leaks; 0 parent untrusted executions; 0 orphan workers |
| Terminal accounting | 100% started runs reach or recover to one coherent terminal state; no silent zero-work completion |
| Cancellation | Full worker tree absent within 5 seconds locally after core accepts cancel, or typed cancellation failure |
| Recovery | Core restart exposes coherent completed/interrupted state within 10 seconds for acceptance fixtures |
| Event/UI | Normal local event append-to-client p95 below 1 second; no unreported sequence gaps |
| Inventory 100k LOC | Cold L0/L1 under 10 seconds and 1 GiB peak RSS on reference laptop, excluding toolchain index generation |
| Inventory 1M LOC | Streaming completion under 90 seconds and 2 GiB peak RSS on reference laptop; no agent call for L0/L1 |
| Safe API | Local read p95 below 100 ms for common run/finding pages at 100k events; bounded pagination |
| Report | Frozen 100k-event report/export under 30 seconds and 1 GiB peak RSS; explicit output size cap |
| Storage | Identical inputs/tool versions yield identical deterministic report/receipt digests excluding declared nondeterministic fields |

Budgets are adjusted only from benchmark evidence and documented workload needs. A lowered safety/reliability target is not a performance trade.

## Benchmark methodology

- Pin fixture digest, product/adapter/runtime/toolchain/database version, power mode, OS/architecture, CPU/RAM, filesystem, cache state, and executor backend.
- Separate cold/warm cache, inventory/model/executor/report/storage timing, and wall/CPU/resource use.
- Run sufficient repetitions, report median/p95/range and failures, and retain raw safe results as artifacts.
- Measure 10k/100k/1M LOC, 1k/100k/1M observations, small/large artifacts, concurrent reads, bounded concurrent runs, and pathological inputs.
- Include cancellation and crash latency, not only happy-path throughput.
- Never compare model costs without price table/model/prompt/context versions and estimated-versus-observed labels.
- Regression thresholds are relative plus absolute; noisy tests require documented variance rather than repeated reruns until green.

## CI and platform matrix

At the relevant phase, required CI covers formatting/lint, unit/property/fuzz-smoke, contracts/all-language bindings, Python/Node adapters, Rust core, executor, UI/TUI, installers, dependency/license/secret/SBOM/provenance, and hostile corpus.

Claimed stable platforms require clean macOS, Linux, and Windows install/upgrade/export/uninstall smoke plus platform-specific process-tree, socket/pipe, path/case, terminal, key-store, and signing tests. OCI backend claims name the tested runtime/version/platform. Manual tests do not replace CI where automation is possible.

## Release blockers

Release or the affected support cell is blocked by:

- any failed SEC invariant;
- unresolved critical/high relevant security finding;
- unsupported/ambiguous work hidden from the report;
- stable operation matrix gap;
- flaky test without owner/root cause/explicit non-release status;
- unverified migration/restore or installer lifecycle;
- documentation/UI claim without mapped passing evidence;
- missing dependency/license/name/legal decision for publication;
- signing/provenance claim without verifier-tested artifact.

## Manual acceptance

Before stable public release:

- two fresh users complete Inspect, Audit, supported Draft, review/export, cancellation, and safe Apply on fixtures from clean installation;
- keyboard-only and screen-reader/plain-mode flows preserve all decision information;
- macOS/Linux/Windows and representative SSH/tmux/Windows Terminal paths are physically checked where claimed;
- security reviewer independently runs the hostile corpus and verifies threat closure;
- maintainer verifies release signatures/provenance/SBOM and install/upgrade/uninstall from public artifacts;
- README quickstart is executed verbatim against released artifacts.

Human acceptance records device/platform/result and does not generalize beyond tested conditions.
