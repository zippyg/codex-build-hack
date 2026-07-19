# CLI, TUI, GUI, report, and consent UX contracts

Status: accepted Phase 0 functional design
Date: 18 July 2026
Visual design/polish is deliberately deferred until the functional contracts are implemented

## UX principle

Every surface answers five questions before visual spectacle:

1. What repository/snapshot and capability level am I looking at?
2. What can PROMPTECTOMY read, write, execute, transmit, and retain right now?
3. What work actually ran, what did not, and why?
4. What evidence supports each finding/candidate and what remains uncertain?
5. What explicit action, if any, changes my repository?

CLI, TUI, GUI, and reports are clients of the same contract. A client cannot invent a success state, hide unsupported work, widen authority, or implement orchestration unavailable through the core API.

## Shared information architecture

Every run exposes:

- source display name, immutable commit/snapshot digest, dirty/untracked policy;
- mode, authority/egress summary, executor/network/environment status;
- L0-L5 level overall and per callsite with stable/experimental/unsupported labels;
- stages with status, reason, attempt/budget, start/duration, cancellation;
- callsite inventory and deterministic coverage/exclusions;
- evidence grade, sample/split coverage, domain-truth boundary;
- findings, candidate classes, costs/latency with price source, uncertainty;
- patch/tests/dependency/config/binary/path changes;
- evaluator/security results, limitations, artifact/receipt digests;
- retained/protected storage, expiry, cleanup/deletion status;
- export options and Apply as a separate authority action.

States include loading, empty, no findings, unsupported, insufficient evidence, awaiting authority, queued/running/paused/cancelling, cancelled, interrupted/resumable, failed by cause, cleanup pending/failed, and completed. Empty and unsupported are never styled as success without text.

## Preflight and consent

Preflight is a reviewable manifest, not a generic warning. It displays:

- exact source/revision/selected roots;
- mode and highest requested L-level;
- target writes: always "none" until Apply;
- executable code/commands and accepted executor/limits;
- network destinations and whether repository/generated tools are offline;
- environment variable names exposed, never values;
- model/provider/prompt bundle and maximum time/tokens/spend;
- source/trace/content classes eligible for external transmission, selected files/symbol slices, and destination;
- local retention/expiry/deletion and external-copy limitations;
- cancellation and cleanup behavior;
- unsupported areas known before start.

Actions are `Back`, `Run with this authority`, `Save policy` where permitted, and `Run local-only` when meaningful. A changed manifest highlights the diff and requires new approval. Consent is not bundled with analytics, publication, Apply, or Integrate.

## CLI

Target command surface:

```text
promptectomy init [path]
promptectomy doctor [source] [--json]
promptectomy inspect <source> [--json]
promptectomy audit <source> [--policy <file>] [--json]
promptectomy draft <source> [--policy <file>] [--json]
promptectomy status [run-id] [--watch] [--json]
promptectomy calls <run-id> [--json]
promptectomy finding <finding-id> [--json]
promptectomy candidate <candidate-id> [--json]
promptectomy diff <candidate-id>
promptectomy report <run-id> --format json|md|html|ndjson|sarif|junit
promptectomy apply <candidate-id> --branch <name> [--policy <file>]
promptectomy cancel <run-id>
promptectomy resume <run-id>
promptectomy export <run-id>
promptectomy delete <run-id-or-artifact> [--dry-run]
promptectomy tui [run-id]
promptectomy daemon
promptectomy gc --dry-run
```

Rules:

- `inspect`, `audit`, and `draft` are separate commands. The legacy overloaded `run` is deprecated and cannot be the safe default.
- Every table has a stable `--json` representation. JSON writes only JSON to stdout; diagnostics go to stderr and remain safe.
- Noninteractive commands never prompt. Missing authority/policy exits nonzero with error code and exact next action.
- Interactive mode may confirm a fully displayed manifest, but confirmation cannot replace required explicit arguments such as Apply branch.
- `--no-color` and plain text are supported. Untrusted ANSI/OSC/bidi/control content is escaped.
- `doctor` reports adapter, toolchain, Git, storage, executor, Codex connector, key store, local API, and version compatibility without secret values.
- Exit semantics follow [contract v2](contracts-v2.md). Machine consumers never parse human prose.
- `status --watch` is the plain streaming fallback and contains all decision-relevant state available in TUI/GUI.

Phase 1A initially exposes Inspect/Audit/Draft-unverified/status/report semantics in the existing Python CLI. It does not claim the complete target command set.

## TUI

The TUI is a first-class local/SSH keyboard client, not ASCII decoration around the demo.

```text
+ Source and authority ------------------------------------------------------+
| repo@commit  Draft-unverified  Python L2  no executor  $0.44/$5  [Cancel] |
+ Stages ----------------------+ Detail ------------------------------------+
| Preflight          complete  | Findings Evidence Candidate Tests Diff      |
| Discovery          complete  |                                             |
| Evidence           warning   | selected callsite, coverage, reasons        |
| Candidate          running   |                                             |
| Evaluation         blocked   |                                             |
+ Agents ----------------------+---------------------------------------------+
| Synthesizer  42s/120s        | goal, permissions, budget, typed activity    |
+ Status -------------------------------------------------------------------+
| q quit  ? help  / filter  enter inspect  d diff  e export  x cancel       |
+----------------------------------------------------------------------------+
```

Screens:

- repository/run picker and daemon/storage health;
- preflight/authority/egress/doctor;
- stage pipeline with reason-aware warnings;
- callsite inventory/support/coverage filters;
- finding/evidence/uncertainty detail;
- candidate comparison and patch/test/security/evaluation views;
- bounded agent office;
- receipt/reproducibility/export/delete;
- Apply review as a separately entered flow;
- settings for storage/retention/redaction/adapters/executors/model budgets/update channel.

Requirements:

- full keyboard operation, visible shortcut help, predictable focus, search/filter;
- resize/narrow-terminal behavior and a semantically equivalent plain mode;
- color never carries status alone; reduced motion/no animation dependency;
- reconnect after daemon restart and explicit sequence-gap handling;
- large lists/diffs virtualized or paged without hiding totals;
- untrusted control sequences and pathological Unicode rendered safely;
- cancellation is immediate to request and remains visible until core verifies termination;
- no TUI-only orchestration or hidden command.

## Desktop GUI

Tauri 2 plus React is the target shell. It uses bundled local content and explicit minimal capabilities. Tauri's runtime authority checks which window/origin can call which command, but it is not the executor sandbox: [permissions](https://v2.tauri.app/security/permissions/), [capabilities](https://v2.tauri.app/security/capabilities/), [runtime authority](https://v2.tauri.app/security/runtime-authority/).

Primary flows:

1. Home: recent repositories/runs/pinned reports plus daemon/storage/update health.
2. Import: local path, explicit Git URL, archive, evidence bundle. Private Git authentication is a brokered subflow.
3. Preflight: capability matrix, authority/egress manifest, executor, content policy, budget, retention, known unsupported areas.
4. Run overview: authoritative stages, findings, evidence gaps, budget, cancellation, cleanup.
5. Callsite inventory: provider/language/L-level/stability/cost/latency/error/opportunity filters and coverage.
6. Finding workspace: source context reference, observations, rationale, uncertainty, candidate classes.
7. Candidate review: source/diff, tests, dependency/config changes, evaluator lenses, security findings, limitations, artifacts, receipt.
8. Agent office: role, one-sentence goal, accessible files/tools, network/environment status, time/token/spend/attempt budget, typed phase/activity, artifacts/warnings, cancel.
9. Apply: fresh target/snapshot check, branch, full diff, recovery reference, approved checks, explicit execution.
10. History: compare snapshots/runs/candidates/accepted changes/drift.
11. Privacy/storage: classes, expiries, protected access, export/deletion preview and receipts.
12. Settings: adapters, runtimes, Codex/model, toolchains, price tables, retention, analytics off-by-default, update channel.

The historical replay is a separately labelled `Demo fixture` surface. It cannot appear as a live repository run, and the public web replay has no repository execution controls.

GUI requirements include keyboard-only flow, semantic headings/landmarks, focus restoration, accessible names/status announcements, contrast, zoom/reflow, reduced motion, no color-only state, recovery from disconnected/failed states, and platform screen-reader checks. Final visual design does not change authority semantics.

## Agent office

The product shows structured activity, not private chain-of-thought. Each card contains role/goal, run/candidate, read/write roots, tools, network/environment status, elapsed/limit, tokens/spend/limit, attempt/max, current typed phase, safe events, artifacts, warnings, and cancel.

Retry is offered only when the typed cause is known and policy permits another bounded attempt. Agents cannot be promoted to broader authority from their card. Conflicting reviewer/synthesizer output is shown as a review warning or typed failure, not auto-resolved by another unbounded agent.

## Reports and exports

Every report begins with limitations and decision facts:

1. source/revision/snapshot, mode, authority, support level;
2. terminal result, performed/skipped/unsupported work, evidence grade;
3. baseline cost/latency with observed/estimated and price source/version;
4. callsite inventory, coverage, findings, opportunity map;
5. candidate cards with behavior/contract/domain results, security, maintenance, uncertainty;
6. evaluation design, grouping/splits/holdout/sample coverage/failures;
7. patch/tests/dependencies/config/binaries and Apply instructions;
8. privacy/egress/retention/redactions and protected references;
9. reproducibility manifest, tool/adapters/prompt/model/executor versions, artifacts, digest-bound receipt;
10. structured export references.

Formats are canonical versioned JSON, human Markdown, sanitized self-contained HTML, NDJSON events, SARIF 2.1.0 findings, JUnit evaluation/test results, patch, and optional Git bundle after separate policy. All are generated from one frozen run snapshot. Format differences are presentation only; counts/status/support/limitations must agree.

HTML is unprivileged, sanitized, and usable offline without a native bridge. External links are explicit and safe-schemed. Source/protected content is excluded by default and every export includes a redaction/exclusion manifest.

## Apply UX

Apply is visually and operationally separate from candidate review:

1. re-resolve target path, repository, default branch, and current state;
2. compare snapshot/receipt/patch digests and refuse stale state;
3. show branch destination, recovery reference plan, every affected path, dependency/config/binary/symlink/workflow change;
4. show checks, executor, network/environment, time/budget;
5. require explicit `Apply to <branch>` action or CLI branch argument;
6. apply without force/destructive cleanup, run only approved isolated checks, record resulting diff/commit/divergence;
7. show recovery instructions and leave user work intact on failure.

Default branch Apply is unavailable in v1. Dirty state is refused or requires a separately designed explicit acknowledgement policy; the default is refusal. A changed target creates a new evaluation requirement rather than an auto-rebase.

## Error, unsupported, and recovery language

Every failure view shows stable code, safe message, stage/entity, retryability, exact next action, retained artifacts, cleanup state, and optional protected diagnostics. It does not show raw exceptions, secrets, or generic "something went wrong".

Examples:

- `missing_isolation_backend`: "Verified Draft requires an accepted executor. Configure OCI or run Audit."
- `safe_agent_transport_unavailable`: "Tool-free structured Codex Draft is unavailable. Configure the approved Responses connector or run Audit."
- `insufficient_evidence`: "14 distinct grouped observations do not meet the 50-case review threshold. Import more evidence or keep this exploratory."
- `ambiguous_dynamic_callsite`: "The adapter found a dynamic client call it cannot bind to one operation. L1 coverage is incomplete."
- `completed_with_unsupported`: "Supported analysis finished. 3 callsites remain unsupported; no optimization claim includes them."
- `event_cursor_expired`: "Stored events before sequence 1200 were compacted. Reload the frozen run snapshot."

## Parity acceptance

For one frozen run, CLI JSON, TUI, GUI, HTML, Markdown, SARIF, and JUnit must agree on source/snapshot, terminal status, support/coverage, finding/candidate/evaluation counts, evidence grades, limitations, receipt/artifact IDs, and unsupported work. TUI/GUI convenience actions map to one documented API/CLI operation. Closing a client cannot change run correctness.

Test IDs `CLI-*`, `TUI-*`, `GUI-*`, `API-*`, `REPORT-*`, `INV-AUTH-*`, and accessibility/manual gates are specified in [testing and benchmarks](testing-and-benchmarks.md).
