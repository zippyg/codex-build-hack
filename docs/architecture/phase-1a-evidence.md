# Phase 1A implementation evidence

Status: accepted
Date: 19 July 2026
Branch: `zc/product-v1`
Entry commit: `e861822eb41e130c97d1cdd33a90ea97ffab5f9d`

## Delivered boundary

The Python package now provides the Phase 1A conformance oracle:

- `doctor`, `inspect`, `audit`, `draft`, `status`, and JSON/Markdown `report` commands;
- local-path inventory and static OpenAI Responses discovery for Python and direct TypeScript/JavaScript patterns;
- explicit unsupported accounting for other languages, providers, SDK/operation surfaces, dynamic calls, malformed source, unsafe paths, symlinks, and nested repositories;
- exact target and Git-metadata digest checks before and after Inspect, Audit, and Draft;
- a direct OpenAI Responses connector with one fixed endpoint, Codex-model validation, strict structured output, no tool or tool-choice field, bounded request/response data, and no inherited HTTP proxy environment;
- private owner-only run storage, append-only safe events, content-addressed candidate/report/receipt artifacts, deterministic cleanup metadata, and digest-bound local receipt language;
- only `unverified` candidate state, with no repository/generated code execution and no Apply behavior;
- typed missing-policy, stale/widened policy, unavailable connector, unsupported, no-finding, failure, cancellation, and internal-failure outcomes;
- hard gating for the old `run`, `accept`, `disable`, and `serve` paths. `scan` is now only a local Inspect alias.

Phase 1A did not add an executor, verified evaluation, remote acquisition, SQLite, the local API, Rust, TUI, GUI, Apply, deployment, publishing, or a live model probe.

## Changed implementation

Behavior:

- `engine/promptectomy/cli.py`
- `engine/promptectomy/connector.py`
- `engine/promptectomy/reference.py`
- `engine/promptectomy/reference_contracts.py`
- `engine/promptectomy/schema_assets/draft-candidate-v1.json`
- `engine/pyproject.toml`
- `engine/uv.lock`

Tests:

- `engine/tests/test_phase1a.py`
- `engine/tests/test_security_packaging.py`

Evidence and state:

- this file;
- `.agent/state/ACTIVE_PLAN.md`;
- `.agent/state/CURRENT_TASK.md`;
- `.agent/state/STATUS_2026-07-19.md`;
- `.agent/logs/2026-07-19/02-phase-1a-safe-python-reference.md`.

The protected `engine/promptectomy/generated/route_ticket.py` was not edited, staged, restored, formatted, regenerated, or included in this phase. Its before/after SHA-256 remained:

```text
a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c
```

## Acceptance map

| Phase 0 IDs | Phase 1A runnable evidence |
|---|---|
| `INV-AUTH-01..04` | `test_general_static_modes_are_non_mutating_and_do_not_execute`, `test_draft_requires_exact_manifest_and_confines_unverified_artifacts`, `test_inspect_accounts_for_python_typescript_unsupported_and_zero_findings`, `test_draft_with_no_supported_callsite_is_typed_without_connector_use` |
| `INV-NM-01..03` | `test_dirty_git_state_is_exact_across_all_phase1a_terminal_paths`, `test_legacy_commands_are_gated_and_scan_is_only_an_inspect_alias`, `test_keyboard_interrupt_becomes_a_typed_cancelled_terminal_run` |
| `PARENT-01..06` | `test_general_static_modes_are_non_mutating_and_do_not_execute`, `test_cli_import_does_not_load_legacy_execution_modules`, legacy command gating test |
| `GIT-*`, `PATH-*` subset | nested `.git` file fixture, symlink fixture, normalized policy-path failures, linked-worktree Git metadata confinement, target-state digest comparisons |
| `CONNECTOR-01..10` | exact endpoint/model/schema assertions, omitted tools/tool-choice, approved-slice-only and ambient-environment canaries, response metadata, byte/token limits, invalid/duplicate/unknown schema cases, cancellation, unavailable transport, unexpected patch target |
| `AGENT-*` subset | untrusted source remains data, schema-only output, fixed authority, bounded attempt, no tools/network widening, unverified-only candidate |
| `PRIV-01..10` | `test_privacy_canaries_do_not_enter_safe_state_events_or_reports`, unapproved source/environment request canaries, credentialed URL redaction, protected exception canary |
| `STATE-*`, `ART-*`, `RECEIPT-*` subset | owner-only storage, contiguous sequence from 1, append-only event bytes across reads, digest-matched candidate/report/receipt artifacts, receipt manifest binding |
| `CONTRACT-*`, `CLI-*`, `REPORT-*` subset | closed Pydantic models, strict candidate schema asset, stable terminal/error JSON, failed-run status read exit 0, deterministic JSON/Markdown report |

The synthetic dirty-Git fixture compares target bytes, staged diff, unstaged diff, refs, local config, worktree list, and untracked inventory before and after Inspect, Audit, Draft success, Draft failure, and Draft cancellation.

## Verification receipts

From `engine/`:

```text
ruff check promptectomy/cli.py promptectomy/connector.py promptectomy/reference.py promptectomy/reference_contracts.py tests/test_phase1a.py tests/test_security_packaging.py
PASS

uv sync --frozen
PASS: 36 packages checked

PYTHONDONTWRITEBYTECODE=1 uv run pytest -q
PASS: 73 passed, 0 failed, 0 skipped
WARNING: one third-party Starlette/httpx deprecation warning

uv lock --check
PASS: 37 packages resolved with no lock drift
```

Clean installed-wheel acceptance used a fresh Python 3.12 virtual environment outside the checkout:

```text
wheel: promptectomy-0.1.0-py3-none-any.whl
wheel sha256: 96ddb237a8140474ddc5f56046f528b3e0f79a0ca057431d78e5a1a9a1134187
installed dependencies: 31
installed command checks: doctor, inspect, status, report, help surface, packaged schema
result: completed with one supported Python Responses callsite
packaged draft-candidate-v1.json: loaded and strict
```

The wheel path was disposable under `/tmp/promptectomy-phase1a-accepted.TZQo7K`; it is evidence, not a release artifact.

## Safe terminal JSON samples

These are minimized safe projections exercised by the tests. Opaque IDs and digests are representative.

```json
{"mode":"inspect","status":"completed","support":{"highest_level":"L1","callsites":2,"unsupported_areas":0},"candidate":null,"error":null}
{"mode":"audit","status":"completed_no_findings","work":{"performed":4,"zero_work":false},"candidate":null,"error":null}
{"mode":"inspect","status":"completed_with_unsupported","unsupported":[{"code":"unsupported_language","highest_level":"L0"}],"candidate":null,"error":null}
{"mode":"draft","status":"failed","candidate":null,"error":{"code":"missing_egress_manifest","category":"policy","retryable":false}}
{"mode":"draft","status":"cancelled","candidate":null,"error":{"code":"cancelled","category":"cancel","retryable":false}}
{"mode":"draft","status":"completed","candidate":{"state":"unverified","patch_artifact":"sha256:<digest>","tests_artifact":"sha256:<digest>"},"error":null}
```

No safe sample contains a source body, raw path, locator credential, API key, environment value, model prompt, raw model response, or arbitrary exception string.

## Review closure

The architecture pressure test initially reported four P1 gaps: legacy command reachability, incomplete Git-state proof, insufficient negative manifest tests, and missing event/artifact/receipt integrity assertions. All four were fixed and covered by tests.

The security review initially reported one P2 unbounded pre-inventory digest read. The digest now rejects source files over 100 MB, total source input over 2 GB, and growth during read. Git object databases are excluded from source quotas while bounded mutable metadata remains receipt-bound. A later P2 showed that a forged top-level `.git` pointer could direct reads outside the checkout. Linked-worktree pointers now require Git's backlink, common-directory structure, expected common metadata, and no-follow/inode-stable reads before any external metadata digest. Sparse-file, oversized Git-object, valid linked-worktree, and forged-pointer regressions pass.

The diff review initially reported a P1 nested `.git` file gap and P2 gaps in `status` exit behavior, TypeScript comment masking, invalid state-root typing, and Git-object source quotas. Each was reproduced, fixed, and covered by a regression. Final fresh architecture, diff, and security review found no unresolved P0/P1/P2.

## Deferred to Phase 1B and later

- accepted OCI executor and all generated/repository code execution;
- verified Draft, compile/test/evaluator behavior, holdouts, and performance/cost verdicts;
- hostile executor network/environment/process/resource enforcement;
- remote Git/archive acquisition and credential brokering;
- Contract v2 schemas/bindings, SQLite/CAS migration, crash recovery, and local API;
- complete stable Python and TypeScript adapter matrices, evidence capture, Rust, TUI, GUI, Apply, integrations, packaging, and public release.

No Phase 1A result is production-ready, signed, attested, verified, or eligible for Apply.
