# Phase 4 foundation evidence

Date: 19 July 2026
Branch: `zc/product-v1`
Status: foundation slice accepted locally, Phase 4 not complete

## Scope

This slice implements safe local source acquisition, non-executing tar and source-bundle acquisition, deterministic Python and TypeScript or JavaScript Responses discovery, Python and Node metadata-only capture adapters, OTLP and OpenInference evidence normalization, egress previews, retention/deletion primitives, protected-envelope primitives, and a receipt-bound support matrix.

This slice does not claim stable public HTTPS Git, private SSH Git, hosted multi-tenant execution, isolated Codex synthesis, safe Apply, TUI, or GUI completion.

## Implemented

- Rust acquisition crate with immutable tool-owned snapshots for local paths, USTAR archives, and PROMPTECTOMY source bundles.
- Path policy rejects traversal, absolute paths, control characters, non-ASCII paths, Windows device names, `.git`, duplicate normalized paths, case collisions, symlinks, hardlinks, special files, oversized paths, excessive files, excessive bytes, and source/storage overlap.
- Snapshot receipts are content-bound, redacted, idempotent, and integrity-checked before reuse.
- Remote Git command planning neutralizes inherited Git config, helpers, hooks, filters, LFS, submodules, protocols, prompts, global config, and arbitrary environment.
- Public system remote acquisition is typed unavailable until a bounded broker integration exists. Internal fake-runner tests exercise the neutral Git plan without network or real credentials.
- Python discovery now uses deterministic adapter versions, normalized AST digests, callsite ordinals, enclosing-symbol references, stable features, and explicit unsupported gaps.
- TypeScript and JavaScript discovery use the pinned Tree-sitter TypeScript adapter and fail closed with `unsupported_toolchain` when unavailable.
- Python capture wraps verified Responses callsites without monkeypatching, preserves application error identity, handles sync, async, parse, stream, cancellation, retries, tools, and structured-output metadata, and emits content-free observations.
- Node capture adapter provides the same metadata-only boundary for Promise-based Responses resources with a verified callsite registry and synchronous sink budget.
- OTLP HTTP JSON and gRPC protobuf imports are bounded, strict, duplicate-aware, out-of-order-aware, partial-aware, malformed-input-aware, and content-minimizing.
- Egress preview requires exact authority, approved destination host, source minimization, secret/canary scan, retention budgets, and local-only fail-closed behavior.
- Protected evidence envelope uses AES-256-GCM through a supplied key-store boundary. No OS key-store adapter is claimed in this slice.
- Support matrix construction refuses to publish stable cells without a content-bound Phase 4 evidence receipt.

## Security review notes

- Trust boundary: hostile repositories, archive bytes, source bundles, Git locators, Git output, runtime capture metadata, OTLP/OpenInference payloads, and egress source slices enter trusted PROMPTECTOMY code.
- Attacker entry points: path names, file metadata, symlink or hardlink swaps, tar headers, bundle JSON, remote URLs, SSH broker handles, Git stdout/stderr, callsite IDs, trace attributes, model labels, source-slice content, deletion artifact IDs, and protected-envelope bytes.
- Fixes made during review:
  - rejected local hardlinks before reading file bytes;
  - made tar content indexing overflow-safe;
  - restricted HTTPS Git planning to a known public host allowlist;
  - made public system remote acquisition typed unavailable until disk/network limits are enforced;
  - restricted egress previews to approved destination hosts.
- Residual P0/P1 for this accepted slice: none known.
- Honest unsupported gaps: public HTTPS Git acquisition, private SSH brokered acquisition, OS key-store integration, real Node package release, hosted execution, and Apply.

## Acceptance evidence

- `cd engine && uv run pytest -q tests/test_phase4_discovery.py tests/test_phase4_capture_python.py tests/test_phase4_evidence.py tests/test_phase4_privacy.py tests/test_phase4_support_matrix.py`: 52 passed.
- `cd engine && uv run ruff check promptectomy/reference.py promptectomy/reference_contracts.py promptectomy/discovery_models.py promptectomy/discovery_python.py promptectomy/discovery_javascript.py promptectomy/capture_python.py promptectomy/evidence_phase4.py promptectomy/privacy_phase4.py promptectomy/support_matrix_phase4.py tests/test_phase4_discovery.py tests/test_phase4_capture_python.py tests/test_phase4_evidence.py tests/test_phase4_privacy.py tests/test_phase4_support_matrix.py`: passed.
- `cd engine && PYTHONDONTWRITEBYTECODE=1 uv run pytest -q`: 184 passed, 14 expected OCI skips, 1 existing Starlette warning.
- `cd engine && uv run python scripts/generate_contract_bindings.py && test -z "$(git status --porcelain=v1 --untracked-files=all -- generated/contracts_v2 ../rust/crates/promptectomy-contracts)" && uv run pytest -q tests/test_contracts_v2.py`: 12 passed, no generated binding drift.
- `cd rust && cargo fmt --all --check && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo test --workspace --all-features --locked`: passed, including 16 acquisition tests and the existing workspace tests.
- `cd ui && bun run typecheck && bun run build`: passed.
- `cd ui && bunx playwright test`: 10 passed.
- `cd adapters/node && bun install --frozen-lockfile && bun run typecheck && bun test`: passed, 8 tests.
- Protected file `engine/promptectomy/generated/route_ticket.py` remained at SHA-256 `a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c` and is excluded from this slice.

## Next Phase 4 work

1. Add a real bounded remote Git acquisition broker with enforced disk/network/runtime quotas.
2. Add a reviewed private SSH broker wrapper and request format.
3. Add real public-repo and brokered-private-repo conformance cells before changing their support-matrix state.
4. Integrate the Phase 4 acquisition and evidence APIs into the Rust daemon and CLI.
5. Add CI jobs for `engine` Phase 4 focused tests and `adapters/node` typecheck/tests.
