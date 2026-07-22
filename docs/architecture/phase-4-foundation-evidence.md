# Phase 4 foundation evidence

Date: 21 July 2026
Branch: `zc/product-v1`
Status: implementation and local verification complete; clean-commit receipt and CI pending

## Scope

This slice implements safe local, archive, bundle, public HTTPS, and brokered SSH source acquisition; deterministic Python and TypeScript or JavaScript Responses discovery; Python and Node metadata-only capture adapters; OTLP and OpenInference evidence normalization; egress previews; transactional retention and deletion; macOS Keychain-backed protected storage; daemon and CLI integration; and a receipt-bound support matrix.

Public HTTPS and brokered SSH require the reviewed macOS arm64 OrbStack backend. SSH remains experimental because its acceptance uses a controlled Linux ssh-agent and pinned sshd fixture, not a real private hosting account. This slice does not claim hosted multi-tenant execution, isolated Codex synthesis, safe Apply, TUI, or GUI completion.

## Implemented

- Rust acquisition crate with immutable tool-owned snapshots for local paths, USTAR archives, and PROMPTECTOMY source bundles.
- Path policy rejects traversal, absolute paths, control characters, non-ASCII paths, Windows device names, `.git`, duplicate normalized paths, case collisions, symlinks, hardlinks, special files, oversized paths, excessive files, excessive bytes, and source/storage overlap.
- Snapshot receipts are content-bound, redacted, idempotent, and integrity-checked before reuse.
- Remote Git command planning neutralizes inherited Git config, helpers, hooks, filters, LFS, submodules, protocols, prompts, global config, and arbitrary environment.
- Public HTTPS acquisition uses an OCI worker with no default route and a dual-homed exact-destination CONNECT proxy. The reviewed public Git path passed against a real public repository through the Rust acquisition layer and through the daemon and CLI.
- Brokered SSH uses a relay sidecar that alone can reach the host agent. The worker mounts only the filtered relay socket, sees one selected public identity, uses a fixed SSH helper and Git configuration, and cannot receive the broker handle or raw host socket. The grant binds the selected key, destination, repository, revision, host key, manifest, runtime, frame, connection, and signature quotas. A live receipt is published only after a successful session-bound signature.
- The production image is `sha256:826575ce5fd3b427e4522d64fe13204a174836cd7a052361ac7dee51d42b182e`. Its runner is `sha256:9eebe416b538fc6602313e0a306c8d25b8eac5d990d7b31c109ecc30577dd3fc`, proxy `sha256:9291a931763138b51888bb2393fc3e2bdc28c9df0d31e7eb8a7ae55db39f026b`, relay `sha256:399c89fce01f0c87a95b09ca5081ae5399eb2446cd31e6d400521c5ec4b183c7`, SSH helper `sha256:f8e1b1d58b7ccc78435b04ea988972ca3a348cebf4de711ffdc172ea4448a256`, and OS package manifest `sha256:0cbbe5492ce23661ea73629f28fd6902c5c0709fd7a9179617f160fdc798b3d9`.
- The controlled SSH fixture image is pinned at `sha256:4b04820c83b9890c1f58fd03004e5df289b67182dc80438cb19fab61e6db0b91` and built from `rust/remote-git-image/ssh-fixture.Dockerfile`.
- Python discovery now uses deterministic adapter versions, normalized AST digests, callsite ordinals, enclosing-symbol references, stable features, and explicit unsupported gaps.
- TypeScript and JavaScript discovery use the pinned Tree-sitter TypeScript adapter and fail closed with `unsupported_toolchain` when unavailable.
- Python capture wraps verified Responses callsites without monkeypatching, preserves application error identity, handles sync, async, parse, stream, cancellation, retries, tools, and structured-output metadata, and emits content-free observations.
- Node capture adapter provides the same metadata-only boundary for Promise-based Responses resources with a verified callsite registry and synchronous sink budget.
- OTLP HTTP JSON and gRPC protobuf imports are bounded, strict, duplicate-aware, out-of-order-aware, partial-aware, malformed-input-aware, and content-minimizing. Python capture and OTLP normalized observations keep digest-scoped trace, span, request, and attempt identities; SDK and policy digests; protected-content handles; semantic stream, tool, structured-output, and retry metadata; explicit cost confidence and pricing provenance; and a provenance digest. Node emits its separately versioned metadata-only capture contract.
- Egress preview requires exact authority, approved destination host, source minimization, secret/canary scan, retention budgets, and local-only fail-closed behavior.
- Protected evidence uses AES-256-GCM envelopes, a native macOS Keychain backend, crash-resumable reference-aware deletion, key destruction, authenticated backup inventory, and deletion receipts. Linux and Windows native key-store support remain unverified.
- Support matrix construction refuses to publish stable cells without a content-bound Phase 4 evidence receipt. Cells identify exact operations, pinned runtime versions, and accepted platforms.

## Security review notes

- Trust boundary: hostile repositories, archive bytes, source bundles, Git locators, Git output, runtime capture metadata, OTLP/OpenInference payloads, and egress source slices enter trusted PROMPTECTOMY code.
- Attacker entry points: path names, file metadata, symlink or hardlink swaps, tar headers, bundle JSON, remote URLs, SSH broker handles, Git stdout/stderr, callsite IDs, trace attributes, model labels, source-slice content, deletion artifact IDs, and protected-envelope bytes.
- Fixes made during review:
  - rejected local hardlinks before reading file bytes;
  - made tar content indexing overflow-safe;
  - restricted HTTPS Git planning to a known public host allowlist;
  - made public system remote acquisition typed unavailable until disk/network limits are enforced;
  - restricted egress previews to approved destination hosts.
- The protected-store deletion P1 is closed by crash injection after every destructive step and retry tests for key-store deletion failure.
- The SSH worker has no default route. The proxy alone reaches the approved destination. Relay and worker filesystems, binary digests, environment, mounts, capabilities, resource limits, terminal reports, and cleanup are rechecked by the host.
- The relay receipt is credential-use evidence, not acquisition success. The worker report, source bundle, proxy terminal report, cleanup attestation, and receipt are independently required.
- Honest gaps: a real private-host SSH acceptance account, Linux and Windows native key stores, a published Node package, hosted execution, isolated evaluation, and Apply.

## Acceptance evidence

- `cd engine && uv run ruff check promptectomy tests scripts && uv run pytest -q`: 213 passed, 14 expected optional skips, and one third-party Starlette warning.
- `cd rust && cargo fmt --all --check && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo test --workspace --all-features --locked`: passed, with 179 unit and integration tests passing and 7 explicit live or benchmark tests ignored in the default run.
- `cd rust && PROMPTECTOMY_SSH_FIXTURE_IMAGE=promptectomy-ssh-fixture@sha256:4b04820c83b9890c1f58fd03004e5df289b67182dc80438cb19fab61e6db0b91 cargo test -q -p promptectomy-acquisition --locked --offline -- --ignored`: 4 live tests passed, covering direct and wrong-destination egress denial, cancellation cleanup, controlled SSH, and a real public repository.
- The controlled SSH test passed twice independently in 7.86 and 7.68 seconds. Each run left zero labeled session or fixture containers, networks, and volumes.
- `cd rust && cargo test -q -p promptectomy-cli --locked --offline tests::cli_inspect_public_https_uses_the_real_reviewed_daemon_backend -- --ignored --exact`: passed against the reviewed daemon backend.
- `cd rust && cargo test -q -p promptectomy-protected-store --locked --offline`: 29 passed.
- `cd rust && cargo test -q -p promptectomy-protected-store --test system_key_store --locked --offline -- --ignored --exact native_key_store_round_trip_leaves_no_test_key`: passed on macOS, and final readiness was `KeyMissing`.
- `cd adapters/node && bun install --frozen-lockfile --ignore-scripts && bun run typecheck && bun test && bun run package:check`: 10 tests passed; deterministic package SHA-256 was `1dc259ca8a314684c369d24fe0a40f1933dbd02f41a69b6179518a11330075a2`; a clean OpenAI 6.48.0 consumer typechecked and ran.
- Windows MSVC all-target compilation passed. The receipt still limits runtime support claims to the locally accepted platforms.
- Protected file `engine/promptectomy/generated/route_ticket.py` remained at SHA-256 `a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c` and is excluded from this slice.

## Remaining Phase 4 gate

The source must pass fresh security and landing reviews, be committed without the protected user file, and then run the full acceptance harness from that exact clean commit. The generated receipt and support matrix must bind that commit before Phase 4 closes. CI must pass on the pushed receipt commit.
