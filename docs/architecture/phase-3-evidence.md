# Phase 3 acceptance evidence

Status: accepted locally and on release-platform CI
Date: 19 July 2026
Scope: Rust trusted core, local daemon transport, canonical CLI, isolated adapter protocol, and Python v2 state migration

## Outcome

Phase 3 moves the trusted local control plane and primary state/report interface into Rust without claiming repository acquisition, model adapters, evaluation, or Apply.

- The Rust workspace separates contracts, trusted state and policy, local acquisition types, adapter protocols, daemon/API, CLI, and shared fixtures.
- Contract v2 remains the only contract authority. The tracked schema, examples, Python/TypeScript bindings, and Rust bindings regenerate deterministically from the same source.
- The Rust core owns schema-versioned SQLite state, authority checks, state transitions, cancellation, leases, budgets, content-addressed artifacts, reports, receipts, backup, migration, and dry-run garbage collection.
- Canonical authority bytes are persisted and revalidated on every privileged mutation. Revoked, expired, forged, escalated, or legacy authority fails closed.
- Imported legacy runs are zero-budget, report-only records in `awaiting_authority`. No fabricated grant or resumable capability survives migration.
- SQLite state requires private paths and files, WAL mode, foreign keys, full integrity checks, and an embedded SQLite 3.51.3. Import and replacement use verified private copies, file and directory synchronization, rollback backups, and sidecar reconciliation.
- Python v2 import never opens the user-owned database through SQLite. It requires a quiescent source, verifies an exact private copy, imports from that copy, and proves the original database family remains byte-identical.
- The daemon uses a private Unix-domain socket and bearer capability. It enforces exact Host and Origin policy, bounded HTTP/1 framing, body and connection limits, request deadlines, authentication before state validation, and request-time owner/mode/symlink checks.
- Long macOS temporary paths use a deterministic owner-private short socket directory under the canonical system temporary directory. There is no loopback TCP fallback.
- The primary CLI provides stable JSON envelopes, human-safe output, typed exit classes, daemon lifecycle, doctor, status, watch/reconnect, report, cancellation, dry-run GC, and offline Python v2 migration.
- Repository inspection, audit, draft, and Apply remain explicit typed-unavailable Rust commands. The accepted Python oracle remains the current non-mutating repository inspection path until Phase 4 adapters are connected.
- The process protocol performs exact version/capability negotiation, bounds every frame, clears the child environment, uses an absolute executable and private working directory, drains but never exposes stderr, and kills the Unix process group on failure, timeout, or cancellation.
- Windows process-tree supervision remains typed unsupported. The Rust crates are configured to compile and test under the declared CI matrix, but no Windows adapter execution claim is made.

SQLite 3.51.3 is the minimum embedded version because it contains the upstream WAL-reset corruption fix documented in the [SQLite 3.51.3 release notes](https://www.sqlite.org/releaselog/3_51_3.html). The workspace pins `rusqlite` 0.39.0 and its bundled SQLite dependency rather than accepting an older vulnerable bundle or a newer crate that requires a later Rust compiler.

## Canonical CLI boundary

The Rust binary is authoritative for trusted daemon state and safe reports:

```bash
cd rust
cargo build --release --bins --locked
target/release/promptectomy --json doctor
target/release/promptectomy --json --daemon-dir /private/tool/root daemon
target/release/promptectomy --json --daemon-dir /private/tool/root status RUN_ID
target/release/promptectomy --json --daemon-dir /private/tool/root report RUN_ID --format json
```

The daemon is intentionally a separate foreground process. Its endpoint metadata redacts the socket path and bearer token from ordinary CLI JSON.

## Verification

The machine-readable receipt is [phase-3-receipt.json](phase-3-receipt.json). The final acceptance run passed:

- 65 Rust tests across 18 test binaries with all features enabled;
- 2,560 deterministic property/fuzz-smoke cases across strict JSON, path, and protocol decoding;
- a release-mode local-state microbenchmark: 4 microseconds read p95, 18 microseconds small-report p95, and 429 microseconds to reopen and read one run on the 18-core arm64 acceptance host;
- locked all-target/all-feature Rust check and strict Clippy with warnings denied;
- deterministic cross-language contract regeneration and strict TypeScript compilation;
- 30 focused Contract v2, state, artifact, API/report, and migration Python tests;
- 146 full Python tests with the accepted digest-pinned OrbStack OCI image;
- 132 full Python tests plus 14 expected optional-OCI skips with no image selected;
- a real Python v2 run imported once, queried and reported through the release Rust CLI, restarted twice with an identical projection, and left the source store unchanged;
- release `doctor` success and typed unsupported exit 3 for Rust repository inspection;
- protected route source preservation at SHA-256 `a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c`.

[GitHub Actions run 29688503367](https://github.com/zippyg/codex-build-hack/actions/runs/29688503367) then passed on commit `6abcd348eec952ff2e51d92e7c718e1337cbae1e`. Contract generation and the complete locked Rust check, strict Clippy, test, and release benchmark sequence succeeded on `macos-15`, `ubuntu-24.04`, and `windows-2025`.

The protocol child-exit race was then repeated 320 times through the focused supervisor test without a failure. Benchmark values are warm-cache Phase 3 boundary measurements, not the full release performance qualification scheduled for Phase 9. The accepted OCI image remained exactly `sha256:23b8908a955aa2b7eb602845e08b50e1821d072ed67e510580d2392fbffec4f0`.

## Review findings resolved

The acceptance loop exposed four issues that narrower unit runs had missed:

1. Opening a Python WAL database read-only could still create SQLite sidecars in the source directory. Import now works only from a stable private byte copy and rejects live sidecars without changing them.
2. A fast nonzero adapter exit could race the protocol EOF and surface as a generic protocol failure. The supervisor now gives the process status a bounded exit-reconciliation window, and the regression is repeated within the test.
3. macOS Unix socket paths can be shorter than long temporary state paths. The daemon now selects a deterministic private short socket directory when the direct path exceeds the conservative cross-Unix bound, with no TCP fallback.
4. Windows cannot use Unix-style directory handles for a portable directory fsync, and `FlushFileBuffers` requires a write-capable file handle. The core now retains real directory fsync on Unix, validates the parent boundary on Windows after flushing the actual file, and opens backup files with write authority for their durability flush. The repaired Windows state, migration, import, CAS, and benchmark paths passed the real Windows CI job.

Core and daemon/CLI ownership reviews found no residual P0/P1 after authority, idempotency, import graph, backup/rollback, permission, framing, and restart hardening. Fresh integrated diff, security, and portability reviews were run against the accepted tree before the phase commit; their final disposition is recorded in the Phase 3 agent log.

## Deliberate limits

Phase 3 does not claim safe remote Git/archive acquisition, Python/TypeScript Responses discovery, capture or OTLP import, protected-content encryption, Codex synthesis, isolated candidate evaluation, TUI, desktop GUI, agents, Apply, signing, packaging, or public release. Those remain explicit later-phase gates.
