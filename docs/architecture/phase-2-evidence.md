# Phase 2 acceptance evidence

Status: accepted
Date: 19 July 2026
Scope: Contract v2, durable local state, content-addressed artifacts, local API contract, deterministic reports, and Phase 1 import

## Outcome

Phase 2 replaces prototype-only state assumptions with a versioned, fail-closed product foundation. It does not claim the Phase 3 Rust daemon or CLI.

- JSON Schema Draft 2020-12 is the canonical source for 15 core entities.
- RFC 8785 canonical JSON and purpose/schema domain separation bind SHA-256 identifiers and receipts.
- Python, TypeScript, and Rust transport bindings regenerate deterministically and embed the canonical schema digest.
- APSW 3.53.3.1 embeds SQLite 3.53.3, above the accepted 3.51.3 WAL safety floor.
- Run and stage projections update in the same transaction as their immutable events.
- Run-local sequences, idempotency keys, event IDs, state transitions, completion evidence, and retention gaps fail closed.
- State roots must be absolute, private, owner-controlled, and on an accepted local filesystem.
- SQLite uses WAL, `synchronous=FULL`, foreign keys, secure deletion, no-follow open, defensive mode, disabled double-quoted strings, and disabled trusted schema.
- Artifact writes use private same-filesystem temporary files, full digest and size verification, file sync, atomic hard-link publication, directory sync, then database registration.
- Startup reconciliation quarantines unknown, missing, symlinked, incomplete, and tampered artifacts.
- Garbage collection defaults to dry-run and respects pins, retention, and transactional references.
- The local API requires a high-entropy bearer capability, strict Host and Origin checks, no wildcard CORS, bounded bodies, rate limits, strict duplicate-free JSON, idempotency, and safe typed errors.
- Only safe artifact bodies can cross the API. Protected canaries are denied and never echoed.
- JSON and Markdown reports derive from one frozen safe run/event snapshot and are byte-deterministic.
- Phase 1 run import preserves the target repository and records the original safe result as a pinned artifact.

## Compatibility boundary

The Python ASGI application defines and tests the canonical `/v2` handler behavior. It is not a hosted service and does not bind a network interface. Phase 3 adds the Rust daemon, Unix-domain-socket or named-pipe transport, lifecycle, and primary CLI while preserving these fixtures.

The `.invalid` schema URI is deliberate. It provides a stable, non-resolving identifier until the project name and public domain receive explicit approval.

## Verification

The machine-readable receipt is [phase-2-receipt.json](phase-2-receipt.json). Final acceptance covers:

- Contract examples, strict JSON, canonicalization, identifier shapes, path boundaries, and reproducible bindings;
- SQLite migration/version gates, two-connection WAL reads, backup/integrity, atomic sequence rejection, run/stage transitions, recovery proof, and cursor expiry;
- CAS authorization, metadata conflicts, tamper/symlink detection, quarantine, reconciliation, reference-aware dry-run GC, and atomic-write fault injection;
- API capability, Host, Origin, body, rate, idempotency, duplicate JSON, safe-error, cursor, report parity, and protected-artifact boundaries;
- source and hostile installed-wheel runs with and without the accepted OCI image;
- locked Python dependencies, locked offline Rust compilation, strict TypeScript compilation, Ruff, Pyright, Semgrep, pip-audit, Gitleaks, and protected-file digest preservation.

The installed artifact acceptance produced two byte-identical wheels and passed outside the source checkout with Python sockets disabled. No generated hackathon code or obsolete execution modules entered the wheel.

## Review findings

The first hostile installed test attempted to use Starlette's in-process test client, which creates a Unix socketpair. The no-socket harness correctly rejected it. Installed acceptance now constructs the API routes and tests state/report/artifact behavior without sockets, while source tests exercise HTTP semantics separately.

The security review also closed duplicate-member ambiguity, attacker-value error reflection, artifact orphan recovery, database symlink following, mismatched event/state transitions, completion without performed-work evidence, and interruption without explicit worker-absence proof.

No unresolved P0, P1, critical, or high finding remains in Phase 2. The current Starlette TestClient deprecation warning is third-party test-only noise and does not affect runtime behavior.
