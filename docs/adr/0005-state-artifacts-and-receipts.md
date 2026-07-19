# ADR 0005: State, artifacts, and receipts

Status: accepted
Date: 18 July 2026

## Context

Prototype JSONL and registry files are useful evidence but do not provide transactional state transitions, crash recovery, stable compatibility, protected-content separation, or artifact integrity. The product also needs to distinguish local consistency from third-party identity claims.

## Decision

- SQLite is the authoritative local run/job/event store.
- Every state transition atomically appends an immutable event and updates a derived projection.
- Large, generated, and protected blobs live in a private content-addressed artifact store, not in ordinary events.
- Artifact identifiers include the algorithm and lowercase digest, initially `sha256:<64 hex>` for interoperable receipts. BLAKE3 may be used for internal cache indexing only when the algorithm remains explicit.
- Writes use a same-filesystem temporary file, byte count and digest validation, atomic rename, directory sync where supported, then database reference creation. Incomplete artifacts are quarantined and never referenced as complete.
- Reference tracking and garbage collection are transactional. Garbage collection defaults to dry-run, respects pins/retention/legal holds, and never traverses user repositories.
- SQLite WAL is local-disk only and requires an embedded upstream-fixed version: 3.51.3 or later, or a documented patched line such as 3.50.7/3.44.6. Backup/checkpoint/recovery procedures treat the database, `-wal`, and `-shm` files as one live state set.
- Legacy ledgers, registries, and event fixtures are import-only. Import records provenance gaps and never rewrites originals.

### Receipt semantics

V1 evaluation receipts are canonical, digest-bound local manifests. They bind at least:

- receipt schema and policy version;
- repository/snapshot and authority digests;
- callsite/finding/candidate/patch digests;
- adapter, prompt bundle, model/runtime, toolchain, executor image/config, and evaluator manifests;
- evidence/dataset/split/holdout digests and evidence grade;
- commands, limits, normalized results, resource use, timestamps, and declared nondeterminism;
- artifact digests and safe report snapshot digest.

The receipt root digest detects changes to bound bytes. It does not prove who ran the evaluation, that the local core was uncompromised, or that a third party should trust the result. UI/docs call it digest-bound or tamper-evident within the trusted local boundary, never signed.

Identity signatures are deferred until a separate ADR defines signer identity, key generation/storage, allowed algorithms, rotation, revocation, expiry, export, recovery, verifier trust roots, and verification UX. Release signatures and SLSA provenance are separate supply-chain artifacts.

## Consequences

- The UI can reconstruct a run after a crash and detect gaps rather than infer success.
- Private content can be access-controlled and deleted independently of safe events.
- Storage migration, checkpointing, quota, backup, and garbage collection become product features with tests.
- Digest binding gives reproducibility evidence without making a false identity claim.

## Rejected alternatives

- Continue with mutable JSON files as authority: rejected because multi-process recovery and atomic state/artifact relationships are required.
- Put blobs in SQLite: rejected for large report/source/trace payloads and protected-content lifecycle separation.
- Call hash manifests signed receipts: rejected because a digest has no signer or key trust policy.
- Network database for local v1: rejected as unnecessary operational and privacy complexity.

## Verification

Contract fields and lifecycle are in [contract v2](../architecture/contracts-v2.md). Tests `STATE-*`, `ART-*`, `RECEIPT-*`, `MIG-*`, and `PRIV-DEL-*` in [testing and benchmarks](../architecture/testing-and-benchmarks.md) are required.
