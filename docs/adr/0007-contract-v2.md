# ADR 0007: Contract v2 source and compatibility

Status: accepted
Date: 18 July 2026

## Context

The prototype manually mirrors Pydantic and Zod event types. Several domain concepts have no durable contract, and current events can contain raw diff inputs/outputs. Rust, Python, TypeScript, multiple clients, reports, and adapters need one compatible, privacy-aware contract.

## Decision

Canonical external contracts use JSON Schema Draft 2020-12 in a tracked `schemas/v2` tree when Phase 2 begins. Phase 0 defines the domain and validates the approach but does not create product schemas or a Rust workspace.

Rules:

1. Every document has `schema_uri` and `schema_version`. External versions use semantic major/minor/patch metadata; persisted objects record the exact schema digest.
2. IDs are opaque, typed, ASCII, length-bounded, and namespace-specific. Artifact IDs encode the digest algorithm. Repository-relative paths are separate validated fields, never IDs.
3. Ordinary object schemas reject unknown fields. Explicit extension maps use namespaced keys and size/type limits.
4. Events use one envelope with event ID, run ID, monotonic run-local sequence, timestamp, type, payload schema/version, idempotency key where applicable, safe payload, and artifact references.
5. Event sequence is gap-detecting, replayable, and append-only. Consumers resume after a cursor and detect a retention gap.
6. Readers may accept a newer minor only when the schema declares compatible additive behavior and the generated binding proves unknown-field handling at the chosen boundary. Unknown majors are rejected with `unsupported_contract_major`.
7. Database migrations are forward-only with verified backup and export compatibility. Static reports use a frozen run snapshot, not a live database.
8. Errors have a stable code, category, retryability, safe message, optional next action, stage/entity references, and protected diagnostic artifact reference. Exceptions and secrets do not enter safe events.
9. Machine JSON and exit codes are stable public contracts. Human text is not parsed as an API.
10. Code generation is reproducible and pinned. Generated files carry schema digest/tool version and are checked for a clean regeneration diff in CI.

Canonical entities are Repository, Snapshot, Authority, Run, Stage, Event, Callsite, Observation, Finding, Candidate, Evaluation, Patch, Artifact, Receipt, and Error. Their required fields and invariants are specified in [contract v2](../architecture/contracts-v2.md).

The choice of JSON Schema 2020-12 follows the published [Draft 2020-12 specification](https://json-schema.org/draft/2020-12). Protobuf remains a future option if binary streaming or broader ecosystem constraints justify a second transport; it is not needed for the local v1 control plane.

## Consequences

- Rust, Python, TypeScript, CLI, TUI, GUI, and reports can be tested against one source.
- Strict safe events prevent raw protected content from leaking through convenience fields.
- Compatibility becomes intentional rather than whichever validator is more permissive.
- Contract evolution has ceremony, but migrations and external adapters become reviewable.

## Rejected alternatives

- Keep Pydantic and Zod as co-equal sources: rejected because drift already requires manual discipline.
- Rust structs as the only source: rejected because adapter and report ecosystems need a language-neutral published schema.
- Protobuf immediately: rejected because readable JSON/NDJSON and schema-generated local clients are sufficient for v1.
- Accept arbitrary unknown fields everywhere: rejected because it hides typos and creates unreviewed data/egress surfaces.

## Verification

Phase 0's disposable proof validates representative Repository, Run, Event, Error, and Receipt examples using Rust, Python, and TypeScript validators. Its result is recorded in [contract v2](../architecture/contracts-v2.md). Full generation/compatibility tests start in Phase 2.
