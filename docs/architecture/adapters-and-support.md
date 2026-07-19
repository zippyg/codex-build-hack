# Adapters and supported surface

Status: accepted Phase 0 contract
Date: 18 July 2026

## Support principle

Support is a proven conformance level for a specific snapshot, callsite, language, provider operation, SDK/toolchain, evidence source, and adapter version. It is not inferred from Codex's general code knowledge.

Stable v1 is Python and TypeScript/JavaScript with OpenAI Responses. Other languages can receive L0 inventory and may use experimental adapters, but cannot be called stable until their public conformance suite passes.

## Adapter families

| Family | Responsibility | Never owns |
|---|---|---|
| Inventory | Languages, manifests, lockfiles, toolchains, generated/vendor roots | Repository execution or semantic support claims |
| Discovery | Deterministic syntax/symbol rules, callsite fingerprints, coverage | Final eligibility or hidden silent exclusions |
| Evidence | Parse/import/capture, normalize, deduplicate, correlate, classify protection | Raw content in normal events or external egress authority |
| Provider | Normalize operation semantics, request/response/tool/stream/error/retry shapes | Core run state or provider credentials in target code |
| Language/toolchain | Map findings/candidates/tests/patches to target language and project layout | Host execution or package-manager substitution |
| Evaluator | Execute declared behavior/contract/domain checks and report evidence | Candidate generation or authority escalation |
| AgentRuntime | Typed bounded semantic task to proposal/activity | Final correctness, hidden holdout, Apply, or executor policy |
| Executor | Enforce a declared execution manifest | Product support decision or automatic weaker fallback |
| Exporter | Convert frozen safe run state to an external format | Querying live mutable state or reading protected blobs without grant |

Adapters run out of process where a parser/runtime or dependency increases the trusted surface. The core sends opaque artifact references or scoped bytes, not its storage roots. Protocol messages are size-bounded and contract-versioned.

## Stable v1 feature matrix

| Feature | Python | TypeScript/JavaScript | Stable evidence requirement |
|---|---:|---:|---|
| Repository inventory | Required | Required | Manifests, lockfiles, versions, exclusions |
| OpenAI Responses static discovery | Required | Required | Golden true/false positive corpus and coverage report |
| Aliases/wrappers | Declared supported patterns | Declared supported patterns | Unresolved dynamic calls reported ambiguous |
| Synchronous calls | Required | Required | Mock endpoint and fixture correlation |
| Asynchronous calls | Required | Required | Await/cancellation/error fixture coverage |
| Streaming | Required | Required | Event ordering, partial/error/cancel/final semantics |
| Structured output | Required | Required | Schema/output shape preservation and invalid-output cases |
| Tool calls | Required | Required | Tool definitions, arguments, results, parallel/order semantics |
| Retries and errors | Required | Required | Attempt identity, duplicate handling, final error semantics |
| OTLP HTTP/gRPC import | Language-neutral | Language-neutral | Duplicate/out-of-order/partial/malformed/unknown-field cases |
| OpenInference normalization | Required where present | Required where present | Versioned mapping and unmapped fields report |
| Metadata-only operation | Required | Required | Protected-content canary suite |
| L3 isolated evaluation | Required before stable L3 | Required before stable L3 | Accepted executor/toolchain matrix |
| L4 patch/tests/report/receipt | Required before stable L4 | Required before stable L4 | Reviewable artifact and receipt gates |

The OpenTelemetry GenAI conventions have moved into a separate evolving repository, so mappings pin a convention version and retain unknown/unmapped attributes rather than assuming a timeless schema. OTLP itself defines HTTP/gRPC delivery and may produce duplicates after retry: [OTLP specification](https://opentelemetry.io/docs/specs/otlp/). [OpenInference](https://github.com/Arize-ai/openinference) is treated as a complementary convention over OpenTelemetry, not a transport replacement.

## Discovery contract

Discovery runs in this order:

1. Inventory selected roots, manifests, lockfiles, imports, generated/vendor rules, and versions.
2. Apply pinned ast-grep/Tree-sitter rules for supported SDK surfaces.
3. Optionally consume a pinned SCIP index when symbol/reference precision justifies it.
4. Produce callsite candidates plus deterministic evidence, exclusions, and coverage gaps.
5. Ask Codex to classify minimized candidates only after deterministic discovery.
6. Validate every agent-reported path, symbol, operation, and support claim against the snapshot and adapter schema.
7. Return ambiguous/unsupported candidates explicitly.

Callsite identity uses repository/snapshot digest, normalized relative path, enclosing symbol, provider operation, normalized AST digest, and adapter version. Cross-commit matching emits old/new IDs plus confidence and reasons. It never silently changes an identity.

## Observation contract

Each normalized observation includes:

- observation/event ID and schema/adapter version;
- callsite fingerprint and correlation confidence/reason;
- provider/model/operation/SDK version;
- timestamp and trace/span/request attempt identities;
- normalized request/response shapes and digests;
- optional protected content references;
- latency, usage, price source/version, and estimated/observed cost label;
- streaming/tool/structured/error/retry/cancellation metadata;
- capture/redaction/retention policy IDs;
- provenance and synthetic/imported/captured classification.

Raw prompt, output, tool data, retrieved content, and user identifiers are protected content, not ordinary observation fields. Unknown provider attributes are preserved only in a bounded protected/raw artifact when policy allows.

## Evidence and evaluation levels

An evaluation uses all applicable lenses:

1. Behavioral preservation: observed output/shape/error/stream semantics and latency.
2. Contract/invariant correctness: schemas, property tests, security/business rules, repository tests.
3. Domain truth: labels, task metrics, calibrated judge, or human review.

Grades are:

- `insufficient`: missing samples, coverage, evaluator, isolation, or required domain evidence;
- `exploratory`: useful result with material unvalidated assumptions;
- `reviewable`: declared thresholds and applicable lenses pass for human review;
- `strong`: predeclared coverage/confidence thresholds and independent domain/contract evidence pass.

Baseline agreement alone cannot exceed `exploratory` when domain truth is applicable but absent. Synthetic evidence is clearly labelled and cannot become hidden ground truth.

Splits group exact/near duplicates, support domain hashes, use deterministic train/development/hidden holdout, prefer time-based holdouts where drift matters, track rare/high-impact cases, and enforce minimum counts. Candidate agents cannot read holdout content or a reversible identifier that reveals it.

## Conformance levels

An adapter release reports:

- protocol/schema versions;
- languages/providers/operations/SDK/toolchain versions;
- stable/experimental/deprecated state;
- supported L0-L5 cells;
- fixture and hostile-corpus versions;
- platform matrix;
- privacy classes read/produced/transmitted;
- executor requirements;
- known false positives, false negatives, dynamic gaps, and limits;
- compatibility and support window.

Promotion to stable requires all declared feature cells, installed-artifact tests, privacy canaries, no silent drop/zero-work success, cross-platform CI for claimed platforms, and no unresolved critical/high relevant security finding. Removal or incompatible behavior requires major protocol handling or a deprecation window.

## Typed unsupported outcomes

At minimum:

- `unsupported_language`
- `unsupported_provider`
- `unsupported_sdk_version`
- `unsupported_operation`
- `unsupported_call_pattern`
- `ambiguous_dynamic_callsite`
- `missing_evidence_adapter`
- `insufficient_evidence`
- `missing_isolation_backend`
- `safe_agent_transport_unavailable`
- `unsupported_toolchain`
- `policy_denied_content`
- `local_only_model_stage_unavailable`

Each outcome names entity/stage, adapter/version, observed facts, highest level reached, retryability, and exact next action. A repository with only unsupported callsites ends `completed_with_unsupported`, not `completed` and not a zero-finding success.

## Versioning and lifecycle

Adapters use a compatibility handshake before work. Unknown major versions are rejected. Minor additive behavior is accepted only where the contract explicitly allows it. The core records adapter binary/package digest and configuration digest in every affected artifact/receipt.

Broken adapters can be disabled or pinned without migrating the core database backward. Stable support is withdrawn only through a security advisory or documented release/deprecation process, never a silent remote flag.

## Verification

The golden repository/evidence matrix and test identifiers are in [testing and benchmarks](testing-and-benchmarks.md). Privacy behavior is in [privacy and data egress](privacy-and-data-egress.md). Contract shapes are in [contract v2](contracts-v2.md).
