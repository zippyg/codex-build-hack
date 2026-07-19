# Privacy, storage, and data-egress policy

Status: accepted Phase 0 policy
Date: 18 July 2026

## Default

PROMPTECTOMY is local-first and metadata-only by default. Reading local source is not permission to retain it, send it to Codex, capture prompts/outputs, export it, or upload diagnostics. Each of those is a distinct capability shown before use.

Local-only mode disables external model calls, remote analytics, remote diagnostics, and remote dependency/repository acquisition. Deterministic inventory, supported local parsing, imported local evidence, and already-available offline evaluation can still run. A stage that requires an external model returns `local_only_model_stage_unavailable`; it never silently transmits or pretends it ran.

## Data classes

| Class | Examples | Default persistence | Default egress |
|---|---|---|---|
| D0 public/safe metadata | Versioned IDs, counts, durations, safe status/reason codes, digests, adapter/tool versions | Run store, 30-day default unless pinned/configured | None; optional content-free analytics requires separate opt-in |
| D1 source confidential | Source files, diffs, filenames/paths, manifests, Git history, local/remote identity | Snapshot only for active run; deleted at terminal cleanup unless pinned, with 7-day default for a pinned reproducibility snapshot | No source leaves machine without an exact source-context manifest |
| D2 protected evidence | Prompts, completions, tool arguments/results, retrieved documents, raw spans, user/tenant/trace identifiers, labels | Off by default; session-only when enabled unless user selects retention | No egress without an exact content-class/destination/purpose grant |
| D3 credentials and secrets | API keys, tokens, cookies, auth headers, credential stores, SSH private keys, model connector secrets | Never in run/artifact/report/event storage | Only trusted connector/broker receives the credential it needs; never an agent tool/executor/report |
| D4 untrusted generated/output content | Repository text, agent text, command logs, patches, HTML/Markdown/SVG, terminal sequences | Safe/sanitized form only in normal store; raw only as protected artifact if approved | Export only after sanitization/redaction policy |
| D5 security/diagnostic material | Cause chains, crash data, host/tool details, rejected malicious input | Safe diagnostics for 7 days by default; protected raw diagnostics opt-in | User preview and explicit destination grant required |

Paths and repository names can be sensitive. Safe UI may show them locally, but analytics/diagnostic exports replace them with scoped opaque IDs unless the user explicitly includes them.

## Preflight and egress manifest

Before a capability can transmit data, preflight shows and persists:

- run/action ID, source identity, immutable revision/snapshot digest, selected roots and exclusions;
- mode, stage, adapter/AgentRuntime/prompt bundle/model version;
- destination organization/service, endpoint class, transport, region/data policy link where known;
- purpose and one-time/reusable scope;
- exact source files/symbol slices or artifact classes eligible to leave the machine;
- evidence fields/content classes eligible to leave;
- minimization/redaction versions and a sample preview that contains no unredacted secret;
- maximum files/bytes/requests/tokens/cost/time;
- whether content may be retained by the destination and the product's inability to delete external copies;
- local retention/deletion policy and cleanup behavior;
- authority expiry and revocation/cancellation behavior.

The user approves the manifest digest. If selected files, destination, model, prompt bundle, content class, budget, or retention expands, the grant no longer matches and work pauses for new authority. A blanket "repository access" checkbox is insufficient.

For noninteractive CI, a checked-in policy can pre-authorize exact classes/destinations/budgets. Policy mismatch fails closed with a machine-readable reason.

## Source minimization

Deterministic discovery identifies the smallest relevant symbol slices before external semantic analysis. The context builder:

1. starts from selected roots and support rules;
2. excludes ignored/vendor/generated/binary/secret-designated files unless explicitly needed;
3. includes the callsite, enclosing symbol, required type/signature/import context, and bounded references;
4. replaces unrelated literals/content with typed summaries where semantics permit;
5. scans for secrets and protected content before transmission;
6. records file paths/ranges and digests in the manifest;
7. refuses transmission if minimization or redaction cannot preserve the declared policy.

Whole-repository upload is not a stable v1 default or hidden fallback. Repository prompt instructions are delimited as untrusted data.

## Evidence capture

- Metadata-only capture records operation/model/SDK, timestamps, status, durations, token/usage counts, safe shape/digests, streaming/tool/error/retry flags, and opaque correlation identifiers.
- Prompt, output, tool/retrieval content, labels, and user identifiers are off by default.
- Protected capture requires field allowlists, value/secret detection, sample preview, purpose, retention, and destination decisions.
- Allowlist beats denylist. Redaction runs before persistence and again before model context/export.
- Unknown fields are not copied into safe events. They are dropped with a coverage warning or retained only in an approved protected raw artifact.
- Synthetic evidence is labelled. It cannot be confused with captured production data.

OTLP receivers handle retries, partial success, duplicate/out-of-order delivery, input limits, and unknown fields according to the pinned protocol mapping. Duplicate identity never requires storing raw content in the dedupe key.

## Storage boundary

Local state lives in an OS-user-private directory, never inside the target repository. Directory/file permissions are restrictive at creation and verified on every open. Symlinks, unsafe ownership, network filesystems for SQLite WAL, and permissive pre-existing files fail closed.

Safe metadata, protected artifacts, and source snapshots are separate classes:

- ordinary safe metadata and events use the SQLite store;
- immutable blobs use content-addressed storage with class metadata and reference tracking;
- D2 protected content is independently authenticated/encrypted per blob;
- D3 credentials remain in an OS credential store or a just-in-time broker, outside artifact storage;
- the GUI and reports receive opaque artifact handles, not storage paths.

Protected storage implementation must use a reviewed library and versioned authenticated-encryption envelope with algorithm/version, unique nonce, associated metadata binding artifact/class/installation, ciphertext, and authentication tag. A per-install wrapping key resides in a supported OS credential store; data keys are never logged/exported with ciphertext. Key loss, rotation, backup, restore, wrong-key, tamper, and secure-store-unavailable behavior are specified and tested before D2 persistence is enabled. No homegrown cryptography is allowed.

If secure key storage is unavailable, persistent D2 capture is disabled. Session-only in-memory use is allowed only when the user explicitly grants it and the process guarantees no swap/crash/report persistence claim beyond the platform's documented boundary.

## Retention and deletion

Defaults:

- D0 safe run metadata/reports/receipts/patches: 30 days;
- D1 active source snapshot/scratch: delete after terminal cleanup; a user-pinned reproducibility snapshot defaults to 7 days and requires visible expiry;
- D2 protected content: session-only unless the user selects a duration/count; never inherited from another run;
- D5 safe diagnostics: 7 days;
- user-pinned final report/receipt/patch: retained until unpinned/deleted.

The user can select shorter retention and storage quotas. A policy cannot silently lengthen retention after capture.

Deletion is an inventory operation:

1. resolve references for the requested run/artifact/data class;
2. show pinned/shared dependencies and external/exported copies PROMPTECTOMY cannot delete;
3. delete database references and unreferenced blobs transactionally;
4. clear caches, temporary snapshots, scratch, and pending upload queues;
5. record a safe deletion receipt containing IDs/digests/classes/counts, not deleted content;
6. report retained backups, OS snapshots, remote model/provider retention, and failed cleanup honestly.

The product never promises physical or cryptographic erasure beyond stores it controls. Backup/export documentation explains how users delete external copies.

## Safe events, logs, terminal, API, and reports

Normal events and `/state`/`events` equivalents permit D0 plus safe D4 summaries and opaque references. They prohibit D1 source bodies, D2 content, D3 credentials, raw D5 diagnostics, reversible group keys, and untrusted terminal control bytes.

All human terminal/log text escapes control characters, hyperlinks, ANSI, bidirectional overrides, and unsafe Unicode display cases while preserving a downloadable protected raw log only when approved. Exception traces go to protected diagnostics, not CLI JSON.

HTML/Markdown/SVG/code/diff/path/URL content is treated as untrusted. Static HTML has no privileged bridge, inline executable repository content, arbitrary remote scripts, or unsafe link schemes. Export policy is frozen with the run snapshot and records redactions/exclusions.

Diagnostic bundles are previewable manifests. Upload is always explicit, destination-scoped, redacted, size-bounded, and separately cancellable. Product analytics are off by default, content-free, schema-published, independently revocable, and never required for core function.

## Credential and network separation

- Git credentials go only to the acquisition broker for the approved host/repository.
- Model credentials go only to the trusted model connector for approved endpoints.
- Provider capture credentials stay in the user's application/capture connector and never enter reports or candidate evaluation.
- Agent shell tools, generated code, repository code, tests, package scripts, and evaluators receive an empty environment plus a non-secret allowlist and are offline during evaluation.
- No child receives credential-store paths, browser profiles, SSH private keys, cloud config directories, or connector control sockets.

## Privacy canary acceptance

The hostile privacy corpus places unique canaries in source, prompt, completion, tool arguments/results, trace attributes, labels, environment, Git URL, filenames, exception messages, terminal output, and dependency output. Tests must prove canaries do not appear in:

- `events.ndjson` or contract v2 event tables;
- CLI human/JSON stdout or stderr;
- local API state/event/error payloads;
- TUI/GUI safe projections;
- Markdown/HTML/JSON/NDJSON/SARIF/JUnit exports;
- default reports, receipts, analytics, crash/diagnostic bundles;
- agent prompts outside the exact approved manifest;
- executor environment, logs, or returned artifacts when not declared.

Tests also prove authorized protected content is encrypted, access-controlled, excluded from safe exports, deletable, and rejected when key storage is unavailable.

## User-visible promises

Approved wording:

- "Metadata-only by default."
- "Source or trace content leaves your machine only under the preflight manifest you approve."
- "Local-only mode disables external agent/model stages and reports them as unavailable."
- "Deletion covers PROMPTECTOMY-controlled local stores and reports external/backed-up copies it cannot erase."

Prohibited wording includes "we never store data" when a run is persisted, "fully local" when Codex is used, "anonymous" when identifiers can be linked, or "securely erased" without a bounded technical claim.

## Verification map

Controls map to `PRIV-*`, `EGRESS-*`, `CRED-*`, `REPORT-*`, and `BACKUP-*` threats in [the threat model](threat-model.md) and to matching tests in [testing and benchmarks](testing-and-benchmarks.md). No real/private traffic capture is supported until the relevant release gates pass.
