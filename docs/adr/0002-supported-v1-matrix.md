# ADR 0002: Stable v1 support matrix

Status: accepted
Date: 18 July 2026

## Context

Codex can reason about many languages, but the surrounding discovery, capture, correlation, execution, and evaluation contracts determine actual product support. The prototype is Python/OpenAI-specific and its synchronous shim is not representative of the full Responses surface.

## Decision

Stable v1 targets Python and TypeScript/JavaScript with the OpenAI Responses API.

| Capability | Python | TypeScript/JavaScript | Other languages |
|---|---:|---:|---:|
| L0 inventory | Stable | Stable | Best-effort inventory with explicit exclusions |
| L1 Responses discovery | Stable | Stable | Adapter required |
| L2 OTLP/OpenInference evidence link | Stable | Stable | Language-neutral only when correlation is proven |
| L3 isolated candidate evaluation | Stable for declared fixtures/toolchains | Stable for declared fixtures/toolchains | Experimental adapter required |
| L4 patch, tests, report, receipt | Stable for declared fixtures/toolchains | Stable for declared fixtures/toolchains | Experimental adapter required |
| L5 integration | Not part of initial stable local release | Not part of initial stable local release | Unsupported |

The stable operation matrix requires synchronous, asynchronous, streaming, structured output, tool calls, retries, errors, cancellation, and SDK-version compatibility. A missing cell lowers the affected callsite's support level. It does not become a warning attached to a success claim.

OpenAI Responses is the first provider adapter, not a core dependency. Provider, language, evidence, and executor adapters are versioned independently against a public conformance suite.

Supported means all of the following are true:

1. Deterministic discovery coverage is measured on golden fixtures.
2. Observations correlate to stable callsite fingerprints with reported confidence.
3. Required content fields can remain protected and metadata-only operation works.
4. Candidate and repository execution use an accepted executor.
5. Evaluation covers operation semantics, including stream events, tools, structured data, retry/error behavior, and cancellation where applicable.
6. Installed artifacts pass the declared clean-environment matrix.
7. Unsupported wrappers, dynamic dispatch, SDK versions, or toolchains produce typed coverage gaps.

## Consequences

- Marketing cannot say "any codebase" without immediately qualifying that any input can receive L0 inventory while L1-L4 are adapter-scoped.
- Python hardening precedes TypeScript implementation, but both are release requirements for the stable v1 promise.
- New languages/providers start experimental and become stable only after the same conformance evidence exists.
- The current sync-only Python shim remains historical/experimental and cannot define stable capture behavior.

## Rejected alternatives

- Python-only stable v1: faster, but it would not meet the stated cross-language product direction.
- Every language via Codex: rejected because semantic understanding does not supply capture, toolchain, isolation, correlation, or evaluation guarantees.
- Provider-specific core schema: rejected because it would make migration and evidence import brittle.

## Verification

The exact adapter interface, feature cells, and promotion rules are in [adapters and support](../architecture/adapters-and-support.md). Tests `SUP-*`, `DISC-*`, `CAP-*`, and `EVAL-*` in [testing and benchmarks](../architecture/testing-and-benchmarks.md) are release gates.
