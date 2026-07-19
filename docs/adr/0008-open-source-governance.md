# ADR 0008: Open-source governance and release gates

Status: accepted recommendation, legal actions deferred
Date: 18 July 2026

## Context

The repository is currently private and the product name/package namespaces are not legally cleared. Open-sourcing also creates contribution, vulnerability disclosure, compatibility, support, signing, and supply-chain obligations. Phase 0 must choose a direction without pretending that a legal or release action has happened.

## Decision

- Recommend Apache-2.0 because it is permissive and includes an express patent license. Do not add `LICENSE` or represent the project as licensed until dependency and legal review approve the choice.
- Recommend Developer Certificate of Origin (DCO) sign-off for initial contributions. Adopt a CLA only if counsel, ownership, relicensing, or organizational governance requires it.
- Keep PROMPTECTOMY as the development name. Before public release, perform trademark/legal review and reserve/verify GitHub, domain, PyPI, npm, crates.io, Homebrew, and application identifiers. A search is not clearance.
- Begin with a named maintainer group, documented decision rights, ADR/RFC process, code review requirements, conflict policy, release managers, security contacts, and a time-bounded support policy.
- Public release requires `LICENSE`/`NOTICE`, `SECURITY.md`, private disclosure route, `CONTRIBUTING.md`, DCO/CLA instructions, code of conduct, governance, support/compatibility policy, changelog, roadmap, architecture/threat/privacy docs, and honest supported matrix.
- Every contribution that changes a contract, authority, privacy, executor, Git, local IPC, Tauri capability, Apply, release, or credential boundary requires the named specialist review and acceptance tests.
- Releases use clean CI, pinned lockfiles/toolchains, dependency and license review, secret scanning, SBOM, checksums, platform signing/notarization, provenance/attestations, and clean install/upgrade/uninstall smoke tests.
- SLSA is used as a vocabulary and incremental release target, not a badge claimed without evidence. The current [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/) defines build/source tracks and provenance requirements. [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) are one possible implementation for GitHub-built artifacts.
- Supported release claims are blocked by any critical/high security finding, source mutation in Inspect/Audit/Draft, parent-process untrusted execution, executor secret/network escape, false-success state, missing stable matrix cell, unverified installer, or documentation claim beyond evidence.

The [Developer Certificate of Origin](https://developercertificate.org/) is the recommended initial contributor attestation. This ADR does not bind contributors until the repository is public and the governance files are adopted.

## Consequences

- Phase 0 makes no legal commitment and performs no publication.
- Release work is larger than making the GitHub repository public.
- DCO keeps initial contribution operations simple while preserving a documented origin attestation.
- Signed release artifacts and digest-bound evaluation receipts remain distinct concepts.

## Rejected alternatives

- Open the repository immediately under no license: rejected because public visibility does not grant clear reuse rights and bypasses security/release preparation.
- Claim Apache-2.0 now: rejected because dependency and legal review are incomplete.
- Require a CLA immediately: rejected as unnecessary contributor friction without a named legal/governance need.
- Sign only a checksum file and call the supply chain secure: rejected because identity, provenance, builder hardening, verification, and dependency risk are separate.

## Release decision gate

The repository may be made public only after a human approves the license/name decision and the Phase 9 release checklist is satisfied or explicitly labels a pre-release with its missing guarantees. Publication, package reservation, signing keys, and external writes remain human-authorized actions.
