from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

import rfc8785


class SupportMatrixError(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceRecord:
    suite_id: str
    result_digest: str
    status: Literal["passed", "failed", "unsupported"]


@dataclass(frozen=True)
class Phase4EvidenceReceipt:
    schema_version: Literal["promptectomy.phase4-evidence.v1"]
    source_head: str
    records: tuple[EvidenceRecord, ...]

    def canonical_payload(self) -> bytes:
        return rfc8785.dumps(
            {
                "schema_version": self.schema_version,
                "source_head": self.source_head,
                "records": [record.__dict__ for record in sorted(self.records, key=lambda item: item.suite_id)],
            }
        )

    def receipt_id(self) -> str:
        return f"receipt_sha256_{hashlib.sha256(self.canonical_payload()).hexdigest()}"


@dataclass(frozen=True)
class SupportCell:
    cell_id: str
    capability: str
    language: str
    provider: str
    operation: str
    level: Literal["L0", "L1", "L2", "L3", "L4", "L5"]
    state: Literal["stable", "experimental", "unsupported"]
    evidence: tuple[str, ...]
    limitation: str | None = None


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_HEAD = re.compile(r"^[0-9a-f]{40}$")
_SUITE_ID = re.compile(r"^[A-Z][A-Z0-9-]{0,63}$")
_STABLE_REQUIREMENTS = {
    "acquisition_local": ("GIT-LOCAL", "PATH", "NONMUTATION"),
    "acquisition_archive": ("ARCH", "PATH", "NONMUTATION"),
    "acquisition_bundle": ("BUNDLE", "PATH", "NONMUTATION"),
    "python_responses_discovery": ("DISC-PY", "DISC-GOLDEN", "DISC-DYNAMIC"),
    "typescript_responses_discovery": ("DISC-TS", "DISC-GOLDEN", "DISC-DYNAMIC", "TREE-SITTER-PINNED"),
    "metadata_normalization": ("CAP-NORMALIZE", "PRIV-CANARY"),
    "python_runtime_capture": ("CAP-PY", "PRIV-CANARY"),
    "node_runtime_capture": ("CAP-NODE", "PRIV-CANARY"),
    "otlp_http_json": ("OTLP-HTTP", "OTLP-MAPPING", "PRIV-CANARY"),
    "otlp_grpc_protobuf": ("OTLP-GRPC", "OTLP-MAPPING", "PRIV-CANARY"),
    "egress_manifest": ("EGRESS", "PRIV-CANARY"),
}


def _verified_evidence(receipt: Phase4EvidenceReceipt, receipt_id: str) -> set[str]:
    if receipt.schema_version != "promptectomy.phase4-evidence.v1" or not _SOURCE_HEAD.fullmatch(receipt.source_head):
        raise SupportMatrixError("support matrix evidence receipt metadata is invalid")
    if receipt_id != receipt.receipt_id():
        raise SupportMatrixError("support matrix requires a valid content-bound Phase 4 receipt")
    if len({record.suite_id for record in receipt.records}) != len(receipt.records):
        raise SupportMatrixError("support matrix evidence receipt contains duplicate suite identities")
    for record in receipt.records:
        if not _SUITE_ID.fullmatch(record.suite_id) or not _DIGEST.fullmatch(record.result_digest):
            raise SupportMatrixError("support matrix evidence receipt contains an invalid record")
    return {record.suite_id for record in receipt.records if record.status == "passed"}


def _stable(
    cell_id: str,
    evidence: set[str],
    *,
    capability: str,
    language: str,
    provider: str,
    operation: str,
    level: Literal["L0", "L1", "L2", "L3", "L4", "L5"],
    limitation: str | None = None,
) -> SupportCell:
    required = _STABLE_REQUIREMENTS[cell_id]
    missing = sorted(set(required) - evidence)
    if missing:
        raise SupportMatrixError(f"stable cell {cell_id!r} lacks evidence: {', '.join(missing)}")
    return SupportCell(
        cell_id=cell_id,
        capability=capability,
        language=language,
        provider=provider,
        operation=operation,
        level=level,
        state="stable",
        evidence=required,
        limitation=limitation,
    )


def build_phase4_support_matrix(
    *,
    receipt: Phase4EvidenceReceipt,
    receipt_id: str,
) -> dict[str, object]:
    evidence = _verified_evidence(receipt, receipt_id)
    cells = [
        _stable(
            "acquisition_local",
            evidence,
            capability="repository_acquisition",
            language="language_neutral",
            provider="local",
            operation="immutable_snapshot",
            level="L0",
            limitation="macOS and Linux only; Windows private storage is typed unsupported.",
        ),
        _stable(
            "acquisition_archive",
            evidence,
            capability="repository_acquisition",
            language="language_neutral",
            provider="ustar",
            operation="validated_snapshot",
            level="L0",
            limitation="macOS and Linux only; Windows private storage is typed unsupported.",
        ),
        _stable(
            "acquisition_bundle",
            evidence,
            capability="repository_acquisition",
            language="language_neutral",
            provider="source_bundle",
            operation="validated_snapshot",
            level="L0",
            limitation="macOS and Linux only; Windows private storage is typed unsupported.",
        ),
    ]
    for language, cell_id in (
        ("python", "python_responses_discovery"),
        ("typescript_javascript", "typescript_responses_discovery"),
    ):
        cells.append(
            _stable(
                cell_id,
                evidence,
                capability="static_discovery",
                language=language,
                provider="openai",
                operation="responses.create_parse_declared_surface",
                level="L1",
            )
        )
    cells.extend(
        [
            _stable(
                "metadata_normalization",
                evidence,
                capability="metadata_normalization",
                language="language_neutral",
                provider="openai",
                operation="bounded_content_free_record",
                level="L2",
            ),
            _stable(
                "python_runtime_capture",
                evidence,
                capability="metadata_only_capture",
                language="python",
                provider="openai",
                operation="responses_runtime_adapter",
                level="L2",
            ),
            _stable(
                "node_runtime_capture",
                evidence,
                capability="metadata_only_capture",
                language="node",
                provider="openai",
                operation="responses_runtime_adapter",
                level="L2",
            ),
            _stable(
                "otlp_http_json",
                evidence,
                capability="evidence_import",
                language="language_neutral",
                provider="otlp_http_json",
                operation="offline_trace_export_import",
                level="L2",
            ),
            _stable(
                "otlp_grpc_protobuf",
                evidence,
                capability="evidence_import",
                language="language_neutral",
                provider="otlp_grpc_protobuf",
                operation="offline_trace_export_import",
                level="L2",
            ),
            _stable(
                "egress_manifest",
                evidence,
                capability="data_egress",
                language="language_neutral",
                provider="approved_destination",
                operation="authority_complete_manifest_preview",
                level="L2",
            ),
            SupportCell(
                "local_deletion",
                "retention_deletion",
                "language_neutral",
                "local_tool_storage",
                "reference_aware_deletion_receipt",
                "L2",
                "experimental",
                (),
                "Flat synthetic artifacts are covered, but transactional protected storage, backup references, key destruction, and crash recovery are not complete.",
            ),
            SupportCell(
                "acquisition_https",
                "repository_acquisition",
                "language_neutral",
                "git_https",
                "no_checkout_snapshot",
                "L0",
                "unsupported",
                (),
                "The Git process is neutralized, but clone disk usage is not yet kernel-bounded.",
            ),
            SupportCell(
                "acquisition_ssh_broker",
                "repository_acquisition",
                "language_neutral",
                "git_ssh_broker",
                "no_checkout_snapshot",
                "L0",
                "unsupported",
                (),
                "Broker attestation and controlled private-repository acceptance are not complete.",
            ),
            SupportCell(
                "persistent_protected_storage",
                "protected_storage",
                "language_neutral",
                "os_key_store",
                "authenticated_envelope",
                "L2",
                "unsupported",
                (),
                "The envelope primitive exists, but no supported OS key-store adapter is integrated.",
            ),
            SupportCell(
                "other_language_semantics",
                "static_discovery",
                "other",
                "openai",
                "responses",
                "L0",
                "unsupported",
                (),
                "Other languages receive inventory only until a public adapter conformance suite passes.",
            ),
            SupportCell(
                "other_provider_semantics",
                "static_discovery",
                "python_typescript_javascript",
                "other",
                "provider_operations",
                "L0",
                "unsupported",
                (),
                "Stable v1 supports OpenAI Responses only.",
            ),
            SupportCell(
                "candidate_evaluation",
                "isolated_evaluation",
                "python_typescript_javascript",
                "openai",
                "candidate_behavior",
                "L3",
                "experimental",
                (),
                "Phase 5 owns the hidden-holdout and independent evaluation gates.",
            ),
            SupportCell(
                "patch_receipt",
                "patch_generation",
                "python_typescript_javascript",
                "openai",
                "reviewable_patch_tests_receipt",
                "L4",
                "experimental",
                (),
                "Phase 5 owns stable L4 evaluation and receipt gates.",
            ),
            SupportCell(
                "integration",
                "repository_integration",
                "all",
                "all",
                "apply_or_merge",
                "L5",
                "unsupported",
                (),
                "L5 is not part of the initial stable local release.",
            ),
        ]
    )
    return {
        "schema_version": "promptectomy.support-matrix.v1",
        "phase": 4,
        "receipt_id": receipt_id,
        "cells": [cell.__dict__ for cell in cells],
    }
