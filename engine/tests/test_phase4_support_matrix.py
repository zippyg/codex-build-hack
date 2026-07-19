from __future__ import annotations

from dataclasses import replace

import pytest

from promptectomy.support_matrix_phase4 import (
    EvidenceRecord,
    Phase4EvidenceReceipt,
    SupportMatrixError,
    build_phase4_support_matrix,
)


EVIDENCE = {
    "ARCH",
    "BACKUP-DELETE",
    "BUNDLE",
    "CAP-NODE",
    "CAP-PY",
    "CAP-NORMALIZE",
    "DISC-DYNAMIC",
    "DISC-GOLDEN",
    "DISC-PY",
    "DISC-TS",
    "EGRESS",
    "GIT-LOCAL",
    "NONMUTATION",
    "OTLP-GRPC",
    "OTLP-HTTP",
    "OTLP-MAPPING",
    "PATH",
    "PRIV-CANARY",
    "PRIV-DEL",
    "TREE-SITTER-PINNED",
}


def _receipt(evidence: set[str] = EVIDENCE) -> Phase4EvidenceReceipt:
    return Phase4EvidenceReceipt(
        schema_version="promptectomy.phase4-evidence.v1",
        source_head="a" * 40,
        records=tuple(
            EvidenceRecord(suite_id, "sha256:" + f"{index:064x}", "passed")
            for index, suite_id in enumerate(sorted(evidence), start=1)
        ),
    )


def test_matrix_publishes_only_evidenced_stable_cells_and_visible_gaps() -> None:
    receipt = _receipt()
    matrix = build_phase4_support_matrix(receipt=receipt, receipt_id=receipt.receipt_id())
    cells = matrix["cells"]
    assert isinstance(cells, list)
    stable = [cell for cell in cells if cell["state"] == "stable"]
    assert len(stable) == 12
    assert all(cell["evidence"] for cell in stable)
    assert any(cell["cell_id"] == "acquisition_https" and cell["state"] == "unsupported" for cell in cells)
    assert any(cell["cell_id"] == "python_runtime_capture" and cell["state"] == "stable" for cell in cells)
    assert any(cell["cell_id"] == "node_runtime_capture" and cell["state"] == "stable" for cell in cells)
    assert any(cell["cell_id"] == "persistent_protected_storage" and cell["state"] == "unsupported" for cell in cells)
    assert any(cell["state"] == "experimental" and cell["level"] == "L3" for cell in cells)
    assert any(cell["state"] == "unsupported" and cell["level"] == "L5" for cell in cells)


def test_missing_or_failed_evidence_cannot_be_published_as_stable() -> None:
    missing = _receipt(EVIDENCE - {"TREE-SITTER-PINNED"})
    with pytest.raises(SupportMatrixError, match="TREE-SITTER-PINNED"):
        build_phase4_support_matrix(receipt=missing, receipt_id=missing.receipt_id())
    receipt = _receipt()
    failed = replace(
        receipt,
        records=tuple(
            replace(record, status="failed") if record.suite_id == "TREE-SITTER-PINNED" else record
            for record in receipt.records
        ),
    )
    with pytest.raises(SupportMatrixError, match="TREE-SITTER-PINNED"):
        build_phase4_support_matrix(receipt=failed, receipt_id=failed.receipt_id())


def test_matrix_requires_exact_content_bound_receipt() -> None:
    receipt = _receipt()
    with pytest.raises(SupportMatrixError, match="content-bound"):
        build_phase4_support_matrix(receipt=receipt, receipt_id="receipt_sha256_" + "0" * 64)
    forged = replace(receipt, source_head="b" * 40)
    with pytest.raises(SupportMatrixError, match="content-bound"):
        build_phase4_support_matrix(receipt=forged, receipt_id=receipt.receipt_id())
