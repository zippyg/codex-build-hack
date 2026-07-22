from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from promptectomy.support_matrix_phase4 import Phase4EvidenceReceipt
from scripts import phase4_acceptance
from scripts.phase4_acceptance import (
    CommandEvidence,
    SUITE_PLAN,
    build_receipt,
    normalize_output,
    receipt_document,
    result_digest,
    write_outputs,
    verify_tracked_outputs,
    verify_remote_artifact_pins,
)


def _evidence(label: str, stdout: str = "passed") -> CommandEvidence:
    return CommandEvidence(
        label=label,
        command=("offline-test", label),
        cwd="engine",
        returncode=0,
        stdout=stdout,
        stderr="",
    )


def _all_evidence() -> dict[str, CommandEvidence]:
    return {
        label: _evidence(label)
        for plan in SUITE_PLAN.values()
        for label in plan.evidence_labels
    }


def test_normalization_removes_host_paths_ansi_and_nondeterministic_durations() -> None:
    temporary = "/tmp/private-phase4"
    raw = f"\x1b[31mBuilt {temporary}/wheel in 18ms\x1b[0m\r\nfinished in 0.42s\n"
    assert normalize_output(raw, ((temporary, "$TEMPORARY"),)) == (
        "Built $TEMPORARY/wheel in <duration>\nfinished in <duration>"
    )


def test_result_digest_is_domain_separated_and_binds_real_command_evidence() -> None:
    evidence = (_evidence("discovery"),)
    first = result_digest("DISC-PY", "passed", evidence)
    assert first.startswith("sha256:")
    assert len(first) == 71
    assert result_digest("DISC-TS", "passed", evidence) != first
    assert result_digest("DISC-PY", "unsupported", evidence) != first
    assert (
        result_digest("DISC-PY", "passed", (replace(evidence[0], stdout="different"),))
        != first
    )


def test_receipt_covers_every_stable_requirement_and_keeps_boundaries_unsupported() -> (
    None
):
    receipt = build_receipt("a" * 40, _all_evidence())
    records = {record.suite_id: record for record in receipt.records}
    expected_passed = {
        "ARCH",
        "BACKUP-DELETE",
        "BOUND-SOURCE-CLEAN",
        "BUNDLE",
        "CAP-NODE",
        "CAP-NORMALIZE",
        "DAEMON-INSPECT",
        "DISC-DYNAMIC",
        "DISC-GOLDEN",
        "DISC-PY",
        "DISC-TS",
        "EGRESS",
        "GIT-LOCAL",
        "GIT-HTTPS",
        "KEYSTORE-MACOS-NATIVE",
        "KEYSTORE-PERSISTENT",
        "NONMUTATION",
        "OTLP-GRPC",
        "OTLP-HTTP",
        "OTLP-MAPPING",
        "PATH",
        "PRIV-CANARY",
        "PRIV-DEL",
        "REMOTE-ARTIFACT-PINS",
        "REMOTE-IMAGE-PACKAGES",
        "TREE-SITTER-PINNED",
    }
    assert all(records[suite_id].status == "passed" for suite_id in expected_passed)
    assert records["GIT-HTTPS"].status == "passed"
    assert records["GIT-SSH-BROKER"].status == "passed"
    assert records["CAP-PY"].status == "passed"
    assert records["WHEEL-CLEAN"].status == "passed"
    assert len({record.result_digest for record in receipt.records}) == len(
        receipt.records
    )


def test_missing_command_evidence_fails_closed() -> None:
    evidence = _all_evidence()
    del evidence["privacy"]
    with pytest.raises(RuntimeError, match="lacks command evidence"):
        build_receipt("a" * 40, evidence)


def test_outputs_round_trip_exact_receipt_and_support_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_path = tmp_path / "phase-4-receipt.json"
    matrix_path = tmp_path / "support-matrix-v1.json"
    monkeypatch.setattr(phase4_acceptance, "RECEIPT_PATH", receipt_path)
    monkeypatch.setattr(phase4_acceptance, "MATRIX_PATH", matrix_path)
    receipt = build_receipt("b" * 40, _all_evidence())

    receipt_value, matrix = write_outputs(receipt)

    assert json.loads(receipt_path.read_text()) == receipt_value
    assert json.loads(matrix_path.read_text()) == matrix
    reconstructed = Phase4EvidenceReceipt(
        schema_version=receipt_value["schema_version"],
        source_head=receipt_value["source_head"],
        records=receipt.records,
    )
    assert receipt_value["receipt_id"] == reconstructed.receipt_id()
    assert matrix["receipt_id"] == receipt_value["receipt_id"]
    cells = {cell["cell_id"]: cell for cell in matrix["cells"]}
    assert cells["acquisition_local"]["state"] == "stable"
    assert cells["acquisition_https"]["state"] == "experimental"
    assert cells["acquisition_https"]["platforms"] == ["macos-arm64-orbstack"]
    assert cells["acquisition_ssh_broker"]["state"] == "experimental"
    assert cells["acquisition_ssh_broker"]["platforms"] == ["macos-arm64-orbstack"]
    assert cells["python_runtime_capture"]["state"] == "stable"
    assert cells["node_runtime_capture"]["state"] == "stable"
    assert cells["persistent_protected_storage"]["state"] == "stable"
    assert cells["persistent_protected_storage"]["platforms"] == ["macos"]
    assert cells["local_deletion"]["state"] == "stable"


def test_receipt_identifier_changes_with_source_or_command_evidence() -> None:
    evidence = _all_evidence()
    original = build_receipt("a" * 40, evidence)
    changed_head = build_receipt("b" * 40, evidence)
    changed_evidence = dict(evidence)
    changed_evidence["acquisition"] = replace(
        changed_evidence["acquisition"], stdout="17 tests passed"
    )
    changed_result = build_receipt("a" * 40, changed_evidence)
    assert (
        len(
            {
                original.receipt_id(),
                changed_head.receipt_id(),
                changed_result.receipt_id(),
            }
        )
        == 3
    )


def test_receipt_document_contains_only_content_bound_payload_and_identifier() -> None:
    receipt = build_receipt("c" * 40, _all_evidence())
    value = receipt_document(receipt)
    assert set(value) == {"schema_version", "source_head", "records", "receipt_id"}
    assert value["receipt_id"] == receipt.receipt_id()


def test_clean_checkout_and_preserved_local_diff_have_separate_protected_digests() -> (
    None
):
    assert (
        phase4_acceptance.PROTECTED_DIGEST != phase4_acceptance.PROTECTED_TRACKED_DIGEST
    )
    assert len(phase4_acceptance.PROTECTED_DIGEST) == 64
    assert len(phase4_acceptance.PROTECTED_TRACKED_DIGEST) == 64


def test_remote_artifact_evidence_matches_the_reviewed_rust_policy_and_package_lock() -> (
    None
):
    assert phase4_acceptance.REMOTE_ARTIFACT_PINS["ssh_connect_digest"].startswith(
        "sha256:"
    )
    assert phase4_acceptance.REMOTE_ARTIFACT_PINS["relay_digest"].startswith("sha256:")
    assert phase4_acceptance.REMOTE_ARTIFACT_PINS[
        "ssh_fixture_image_digest"
    ].startswith("sha256:")
    source = (
        phase4_acceptance.RUST_ROOT
        / "crates"
        / "promptectomy-acquisition"
        / "src"
        / "remote.rs"
    ).read_text(encoding="utf-8")
    verify_remote_artifact_pins(source)
    with pytest.raises(RuntimeError, match="disagree"):
        verify_remote_artifact_pins(
            source.replace(
                phase4_acceptance.REMOTE_ARTIFACT_PINS["image_digest"],
                "sha256:" + "0" * 64,
                1,
            )
        )


def test_receipt_staleness_boundary_covers_phase4_ci_and_line_endings() -> None:
    assert ".github/workflows/phase4.yml" in phase4_acceptance.BOUND_PATHS
    assert ".github/workflows/rust.yml" in phase4_acceptance.BOUND_PATHS
    assert ".gitattributes" in phase4_acceptance.BOUND_PATHS
    assert "rust/crates/promptectomy-protected-store" in phase4_acceptance.BOUND_PATHS
    assert "rust/crates/promptectomy-daemon" in phase4_acceptance.BOUND_PATHS
    assert "rust/crates/promptectomy-cli" in phase4_acceptance.BOUND_PATHS
    assert "rust/crates/promptectomy-ssh-agent-relay" in phase4_acceptance.BOUND_PATHS
    assert ".gitignore" in phase4_acceptance.BOUND_PATHS
    assert "rust/.gitignore" in phase4_acceptance.BOUND_PATHS
    assert "rust/rust-toolchain.toml" in phase4_acceptance.BOUND_PATHS


def test_tracked_output_verification_rejects_stale_bound_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    matrix_path = tmp_path / "matrix.json"
    monkeypatch.setattr(phase4_acceptance, "RECEIPT_PATH", receipt_path)
    monkeypatch.setattr(phase4_acceptance, "MATRIX_PATH", matrix_path)
    receipt = build_receipt("a" * 40, _all_evidence())
    write_outputs(receipt)

    class _Result:
        def __init__(self, returncode: int, stdout: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout

    results = iter((_Result(0), _Result(0), _Result(1)))
    monkeypatch.setattr(
        phase4_acceptance.subprocess, "run", lambda *args, **kwargs: next(results)
    )
    with pytest.raises(RuntimeError, match="stale"):
        verify_tracked_outputs()


def test_tracked_output_verification_rejects_dirty_bound_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    matrix_path = tmp_path / "matrix.json"
    monkeypatch.setattr(phase4_acceptance, "RECEIPT_PATH", receipt_path)
    monkeypatch.setattr(phase4_acceptance, "MATRIX_PATH", matrix_path)
    write_outputs(build_receipt("a" * 40, _all_evidence()))

    class _Result:
        returncode = 0
        stdout = " M rust/rust-toolchain.toml\n"

    monkeypatch.setattr(
        phase4_acceptance.subprocess, "run", lambda *args, **kwargs: _Result()
    )
    with pytest.raises(RuntimeError, match="dirty bound"):
        verify_tracked_outputs()
