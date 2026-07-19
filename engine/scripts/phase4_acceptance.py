from __future__ import annotations

import hashlib
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import rfc8785


ENGINE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ENGINE_ROOT.parent
RUST_ROOT = REPOSITORY_ROOT / "rust"
NODE_ROOT = REPOSITORY_ROOT / "adapters" / "node"
sys.path.insert(0, str(ENGINE_ROOT))

from promptectomy.support_matrix_phase4 import (  # noqa: E402
    EvidenceRecord,
    Phase4EvidenceReceipt,
    build_phase4_support_matrix,
)
from promptectomy.contracts_v2 import ContractError, parse_json_strict  # noqa: E402


PROTECTED_DIGEST = "a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c"
PROTECTED_TRACKED_DIGEST = (
    "75944ba99d386798002496ae0ef39bf8d0159f4bb2d2daea57b65009e00a9d8c"
)
RECEIPT_PATH = REPOSITORY_ROOT / "docs" / "architecture" / "phase-4-receipt.json"
MATRIX_PATH = REPOSITORY_ROOT / "docs" / "architecture" / "support-matrix-v1.json"
BOUND_PATHS = (
    ".gitattributes",
    ".github/workflows/phase4.yml",
    "adapters/node",
    "engine/promptectomy/capture_python.py",
    "engine/promptectomy/discovery_javascript.py",
    "engine/promptectomy/discovery_models.py",
    "engine/promptectomy/discovery_python.py",
    "engine/promptectomy/evidence_phase4.py",
    "engine/promptectomy/privacy_phase4.py",
    "engine/promptectomy/reference.py",
    "engine/promptectomy/reference_contracts.py",
    "engine/promptectomy/support_matrix_phase4.py",
    "engine/pyproject.toml",
    "engine/scripts/phase4_acceptance.py",
    "engine/tests/fixtures/phase4_discovery",
    "engine/tests/test_phase4_acceptance.py",
    "engine/tests/test_phase4_capture_python.py",
    "engine/tests/test_phase4_discovery.py",
    "engine/tests/test_phase4_evidence.py",
    "engine/tests/test_phase4_privacy.py",
    "engine/tests/test_phase4_support_matrix.py",
    "engine/uv.lock",
    "rust/Cargo.lock",
    "rust/Cargo.toml",
    "rust/crates/promptectomy-acquisition",
    "rust/crates/promptectomy-protected-store",
)
_DURATION = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s)\b")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@dataclass(frozen=True)
class CommandEvidence:
    label: str
    command: tuple[str, ...]
    cwd: Literal["engine", "rust", "repository", "temporary"]
    returncode: int
    stdout: str
    stderr: str

    def canonical_value(self) -> dict[str, object]:
        return {
            "label": self.label,
            "command": list(self.command),
            "cwd": self.cwd,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


@dataclass(frozen=True)
class SuitePlan:
    status: Literal["passed", "unsupported"]
    evidence_labels: tuple[str, ...]


SUITE_PLAN = {
    "ARCH": SuitePlan("passed", ("acquisition",)),
    "BACKUP-DELETE": SuitePlan("unsupported", ("privacy", "protected-store")),
    "BUNDLE": SuitePlan("passed", ("acquisition",)),
    "CAP-NODE": SuitePlan("passed", ("capture-node",)),
    "CAP-NORMALIZE": SuitePlan(
        "passed", ("evidence", "capture-python", "capture-node")
    ),
    "CAP-PY": SuitePlan("passed", ("capture-python",)),
    "DISC-DYNAMIC": SuitePlan("passed", ("discovery",)),
    "DISC-GOLDEN": SuitePlan("passed", ("discovery",)),
    "DISC-PY": SuitePlan("passed", ("discovery",)),
    "DISC-TS": SuitePlan("passed", ("discovery",)),
    "EGRESS": SuitePlan("passed", ("privacy",)),
    "GIT-HTTPS": SuitePlan("unsupported", ("acquisition",)),
    "GIT-LOCAL": SuitePlan("passed", ("acquisition",)),
    "GIT-SSH-BROKER": SuitePlan("unsupported", ("acquisition",)),
    "KEYSTORE-PERSISTENT": SuitePlan("unsupported", ("privacy", "protected-store")),
    "NONMUTATION": SuitePlan("passed", ("acquisition", "source-guard")),
    "OTLP-GRPC": SuitePlan("passed", ("evidence",)),
    "OTLP-HTTP": SuitePlan("passed", ("evidence",)),
    "OTLP-MAPPING": SuitePlan("passed", ("evidence",)),
    "PATH": SuitePlan("passed", ("acquisition",)),
    "PRIV-CANARY": SuitePlan(
        "passed", ("evidence", "privacy", "capture-python", "capture-node")
    ),
    "PRIV-DEL": SuitePlan("unsupported", ("privacy", "protected-store")),
    "PROTECTED-DIGEST": SuitePlan("passed", ("source-guard",)),
    "SOURCE-STATUS": SuitePlan("passed", ("source-guard",)),
    "TREE-SITTER-PINNED": SuitePlan("passed", ("lock", "discovery")),
    "WHEEL-CLEAN": SuitePlan("passed", ("clean-install",)),
}


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_output(value: str, replacements: tuple[tuple[str, str], ...] = ()) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _ANSI.sub("", normalized)
    for original, replacement in replacements:
        normalized = normalized.replace(original, replacement)
    normalized = normalized.replace(str(REPOSITORY_ROOT), "$REPOSITORY")
    normalized = _DURATION.sub("<duration>", normalized)
    return normalized.strip()


def run_command(
    label: str,
    command: list[str],
    *,
    cwd: Path,
    cwd_label: Literal["engine", "rust", "repository", "temporary"],
    display_command: tuple[str, ...] | None = None,
    replacements: tuple[tuple[str, str], ...] = (),
    timeout: int = 900,
) -> CommandEvidence:
    environment = {
        name: os.environ[name]
        for name in (
            "APPDATA",
            "HOME",
            "LOCALAPPDATA",
            "PATH",
            "SystemRoot",
            "TMPDIR",
            "USERPROFILE",
            "WINDIR",
        )
        if name in os.environ
    }
    environment.update(
        {
            "CARGO_TERM_COLOR": "never",
            "NO_COLOR": "1",
            "PYTHONHASHSEED": "0",
            "UV_NO_PROGRESS": "1",
        }
    )
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    evidence = CommandEvidence(
        label=label,
        command=tuple(command) if display_command is None else display_command,
        cwd=cwd_label,
        returncode=result.returncode,
        stdout=normalize_output(result.stdout, replacements),
        stderr=normalize_output(result.stderr, replacements),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Phase 4 acceptance command {label!r} failed with exit {result.returncode}: "
            f"{evidence.command!r}\nstdout:\n{evidence.stdout[-12000:]}\nstderr:\n{evidence.stderr[-12000:]}"
        )
    return evidence


def result_digest(
    suite_id: str,
    status: Literal["passed", "unsupported"],
    evidence: tuple[CommandEvidence, ...],
) -> str:
    return _sha256(
        rfc8785.dumps(
            {
                "suite_id": suite_id,
                "status": status,
                "evidence": [item.canonical_value() for item in evidence],
            }
        )
    )


def build_receipt(
    source_head: str, evidence: dict[str, CommandEvidence]
) -> Phase4EvidenceReceipt:
    records = []
    for suite_id, plan in sorted(SUITE_PLAN.items()):
        missing = [label for label in plan.evidence_labels if label not in evidence]
        if missing:
            raise RuntimeError(
                f"Phase 4 suite {suite_id} lacks command evidence: {', '.join(missing)}"
            )
        command_evidence = tuple(evidence[label] for label in plan.evidence_labels)
        records.append(
            EvidenceRecord(
                suite_id,
                result_digest(suite_id, plan.status, command_evidence),
                plan.status,
            )
        )
    return Phase4EvidenceReceipt(
        schema_version="promptectomy.phase4-evidence.v1",
        source_head=source_head,
        records=tuple(records),
    )


def receipt_document(receipt: Phase4EvidenceReceipt) -> dict[str, object]:
    return {
        "schema_version": receipt.schema_version,
        "source_head": receipt.source_head,
        "records": [record.__dict__ for record in receipt.records],
        "receipt_id": receipt.receipt_id(),
    }


def write_outputs(
    receipt: Phase4EvidenceReceipt,
) -> tuple[dict[str, object], dict[str, object]]:
    receipt_value = receipt_document(receipt)
    matrix = json.loads(
        json.dumps(
            build_phase4_support_matrix(
                receipt=receipt, receipt_id=receipt.receipt_id()
            )
        )
    )
    RECEIPT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT_PATH.write_text(
        json.dumps(receipt_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    MATRIX_PATH.write_text(
        json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt_value, matrix


def verify_tracked_outputs() -> None:
    try:
        receipt_value = parse_json_strict(RECEIPT_PATH.read_bytes())
        matrix_value = parse_json_strict(MATRIX_PATH.read_bytes())
    except (OSError, ContractError) as exc:
        raise RuntimeError(
            "Phase 4 tracked acceptance outputs are missing or invalid"
        ) from exc
    if not isinstance(receipt_value, dict) or set(receipt_value) != {
        "schema_version",
        "source_head",
        "records",
        "receipt_id",
    }:
        raise RuntimeError("Phase 4 tracked receipt shape is invalid")
    raw_records = receipt_value["records"]
    if not isinstance(raw_records, list):
        raise RuntimeError("Phase 4 tracked receipt records are invalid")
    try:
        records = tuple(
            EvidenceRecord(
                suite_id=record["suite_id"],
                result_digest=record["result_digest"],
                status=record["status"],
            )
            for record in raw_records
            if isinstance(record, dict)
            and set(record) == {"suite_id", "result_digest", "status"}
        )
        receipt = Phase4EvidenceReceipt(
            schema_version=receipt_value["schema_version"],
            source_head=receipt_value["source_head"],
            records=records,
        )
    except (KeyError, TypeError) as exc:
        raise RuntimeError("Phase 4 tracked receipt records are invalid") from exc
    if (
        len(records) != len(raw_records)
        or receipt.receipt_id() != receipt_value["receipt_id"]
    ):
        raise RuntimeError("Phase 4 tracked receipt is not content-bound")
    expected_matrix = json.loads(
        json.dumps(
            build_phase4_support_matrix(
                receipt=receipt, receipt_id=receipt.receipt_id()
            )
        )
    )
    if matrix_value != expected_matrix:
        raise RuntimeError("Phase 4 tracked support matrix does not match its receipt")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", receipt.source_head, "HEAD"],
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ["PATH"]},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if ancestor.returncode != 0:
        raise RuntimeError("Phase 4 tracked receipt source is not an ancestor of HEAD")
    drift = subprocess.run(
        ["git", "diff", "--quiet", receipt.source_head, "HEAD", "--", *BOUND_PATHS],
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ["PATH"]},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if drift.returncode != 0:
        raise RuntimeError(
            "Phase 4 tracked receipt is stale for a bound implementation path"
        )


def _pytest(label: str, test_file: str) -> CommandEvidence:
    return run_command(
        label,
        [
            sys.executable,
            "-m",
            "pytest",
            "-qq",
            "--disable-warnings",
            "--no-header",
            "--no-summary",
            "--disable-socket",
            "--allow-unix-socket",
            test_file,
        ],
        cwd=ENGINE_ROOT,
        cwd_label="engine",
        display_command=(
            "python",
            "-m",
            "pytest",
            "-qq",
            "--disable-warnings",
            "--no-header",
            "--no-summary",
            "--disable-socket",
            "--allow-unix-socket",
            test_file,
        ),
    )


def _clean_install(temporary: Path) -> tuple[CommandEvidence, ...]:
    distribution = temporary / "dist"
    environment = temporary / "venv"
    replacements = ((str(temporary), "$TEMPORARY"),)
    build = run_command(
        "clean-install-build",
        ["uv", "build", "--offline", "--wheel", "--out-dir", str(distribution)],
        cwd=ENGINE_ROOT,
        cwd_label="engine",
        display_command=(
            "uv",
            "build",
            "--offline",
            "--wheel",
            "--out-dir",
            "$TEMPORARY/dist",
        ),
        replacements=replacements,
    )
    wheels = sorted(distribution.glob("promptectomy-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Phase 4 clean install did not produce exactly one wheel")
    create = run_command(
        "clean-install-venv",
        ["uv", "venv", "--python", "3.12", str(environment)],
        cwd=ENGINE_ROOT,
        cwd_label="temporary",
        display_command=("uv", "venv", "--python", "3.12", "$TEMPORARY/venv"),
        replacements=replacements,
    )
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    install = run_command(
        "clean-install-wheel",
        ["uv", "pip", "install", "--offline", "--python", str(python), str(wheels[0])],
        cwd=temporary,
        cwd_label="temporary",
        display_command=(
            "uv",
            "pip",
            "install",
            "--offline",
            "--python",
            "$TEMPORARY/venv/python",
            "$TEMPORARY/dist/promptectomy.whl",
        ),
        replacements=replacements,
    )
    probe = run_command(
        "clean-install-import",
        [
            str(python),
            "-I",
            "-c",
            (
                "import promptectomy.capture_python, promptectomy.discovery_python, "
                "promptectomy.discovery_javascript, promptectomy.evidence_phase4, "
                "promptectomy.privacy_phase4, promptectomy.support_matrix_phase4"
            ),
        ],
        cwd=temporary,
        cwd_label="temporary",
        display_command=(
            "$TEMPORARY/venv/python",
            "-I",
            "-c",
            "import Phase 4 stable modules",
        ),
        replacements=replacements,
    )
    return build, create, install, probe


def run_conformance() -> tuple[str, dict[str, CommandEvidence]]:
    protected = ENGINE_ROOT / "promptectomy" / "generated" / "route_ticket.py"
    protected_status = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--",
            "engine/promptectomy/generated/route_ticket.py",
        ],
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ["PATH"]},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=10,
        check=False,
    )
    expected_protected_digest = (
        PROTECTED_DIGEST
        if protected_status.stdout.strip()
        else PROTECTED_TRACKED_DIGEST
    )
    if (
        protected_status.returncode != 0
        or file_digest(protected) != expected_protected_digest
    ):
        raise RuntimeError(
            "protected route file digest changed before Phase 4 acceptance"
        )
    source_head_result = run_command(
        "source-head",
        ["git", "rev-parse", "HEAD"],
        cwd=REPOSITORY_ROOT,
        cwd_label="repository",
    )
    source_head = source_head_result.stdout
    if not re.fullmatch(r"[0-9a-f]{40}", source_head):
        raise RuntimeError("Phase 4 source HEAD is not a full Git object ID")
    status_before = run_command(
        "source-status-before",
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=REPOSITORY_ROOT,
        cwd_label="repository",
    )
    staged_before = run_command(
        "staged-before",
        ["git", "diff", "--cached", "--name-only"],
        cwd=REPOSITORY_ROOT,
        cwd_label="repository",
    )
    if (
        "engine/promptectomy/generated/route_ticket.py"
        in staged_before.stdout.splitlines()
    ):
        raise RuntimeError("protected route file is staged before Phase 4 acceptance")

    evidence: dict[str, CommandEvidence] = {}
    evidence["lock"] = run_command(
        "lock",
        ["uv", "lock", "--check"],
        cwd=ENGINE_ROOT,
        cwd_label="engine",
    )
    evidence["acquisition"] = run_command(
        "acquisition",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-acquisition",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    evidence["protected-store"] = run_command(
        "protected-store",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-protected-store",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    evidence["discovery"] = _pytest("discovery", "tests/test_phase4_discovery.py")
    evidence["capture-python"] = _pytest(
        "capture-python", "tests/test_phase4_capture_python.py"
    )
    node_install = run_command(
        "capture-node-install",
        ["bun", "install", "--frozen-lockfile"],
        cwd=NODE_ROOT,
        cwd_label="repository",
    )
    node_typecheck = run_command(
        "capture-node-typecheck",
        ["bun", "run", "typecheck"],
        cwd=NODE_ROOT,
        cwd_label="repository",
    )
    node_tests = run_command(
        "capture-node-tests",
        ["bun", "test"],
        cwd=NODE_ROOT,
        cwd_label="repository",
    )
    evidence["capture-node"] = CommandEvidence(
        label="capture-node",
        command=("bun-frozen-install-typecheck-test",),
        cwd="repository",
        returncode=0,
        stdout=_sha256(
            rfc8785.dumps(
                [
                    item.canonical_value()
                    for item in (node_install, node_typecheck, node_tests)
                ]
            )
        ),
        stderr="",
    )
    evidence["evidence"] = _pytest("evidence", "tests/test_phase4_evidence.py")
    evidence["privacy"] = _pytest("privacy", "tests/test_phase4_privacy.py")
    evidence["support"] = _pytest("support", "tests/test_phase4_support_matrix.py")

    with tempfile.TemporaryDirectory(
        prefix="promptectomy-phase4-clean-"
    ) as temporary_name:
        clean = _clean_install(Path(temporary_name))
    combined = CommandEvidence(
        label="clean-install",
        command=("offline-wheel-build-install-import",),
        cwd="temporary",
        returncode=0,
        stdout=_sha256(rfc8785.dumps([item.canonical_value() for item in clean])),
        stderr="",
    )
    evidence["clean-install"] = combined

    status_after = run_command(
        "source-status-after",
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=REPOSITORY_ROOT,
        cwd_label="repository",
    )
    staged_after = run_command(
        "staged-after",
        ["git", "diff", "--cached", "--name-only"],
        cwd=REPOSITORY_ROOT,
        cwd_label="repository",
    )
    source_head_after = run_command(
        "source-head-after",
        ["git", "rev-parse", "HEAD"],
        cwd=REPOSITORY_ROOT,
        cwd_label="repository",
    )
    if source_head_after.stdout != source_head:
        raise RuntimeError("Phase 4 source HEAD changed during conformance")
    if (
        status_after.stdout != status_before.stdout
        or staged_after.stdout != staged_before.stdout
    ):
        raise RuntimeError("Phase 4 conformance changed source or index status")
    if file_digest(protected) != expected_protected_digest:
        raise RuntimeError(
            "protected route file digest changed during Phase 4 acceptance"
        )
    source_guard_value = {
        "protected_digest_valid": True,
        "protected_staged": False,
        "source_head_unchanged": True,
        "source_status_unchanged": True,
        "index_status_unchanged": True,
    }
    evidence["source-guard"] = CommandEvidence(
        label="source-guard",
        command=("internal-source-and-protected-file-guard",),
        cwd="repository",
        returncode=0,
        stdout=json.dumps(source_guard_value, separators=(",", ":"), sort_keys=True),
        stderr="",
    )
    return source_head, evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    arguments = parser.parse_args()
    if arguments.verify:
        verify_tracked_outputs()
        print('{"phase":4,"status":"verified"}')
        return 0
    source_head, evidence = run_conformance()
    receipt = build_receipt(source_head, evidence)
    receipt_value, matrix = write_outputs(receipt)
    print(
        json.dumps(
            {
                "receipt_id": receipt_value["receipt_id"],
                "records": len(receipt.records),
                "stable_cells": sum(
                    cell["state"] == "stable" for cell in matrix["cells"]
                ),
                "unsupported_cells": sum(
                    cell["state"] == "unsupported" for cell in matrix["cells"]
                ),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
