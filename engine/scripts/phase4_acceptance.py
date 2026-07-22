from __future__ import annotations

import argparse
import hashlib
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
    ".gitignore",
    ".gitattributes",
    ".github/workflows/phase4.yml",
    ".github/workflows/rust.yml",
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
    "docs/architecture/phase-4-foundation-evidence.md",
    "rust/Cargo.lock",
    "rust/Cargo.toml",
    "rust/.dockerignore",
    "rust/.gitignore",
    "rust/rust-toolchain.toml",
    "rust/crates/promptectomy-acquisition",
    "rust/crates/promptectomy-cli",
    "rust/crates/promptectomy-daemon",
    "rust/crates/promptectomy-egress-proxy",
    "rust/crates/promptectomy-protected-store",
    "rust/crates/promptectomy-remote-git-runner",
    "rust/crates/promptectomy-ssh-agent-relay",
    "rust/remote-git-image",
)
REMOTE_ARTIFACT_PINS = {
    "image_digest": "sha256:826575ce5fd3b427e4522d64fe13204a174836cd7a052361ac7dee51d42b182e",
    "os_package_manifest_digest": "sha256:0cbbe5492ce23661ea73629f28fd6902c5c0709fd7a9179617f160fdc798b3d9",
    "proxy_digest": "sha256:9291a931763138b51888bb2393fc3e2bdc28c9df0d31e7eb8a7ae55db39f026b",
    "relay_digest": "sha256:399c89fce01f0c87a95b09ca5081ae5399eb2446cd31e6d400521c5ec4b183c7",
    "runner_digest": "sha256:9eebe416b538fc6602313e0a306c8d25b8eac5d990d7b31c109ecc30577dd3fc",
    "ssh_connect_digest": "sha256:f8e1b1d58b7ccc78435b04ea988972ca3a348cebf4de711ffdc172ea4448a256",
    "ssh_fixture_image_digest": "sha256:4b04820c83b9890c1f58fd03004e5df289b67182dc80438cb19fab61e6db0b91",
}
_DURATION = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s)\b")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_RUST_REMOTE_PIN = re.compile(
    r'pub const ORBSTACK_PUBLIC_GIT_(IMAGE|RUNNER|PROXY|RELAY)_DIGEST: &str =\s*"(sha256:[0-9a-f]{64})";'
)
_COMMAND_ENV_ROOT: Path | None = None
_REAL_HOME = Path.home()


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
    "BACKUP-DELETE": SuitePlan("passed", ("protected-store",)),
    "BOUND-SOURCE-CLEAN": SuitePlan("passed", ("source-guard",)),
    "BUNDLE": SuitePlan("passed", ("acquisition",)),
    "CAP-NODE": SuitePlan("passed", ("capture-node",)),
    "CAP-NORMALIZE": SuitePlan(
        "passed", ("evidence", "capture-python", "capture-node")
    ),
    "CAP-PY": SuitePlan("passed", ("capture-python",)),
    "DAEMON-INSPECT": SuitePlan("passed", ("daemon-cli",)),
    "DISC-DYNAMIC": SuitePlan("passed", ("discovery",)),
    "DISC-GOLDEN": SuitePlan("passed", ("discovery",)),
    "DISC-PY": SuitePlan("passed", ("discovery",)),
    "DISC-TS": SuitePlan("passed", ("discovery",)),
    "EGRESS": SuitePlan("passed", ("privacy",)),
    "GIT-HTTPS": SuitePlan(
        "passed",
        ("acquisition", "remote-artifacts", "remote-live", "daemon-cli-live"),
    ),
    "GIT-LOCAL": SuitePlan("passed", ("acquisition",)),
    "GIT-SSH-BROKER": SuitePlan(
        "passed", ("acquisition", "remote-binaries", "remote-artifacts", "remote-live")
    ),
    "KEYSTORE-MACOS-NATIVE": SuitePlan("passed", ("native-key-store",)),
    "KEYSTORE-PERSISTENT": SuitePlan("passed", ("protected-store", "native-key-store")),
    "NONMUTATION": SuitePlan("passed", ("acquisition", "source-guard")),
    "OTLP-GRPC": SuitePlan("passed", ("evidence",)),
    "OTLP-HTTP": SuitePlan("passed", ("evidence",)),
    "OTLP-MAPPING": SuitePlan("passed", ("evidence",)),
    "PATH": SuitePlan("passed", ("acquisition",)),
    "PRIV-CANARY": SuitePlan(
        "passed", ("evidence", "privacy", "capture-python", "capture-node")
    ),
    "PRIV-DEL": SuitePlan("passed", ("privacy", "protected-store")),
    "PROTECTED-DIGEST": SuitePlan("passed", ("source-guard",)),
    "REMOTE-ARTIFACT-PINS": SuitePlan(
        "passed", ("remote-binaries", "remote-artifacts")
    ),
    "REMOTE-IMAGE-PACKAGES": SuitePlan(
        "passed", ("remote-artifacts", "remote-image-packages")
    ),
    "SOURCE-STATUS": SuitePlan("passed", ("source-guard",)),
    "TREE-SITTER-PINNED": SuitePlan("passed", ("lock", "discovery")),
    "WHEEL-CLEAN": SuitePlan("passed", ("clean-install",)),
}


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_remote_artifact_pins(source: str) -> None:
    names = {
        "IMAGE": "image_digest",
        "RUNNER": "runner_digest",
        "PROXY": "proxy_digest",
        "RELAY": "relay_digest",
    }
    parsed = {names[name]: digest for name, digest in _RUST_REMOTE_PIN.findall(source)}
    expected = {name: REMOTE_ARTIFACT_PINS[name] for name in names.values()}
    if parsed != expected:
        raise RuntimeError("reviewed remote artifact pins disagree with Rust policy")
    package_lock = RUST_ROOT / "remote-git-image" / "os-packages.lock"
    package_digest = f"sha256:{file_digest(package_lock)}"
    if package_digest != REMOTE_ARTIFACT_PINS["os_package_manifest_digest"]:
        raise RuntimeError("reviewed remote image package manifest digest changed")


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
    extra_environment: dict[str, str] | None = None,
) -> CommandEvidence:
    environment = {
        name: os.environ[name]
        for name in (
            "APPDATA",
            "LOCALAPPDATA",
            "PATH",
            "SystemRoot",
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
    if _COMMAND_ENV_ROOT is not None:
        environment.update(
            {
                "BUN_INSTALL_CACHE_DIR": str(_COMMAND_ENV_ROOT / "bun-cache"),
                "CARGO_HOME": str(_COMMAND_ENV_ROOT / "cargo"),
                "CARGO_NET_OFFLINE": "true",
                "DOCKER_CONFIG": str(_COMMAND_ENV_ROOT / "docker"),
                "DOCKER_HOST": f"unix://{_REAL_HOME / '.orbstack/run/docker.sock'}",
                "GIT_CONFIG_GLOBAL": str(_COMMAND_ENV_ROOT / "empty-gitconfig"),
                "HOME": str(_COMMAND_ENV_ROOT / "home"),
                "NPM_CONFIG_USERCONFIG": str(_COMMAND_ENV_ROOT / "empty-npmrc"),
                "RUSTUP_HOME": str(_REAL_HOME / ".rustup"),
                "TMPDIR": str(_COMMAND_ENV_ROOT / "tmp"),
                "UV_CACHE_DIR": str(_REAL_HOME / ".cache/uv"),
                "XDG_CONFIG_HOME": str(_COMMAND_ENV_ROOT / "config"),
            }
        )
    if extra_environment is not None:
        environment.update(extra_environment)
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
    dirty = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *BOUND_PATHS,
        ],
        cwd=REPOSITORY_ROOT,
        env={"PATH": os.environ["PATH"]},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=30,
        check=False,
    )
    if dirty.returncode != 0 or dirty.stdout:
        raise RuntimeError("Phase 4 tracked receipt has dirty bound source paths")
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
                "from importlib.resources import files; "
                "import promptectomy.capture_python, promptectomy.discovery_python, "
                "promptectomy.discovery_javascript, promptectomy.evidence_phase4, "
                "promptectomy.privacy_phase4, promptectomy.support_matrix_phase4; "
                "from promptectomy.contracts_v2 import validate_schema_document; "
                "validate_schema_document(); "
                "assert files('promptectomy.schema_assets').joinpath('draft-candidate-v1.json').is_file(); "
                "assert files('promptectomy.schema_v2').joinpath('contract.schema.json').is_file()"
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
    source = temporary / "source"
    source.mkdir(mode=0o700)
    source_file = source / "client.py"
    source_bytes = (
        b"from openai import OpenAI\n\n"
        b"client = OpenAI()\n\n"
        b"def send():\n"
        b"    return client.responses.create(model='gpt-5', input='hello')\n"
    )
    source_file.write_bytes(source_bytes)
    state = temporary / "state"
    cli = environment / (
        "Scripts/promptectomy.exe" if os.name == "nt" else "bin/promptectomy"
    )
    command_environment = {"PROMPTECTOMY_HOME": str(state)}
    doctor = run_command(
        "clean-install-doctor",
        [str(cli), "doctor", str(source), "--json"],
        cwd=temporary,
        cwd_label="temporary",
        display_command=(
            "$TEMPORARY/venv/promptectomy",
            "doctor",
            "$TEMPORARY/source",
            "--json",
        ),
        replacements=replacements,
        extra_environment=command_environment,
    )
    doctor_value = parse_json_strict(doctor.stdout)
    doctor_checks = (
        doctor_value.get("checks") if isinstance(doctor_value, dict) else None
    )
    if (
        not isinstance(doctor_checks, dict)
        or doctor_checks.get("draft_schema_packaged") is not True
    ):
        raise RuntimeError("installed Phase 4 doctor did not load packaged schemas")
    inspect = run_command(
        "clean-install-inspect",
        [str(cli), "inspect", str(source), "--json"],
        cwd=temporary,
        cwd_label="temporary",
        display_command=(
            "$TEMPORARY/venv/promptectomy",
            "inspect",
            "$TEMPORARY/source",
            "--json",
        ),
        replacements=replacements,
        extra_environment=command_environment,
    )
    inspect_value = parse_json_strict(inspect.stdout)
    inspect_work = (
        inspect_value.get("work") if isinstance(inspect_value, dict) else None
    )
    inspect_support = (
        inspect_value.get("support") if isinstance(inspect_value, dict) else None
    )
    inspect_callsites = (
        inspect_value.get("callsites") if isinstance(inspect_value, dict) else None
    )
    if (
        not isinstance(inspect_value, dict)
        or inspect_value.get("status")
        not in {"completed", "completed_with_unsupported"}
        or not isinstance(inspect_work, dict)
        or inspect_work.get("zero_work") is not False
        or not isinstance(inspect_support, dict)
        or inspect_support.get("callsites") != 1
        or not isinstance(inspect_callsites, list)
        or len(inspect_callsites) != 1
        or source_file.read_bytes() != source_bytes
    ):
        raise RuntimeError("installed Phase 4 scanner did not pass its real CLI probe")
    return build, create, install, probe, doctor, inspect


def run_conformance() -> tuple[str, dict[str, CommandEvidence]]:
    if sys.platform != "darwin":
        raise RuntimeError(
            "Phase 4 receipt generation requires the accepted macOS native key-store platform"
        )
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
    bound_status = run_command(
        "bound-source-status",
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *BOUND_PATHS,
        ],
        cwd=REPOSITORY_ROOT,
        cwd_label="repository",
    )
    if bound_status.stdout:
        raise RuntimeError(
            "Phase 4 acceptance requires all receipt-bound source paths at clean HEAD"
        )

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
    evidence["native-key-store"] = run_command(
        "native-key-store",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-protected-store",
            "--test",
            "system_key_store",
            "--locked",
            "--offline",
            "--",
            "--ignored",
            "--exact",
            "native_key_store_round_trip_leaves_no_test_key",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    remote_runner = run_command(
        "remote-git-runner",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-remote-git-runner",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    remote_proxy = run_command(
        "egress-proxy",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-egress-proxy",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    ssh_relay = run_command(
        "ssh-agent-relay",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-ssh-agent-relay",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    evidence["remote-binaries"] = CommandEvidence(
        label="remote-binaries",
        command=("cargo-test-remote-git-runner-egress-proxy-and-ssh-relay",),
        cwd="rust",
        returncode=0,
        stdout=_sha256(
            rfc8785.dumps(
                [
                    remote_runner.canonical_value(),
                    remote_proxy.canonical_value(),
                    ssh_relay.canonical_value(),
                ]
            )
        ),
        stderr="",
    )
    evidence["remote-artifacts"] = CommandEvidence(
        label="remote-artifacts",
        command=("receipt-bind-pinned-remote-artifact-digests",),
        cwd="repository",
        returncode=0,
        stdout=json.dumps(REMOTE_ARTIFACT_PINS, separators=(",", ":"), sort_keys=True),
        stderr="",
    )
    verify_remote_artifact_pins(
        (
            RUST_ROOT / "crates" / "promptectomy-acquisition" / "src" / "remote.rs"
        ).read_text(encoding="utf-8")
    )
    remote_image_packages = run_command(
        "remote-image-packages",
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/usr/bin/sha256sum",
            f"promptectomy-remote-git@{REMOTE_ARTIFACT_PINS['image_digest']}",
            "/usr/share/promptectomy/os-packages.lock",
            "/usr/local/bin/promptectomy-remote-git-runner",
            "/usr/local/bin/promptectomy-egress-proxy",
            "/usr/local/bin/promptectomy-ssh-connect",
            "/usr/local/bin/promptectomy-ssh-agent-relay",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    image_files = {
        path: digest
        for digest, path in (
            line.split(maxsplit=1) for line in remote_image_packages.stdout.splitlines()
        )
    }
    expected_image_files = {
        "/usr/share/promptectomy/os-packages.lock": REMOTE_ARTIFACT_PINS[
            "os_package_manifest_digest"
        ].removeprefix("sha256:"),
        "/usr/local/bin/promptectomy-remote-git-runner": REMOTE_ARTIFACT_PINS[
            "runner_digest"
        ].removeprefix("sha256:"),
        "/usr/local/bin/promptectomy-egress-proxy": REMOTE_ARTIFACT_PINS[
            "proxy_digest"
        ].removeprefix("sha256:"),
        "/usr/local/bin/promptectomy-ssh-connect": REMOTE_ARTIFACT_PINS[
            "ssh_connect_digest"
        ].removeprefix("sha256:"),
        "/usr/local/bin/promptectomy-ssh-agent-relay": REMOTE_ARTIFACT_PINS[
            "relay_digest"
        ].removeprefix("sha256:"),
    }
    if image_files != expected_image_files:
        raise RuntimeError("reviewed remote image files changed")
    evidence["remote-image-packages"] = remote_image_packages
    evidence["remote-live"] = run_command(
        "remote-live",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-acquisition",
            "--locked",
            "--offline",
            "--",
            "--ignored",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
        extra_environment={
            "PROMPTECTOMY_SSH_FIXTURE_IMAGE": (
                "promptectomy-ssh-fixture@"
                f"{REMOTE_ARTIFACT_PINS['ssh_fixture_image_digest']}"
            )
        },
    )
    evidence["daemon-cli"] = run_command(
        "daemon-cli",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-daemon",
            "-p",
            "promptectomy-cli",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
        cwd_label="rust",
    )
    evidence["daemon-cli-live"] = run_command(
        "daemon-cli-live",
        [
            "cargo",
            "test",
            "-q",
            "-p",
            "promptectomy-cli",
            "--locked",
            "--offline",
            "tests::cli_inspect_public_https_uses_the_real_reviewed_daemon_backend",
            "--",
            "--ignored",
            "--exact",
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
        ["bun", "install", "--frozen-lockfile", "--ignore-scripts"],
        cwd=NODE_ROOT,
        cwd_label="repository",
    )
    node_version = run_command(
        "capture-node-version",
        ["node", "--version"],
        cwd=NODE_ROOT,
        cwd_label="repository",
    )
    bun_version = run_command(
        "capture-bun-version",
        ["bun", "--version"],
        cwd=NODE_ROOT,
        cwd_label="repository",
    )
    if node_version.stdout != "v24.18.0" or bun_version.stdout != "1.3.10":
        raise RuntimeError("Phase 4 Node or Bun runtime version is not accepted")
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
    node_package = run_command(
        "capture-node-package",
        ["bun", "run", "package:check"],
        cwd=NODE_ROOT,
        cwd_label="repository",
    )
    evidence["capture-node"] = CommandEvidence(
        label="capture-node",
        command=("bun-frozen-install-typecheck-test-package",),
        cwd="repository",
        returncode=0,
        stdout=_sha256(
            rfc8785.dumps(
                [
                    item.canonical_value()
                    for item in (
                        node_install,
                        node_version,
                        bun_version,
                        node_typecheck,
                        node_tests,
                        node_package,
                    )
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
        "bound_source_clean_at_head": True,
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
    global _COMMAND_ENV_ROOT
    with tempfile.TemporaryDirectory(
        prefix="promptectomy-phase4-environment-"
    ) as environment_name:
        _COMMAND_ENV_ROOT = Path(environment_name)
        for name in ("bun-cache", "cargo", "config", "docker", "home", "tmp"):
            (_COMMAND_ENV_ROOT / name).mkdir(mode=0o700)
        (_COMMAND_ENV_ROOT / "empty-gitconfig").write_text("", encoding="utf-8")
        (_COMMAND_ENV_ROOT / "empty-npmrc").write_text("", encoding="utf-8")
        cargo_registry = _REAL_HOME / ".cargo" / "registry"
        if cargo_registry.is_dir():
            (_COMMAND_ENV_ROOT / "cargo" / "registry").symlink_to(
                cargo_registry, target_is_directory=True
            )
        try:
            source_head, evidence = run_conformance()
            receipt = build_receipt(source_head, evidence)
            receipt_value, matrix = write_outputs(receipt)
        finally:
            _COMMAND_ENV_ROOT = None
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
