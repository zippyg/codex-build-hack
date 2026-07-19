from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import apsw


ENGINE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ENGINE_ROOT.parent
PROTECTED_DIGEST = "a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c"
V2_TESTS = (
    "tests/test_contracts_v2.py",
    "tests/test_state_v2.py",
    "tests/test_artifacts_v2.py",
    "tests/test_api_reports_v2.py",
    "tests/test_migration_v2.py",
)


def run(command: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=ENGINE_ROOT,
        env=os.environ.copy() if env is None else env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"acceptance command failed with exit {result.returncode}: {command!r}\n"
            f"stdout:\n{result.stdout[-8000:]}\nstderr:\n{result.stderr[-8000:]}"
        )
    return result.stdout.strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pytest_summary(output: str) -> str:
    for line in reversed(output.splitlines()):
        if " passed" in line and " in " in line:
            return line.strip("= ")
    raise RuntimeError("pytest output did not contain a passing summary")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    protected = ENGINE_ROOT / "promptectomy" / "generated" / "route_ticket.py"
    if digest(protected) != PROTECTED_DIGEST:
        raise RuntimeError("protected route file digest changed before Phase 2 acceptance")
    source_before = run(["git", "status", "--porcelain=v1"])
    run(["uv", "lock", "--check"])
    generated_paths = (
        ENGINE_ROOT / "generated" / "contracts_v2" / "python" / "promptectomy_contracts_v2.py",
        ENGINE_ROOT / "generated" / "contracts_v2" / "typescript" / "contracts-v2.ts",
        ENGINE_ROOT / "generated" / "contracts_v2" / "rust" / "src" / "lib.rs",
    )
    generated_before = {path: digest(path) for path in generated_paths}
    run(["uv", "run", "python", "scripts/generate_contract_bindings.py"])
    if {path: digest(path) for path in generated_paths} != generated_before:
        raise RuntimeError("tracked Contract v2 bindings were stale")
    run(
        [
            str(REPOSITORY_ROOT / "ui" / "node_modules" / ".bin" / "tsc"),
            "--strict",
            "--noEmit",
            "--skipLibCheck",
            "generated/contracts_v2/typescript/contracts-v2.ts",
        ]
    )
    with tempfile.TemporaryDirectory(prefix="promptectomy-phase2-cargo-") as target:
        rust = run(
            [
                "cargo",
                "check",
                "--locked",
                "--offline",
                "--target-dir",
                target,
                "--manifest-path",
                "generated/contracts_v2/rust/Cargo.toml",
            ]
        )
    v2_tests = run(["uv", "run", "pytest", "-q", *V2_TESTS])
    image_environment = os.environ.copy()
    image_environment["PROMPTECTOMY_OCI_IMAGE"] = args.image
    image_environment["PROMPTECTOMY_OCI_CONTEXT"] = "orbstack"
    full_with_image = run(
        ["uv", "run", "pytest", "-q"], env=image_environment
    )
    no_image_environment = os.environ.copy()
    no_image_environment.pop("PROMPTECTOMY_OCI_IMAGE", None)
    full_without_image = run(
        ["uv", "run", "pytest", "-q"], env=no_image_environment
    )
    source_after = run(["git", "status", "--porcelain=v1"])
    if source_after != source_before:
        raise RuntimeError("Phase 2 acceptance changed source-controlled state")
    if digest(protected) != PROTECTED_DIGEST:
        raise RuntimeError("protected route file digest changed during Phase 2 acceptance")
    schema = ENGINE_ROOT / "schemas" / "v2" / "contract.schema.json"
    receipt = {
        "schema_version": "phase2-1",
        "accepted_at": datetime.now(UTC).isoformat(),
        "contract": {
            "draft": "2020-12",
            "schema_version": "2.0.0",
            "sha256": digest(schema),
            "entity_count": 15,
            "canonicalization": "rfc8785",
            "digest_algorithm": "sha256_domain_separated",
        },
        "bindings": {
            path.relative_to(ENGINE_ROOT).as_posix(): value
            for path, value in generated_before.items()
        },
        "state": {
            "apsw": apsw.apswversion(),
            "sqlite": apsw.sqlitelibversion(),
            "journal_mode": "WAL",
            "minimum_sqlite": "3.51.3",
            "schema_version": 1,
        },
        "boundaries": {
            "owner_only_local_state": True,
            "atomic_event_projection": True,
            "artifact_write_before_reference": True,
            "artifact_rehash_on_read": True,
            "protected_artifact_api_denied": True,
            "api_capability_required": True,
            "api_host_origin_bounded": True,
            "reports_frozen_from_safe_snapshot": True,
            "phase1_import_preserves_target": True,
            "protected_source_digest_unchanged": True,
            "source_status_unchanged": True,
        },
        "tests": {
            "v2": pytest_summary(v2_tests),
            "full_with_accepted_oci": pytest_summary(full_with_image),
            "full_without_oci": pytest_summary(full_without_image),
            "rust": rust.splitlines()[-1] if rust else "cargo check passed",
            "typescript": "strict noEmit passed",
        },
        "executor_image": args.image,
        "known_non_product_warning": "Starlette TestClient deprecation in current pinned dependency set",
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
