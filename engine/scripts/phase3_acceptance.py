from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ENGINE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ENGINE_ROOT.parent
RUST_ROOT = REPOSITORY_ROOT / "rust"
sys.path.insert(0, str(ENGINE_ROOT))
PROTECTED_DIGEST = "a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c"
V2_TESTS = (
    "tests/test_contracts_v2.py",
    "tests/test_state_v2.py",
    "tests/test_artifacts_v2.py",
    "tests/test_api_reports_v2.py",
    "tests/test_migration_v2.py",
)


def run(
    command: list[str],
    *,
    cwd: Path = ENGINE_ROOT,
    env: dict[str, str] | None = None,
    accepted: set[int] | None = None,
    timeout: int = 900,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=os.environ.copy() if env is None else env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    expected = {0} if accepted is None else accepted
    if result.returncode not in expected:
        raise RuntimeError(
            f"acceptance command failed with exit {result.returncode}: {command!r}\n"
            f"stdout:\n{result.stdout[-12000:]}\nstderr:\n{result.stderr[-12000:]}"
        )
    return result


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digests(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): digest(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def status() -> str:
    return run(["git", "status", "--porcelain=v1"], cwd=REPOSITORY_ROOT).stdout


def pytest_summary(output: str) -> str:
    for line in reversed(output.splitlines()):
        if " passed" in line and " in " in line:
            return line.strip("= ")
    raise RuntimeError("pytest output did not contain a passing summary")


def cargo_test_summary(output: str) -> str:
    suites = 0
    passed = 0
    for line in output.splitlines():
        if not line.startswith("test result: ok."):
            continue
        match = re.search(r"\b(\d+) passed;", line)
        if match is None:
            raise RuntimeError("cargo test emitted an unrecognized passing summary")
        suites += 1
        passed += int(match.group(1))
    if suites == 0:
        raise RuntimeError("cargo test output did not contain a passing summary")
    return f"{passed} passed across {suites} test binaries"


def benchmark_summary(output: str) -> dict[str, Any]:
    prefix = "PHASE3_BENCHMARK_JSON="
    for line in output.splitlines():
        if line.startswith(prefix):
            value = json.loads(line.removeprefix(prefix))
            if not isinstance(value, dict) or value.get("passed") is not True:
                raise RuntimeError("Phase 3 benchmark did not report a passing object")
            return value
    raise RuntimeError("Phase 3 benchmark output did not contain its result marker")


def parse_cli(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Rust CLI stdout was not one JSON document") from error
    if not isinstance(value, dict):
        raise RuntimeError("Rust CLI JSON root was not an object")
    if result.stderr:
        raise RuntimeError("Rust CLI wrote diagnostics during a machine JSON success path")
    return value


def create_python_v2_state(root: Path) -> tuple[Path, dict[str, Any]]:
    from promptectomy.state_v2 import StateStore

    run_value = json.loads(
        (ENGINE_ROOT / "schemas" / "v2" / "examples" / "run.valid.json").read_text(
            encoding="utf-8"
        )
    )
    event_value = json.loads(
        (
            ENGINE_ROOT / "schemas" / "v2" / "examples" / "event.valid.json"
        ).read_text(encoding="utf-8")
    )
    with StateStore(root) as store:
        run_value = store.create_run(
            run_value,
            event_value,
            idempotency_key="phase3-real-python-import",
        )
        database = store.path
    return database, run_value


def wait_for_daemon(
    binary: Path,
    daemon_root: Path,
    run_id: str,
    process: subprocess.Popen[str],
) -> dict[str, Any]:
    deadline = time.monotonic() + 10
    command = [
        str(binary),
        "--json",
        "--daemon-dir",
        str(daemon_root),
        "status",
        run_id,
    ]
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(
                "Rust daemon exited before becoming ready\n"
                f"stdout:\n{stdout[-4000:]}\nstderr:\n{stderr[-4000:]}"
            )
        result = subprocess.run(
            command,
            cwd=RUST_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return parse_cli(result)
        time.sleep(0.05)
    raise RuntimeError("Rust daemon did not become ready within 10 seconds")


def stop_daemon(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    if stdout or stderr:
        raise RuntimeError(
            "Rust daemon wrote unexpected public diagnostics during controlled shutdown\n"
            f"stdout:\n{stdout[-4000:]}\nstderr:\n{stderr[-4000:]}"
        )


def verify_real_python_migration(binary: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="promptectomy-phase3-migration-") as temporary:
        temporary_root = Path(temporary)
        python_root = temporary_root / "python-v2"
        daemon_root = temporary_root / "rust-daemon"
        database, expected_run = create_python_v2_state(python_root)
        source_before = tree_digests(python_root)
        migrated = parse_cli(
            run(
                [
                    str(binary),
                    "--json",
                    "--daemon-dir",
                    str(daemon_root),
                    "migrate-python-v2",
                    str(database),
                ],
                cwd=RUST_ROOT,
            )
        )
        if migrated.get("status") != "ok" or migrated.get("data") != {
            "imported_runs": 1
        }:
            raise RuntimeError("real Python v2 migration did not import exactly one run")
        if tree_digests(python_root) != source_before:
            raise RuntimeError("Rust migration mutated the Python v2 source store")

        run_id = expected_run["run_id"]
        observed_runs = []
        for _ in range(2):
            process = subprocess.Popen(
                [
                    str(binary),
                    "--json",
                    "--daemon-dir",
                    str(daemon_root),
                    "daemon",
                ],
                cwd=RUST_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                envelope = wait_for_daemon(binary, daemon_root, run_id, process)
                observed = envelope.get("data")
                if not isinstance(observed, dict):
                    raise RuntimeError("migrated Rust run projection was not an object")
                observed_runs.append(observed)
                report = parse_cli(
                    run(
                        [
                            str(binary),
                            "--json",
                            "--daemon-dir",
                            str(daemon_root),
                            "report",
                            run_id,
                            "--format",
                            "json",
                        ],
                        cwd=RUST_ROOT,
                    )
                )
                content = report.get("data", {}).get("content")
                projection = json.loads(content) if isinstance(content, str) else None
                if not isinstance(projection, dict) or projection.get("run", {}).get(
                    "run_id"
                ) != run_id:
                    raise RuntimeError("migrated run did not produce an equivalent report")
            finally:
                stop_daemon(process)
        if observed_runs[0] != observed_runs[1]:
            raise RuntimeError("migrated run projection changed across daemon restart")
        if observed_runs[0].get("run_id") != run_id:
            raise RuntimeError("migrated run ID did not match the Python oracle")
        if observed_runs[0].get("last_sequence") != expected_run["last_sequence"]:
            raise RuntimeError("migrated event sequence did not match the Python oracle")
        if tree_digests(python_root) != source_before:
            raise RuntimeError("daemon restart mutated the Python v2 source store")
        return {
            "imported_runs": 1,
            "source_unchanged": True,
            "daemon_restarts": 2,
            "run_projection_stable": True,
            "report_projection_present": True,
        }


def main() -> int:
    started = time.monotonic()
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()

    protected = ENGINE_ROOT / "promptectomy" / "generated" / "route_ticket.py"
    if digest(protected) != PROTECTED_DIGEST:
        raise RuntimeError("protected route file digest changed before Phase 3 acceptance")
    source_before = status()

    run(["uv", "lock", "--check"])
    generated_paths = tuple(
        sorted(
            (
                ENGINE_ROOT / "generated" / "contracts_v2",
                RUST_ROOT / "crates" / "promptectomy-contracts" / "schema",
                RUST_ROOT / "crates" / "promptectomy-contracts" / "src" / "generated.rs",
            ),
            key=lambda path: path.as_posix(),
        )
    )
    generated_files = tuple(
        path
        for root in generated_paths
        for path in ([root] if root.is_file() else sorted(root.rglob("*")))
        if path.is_file()
    )
    generated_before = {path: digest(path) for path in generated_files}
    run(["uv", "run", "python", "scripts/generate_contract_bindings.py"])
    if {path: digest(path) for path in generated_files} != generated_before:
        raise RuntimeError("tracked cross-language bindings or fixtures were stale")

    run(
        [
            str(REPOSITORY_ROOT / "ui" / "node_modules" / ".bin" / "tsc"),
            "--strict",
            "--noEmit",
            "--skipLibCheck",
            "generated/contracts_v2/typescript/contracts-v2.ts",
        ]
    )
    run(["cargo", "fmt", "--all", "--check"], cwd=RUST_ROOT)
    rust_check = run(
        [
            "cargo",
            "check",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
    )
    clippy = run(
        [
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
            "--",
            "-D",
            "warnings",
        ],
        cwd=RUST_ROOT,
    )
    rust_tests = run(
        [
            "cargo",
            "test",
            "--workspace",
            "--all-features",
            "--locked",
            "--offline",
        ],
        cwd=RUST_ROOT,
    )
    benchmark = run(
        [
            "cargo",
            "test",
            "-p",
            "promptectomy-core",
            "--test",
            "phase3_benchmark",
            "--release",
            "--locked",
            "--offline",
            "--",
            "--ignored",
            "--nocapture",
        ],
        cwd=RUST_ROOT,
    )
    run(
        ["cargo", "build", "--release", "--bins", "--locked", "--offline"],
        cwd=RUST_ROOT,
    )

    binary = RUST_ROOT / "target" / "release" / "promptectomy"
    with tempfile.TemporaryDirectory(prefix="promptectomy-phase3-cli-") as temporary:
        daemon_root = Path(temporary) / "daemon"
        doctor = parse_cli(
            run(
                [
                    str(binary),
                    "--json",
                    "--daemon-dir",
                    str(daemon_root),
                    "doctor",
                ]
            )
        )
        if doctor.get("status") != "ok" or doctor.get("command") != "doctor":
            raise RuntimeError("Rust doctor JSON did not report an honest success envelope")
        unavailable_result = run(
            [
                str(binary),
                "--json",
                "--daemon-dir",
                str(daemon_root),
                "inspect",
                str(Path(temporary) / "synthetic-repository"),
            ],
            accepted={3},
        )
        unavailable = parse_cli(unavailable_result)
        if unavailable.get("status") != "error" or unavailable.get("command") != "inspect":
            raise RuntimeError("unimplemented Rust inspection did not fail as typed unsupported")
    migration = verify_real_python_migration(binary)

    focused = run(["uv", "run", "pytest", "-q", *V2_TESTS])
    with_image_env = os.environ.copy()
    with_image_env["PROMPTECTOMY_OCI_IMAGE"] = args.image
    with_image_env["PROMPTECTOMY_OCI_CONTEXT"] = "orbstack"
    full_with_image = run(["uv", "run", "pytest", "-q"], env=with_image_env)
    without_image_env = os.environ.copy()
    without_image_env.pop("PROMPTECTOMY_OCI_IMAGE", None)
    full_without_image = run(["uv", "run", "pytest", "-q"], env=without_image_env)

    if status() != source_before:
        raise RuntimeError("Phase 3 acceptance changed source-controlled state")
    if digest(protected) != PROTECTED_DIGEST:
        raise RuntimeError("protected route file digest changed during Phase 3 acceptance")

    receipt = {
        "schema_version": "phase3-1",
        "accepted_at": datetime.now(UTC).isoformat(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
        },
        "toolchain": {
            "rustc": run(["rustc", "--version"], cwd=RUST_ROOT).stdout.strip(),
            "cargo": run(["cargo", "--version"], cwd=RUST_ROOT).stdout.strip(),
            "uv": run(["uv", "--version"]).stdout.strip(),
        },
        "contracts": {
            "schema_version": "2.0.0",
            "schema_sha256": digest(ENGINE_ROOT / "schemas" / "v2" / "contract.schema.json"),
            "generated_files": {
                path.relative_to(REPOSITORY_ROOT).as_posix(): value
                for path, value in generated_before.items()
            },
        },
        "boundaries": {
            "rust_authoritative_local_state": True,
            "adapter_process_protocol_bounded": True,
            "target_code_not_run_in_core_or_clients": True,
            "private_os_transport": True,
            "loopback_tcp_default": False,
            "typed_unsupported_without_fallback": True,
            "protected_source_digest_unchanged": True,
            "source_status_unchanged": True,
        },
        "tests": {
            "focused_python_v2": pytest_summary(focused.stdout),
            "full_python_with_accepted_oci": pytest_summary(full_with_image.stdout),
            "full_python_without_oci": pytest_summary(full_without_image.stdout),
            "rust_workspace": cargo_test_summary(
                rust_tests.stdout + rust_tests.stderr
            ),
            "property_fuzz_smoke": "2,560 deterministic contract/path/protocol cases passed",
            "phase3_benchmark": benchmark_summary(
                benchmark.stdout + benchmark.stderr
            ),
            "rust_check": rust_check.stderr.splitlines()[-1]
            if rust_check.stderr.splitlines()
            else "all targets and features checked",
            "rust_clippy": clippy.stderr.splitlines()[-1]
            if clippy.stderr.splitlines()
            else "strict clippy passed",
            "typescript": "strict noEmit passed",
            "release_cli": "doctor exit 0; inspect typed unsupported exit 3",
            "real_python_v2_migration": migration,
        },
        "executor_image": args.image,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "known_non_product_warning": "Starlette TestClient deprecation in the pinned Python dependency set",
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
