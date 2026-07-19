from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath


ENGINE_ROOT = Path(__file__).resolve().parents[1]
TEST_FILES = (
    "test_phase1a.py",
    "test_executor_contracts.py",
    "test_executor_oci.py",
)
REQUIRED_WHEEL_FILES = {
    "promptectomy/executor_image/Dockerfile",
    "promptectomy/executor_image/runner.py",
    "promptectomy/schema_assets/audit-v1.json",
    "promptectomy/schema_assets/draft-candidate-v1.json",
    "promptectomy/schema_assets/synthesis-result-v1.json",
    "promptectomy/schema_assets/verdict-v1.json",
}
OWNER_LABEL = "dev.promptectomy.owner=phase1b"
FORBIDDEN_WHEEL_MODULES = {
    "contracts.py",
    "events.py",
    "guard.py",
    "ledger.py",
    "pricing.py",
    "replay.py",
    "scan.py",
    "schemas.py",
    "scoring.py",
    "server.py",
    "shim.py",
    "splitting.py",
    "synthesize.py",
    "verify.py",
    "worktrees.py",
}


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed with exit {result.returncode}: {command[0]} {command[1:]}\n"
            f"stdout:\n{result.stdout[-8000:]}\nstderr:\n{result.stderr[-8000:]}"
        )
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_candidate(destination: Path) -> None:
    destination.mkdir(mode=0o700)
    shutil.copy2(ENGINE_ROOT / "pyproject.toml", destination / "pyproject.toml")
    shutil.copy2(ENGINE_ROOT / "uv.lock", destination / "uv.lock")
    shutil.copytree(
        ENGINE_ROOT / "promptectomy",
        destination / "promptectomy",
        ignore=shutil.ignore_patterns("generated", "__pycache__", "*.pyc"),
        symlinks=True,
    )
    for path in (destination / "promptectomy").rglob("*"):
        if path.is_symlink():
            raise RuntimeError(
                f"candidate source contains symlink: {path.relative_to(destination)}"
            )


def verify_wheel(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise RuntimeError("wheel contains duplicate paths")
        if len(infos) > 10_000 or sum(item.file_size for item in infos) > 100_000_000:
            raise RuntimeError("wheel exceeds bounded inventory limits")
        for item in infos:
            pure = PurePosixPath(item.filename)
            mode = item.external_attr >> 16
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or "\\" in item.filename
                or "\0" in item.filename
                or (pure.parts and ":" in pure.parts[0])
                or stat.S_ISLNK(mode)
                or item.file_size > 10_000_000
            ):
                raise RuntimeError(f"unsafe wheel member: {item.filename}")
        present = set(names)
        missing = REQUIRED_WHEEL_FILES - present
        if missing:
            raise RuntimeError(f"wheel is missing runtime assets: {sorted(missing)}")
        forbidden = [
            name
            for name in names
            if name.startswith("promptectomy/generated/")
            or name.removeprefix("promptectomy/") in FORBIDDEN_WHEEL_MODULES
        ]
        if forbidden:
            raise RuntimeError(f"wheel contains generated code: {forbidden}")
        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(record_names) != 1:
            raise RuntimeError("wheel must contain exactly one RECORD")
        record_rows = list(
            csv.reader(archive.read(record_names[0]).decode("utf-8").splitlines())
        )
        rows = {name: (digest, size) for name, digest, size in record_rows}
        if len(rows) != len(record_rows):
            raise RuntimeError("wheel RECORD contains duplicate paths")
        if set(rows) != present:
            raise RuntimeError(
                "wheel RECORD inventory does not match archive inventory"
            )
        for name in names:
            digest, size = rows[name]
            if name == record_names[0]:
                if digest or size:
                    raise RuntimeError("wheel RECORD must not hash itself")
                continue
            content = archive.read(name)
            encoded = (
                base64.urlsafe_b64encode(hashlib.sha256(content).digest())
                .rstrip(b"=")
                .decode()
            )
            if digest != f"sha256={encoded}" or size != str(len(content)):
                raise RuntimeError(f"wheel RECORD mismatch: {name}")
    return names


def child_environment(root: Path, cache: Path, image: str) -> dict[str, str]:
    environment = {
        "HOME": str(root / "home"),
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "PROMPTECTOMY_HOME": str(root / "state"),
        "PROMPTECTOMY_OCI_CONTEXT": "orbstack",
        "PROMPTECTOMY_OCI_IMAGE": image,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": str(root / "tmp"),
        "UV_CACHE_DIR": str(cache),
        "UV_NO_PROGRESS": "1",
        "XDG_CACHE_HOME": str(root / "xdg-cache"),
        "XDG_CONFIG_HOME": str(root / "xdg-config"),
        "XDG_DATA_HOME": str(root / "xdg-data"),
    }
    for name in ("LANG", "LC_ALL", "LC_CTYPE"):
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def configure_isolated_docker(environment: dict[str, str], root: Path) -> None:
    host = run(
        [
            "docker",
            "context",
            "inspect",
            "orbstack",
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
        cwd=ENGINE_ROOT,
        env=os.environ.copy(),
        timeout=30,
    ).stdout.strip()
    endpoint = json.loads(host)
    run(
        ["docker", "context", "create", "orbstack", "--docker", f"host={endpoint}"],
        cwd=root,
        env=environment,
        timeout=30,
    )


def dependency_inventory(
    python: Path, environment: dict[str, str], root: Path
) -> list[dict[str, object]]:
    program = """
import importlib.metadata as md
import json
rows = []
for dist in md.distributions():
    metadata = dist.metadata
    classifiers = metadata.get_all('Classifier') or []
    licenses = sorted(value.removeprefix('License :: ') for value in classifiers if value.startswith('License :: '))
    rows.append({
        'name': metadata['Name'],
        'version': dist.version,
        'license_expression': metadata.get('License-Expression'),
        'license': metadata.get('License'),
        'license_classifiers': licenses,
        'homepage': metadata.get('Home-page') or metadata.get('Project-URL'),
    })
print(json.dumps(sorted(rows, key=lambda row: row['name'].lower()), separators=(',', ':'), sort_keys=True))
"""
    result = run([str(python), "-I", "-c", program], cwd=root, env=environment)
    inventory = json.loads(result.stdout)
    for item in inventory:
        if not item["name"] or not item["version"]:
            raise RuntimeError(
                "installed distribution is missing name or version metadata"
            )
        has_license = bool(
            item["license_expression"] or item["license"] or item["license_classifiers"]
        )
        if item["name"] != "promptectomy" and not has_license:
            raise RuntimeError(
                f"dependency is missing license metadata: {item['name']}"
            )
    return inventory


def assert_uninstalled(venv: Path) -> None:
    site_packages = next((venv / "lib").glob("python*/site-packages"))
    if (site_packages / "promptectomy").exists() or list(
        site_packages.glob("promptectomy-*.dist-info")
    ):
        raise RuntimeError(f"package remains after uninstall: {venv}")
    if (venv / "bin" / "promptectomy").exists():
        raise RuntimeError(f"entry point remains after uninstall: {venv}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    source_status = run(
        ["git", "status", "--porcelain=v1"],
        cwd=ENGINE_ROOT.parent,
        env=os.environ.copy(),
        timeout=30,
    ).stdout
    protected = ENGINE_ROOT / "promptectomy" / "generated" / "route_ticket.py"
    if (
        sha256(protected)
        != "a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c"
    ):
        raise RuntimeError("protected route file digest changed before acceptance")

    with tempfile.TemporaryDirectory(prefix="promptectomy-phase1c-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        for name in ("home", "state", "tmp", "xdg-cache", "xdg-config", "xdg-data"):
            (root / name).mkdir(mode=0o700)
        cache = root / "uv-cache"
        candidate = root / "candidate"
        copy_candidate(candidate)
        environment = child_environment(root, cache, args.image)
        configure_isolated_docker(environment, root)

        requirements = root / "requirements.txt"
        requirements.write_text(
            run(
                [
                    "uv",
                    "export",
                    "--frozen",
                    "--all-groups",
                    "--no-emit-project",
                    "--format",
                    "requirements-txt",
                ],
                cwd=candidate,
                env=environment,
            ).stdout,
            encoding="utf-8",
        )
        first_dist = root / "dist-first"
        second_dist = root / "dist-second"
        build_command = [
            "uv",
            "build",
            "--wheel",
            "--no-sources",
            "--build-constraints",
            str(requirements),
            "--require-hashes",
        ]
        run(
            [*build_command, "--out-dir", str(first_dist)],
            cwd=candidate,
            env=environment,
        )
        run(
            [*build_command, "--offline", "--out-dir", str(second_dist)],
            cwd=candidate,
            env=environment,
        )
        first_wheel = next(first_dist.glob("*.whl"))
        second_wheel = next(second_dist.glob("*.whl"))
        first_hash = sha256(first_wheel)
        if first_hash != sha256(second_wheel):
            raise RuntimeError("two clean wheel builds are not byte-identical")
        wheel_files = verify_wheel(first_wheel)

        tests = root / "tests"
        tests.mkdir(mode=0o700)
        for name in TEST_FILES:
            shutil.copy2(ENGINE_ROOT / "tests" / name, tests / name)
        shutil.copy2(
            ENGINE_ROOT / "acceptance" / "installed_boundary.py",
            tests / "test_installed_boundary.py",
        )

        online_venv = root / "venv-online"
        offline_venv = root / "venv-offline"
        for venv, offline in ((online_venv, False), (offline_venv, True)):
            run(
                ["uv", "venv", str(venv), "--python", "3.12", "--no-python-downloads"],
                cwd=root,
                env=environment,
            )
            sync = [
                "uv",
                "pip",
                "sync",
                "--python",
                str(venv / "bin" / "python"),
                "--require-hashes",
                str(requirements),
            ]
            install = [
                "uv",
                "pip",
                "install",
                "--python",
                str(venv / "bin" / "python"),
                "--no-deps",
                str(first_wheel),
            ]
            if offline:
                sync.insert(3, "--offline")
                install.insert(3, "--offline")
            run(sync, cwd=root, env=environment)
            run(install, cwd=root, env=environment)
            run(
                [str(venv / "bin" / "promptectomy"), "--help"],
                cwd=root,
                env=environment,
            )

        pytest = run(
            [
                str(offline_venv / "bin" / "python"),
                "-I",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--disable-socket",
                str(tests),
            ],
            cwd=root,
            env=environment,
            timeout=900,
        )
        inventory = dependency_inventory(
            offline_venv / "bin" / "python", environment, root
        )

        containers = run(
            [
                "docker",
                "--context",
                "orbstack",
                "container",
                "ls",
                "--all",
                "--filter",
                f"label={OWNER_LABEL}",
                "--format",
                "{{.Names}}",
            ],
            cwd=root,
            env=environment,
            timeout=30,
        ).stdout.strip()
        if containers:
            raise RuntimeError(
                f"owned containers remain after acceptance: {containers}"
            )

        for venv in (online_venv, offline_venv):
            run(
                [
                    "uv",
                    "pip",
                    "uninstall",
                    "--python",
                    str(venv / "bin" / "python"),
                    "promptectomy",
                ],
                cwd=root,
                env=environment,
            )
            assert_uninstalled(venv)

        processes = run(
            ["ps", "-axo", "pid=,command="], cwd=root, env=environment, timeout=30
        ).stdout
        leftovers = [line for line in processes.splitlines() if str(root) in line]
        if leftovers:
            raise RuntimeError(f"acceptance child processes remain: {leftovers}")

        receipt = {
            "schema_version": "phase1c-1",
            "accepted_at": datetime.now(UTC).isoformat(),
            "artifact": {
                "filename": first_wheel.name,
                "sha256": first_hash,
                "size_bytes": first_wheel.stat().st_size,
                "files": wheel_files,
                "reproducible_builds": 2,
            },
            "dependencies": inventory,
            "license_gate": {
                "dependency_metadata_complete": True,
                "project_license": "unapproved",
            },
            "executor_image": args.image,
            "requirements_sha256": sha256(requirements),
            "test_result": pytest.stdout.strip().splitlines()[-1],
            "boundaries": {
                "generated_code_packaged": False,
                "legacy_execution_modules_packaged": False,
                "installed_outside_source_tree": True,
                "offline_install_passed": True,
                "python_network_disabled_during_tests": True,
                "source_status_unchanged": True,
                "owned_containers_after_tests": 0,
                "package_uninstalled_from_both_environments": True,
                "child_processes_after_tests": 0,
            },
            "toolchain": {
                "python": run(
                    [sys.executable, "--version"], cwd=root, env=environment
                ).stdout.strip(),
                "uv": run(
                    ["uv", "--version"], cwd=root, env=environment
                ).stdout.strip(),
            },
        }
        if (
            run(
                ["git", "status", "--porcelain=v1"],
                cwd=ENGINE_ROOT.parent,
                env=os.environ.copy(),
                timeout=30,
            ).stdout
            != source_status
        ):
            raise RuntimeError("source worktree status changed during acceptance")
        if (
            sha256(protected)
            != "a4fcdab0f1baef70072620e1409d68e732c5a4549d3f36388a7213237dab961c"
        ):
            raise RuntimeError("protected route file changed during acceptance")
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    if Path(temporary).exists():
        raise RuntimeError("acceptance temporary root was not removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
