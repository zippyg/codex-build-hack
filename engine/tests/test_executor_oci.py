from __future__ import annotations

import json
import os
import platform
import subprocess
import threading
import time
import uuid
from functools import lru_cache
from pathlib import Path

import pytest
from typer.testing import CliRunner

from promptectomy.cli import app
from promptectomy.executor import OciExecutor, accept_backend, digest_snapshot
from promptectomy.executor_contracts import ExecutorLimits, ExecutorManifest


IMAGE_ENV = "PROMPTECTOMY_OCI_IMAGE"


def _image() -> str:
    value = os.environ.get(IMAGE_ENV)
    if value is None:
        pytest.skip(f"set {IMAGE_ENV} to the accepted local runner image digest")
    return value


@lru_cache(maxsize=1)
def _executor() -> OciExecutor:
    executor, report = accept_backend(_image(), context="orbstack")
    assert report.accepted, report.model_dump_json()
    return executor


def _source(tmp_path: Path, code: str) -> Path:
    source = tmp_path / "snapshot"
    source.mkdir(mode=0o700, parents=True)
    (source / "source.txt").write_text("immutable\n", encoding="utf-8")
    (source / "probe.py").write_text(code, encoding="utf-8")
    (source / "source.txt").chmod(0o600)
    (source / "probe.py").chmod(0o600)
    return source


def _manifest(source: Path, *, code: str, limits: ExecutorLimits | None = None) -> ExecutorManifest:
    return ExecutorManifest(
        image_digest=_image(),
        snapshot_digest=digest_snapshot(source),
        command=["/usr/local/bin/python3", "-I", f"/workspace/{code}"],
        environment={"PT_ALLOWED": "visible"},
        expected_artifacts=["result.json"],
        limits=limits or ExecutorLimits(),
    )


def _artifact_json(result: object) -> dict[str, object]:
    artifacts = getattr(result, "artifacts")
    assert len(artifacts) == 1
    return json.loads(artifacts[0].content())


def test_oci_backend_proves_filesystem_environment_network_and_privilege_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "PT_HOST_SECRET_CANARY_9f14"
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    monkeypatch.setenv("GH_TOKEN", canary)
    parent_marker = tmp_path / "parent-execution-marker"
    host_secret = tmp_path / "host-secret"
    host_secret.write_text(canary, encoding="utf-8")
    host_secret.chmod(0o600)
    source = _source(
        tmp_path,
        """import json, os, socket, stat
def denied(fn):
    try:
        fn()
    except Exception:
        return True
    return False
status = open('/proc/self/status', encoding='utf-8').read()
result = {
    'uid': os.getuid(),
    'environment': dict(os.environ),
    'source_read': open('/workspace/source.txt', encoding='utf-8').read(),
    'source_write_denied': denied(lambda: open('/workspace/source.txt', 'w')),
    'root_write_denied': denied(lambda: open('/escape', 'w')),
    'docker_socket_absent': not os.path.exists('/var/run/docker.sock'),
    'host_home_absent': not os.path.exists('/Users/zain'),
    'host_secret_denied': denied(lambda: open(__HOST_SECRET__, encoding='utf-8').read()),
    'parent_write_denied': denied(lambda: open(__PARENT_MARKER__, 'w')),
    'dns_denied': denied(lambda: socket.getaddrinfo('example.com', 443)),
    'network_denied': denied(lambda: socket.create_connection(('1.1.1.1', 53), timeout=0.2)),
    'device_denied': denied(lambda: os.mknod('/scratch/device', stat.S_IFCHR, os.makedev(1, 3))),
    'no_new_privs': next(line for line in status.splitlines() if line.startswith('NoNewPrivs:')).endswith('1'),
    'cap_eff': next(line for line in status.splitlines() if line.startswith('CapEff:')).split()[1],
}
open('/scratch/result.json', 'w', encoding='utf-8').write(json.dumps(result, sort_keys=True))
""".replace("__HOST_SECRET__", repr(str(host_secret))).replace(
            "__PARENT_MARKER__", repr(str(parent_marker))
        ),
    )
    before = digest_snapshot(source)

    result = _executor().execute(_manifest(source, code="probe.py"), source)

    assert result.status == "completed", result.model_dump_json()
    assert result.accepted is True
    assert result.error is None
    assert result.cleanup.container_removed is True
    assert digest_snapshot(source) == before
    probe = _artifact_json(result)
    assert probe["uid"] != 0
    assert probe["environment"]["PT_ALLOWED"] == "visible"
    assert set(probe["environment"]) <= {"PT_ALLOWED", "LC_CTYPE"}
    assert probe["source_read"] == "immutable\n"
    assert probe["source_write_denied"] is True
    assert probe["root_write_denied"] is True
    assert probe["docker_socket_absent"] is True
    assert probe["host_home_absent"] is True
    assert probe["host_secret_denied"] is True
    assert probe["parent_write_denied"] is True
    assert probe["dns_denied"] is True
    assert probe["network_denied"] is True
    assert probe["device_denied"] is True
    assert probe["no_new_privs"] is True
    assert probe["cap_eff"] == "0000000000000000"
    assert not parent_marker.exists()
    assert canary not in result.model_dump_json()


def test_oci_backend_enforces_output_and_scratch_limits(tmp_path: Path) -> None:
    output_source = _source(
        tmp_path / "output",
        "import os\nos.write(1, b'x' * 200_000)\n",
    )
    limits = ExecutorLimits(output_bytes=16_384, artifact_bytes=16_384, scratch_bytes=1_048_576)

    output = _executor().execute(
        _manifest(output_source, code="probe.py", limits=limits), output_source
    )

    assert output.status == "failed"
    assert output.error is not None
    assert output.error.code == "executor_output_limit_exceeded", output.model_dump_json()
    assert output.cleanup.container_removed is True

    disk_source = _source(
        tmp_path / "disk",
        """import json, os
try:
    with open('/scratch/fill', 'wb', buffering=0) as handle:
        remaining = 2_000_000
        while remaining:
            remaining -= handle.write(b'x' * min(65_536, remaining))
    denied = False
except OSError:
    denied = True
try:
    os.unlink('/scratch/fill')
except FileNotFoundError:
    pass
open('/scratch/result.json', 'w', encoding='utf-8').write(json.dumps({'disk_limit_enforced': denied}))
""",
    )
    disk = _executor().execute(
        _manifest(disk_source, code="probe.py", limits=limits), disk_source
    )

    assert disk.status == "completed"
    assert _artifact_json(disk)["disk_limit_enforced"] is True

    file_source = _source(
        tmp_path / "file",
        """import json, os
try:
    with open('/scratch/large', 'wb', buffering=0) as handle:
        remaining = 131_072
        while remaining:
            remaining -= handle.write(b'x' * min(65_536, remaining))
    denied = False
except OSError:
    denied = True
try:
    os.unlink('/scratch/large')
except FileNotFoundError:
    pass
open('/scratch/result.json', 'w', encoding='utf-8').write(json.dumps({'file_limit_enforced': denied}))
""",
    )
    file_limits = limits.model_copy(update={"file_bytes": 65_536})
    file_result = _executor().execute(
        _manifest(file_source, code="probe.py", limits=file_limits), file_source
    )

    assert file_result.status == "completed", file_result.model_dump_json()
    assert _artifact_json(file_result)["file_limit_enforced"] is True


def test_oci_backend_enforces_pid_memory_timeout_and_cleanup(tmp_path: Path) -> None:
    pid_source = _source(
        tmp_path / "pids",
        """import json, os, time
children = []
while True:
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        time.sleep(10)
        raise SystemExit(0)
    children.append(pid)
for pid in children:
    os.kill(pid, 9)
for pid in children:
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
open('/scratch/result.json', 'w', encoding='utf-8').write(json.dumps({'children': len(children)}))
""",
    )
    pid_limits = ExecutorLimits(pids=16, wall_time_seconds=5)
    pids = _executor().execute(
        _manifest(pid_source, code="probe.py", limits=pid_limits), pid_source
    )

    assert pids.status == "completed"
    assert 1 <= _artifact_json(pids)["children"] < pid_limits.pids

    memory_source = _source(
        tmp_path / "memory",
        "blocks = []\nwhile True:\n    blocks.append(bytearray(16_777_216))\n",
    )
    memory_limits = ExecutorLimits(memory_bytes=67_108_864, wall_time_seconds=5)
    memory_manifest = _manifest(
        memory_source, code="probe.py", limits=memory_limits
    ).model_copy(update={"expected_artifacts": []})
    memory = _executor().execute(memory_manifest, memory_source)

    assert memory.status == "failed", memory.model_dump_json()
    assert memory.error is not None
    assert memory.error.code == "executor_memory_limit_exceeded"
    assert memory.resources.oom_killed is True

    cpu_source = _source(tmp_path / "cpu", "while True:\n    pass\n")
    cpu_limits = ExecutorLimits(cpu_time_seconds=1, wall_time_seconds=5)
    cpu_manifest = _manifest(cpu_source, code="probe.py", limits=cpu_limits).model_copy(
        update={"expected_artifacts": []}
    )
    cpu = _executor().execute(cpu_manifest, cpu_source)

    assert cpu.status == "failed", cpu.model_dump_json()
    assert cpu.error is not None
    assert cpu.error.code == "executor_cpu_limit_exceeded"

    timeout_source = _source(
        tmp_path / "timeout",
        "import os, time\nif os.fork() == 0:\n    time.sleep(60)\ntime.sleep(60)\n",
    )
    timeout_limits = ExecutorLimits(wall_time_seconds=1)
    timeout = _executor().execute(
        _manifest(timeout_source, code="probe.py", limits=timeout_limits), timeout_source
    )

    assert timeout.status == "timeout", timeout.model_dump_json()
    assert timeout.error is not None
    assert timeout.error.code == "executor_timeout"
    assert timeout.cleanup.container_removed is True
    assert _executor().owned_containers() == []


def test_oci_backend_cancellation_removes_full_container(tmp_path: Path) -> None:
    source = _source(tmp_path, "import time\ntime.sleep(60)\n")
    executor = _executor()
    cancel = threading.Event()
    result_holder: list[object] = []

    def run() -> None:
        result_holder.append(
            executor.execute(
                _manifest(source, code="probe.py", limits=ExecutorLimits(wall_time_seconds=20)),
                source,
                cancel=cancel,
            )
        )

    worker = threading.Thread(target=run)
    worker.start()
    time.sleep(0.5)
    cancel.set()
    worker.join(timeout=10)

    assert not worker.is_alive()
    result = result_holder[0]
    assert getattr(result, "status") == "cancelled"
    assert getattr(result, "cleanup").container_removed is True
    assert executor.owned_containers() == []


def test_oci_backend_rejects_symlink_snapshot_and_unavailable_controls(tmp_path: Path) -> None:
    source = _source(tmp_path, "pass\n")
    (source / "escape").symlink_to("/etc/passwd")
    manifest = ExecutorManifest(
        image_digest=_image(),
        snapshot_digest="sha256:" + "0" * 64,
        command=["/usr/local/bin/python3", "-I", "/workspace/probe.py"],
        expected_artifacts=[],
    )

    result = _executor().execute(manifest, source)

    assert result.status == "unsupported"
    assert result.error is not None
    assert result.error.code == "unsafe_snapshot_entry"
    assert result.cleanup.container_removed is True

    clean = _source(tmp_path / "missing", "pass\n")
    unavailable = OciExecutor(
        context="missing-promptectomy-context", accepted_images=frozenset({_image()})
    ).execute(
        manifest.model_copy(update={"snapshot_digest": digest_snapshot(clean)}),
        clean,
    )
    assert unavailable.status == "unsupported"
    assert unavailable.error is not None
    assert unavailable.error.code == "unsupported_executor_context"

    not_approved = OciExecutor(
        context="orbstack", accepted_images=frozenset({"sha256:" + "f" * 64})
    ).execute(
        manifest.model_copy(update={"snapshot_digest": digest_snapshot(clean)}),
        clean,
    )
    assert not_approved.status == "unsupported"
    assert not_approved.error is not None
    assert not_approved.error.code == "executor_image_not_approved"


def test_oci_backend_rejects_non_private_snapshot(tmp_path: Path) -> None:
    source = _source(tmp_path, "pass\n")
    source.chmod(0o755)
    manifest = ExecutorManifest(
        image_digest=_image(),
        snapshot_digest="sha256:" + "0" * 64,
        command=["/usr/local/bin/python3", "-I", "/workspace/probe.py"],
    )

    result = _executor().execute(manifest, source)

    assert result.status == "unsupported"
    assert result.error is not None
    assert result.error.code == "unsafe_snapshot_permissions"


def test_snapshot_digest_binds_execution_mode_and_rejects_chmod_staleness(tmp_path: Path) -> None:
    source = _source(tmp_path, "pass\n")
    before = digest_snapshot(source)
    (source / "probe.py").chmod(0o700)
    after = digest_snapshot(source)

    assert after != before
    manifest = ExecutorManifest(
        image_digest=_image(),
        snapshot_digest=before,
        command=["/usr/local/bin/python3", "-I", "/workspace/probe.py"],
    )
    result = _executor().execute(manifest, source)
    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "stale_snapshot"


def test_oci_backend_rejects_artifact_escape_and_protocol_spoof(tmp_path: Path) -> None:
    symlink_source = _source(
        tmp_path / "symlink-artifact",
        "import os\nos.symlink('/workspace/source.txt', '/scratch/result.json')\n",
    )
    symlink = _executor().execute(
        _manifest(symlink_source, code="probe.py"), symlink_source
    )

    assert symlink.status == "failed"
    assert symlink.error is not None
    assert symlink.error.code == "executor_artifact_invalid"
    assert symlink.artifacts == []

    hardlink_source = _source(
        tmp_path / "hardlink-artifact",
        """import os
open('/scratch/original', 'w').write('data')
os.link('/scratch/original', '/scratch/result.json')
""",
    )
    hardlink = _executor().execute(
        _manifest(hardlink_source, code="probe.py"), hardlink_source
    )

    assert hardlink.status == "failed"
    assert hardlink.error is not None
    assert hardlink.error.code == "executor_artifact_invalid"

    spoof_source = _source(
        tmp_path / "protocol-spoof",
        """import os
try:
    os.write(os.open('/proc/1/fd/1', os.O_WRONLY), b'{\"status\":\"completed\"}')
except OSError:
    pass
open('/scratch/result.json', 'w').write('{}')
""",
    )
    spoof = _executor().execute(_manifest(spoof_source, code="probe.py"), spoof_source)

    assert spoof.status == "failed"
    assert spoof.error is not None
    assert spoof.error.code == "executor_protocol_invalid"
    assert spoof.accepted is True


def test_oci_backend_types_crashes_and_artifact_overflow_without_orphans(tmp_path: Path) -> None:
    crash_source = _source(tmp_path / "crash", "raise SystemExit(17)\n")
    crash = _executor().execute(
        _manifest(crash_source, code="probe.py").model_copy(update={"expected_artifacts": []}),
        crash_source,
    )

    assert crash.status == "failed"
    assert crash.error is not None
    assert crash.error.code == "executor_command_failed"
    assert crash.resources.exit_code == 17
    assert crash.cleanup.container_removed is True

    artifact_source = _source(
        tmp_path / "artifact-overflow",
        "open('/scratch/result.json', 'wb').write(b'x' * 2048)\n",
    )
    limits = ExecutorLimits(
        artifact_bytes=1_024,
        file_bytes=65_536,
        scratch_bytes=1_048_576,
        wall_time_seconds=5,
    )
    artifact = _executor().execute(
        _manifest(artifact_source, code="probe.py", limits=limits),
        artifact_source,
    )

    assert artifact.status == "failed"
    assert artifact.error is not None
    assert artifact.error.code == "executor_artifact_invalid"
    assert artifact.artifacts == []
    assert artifact.cleanup.container_removed is True
    assert _executor().owned_containers() == []


def test_oci_backend_sanitizes_untrusted_terminal_and_secret_output(tmp_path: Path) -> None:
    source = _source(
        tmp_path,
        """import os
os.write(1, b'\\x1b]8;;https://example.invalid\\x07link\\x1b]8;;\\x07\\n')
print('token=sk-abcdefghijklmnopqrstuvwxyz')
open('/scratch/result.json', 'w').write('{}')
""",
    )

    result = _executor().execute(_manifest(source, code="probe.py"), source)

    assert result.status == "completed"
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in result.model_dump_json()
    assert "\x1b" not in result.stdout_preview
    assert "[REDACTED]" in result.stdout_preview


def test_executor_doctor_reports_real_accepted_backend() -> None:
    result = CliRunner().invoke(
        app,
        ["executor-doctor", "--image", _image(), "--context", "orbstack", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["accepted"] is True
    assert all(payload["probes"].values())
    assert all(payload["backend"]["controls"].values())

    main = CliRunner().invoke(
        app,
        ["doctor", "--json"],
        env={IMAGE_ENV: _image(), "PROMPTECTOMY_OCI_CONTEXT": "orbstack"},
    )
    assert main.exit_code == 0, main.output
    main_payload = json.loads(main.stdout)
    assert main_payload["checks"]["executor_available"] is True
    assert main_payload["checks"]["executor_accepted"] is True
    assert main_payload["capabilities"]["isolated_execution"] is True
    assert main_payload["capabilities"]["draft_verified"] is False


def test_reachable_backend_is_not_accepted_without_hostile_profile(tmp_path: Path) -> None:
    source = _source(tmp_path, "pass\n")
    raw = OciExecutor(context="orbstack", accepted_images=frozenset({_image()}))
    result = raw.execute(
        _manifest(source, code="probe.py").model_copy(update={"expected_artifacts": []}),
        source,
    )

    assert result.status == "completed"
    assert result.accepted is False
    assert result.backend is not None
    assert result.backend.controls.configuration_verified() is True
    assert result.backend.controls.accepted() is False


def test_executor_doctor_rejects_unaccepted_context() -> None:
    result = CliRunner().invoke(
        app,
        ["executor-doctor", "--image", _image(), "--context", "default", "--json"],
    )

    assert result.exit_code == 3
    assert json.loads(result.stdout)["error"]["code"] == "unsupported_executor_context"


def test_executor_rejects_spoofed_labels_with_modified_runner(tmp_path: Path) -> None:
    image = _image()
    name = f"promptectomy-phase1b-test-{uuid.uuid4().hex}"
    environment = {
        "HOME": str(Path.home()),
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    bad_runner = tmp_path / "runner.py"
    bad_runner.write_text("raise SystemExit(0)\n", encoding="utf-8")
    committed = ""
    try:
        created = subprocess.run(
            ["docker", "--context", "orbstack", "container", "create", "--name", name, image],
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert created.returncode == 0, created.stderr
        copied = subprocess.run(
            [
                "docker",
                "--context",
                "orbstack",
                "container",
                "cp",
                str(bad_runner),
                f"{name}:/opt/promptectomy/runner.py",
            ],
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert copied.returncode == 0, copied.stderr
        commit = subprocess.run(
            ["docker", "--context", "orbstack", "container", "commit", name],
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )
        committed = commit.stdout.decode("ascii").strip()
        assert commit.returncode == 0 and committed.startswith("sha256:"), commit.stderr
        source = _source(tmp_path / "source", "pass\n")
        manifest = ExecutorManifest(
            image_digest=committed,
            snapshot_digest=digest_snapshot(source),
            command=["/usr/local/bin/python3", "-I", "/workspace/probe.py"],
        )
        result = OciExecutor(
            context="orbstack", accepted_images=frozenset({committed})
        ).execute(manifest, source)
        assert result.status == "unsupported"
        assert result.error is not None
        assert result.error.code == "executor_image_invalid"
    finally:
        subprocess.run(
            ["docker", "--context", "orbstack", "container", "rm", "--force", "--volumes", name],
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if committed:
            subprocess.run(
                ["docker", "--context", "orbstack", "image", "rm", committed],
                env=environment,
                capture_output=True,
                check=False,
                timeout=30,
            )


def test_executor_doctor_rejects_unavailable_image_digest() -> None:
    result = CliRunner().invoke(
        app,
        ["executor-doctor", "--image", "sha256:" + "f" * 64, "--json"],
    )

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    if platform.system() == "Darwin" and platform.machine() in {"arm64", "aarch64"}:
        assert payload["error"]["code"] in {
            "executor_image_unavailable",
            "missing_isolation_backend",
        }
    else:
        assert payload["error"]["code"] == "unsupported_executor_context"
    assert payload["error"]["category"] == "unsupported"


def test_executor_doctor_fails_closed_without_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(IMAGE_ENV, raising=False)

    result = CliRunner().invoke(app, ["executor-doctor", "--json"])

    assert result.exit_code == 3
    assert json.loads(result.stdout)["error"]["code"] == "executor_image_unavailable"
