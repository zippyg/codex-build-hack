from __future__ import annotations

import base64
import hashlib
import json
import os
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import PurePosixPath


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _limits(value: dict[str, object]) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cpu = int(value["cpu_time_seconds"])
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (int(value["file_bytes"]), int(value["file_bytes"])))
    resource.setrlimit(resource.RLIMIT_NOFILE, (int(value["open_files"]), int(value["open_files"])))


def _capture(
    process: subprocess.Popen[bytes], output_limit: int, wall_time_seconds: int
) -> tuple[bytes, bytes, str | None]:
    selector = selectors.DefaultSelector()
    assert process.stdout is not None
    assert process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    failure: str | None = None
    deadline = time.monotonic() + wall_time_seconds
    while selector.get_map():
        if time.monotonic() >= deadline:
            failure = "timeout"
            _kill(process)
            break
        for key, _ in selector.select(timeout=0.05):
            chunk = os.read(key.fileobj.fileno(), 65_536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            remaining = max(0, output_limit - total)
            streams[key.data].extend(chunk[:remaining])
            total += len(chunk)
            if total > output_limit:
                failure = "output_limit"
                _kill(process)
                break
        if failure is not None:
            break
    selector.close()
    if failure is not None:
        process.stdout.close()
        process.stderr.close()
    process.wait(timeout=5)
    return bytes(streams["stdout"]), bytes(streams["stderr"]), failure


def _artifact(root: str, value: str, file_limit: int) -> bytes:
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("unsafe artifact path")
    descriptors: list[int] = []
    try:
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(directory_fd)
        for component in relative.parts[:-1]:
            directory_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            descriptors.append(directory_fd)
        file_fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        descriptors.append(file_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > file_limit:
            raise ValueError("artifact is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = file_limit + 1
        while remaining:
            chunk = os.read(file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > file_limit:
            raise ValueError("artifact exceeds file limit")
        return content
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _oom_killed() -> bool:
    try:
        with open("/sys/fs/cgroup/memory.events", encoding="ascii") as handle:
            values = {
                name: int(value)
                for name, value in (line.split(maxsplit=1) for line in handle)
            }
    except (OSError, ValueError):
        return False
    return values.get("oom_kill", 0) > 0


def main() -> int:
    raw = sys.stdin.buffer.read(1_048_577)
    if len(raw) > 1_048_576:
        return 126
    try:
        envelope = json.loads(raw)
        manifest = envelope["manifest"]
        digest = envelope["manifest_digest"]
        limits = manifest["limits"]
        command = manifest["command"]
        work = manifest["working_directory"]
        cwd = "/workspace" if work == "." else f"/workspace/{work}"
        if (
            manifest["schema_version"] != "phase1b-1"
            or manifest["operation"] != "offline_evaluation"
            or manifest["network"] != "none"
            or manifest["root_read_only"] is not True
            or manifest["source_read_only"] is not True
            or not command
            or not command[0].startswith("/")
        ):
            return 126
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return 126
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=manifest["environment"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=lambda: _limits(limits),
    )
    stdout, stderr, failure = _capture(process, int(limits["output_bytes"]), int(limits["wall_time_seconds"]))
    if failure is None and process.returncode == -signal.SIGXCPU:
        failure = "cpu_limit"
    artifact_values: list[dict[str, object]] = []
    artifact_total = 0
    if failure is None:
        try:
            for path in manifest["expected_artifacts"]:
                content = _artifact("/scratch", path, int(limits["file_bytes"]))
                artifact_total += len(content)
                if artifact_total > int(limits["artifact_bytes"]):
                    raise ValueError("artifact budget exceeded")
                artifact_values.append(
                    {
                        "path": path,
                        "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
                        "size": len(content),
                        "content_base64": base64.b64encode(content).decode("ascii"),
                    }
                )
        except (OSError, ValueError):
            failure = "artifact_invalid"
    payload = {
        "schema_version": "phase1b-runner-1",
        "manifest_digest": digest,
        "failure": failure,
        "oom_killed": _oom_killed(),
        "command_exit_code": process.returncode,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "artifacts": artifact_values,
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    sys.stdout.flush()
    if failure == "timeout":
        return 124
    if failure in {"output_limit", "artifact_invalid", "cpu_limit"}:
        return 125
    if process.returncode < 0:
        return min(255, 128 + abs(process.returncode))
    return min(255, process.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
