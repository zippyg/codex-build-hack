from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import queue
import re
import shutil
import stat
import subprocess
import threading
import time
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .executor_contracts import (
    DependencyAcquisitionManifest,
    DependencyAcquisitionResult,
    ExecutorArtifact,
    ExecutorAcceptanceReport,
    ExecutorBackend,
    ExecutorCleanup,
    ExecutorControls,
    ExecutorError,
    ExecutorLimits,
    ExecutorManifest,
    ExecutorResourceRecord,
    ExecutorResult,
    dependency_manifest_digest,
    manifest_digest,
)


_CONTAINER_PREFIX = "promptectomy-phase1b-"
_OWNER_LABEL = "dev.promptectomy.owner=phase1b"
_PROTOCOL_LABEL = "dev.promptectomy.executor.protocol"
_RUNNER_LABEL = "dev.promptectomy.executor.runner.sha256"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVIEWED_ROOTFS_LAYERS = (
    "sha256:12cdff3b039e28c684ffd2097ff5a66df274a8500966a1431038b05f50bcf096",
    "sha256:10b5151be3c11f9fd9e64043eaf4bf1dffbacf770da5b29e4480b710be81511f",
    "sha256:cdb2f937b2d0224e8694c43077267d2484502f0e45095b92a24e7eb4f7f484ed",
    "sha256:705c229bb06a03dde6eebf73743ebcb18dff129274ac3564d114a8926d73a628",
    "sha256:6efdb846f5f536c0ac83121ea2f450a51b791fdee53434c104df15a9d404fdf7",
    "sha256:7493fc9be2695fb9d597acf34b8022c467fec4040de29474616e327355f1f717",
)
_REVIEWED_IMAGE_ENVIRONMENT = (
    "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C.UTF-8",
    "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
    "PYTHON_VERSION=3.12.13",
    "PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684",
)
_ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_SECRET = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{16,}|(?:api[_-]?key|authorization|token|secret)\s*[:=]\s*['\"]?[a-z0-9._-]{12,})"
)
_MAX_SNAPSHOT_FILES = 50_000
_MAX_SNAPSHOT_FILE_BYTES = 100_000_000
_MAX_SNAPSHOT_BYTES = 2_000_000_000


class SnapshotFailure(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class BackendFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class _Runtime:
    client_version: str
    server_version: str
    api_version: str
    operating_system: str
    architecture: str
    seccomp_builtin: bool


def digest_snapshot(root: Path, *, reject_unsafe: bool = True) -> str:
    try:
        root_info = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise SnapshotFailure("snapshot_unavailable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise SnapshotFailure("unsafe_snapshot_root")
    if hasattr(os, "getuid"):
        if root_info.st_uid != os.getuid():
            raise SnapshotFailure("unsafe_snapshot_owner")
        if root_info.st_mode & 0o077:
            raise SnapshotFailure("unsafe_snapshot_permissions")
    digest = hashlib.sha256(b"promptectomy-phase1b-snapshot\0")
    digest.update(stat.S_IMODE(root_info.st_mode).to_bytes(4, "big"))
    root_device = root_info.st_dev
    count = 0
    total = 0
    stack = [resolved]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise SnapshotFailure("snapshot_unreadable") from exc
        for entry in entries:
            count += 1
            if count > _MAX_SNAPSHOT_FILES:
                raise SnapshotFailure("snapshot_quota_exceeded")
            path = Path(entry.path)
            relative = path.relative_to(resolved).as_posix().encode("utf-8", errors="surrogatepass")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise SnapshotFailure("snapshot_unreadable") from exc
            if info.st_dev != root_device:
                raise SnapshotFailure("unsafe_snapshot_mount")
            digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
            if stat.S_ISLNK(info.st_mode):
                if reject_unsafe:
                    raise SnapshotFailure("unsafe_snapshot_entry")
                target = os.fsencode(os.readlink(path))
                digest.update(b"l")
                digest.update(len(target).to_bytes(8, "big"))
                digest.update(target)
                continue
            if hasattr(os, "getuid") and (
                info.st_uid != os.getuid() or info.st_mode & 0o077
            ):
                raise SnapshotFailure("unsafe_snapshot_permissions")
            if stat.S_ISDIR(info.st_mode):
                digest.update(b"d")
                stack.append(path)
                continue
            if not stat.S_ISREG(info.st_mode) or (reject_unsafe and info.st_nlink != 1):
                raise SnapshotFailure("unsafe_snapshot_entry")
            if info.st_size > _MAX_SNAPSHOT_FILE_BYTES or total + info.st_size > _MAX_SNAPSHOT_BYTES:
                raise SnapshotFailure("snapshot_quota_exceeded")
            descriptor = -1
            try:
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise SnapshotFailure("snapshot_changed_during_read")
                digest.update(b"f")
                observed = 0
                while chunk := os.read(descriptor, 1_048_576):
                    observed += len(chunk)
                    if observed > _MAX_SNAPSHOT_FILE_BYTES or total + observed > _MAX_SNAPSHOT_BYTES:
                        raise SnapshotFailure("snapshot_quota_exceeded")
                    digest.update(chunk)
                total += observed
            except OSError as exc:
                raise SnapshotFailure("snapshot_unreadable") from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
    return f"sha256:{digest.hexdigest()}"


def _runner_digest() -> str:
    value = files("promptectomy.executor_image").joinpath("runner.py").read_bytes()
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _docker_binary() -> str:
    value = shutil.which("docker")
    if value is None:
        raise BackendFailure("missing_isolation_backend")
    return str(Path(value).resolve())


def _docker_environment() -> dict[str, str]:
    return {
        "HOME": str(Path.home()),
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }


def _require_supported_context(context: str) -> None:
    if (
        context != "orbstack"
        or platform.system() != "Darwin"
        or platform.machine() not in {"arm64", "aarch64"}
    ):
        raise BackendFailure("unsupported_executor_context")


def build_runner_image(*, context: str = "orbstack") -> str:
    _require_supported_context(context)
    docker = _docker_binary()
    assets = files("promptectomy.executor_image")
    root = Path(str(assets))
    runner = _runner_digest()
    command = [
        docker,
        "--context",
        context,
        "build",
        "--quiet",
        "--pull",
        "--network",
        "none",
        "--build-arg",
        f"RUNNER_SHA256={runner}",
        "--tag",
        "promptectomy-executor:phase1b",
        "--file",
        str(root / "Dockerfile"),
        str(root),
    ]
    try:
        built = subprocess.run(
            command,
            env=_docker_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackendFailure("executor_image_build_failed") from exc
    if built.returncode != 0:
        raise BackendFailure("executor_image_build_failed")
    try:
        inspected = subprocess.run(
            [docker, "--context", context, "image", "inspect", "--format", "{{.Id}}", "promptectomy-executor:phase1b"],
            env=_docker_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackendFailure("executor_image_build_failed") from exc
    image = inspected.stdout.decode("ascii", errors="ignore").strip()
    if inspected.returncode != 0 or not _DIGEST.fullmatch(image):
        raise BackendFailure("executor_image_build_failed")
    try:
        OciExecutor(context=context, accepted_images=frozenset({image}))._runtime(image)
    except BackendFailure as exc:
        raise BackendFailure("executor_image_build_failed") from exc
    return image


def smoke_test(image_digest: str, *, context: str) -> ExecutorResult:
    with tempfile.TemporaryDirectory(prefix="promptectomy-executor-doctor-") as temporary:
        snapshot = Path(temporary)
        snapshot.chmod(0o700)
        digest = digest_snapshot(snapshot)
        manifest = ExecutorManifest(
            image_digest=image_digest,
            snapshot_digest=digest,
            command=["/usr/local/bin/python3", "-I", "-c", "pass"],
        )
        return OciExecutor(
            context=context,
            accepted_images=frozenset({image_digest}),
        ).execute(manifest, snapshot)


class OciExecutor:
    def __init__(
        self,
        *,
        context: str,
        accepted_images: frozenset[str],
        _accepted_backend: ExecutorBackend | None = None,
    ) -> None:
        if not context or len(context) > 128 or any(character in context for character in "\0\r\n"):
            raise ValueError("invalid Docker context")
        if not accepted_images or any(not _DIGEST.fullmatch(value) for value in accepted_images):
            raise ValueError("accepted_images must contain digest-pinned image IDs")
        self.context = context
        self.accepted_images = accepted_images
        self.docker = _docker_binary()
        self.environment = _docker_environment()
        self._accepted_backend = _accepted_backend
        self._verified_images: set[str] = set()

    def _run(self, arguments: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                [self.docker, "--context", self.context, *arguments],
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendFailure("missing_isolation_backend") from exc

    def _runtime(self, image_digest: str) -> tuple[_Runtime, dict[str, object]]:
        _require_supported_context(self.context)
        version = self._run(["version", "--format", "{{json .}}"])
        if version.returncode != 0 or len(version.stdout) > 1_000_000:
            raise BackendFailure("missing_isolation_backend")
        try:
            version_value = json.loads(version.stdout)
            client = version_value["Client"]["Version"]
            server = version_value["Server"]["Version"]
            api = version_value["Server"]["ApiVersion"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise BackendFailure("missing_isolation_backend") from exc
        info = self._run(
            [
                "info",
                "--format",
                "{{json .SecurityOptions}}|{{json .OperatingSystem}}|{{json .Architecture}}|{{json .OSType}}",
            ]
        )
        if info.returncode != 0 or len(info.stdout) > 100_000:
            raise BackendFailure("missing_isolation_backend")
        try:
            security_raw, operating_raw, architecture_raw, os_type_raw = info.stdout.decode("utf-8").strip().split("|", 3)
            security = json.loads(security_raw)
            operating_system = json.loads(operating_raw)
            architecture = json.loads(architecture_raw)
            os_type = json.loads(os_type_raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BackendFailure("missing_isolation_backend") from exc
        if os_type != "linux" or not any("seccomp" in item and "builtin" in item for item in security):
            raise BackendFailure("executor_control_unavailable")
        image = self._run(["image", "inspect", "--format", "{{json .}}", image_digest])
        if image.returncode != 0 or len(image.stdout) > 2_000_000:
            raise BackendFailure("executor_image_unavailable")
        try:
            image_value = json.loads(image.stdout)
            labels = image_value["Config"]["Labels"] or {}
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise BackendFailure("executor_image_invalid") from exc
        config = image_value.get("Config", {})
        rootfs = image_value.get("RootFS", {})
        if (
            image_value.get("Id") != image_digest
            or labels
            != {
                _PROTOCOL_LABEL: "phase1b-1",
                _RUNNER_LABEL: _runner_digest(),
            }
            or tuple(rootfs.get("Layers", ())) != _REVIEWED_ROOTFS_LAYERS
            or tuple(config.get("Env", ())) != _REVIEWED_IMAGE_ENVIRONMENT
            or config.get("Entrypoint")
            != ["/usr/local/bin/python3", "-I", "-S", "/opt/promptectomy/runner.py"]
            or config.get("Cmd") is not None
            or config.get("Volumes") is not None
            or config.get("OnBuild") is not None
            or config.get("User") not in {"", None}
            or config.get("WorkingDir") not in {"", "/", None}
        ):
            raise BackendFailure("executor_image_invalid")
        if image_digest not in self._verified_images:
            self._verify_runner_contents(image_digest)
            self._verified_images.add(image_digest)
        runtime = _Runtime(
            client_version=str(client),
            server_version=str(server),
            api_version=str(api),
            operating_system=str(operating_system),
            architecture=str(architecture),
            seccomp_builtin=True,
        )
        return runtime, image_value

    def _verify_runner_contents(self, image_digest: str) -> None:
        name = f"{_CONTAINER_PREFIX}image-check-{uuid.uuid4().hex}"
        created = False
        try:
            result = self._run(
                [
                    "container",
                    "create",
                    "--name",
                    name,
                    "--label",
                    _OWNER_LABEL,
                    "--network",
                    "none",
                    "--entrypoint",
                    "/bin/false",
                    image_digest,
                ],
                timeout=30,
            )
            if result.returncode != 0:
                raise BackendFailure("executor_image_invalid")
            created = True
            with tempfile.TemporaryDirectory(prefix="promptectomy-runner-check-") as temporary:
                target = Path(temporary) / "runner.py"
                copied = self._run(
                    ["container", "cp", f"{name}:/opt/promptectomy/runner.py", str(target)],
                    timeout=30,
                )
                if copied.returncode != 0:
                    raise BackendFailure("executor_image_invalid")
                try:
                    info = target.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1_048_576:
                        raise BackendFailure("executor_image_invalid")
                    observed = f"sha256:{hashlib.sha256(target.read_bytes()).hexdigest()}"
                except OSError as exc:
                    raise BackendFailure("executor_image_invalid") from exc
                if observed != _runner_digest():
                    raise BackendFailure("executor_image_invalid")
        finally:
            if created and not self._remove(name):
                raise BackendFailure("executor_image_invalid")

    def _create(self, manifest: ExecutorManifest, snapshot: Path, name: str) -> str:
        limits = manifest.limits
        cpu = f"{limits.cpu_millis / 1000:.3f}".rstrip("0").rstrip(".")
        mount = (
            f"type=bind,src={snapshot},dst=/workspace,readonly,"
            "bind-recursive=readonly,bind-propagation=rprivate"
        )
        command = [
            "create",
            "--name",
            name,
            "--label",
            _OWNER_LABEL,
            "--pull",
            "never",
            "--interactive",
            "--init",
            "--read-only",
            "--mount",
            mount,
            "--tmpfs",
            f"/scratch:rw,noexec,nosuid,nodev,size={limits.scratch_bytes},mode=0700,uid=65532,gid=65532",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=65532,gid=65532",
            "--network",
            "none",
            "--ipc",
            "none",
            "--cgroupns",
            "private",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(limits.pids),
            "--memory",
            str(limits.memory_bytes),
            "--memory-swap",
            str(limits.memory_bytes),
            "--cpus",
            cpu,
            "--ulimit",
            f"cpu={limits.cpu_time_seconds}:{limits.cpu_time_seconds + 1}",
            "--ulimit",
            f"fsize={limits.file_bytes}:{limits.file_bytes}",
            "--ulimit",
            f"nofile={limits.open_files}:{limits.open_files}",
            "--ulimit",
            "core=0:0",
            "--shm-size",
            "1048576",
            "--restart",
            "no",
            "--no-healthcheck",
            "--log-driver",
            "none",
            "--stop-timeout",
            "1",
            "--hostname",
            "promptectomy-executor",
            "--entrypoint",
            "/usr/local/bin/python3",
            manifest.image_digest,
            "-I",
            "-S",
            "/opt/promptectomy/runner.py",
        ]
        created = self._run(command, timeout=60)
        container = created.stdout.decode("ascii", errors="ignore").strip()
        if created.returncode != 0 or not re.fullmatch(r"[0-9a-f]{64}", container):
            raise BackendFailure("executor_create_failed")
        return container

    def _inspect(self, name: str) -> dict[str, object]:
        inspected = self._run(["container", "inspect", "--format", "{{json .}}", name])
        if inspected.returncode != 0 or len(inspected.stdout) > 2_000_000:
            raise BackendFailure("executor_inspect_failed")
        try:
            value = json.loads(inspected.stdout)
        except json.JSONDecodeError as exc:
            raise BackendFailure("executor_inspect_failed") from exc
        if not isinstance(value, dict):
            raise BackendFailure("executor_inspect_failed")
        return value

    def _backend(
        self,
        manifest: ExecutorManifest,
        runtime: _Runtime,
        inspected: dict[str, object],
        snapshot: Path,
    ) -> ExecutorBackend:
        try:
            config = inspected["Config"]
            host = inspected["HostConfig"]
            mounts = inspected["Mounts"]
            scratch = host["Tmpfs"]["/scratch"]
            security = host["SecurityOpt"] or []
            caps = host["CapDrop"] or []
            ulimits = {item["Name"]: (item["Soft"], item["Hard"]) for item in host["Ulimits"]}
            source_mount = next(item for item in mounts if item["Destination"] == "/workspace")
            host_source_mount = next(item for item in host["Mounts"] if item["Target"] == "/workspace")
        except (KeyError, StopIteration, TypeError) as exc:
            raise BackendFailure("executor_control_unavailable") from exc
        limits = manifest.limits
        allowed_destinations = {"/workspace", "/scratch", "/tmp"}
        controls = ExecutorControls(
            non_root=config.get("User") == "65532:65532",
            root_read_only=host.get("ReadonlyRootfs") is True,
            source_read_only=(
                source_mount.get("RW") is False
                and Path(source_mount["Source"]).resolve() == snapshot
                and host_source_mount.get("ReadOnly") is True
                and host_source_mount.get("BindOptions", {}).get("Propagation") == "rprivate"
                and host_source_mount.get("BindOptions", {}).get("ReadOnlyForceRecursive") is True
            ),
            private_scratch=(
                "noexec" in scratch
                and "nosuid" in scratch
                and "nodev" in scratch
                and f"size={limits.scratch_bytes}" in scratch
            ),
            empty_environment=False,
            network_none=host.get("NetworkMode") == "none" and not host.get("PortBindings"),
            no_new_privileges=any("no-new-privileges" in item for item in security),
            capabilities_dropped="ALL" in caps,
            seccomp_builtin=runtime.seccomp_builtin,
            no_host_sockets=(
                all(item.get("Destination") in allowed_destinations for item in mounts)
                and not host.get("Devices")
                and not host.get("Binds")
            ),
            private_cgroup_namespace=host.get("CgroupnsMode") == "private" and host.get("IpcMode") == "none",
            cpu_limit=host.get("NanoCpus") == limits.cpu_millis * 1_000_000,
            memory_limit=(
                host.get("Memory") == limits.memory_bytes and host.get("MemorySwap") == limits.memory_bytes
            ),
            pid_limit=host.get("PidsLimit") == limits.pids,
            file_limit=(
                ulimits.get("nofile") == (limits.open_files, limits.open_files)
                and ulimits.get("fsize") == (limits.file_bytes, limits.file_bytes)
                and ulimits.get("cpu") == (limits.cpu_time_seconds, limits.cpu_time_seconds + 1)
            ),
            scratch_limit=f"size={limits.scratch_bytes}" in scratch,
            wall_time_limit=False,
            output_limit=False,
            process_tree_cleanup=False,
        )
        if not controls.configuration_verified() or host.get("Privileged") is not False:
            raise BackendFailure("executor_control_unavailable")
        backend = ExecutorBackend(
            context=self.context,
            client_version=runtime.client_version,
            server_version=runtime.server_version,
            api_version=runtime.api_version,
            operating_system=runtime.operating_system,
            architecture=runtime.architecture,
            image_digest=manifest.image_digest,
            runner_digest=_runner_digest(),
            controls=controls,
        )
        accepted = self._accepted_backend
        if accepted is not None and accepted.model_copy(update={"controls": controls}) == backend:
            backend = backend.model_copy(update={"controls": accepted.controls})
        return backend

    def _kill(self, name: str) -> None:
        self._run(["container", "kill", "--signal", "KILL", name], timeout=10)

    def _start(
        self,
        name: str,
        envelope: bytes,
        manifest: ExecutorManifest,
        cancel: threading.Event | None,
    ) -> tuple[bytes, bytes, str | None]:
        process = subprocess.Popen(
            [self.docker, "--context", self.context, "container", "start", "--attach", "--interactive", name],
            env=self.environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdin.write(envelope)
        process.stdin.close()
        output_queue: queue.Queue[tuple[str, bytes] | tuple[str, None]] = queue.Queue()

        def read(name: str, stream: object) -> None:
            while chunk := stream.read(65_536):
                output_queue.put((name, chunk))
            output_queue.put((name, None))

        readers = [
            threading.Thread(target=read, args=("stdout", process.stdout), daemon=True),
            threading.Thread(target=read, args=("stderr", process.stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        values = {"stdout": bytearray(), "stderr": bytearray()}
        finished: set[str] = set()
        reason: str | None = None
        protocol_limit = (
            (manifest.limits.output_bytes + manifest.limits.artifact_bytes) * 2
            + 1_048_576
        )
        deadline = time.monotonic() + manifest.limits.wall_time_seconds + 2
        while len(finished) < 2:
            if cancel is not None and cancel.is_set():
                reason = "cancelled"
                self._kill(name)
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                self._kill(name)
                break
            try:
                stream_name, chunk = output_queue.get(timeout=0.05)
            except queue.Empty:
                continue
            if chunk is None:
                finished.add(stream_name)
                continue
            values[stream_name].extend(chunk)
            if len(values["stdout"]) + len(values["stderr"]) > protocol_limit:
                reason = "protocol_limit"
                self._kill(name)
                break
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=1)
        return bytes(values["stdout"]), bytes(values["stderr"]), reason

    def _remove(self, name: str) -> bool:
        removed = self._run(["container", "rm", "--force", "--volumes", name], timeout=15)
        return removed.returncode == 0

    def _exists(self, name: str) -> bool:
        return self._run(["container", "inspect", name], timeout=10).returncode == 0

    def owned_containers(self) -> list[str]:
        result = self._run(
            ["container", "ls", "--all", "--filter", f"label={_OWNER_LABEL}", "--format", "{{.Names}}"]
        )
        if result.returncode != 0:
            raise BackendFailure("missing_isolation_backend")
        names = sorted(line for line in result.stdout.decode("utf-8", errors="ignore").splitlines() if line)
        return [name for name in names if self._exists(name)]

    @staticmethod
    def acquire_dependencies(
        manifest: DependencyAcquisitionManifest,
    ) -> DependencyAcquisitionResult:
        return DependencyAcquisitionResult(
            manifest_digest=dependency_manifest_digest(manifest),
            error=_error("dependency_network_policy_unavailable"),
        )

    def execute(
        self,
        manifest: ExecutorManifest,
        snapshot: Path,
        *,
        cancel: threading.Event | None = None,
    ) -> ExecutorResult:
        digest = manifest_digest(manifest)
        started = time.monotonic()
        name = f"{_CONTAINER_PREFIX}{uuid.uuid4().hex}"
        container_created = False
        backend: ExecutorBackend | None = None
        raw_stdout = b""
        raw_stderr = b""
        command_stdout = b""
        command_stderr = b""
        artifacts: list[ExecutorArtifact] = []
        status = "unsupported"
        error = _error("missing_isolation_backend")
        exit_code: int | None = None
        oom_killed = False
        accepted = False
        try:
            resolved = snapshot.resolve(strict=True)
            if any(character in str(resolved) for character in ",\0\r\n"):
                raise SnapshotFailure("unsafe_snapshot_root")
            before = digest_snapshot(resolved)
            if before != manifest.snapshot_digest:
                raise SnapshotFailure("stale_snapshot")
            if manifest.image_digest not in self.accepted_images:
                raise BackendFailure("executor_image_not_approved")
            runtime, _ = self._runtime(manifest.image_digest)
            self._create(manifest, resolved, name)
            container_created = True
            inspected = self._inspect(name)
            backend = self._backend(manifest, runtime, inspected, resolved)
            accepted = backend.controls.accepted()
            envelope = json.dumps(
                {"manifest": manifest.model_dump(mode="json"), "manifest_digest": digest},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            raw_stdout, raw_stderr, host_reason = self._start(name, envelope, manifest, cancel)
            state = self._inspect(name)["State"]
            container_exit_code = int(state["ExitCode"])
            exit_code = container_exit_code
            oom_killed = bool(state["OOMKilled"])
            if host_reason == "cancelled":
                status = "cancelled"
                error = _error("executor_cancelled")
            elif host_reason == "timeout":
                status = "timeout"
                error = _error("executor_timeout")
            elif host_reason == "protocol_limit":
                status = "failed"
                error = _error("executor_output_limit_exceeded")
            elif oom_killed:
                status = "failed"
                error = _error("executor_memory_limit_exceeded")
            else:
                payload = _runner_payload(raw_stdout, digest, manifest)
                command_stdout = payload["stdout"]
                command_stderr = payload["stderr"]
                artifacts = payload["artifacts"]
                runner_failure = payload["failure"]
                exit_code = payload["command_exit_code"]
                oom_killed = oom_killed or payload["oom_killed"]
                if oom_killed:
                    status = "failed"
                    error = _error("executor_memory_limit_exceeded")
                elif runner_failure == "timeout":
                    status = "timeout"
                    error = _error("executor_timeout")
                elif runner_failure == "cpu_limit":
                    status = "failed"
                    error = _error("executor_cpu_limit_exceeded")
                elif runner_failure == "output_limit":
                    status = "failed"
                    error = _error("executor_output_limit_exceeded")
                elif runner_failure == "artifact_invalid":
                    status = "failed"
                    error = _error("executor_artifact_invalid")
                elif container_exit_code == 0 and exit_code == 0:
                    status = "completed"
                    error = None
                else:
                    status = "failed"
                    error = _error("executor_command_failed")
            after = digest_snapshot(resolved)
            if after != before:
                status = "failed"
                error = _error("executor_source_mutation_detected")
                artifacts = []
        except SnapshotFailure as exc:
            status = "unsupported" if exc.code.startswith("unsafe_") else "failed"
            error = _error(exc.code)
        except BackendFailure as exc:
            status = "unsupported" if exc.code in {
                "missing_isolation_backend",
                "executor_control_unavailable",
                "executor_image_unavailable",
                "executor_image_invalid",
                "executor_image_not_approved",
                "unsupported_executor_context",
            } else "failed"
            error = _error(exc.code)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            status = "failed"
            error = _error("executor_protocol_invalid")
            artifacts = []
        finally:
            try:
                removed = not container_created or self._remove(name)
            except BackendFailure:
                removed = False
        orphan_free = removed
        safe_stdout = _sanitize(command_stdout)
        safe_stderr = _sanitize(command_stderr if command_stderr else raw_stderr)
        artifact_bytes = sum(item.size for item in artifacts)
        return ExecutorResult(
            status=status,
            accepted=accepted,
            manifest_digest=digest,
            backend=backend,
            resources=ExecutorResourceRecord(
                wall_time_ms=int((time.monotonic() - started) * 1_000),
                exit_code=exit_code,
                oom_killed=oom_killed,
                output_bytes=len(command_stdout) + len(command_stderr),
                artifact_bytes=artifact_bytes,
            ),
            stdout_preview=safe_stdout,
            stderr_preview=safe_stderr,
            stdout_digest=f"sha256:{hashlib.sha256(command_stdout).hexdigest()}",
            stderr_digest=f"sha256:{hashlib.sha256(command_stderr).hexdigest()}",
            artifacts=artifacts,
            error=error,
            cleanup=ExecutorCleanup(container_removed=removed, orphan_check_passed=orphan_free),
        )


def accept_backend(
    image_digest: str,
    *,
    context: str = "orbstack",
) -> tuple[OciExecutor, ExecutorAcceptanceReport]:
    _require_supported_context(context)
    started = time.monotonic()
    raw = OciExecutor(context=context, accepted_images=frozenset({image_digest}))
    raw._runtime(image_digest)
    probes: dict[str, bool] = {
        "configuration": False,
        "static_isolation": False,
        "output_limit": False,
        "memory_limit": False,
        "wall_time_limit": False,
        "cancellation_cleanup": False,
        "orphan_cleanup": False,
    }
    backend: ExecutorBackend | None = None
    failure: ExecutorError | None = None

    def run(code: str, limits: ExecutorLimits, *, cancel: threading.Event | None = None) -> ExecutorResult:
        with tempfile.TemporaryDirectory(prefix="promptectomy-acceptance-") as temporary:
            snapshot = Path(temporary)
            snapshot.chmod(0o700)
            script = snapshot / "probe.py"
            script.write_text(code, encoding="utf-8")
            script.chmod(0o600)
            manifest = ExecutorManifest(
                image_digest=image_digest,
                snapshot_digest=digest_snapshot(snapshot),
                command=["/usr/local/bin/python3", "-I", "/workspace/probe.py"],
                environment={"PT_ACCEPTANCE": "phase1b"},
                limits=limits,
            )
            return raw.execute(manifest, snapshot, cancel=cancel)

    static = run(
        """import json, os, socket, stat
def denied(fn):
    try:
        fn()
    except Exception:
        return True
    return False
status = open('/proc/self/status', encoding='utf-8').read()
print(json.dumps({
    'uid': os.getuid(),
    'environment': sorted(os.environ),
    'source_write_denied': denied(lambda: open('/workspace/probe.py', 'w')),
    'root_write_denied': denied(lambda: open('/escape', 'w')),
    'socket_absent': not os.path.exists('/var/run/docker.sock'),
    'dns_denied': denied(lambda: socket.getaddrinfo('example.com', 443)),
    'network_denied': denied(lambda: socket.create_connection(('1.1.1.1', 53), timeout=0.2)),
    'device_denied': denied(lambda: os.mknod('/scratch/device', stat.S_IFCHR, os.makedev(1, 3))),
    'no_new_privs': next(x for x in status.splitlines() if x.startswith('NoNewPrivs:')).endswith('1'),
    'cap_eff': next(x for x in status.splitlines() if x.startswith('CapEff:')).split()[1],
}, sort_keys=True))
""",
        ExecutorLimits(wall_time_seconds=5),
    )
    backend = static.backend
    probes["configuration"] = bool(
        backend is not None
        and backend.controls.configuration_verified()
        and backend.operating_system == "OrbStack"
        and backend.architecture == "aarch64"
    )
    try:
        observed = json.loads(static.stdout_preview)
    except json.JSONDecodeError:
        observed = {}
    probes["static_isolation"] = static.status == "completed" and observed == {
        "cap_eff": "0000000000000000",
        "device_denied": True,
        "dns_denied": True,
        "environment": ["LC_CTYPE", "PT_ACCEPTANCE"],
        "network_denied": True,
        "no_new_privs": True,
        "root_write_denied": True,
        "socket_absent": True,
        "source_write_denied": True,
        "uid": 65532,
    }

    output = run(
        "import os\nos.write(1, b'x' * 2048)\n",
        ExecutorLimits(output_bytes=1_024, artifact_bytes=1_024, scratch_bytes=1_048_576, wall_time_seconds=5),
    )
    probes["output_limit"] = bool(
        output.status == "failed"
        and output.error is not None
        and output.error.code == "executor_output_limit_exceeded"
        and output.cleanup.container_removed
    )

    memory = run(
        "blocks = []\nwhile True:\n    blocks.append(bytearray(16_777_216))\n",
        ExecutorLimits(memory_bytes=67_108_864, wall_time_seconds=5),
    )
    probes["memory_limit"] = bool(
        memory.status == "failed"
        and memory.error is not None
        and memory.error.code == "executor_memory_limit_exceeded"
        and memory.resources.oom_killed
        and memory.cleanup.container_removed
    )

    timeout = run(
        "import os, time\nif os.fork() == 0:\n    time.sleep(60)\ntime.sleep(60)\n",
        ExecutorLimits(wall_time_seconds=1),
    )
    probes["wall_time_limit"] = bool(
        timeout.status == "timeout"
        and timeout.error is not None
        and timeout.error.code == "executor_timeout"
        and timeout.cleanup.container_removed
    )

    cancel = threading.Event()
    cancel_result: list[ExecutorResult] = []

    def cancel_probe() -> None:
        cancel_result.append(
            run("import time\ntime.sleep(60)\n", ExecutorLimits(wall_time_seconds=20), cancel=cancel)
        )

    worker = threading.Thread(target=cancel_probe)
    worker.start()
    time.sleep(0.5)
    cancel.set()
    worker.join(timeout=10)
    probes["cancellation_cleanup"] = bool(
        not worker.is_alive()
        and cancel_result
        and cancel_result[0].status == "cancelled"
        and cancel_result[0].cleanup.container_removed
    )
    completed_runs = [static, output, memory, timeout, *cancel_result]
    probes["orphan_cleanup"] = all(
        result.cleanup.container_removed and result.cleanup.orphan_check_passed
        for result in completed_runs
    )

    accepted = backend is not None and all(probes.values())
    if accepted:
        controls = backend.controls.model_copy(
            update={
                "empty_environment": True,
                "wall_time_limit": True,
                "output_limit": True,
                "process_tree_cleanup": True,
            }
        )
        backend = backend.model_copy(update={"controls": controls})
    else:
        failure = _error("executor_acceptance_failed")
    profile = {
        "schema_version": "phase1b-acceptance-1",
        "accepted": accepted,
        "context": context,
        "image_digest": image_digest,
        "runner_digest": _runner_digest(),
        "backend": backend.model_dump(mode="json") if backend is not None else None,
        "probes": probes,
    }
    profile_digest = "sha256:" + hashlib.sha256(
        json.dumps(profile, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    report = ExecutorAcceptanceReport(
        accepted=accepted,
        context=context,
        image_digest=image_digest,
        runner_digest=_runner_digest(),
        backend=backend,
        probes=probes,
        profile_digest=profile_digest,
        wall_time_ms=int((time.monotonic() - started) * 1_000),
        error=failure,
    )
    executor = OciExecutor(
        context=context,
        accepted_images=frozenset({image_digest}),
        _accepted_backend=backend if accepted else None,
    )
    return executor, report


def _runner_payload(raw: bytes, expected_digest: str, manifest: ExecutorManifest) -> dict[str, object]:
    if len(raw) > (manifest.limits.output_bytes + manifest.limits.artifact_bytes) * 2 + 1_048_576:
        raise ValueError("runner response exceeds protocol limit")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate runner response key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "manifest_digest",
        "failure",
        "oom_killed",
        "command_exit_code",
        "stdout_base64",
        "stderr_base64",
        "artifacts",
    }:
        raise ValueError("invalid runner response")
    if value["schema_version"] != "phase1b-runner-1" or value["manifest_digest"] != expected_digest:
        raise ValueError("runner response binding mismatch")
    if value["failure"] not in {None, "timeout", "output_limit", "artifact_invalid", "cpu_limit"}:
        raise ValueError("unknown runner failure")
    if not isinstance(value["oom_killed"], bool):
        raise ValueError("invalid runner memory record")
    if not isinstance(value["command_exit_code"], int):
        raise ValueError("invalid command exit code")
    stdout = base64.b64decode(value["stdout_base64"], validate=True)
    stderr = base64.b64decode(value["stderr_base64"], validate=True)
    if len(stdout) + len(stderr) > manifest.limits.output_bytes:
        raise ValueError("runner output exceeds manifest")
    if not isinstance(value["artifacts"], list) or len(value["artifacts"]) > len(manifest.expected_artifacts):
        raise ValueError("invalid runner artifacts")
    artifacts = [ExecutorArtifact.model_validate(item) for item in value["artifacts"]]
    if value["failure"] is None and [item.path for item in artifacts] != manifest.expected_artifacts:
        raise ValueError("runner artifact set mismatch")
    if value["failure"] is not None and artifacts:
        raise ValueError("failed runner response contains artifacts")
    if sum(item.size for item in artifacts) > manifest.limits.artifact_bytes:
        raise ValueError("runner artifacts exceed manifest")
    for artifact in artifacts:
        artifact.content()
    return {
        "failure": value["failure"],
        "oom_killed": value["oom_killed"],
        "command_exit_code": value["command_exit_code"],
        "stdout": stdout,
        "stderr": stderr,
        "artifacts": artifacts,
    }


def _sanitize(value: bytes) -> str:
    without_ansi = _ANSI.sub(b"", value)
    text = without_ansi.decode("utf-8", errors="replace")
    text = "".join(
        character
        for character in text
        if character in "\n\t" or (unicodedata.category(character) not in {"Cc", "Cf"})
    )
    return _SECRET.sub("[REDACTED]", text)[:4_000]


def _error(code: str) -> ExecutorError:
    values = {
        "unsupported_executor_context": ("unsupported", False, "This host and OCI context are not an accepted executor support cell.", "Use Apple Silicon macOS with the reviewed OrbStack support cell or continue without isolated execution."),
        "missing_isolation_backend": ("unsupported", True, "No accepted OCI isolation backend is available.", "Start the approved runtime or continue with Audit/unverified Draft."),
        "executor_control_unavailable": ("unsupported", False, "The OCI backend cannot prove every required isolation control.", "Disable this backend support cell until its controls pass acceptance."),
        "executor_image_unavailable": ("unsupported", True, "The digest-pinned executor image is unavailable locally.", "Build or import the reviewed executor image before retrying."),
        "executor_image_invalid": ("unsupported", False, "The executor image identity or runner binding is invalid.", "Rebuild the reviewed executor image from packaged assets."),
        "executor_image_not_approved": ("policy", False, "The executor image is not in the approved digest set.", "Select a reviewed digest-pinned executor image."),
        "executor_create_failed": ("executor", True, "The isolated container could not be created.", "Inspect the local runtime and retry without weakening controls."),
        "executor_inspect_failed": ("executor", True, "The executor could not verify the container configuration.", "Inspect the local runtime and retry without starting unverified work."),
        "executor_cancelled": ("cancel", False, "The isolated execution was cancelled and cleaned up.", "Start a new execution if the work is still required."),
        "executor_timeout": ("executor", True, "The isolated execution exceeded its wall-time limit.", "Reduce the workload or explicitly approve a bounded larger limit."),
        "executor_output_limit_exceeded": ("executor", False, "The isolated execution exceeded its output limit.", "Reduce emitted output before retrying."),
        "executor_memory_limit_exceeded": ("executor", False, "The isolated execution exceeded its memory limit.", "Reduce memory use or explicitly approve a bounded larger limit."),
        "executor_cpu_limit_exceeded": ("executor", False, "The isolated execution exceeded its CPU-time limit.", "Reduce CPU use or explicitly approve a bounded larger limit."),
        "executor_artifact_invalid": ("executor", False, "A declared executor artifact was missing, unsafe, or over budget.", "Produce only declared bounded regular-file artifacts."),
        "executor_command_failed": ("executor", False, "The isolated command returned a non-zero result.", "Review the sanitized output and candidate evidence."),
        "executor_protocol_invalid": ("executor", False, "The isolated runner returned an invalid result envelope.", "Quarantine the run and inspect the runner/backend version."),
        "executor_source_mutation_detected": ("executor", False, "The immutable snapshot digest changed during execution.", "Disable the backend and investigate the mount boundary."),
        "executor_acceptance_failed": ("policy", False, "The OCI backend failed one or more hostile acceptance probes.", "Keep isolated execution disabled and inspect the failed probe receipt."),
        "dependency_network_policy_unavailable": ("unsupported", False, "This backend cannot enforce the declared registry-only dependency network policy.", "Use a separately accepted acquisition backend or a reviewed prebuilt image digest."),
        "snapshot_unavailable": ("input", True, "The tool-owned snapshot is unavailable.", "Create a fresh private snapshot before execution."),
        "snapshot_unreadable": ("input", True, "The tool-owned snapshot cannot be read safely.", "Repair snapshot permissions or create a fresh snapshot."),
        "snapshot_quota_exceeded": ("input", False, "The tool-owned snapshot exceeds the executor quota.", "Select a smaller bounded snapshot."),
        "snapshot_changed_during_read": ("input", True, "The tool-owned snapshot changed during verification.", "Create and seal a fresh snapshot before retrying."),
        "stale_snapshot": ("policy", False, "The executor manifest does not match the current snapshot.", "Issue a new manifest for the current snapshot digest."),
        "unsafe_snapshot_root": ("unsupported", False, "The snapshot root is unsafe for isolated execution.", "Use a private normalized local snapshot path."),
        "unsafe_snapshot_owner": ("unsupported", False, "The snapshot is not owned by the current user.", "Create a private snapshot owned by the current user."),
        "unsafe_snapshot_permissions": ("unsupported", False, "The snapshot permissions are not owner-only.", "Create an owner-only tool snapshot before execution."),
        "unsafe_snapshot_mount": ("unsupported", False, "The snapshot contains a nested mount boundary.", "Create a flattened tool-owned snapshot."),
        "unsafe_snapshot_entry": ("unsupported", False, "The snapshot contains a symlink, hardlink, or special entry.", "Create a regular-file-only tool-owned snapshot."),
    }
    category, retryable, message, action = values.get(
        code,
        ("internal", False, "The executor failed at an internal trust boundary.", "Quarantine the run and inspect safe diagnostics."),
    )
    return ExecutorError(
        code=code,
        category=category,
        retryable=retryable,
        safe_message=message,
        next_action=action,
    )
