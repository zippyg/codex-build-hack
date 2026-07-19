from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator


Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
SafeValue = Annotated[str, StringConstraints(max_length=4_096)]
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_FORBIDDEN_ENVIRONMENT = re.compile(
    r"(?i)(?:^|_)(?:api_?key|auth|credential|database_?url|docker_?host|git_askpass|gh_token|home|kubeconfig|ld_preload|path|private_?key|proxy|secret|ssh_auth_sock|token)(?:$|_)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{16,}|(?:api[_-]?key|authorization|token|secret)\s*[:=]\s*['\"]?[a-z0-9._-]{12,})"
)


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ExecutorLimits(Closed):
    cpu_millis: int = Field(default=1_000, ge=100, le=8_000)
    cpu_time_seconds: int = Field(default=60, ge=1, le=3_600)
    memory_bytes: int = Field(default=268_435_456, ge=33_554_432, le=4_294_967_296)
    pids: int = Field(default=64, ge=8, le=512)
    open_files: int = Field(default=256, ge=32, le=4_096)
    file_bytes: int = Field(default=16_777_216, ge=65_536, le=1_073_741_824)
    scratch_bytes: int = Field(default=67_108_864, ge=1_048_576, le=2_147_483_648)
    wall_time_seconds: int = Field(default=120, ge=1, le=3_600)
    output_bytes: int = Field(default=1_048_576, ge=1_024, le=16_777_216)
    artifact_bytes: int = Field(default=16_777_216, ge=1_024, le=268_435_456)


class DependencyPolicy(Closed):
    mode: Literal["prebuilt_image"] = "prebuilt_image"
    network: Literal["none"] = "none"
    install_scripts: Literal[False] = False
    lock_digest: Digest | None = None


class DependencyAcquisitionManifest(Closed):
    schema_version: Literal["phase1b-1"] = "phase1b-1"
    operation: Literal["dependency_acquisition"] = "dependency_acquisition"
    image_digest: Digest
    snapshot_digest: Digest
    package_manager: Literal["uv", "bun"]
    lockfile: str
    lock_digest: Digest
    registry_hosts: list[str] = Field(min_length=1, max_length=8)
    install_scripts: Literal[False] = False
    max_download_bytes: int = Field(ge=1_048_576, le=2_147_483_648)
    wall_time_seconds: int = Field(ge=1, le=1_800)

    @field_validator("lockfile")
    @classmethod
    def validate_lockfile(cls, value: str) -> str:
        return _relative_path(value)

    @field_validator("registry_hosts")
    @classmethod
    def validate_registry_hosts(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
            for host in value
        ):
            raise ValueError("registry hosts must be unique lowercase DNS names")
        return sorted(value)


class ExecutorManifest(Closed):
    schema_version: Literal["phase1b-1"] = "phase1b-1"
    operation: Literal["offline_evaluation"] = "offline_evaluation"
    image_digest: Digest
    snapshot_digest: Digest
    command: list[SafeValue] = Field(min_length=1, max_length=128)
    working_directory: str = "."
    environment: dict[str, SafeValue] = Field(default_factory=dict, max_length=32)
    network: Literal["none"] = "none"
    root_read_only: Literal[True] = True
    source_read_only: Literal[True] = True
    expected_artifacts: list[str] = Field(default_factory=list, max_length=64)
    limits: ExecutorLimits = Field(default_factory=ExecutorLimits)
    dependency_policy: DependencyPolicy = Field(default_factory=DependencyPolicy)

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: list[str]) -> list[str]:
        if any(not item or "\0" in item or "\n" in item or "\r" in item for item in value):
            raise ValueError("command entries must be non-empty single-line strings")
        if not value[0].startswith("/") or ".." in value[0].split("/"):
            raise ValueError("command executable must be an absolute image path")
        return value

    @field_validator("working_directory")
    @classmethod
    def validate_working_directory(cls, value: str) -> str:
        if value == ".":
            return value
        return _relative_path(value)

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: dict[str, str]) -> dict[str, str]:
        for name, item in value.items():
            if not _ENVIRONMENT_NAME.fullmatch(name) or _FORBIDDEN_ENVIRONMENT.search(name):
                raise ValueError("environment name is forbidden")
            if "\0" in item or _SECRET_VALUE.search(item):
                raise ValueError("environment value contains credential-like content")
        return dict(sorted(value.items()))

    @field_validator("expected_artifacts")
    @classmethod
    def validate_artifacts(cls, value: list[str]) -> list[str]:
        normalized = [_relative_path(item) for item in value]
        if len(normalized) != len(set(normalized)):
            raise ValueError("expected artifacts must be unique")
        return sorted(normalized)

    @model_validator(mode="after")
    def validate_combined_budgets(self) -> ExecutorManifest:
        if self.limits.artifact_bytes > self.limits.scratch_bytes:
            raise ValueError("artifact byte limit cannot exceed scratch byte limit")
        return self


def _relative_path(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or value.startswith("/")
        or "\\" in value
        or "\0" in value
        or "\n" in value
        or "\r" in value
    ):
        raise ValueError("path must be normalized and relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path must be normalized and relative")
    return value


def manifest_digest(manifest: ExecutorManifest) -> str:
    encoded = json.dumps(
        manifest.model_dump(mode="json"), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def dependency_manifest_digest(manifest: DependencyAcquisitionManifest) -> str:
    encoded = json.dumps(
        manifest.model_dump(mode="json"), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class ExecutorError(Closed):
    code: str = Field(min_length=1, max_length=128)
    category: Literal["input", "unsupported", "policy", "executor", "cancel", "internal"]
    retryable: bool
    safe_message: str = Field(min_length=1, max_length=1_000)
    next_action: str = Field(min_length=1, max_length=1_000)


class ExecutorControls(Closed):
    non_root: bool
    root_read_only: bool
    source_read_only: bool
    private_scratch: bool
    empty_environment: bool
    network_none: bool
    no_new_privileges: bool
    capabilities_dropped: bool
    seccomp_builtin: bool
    no_host_sockets: bool
    private_cgroup_namespace: bool
    cpu_limit: bool
    memory_limit: bool
    pid_limit: bool
    file_limit: bool
    scratch_limit: bool
    wall_time_limit: bool
    output_limit: bool
    process_tree_cleanup: bool

    def accepted(self) -> bool:
        return all(self.model_dump().values())

    def configuration_verified(self) -> bool:
        values = self.model_dump()
        for dynamic in ("empty_environment", "wall_time_limit", "output_limit", "process_tree_cleanup"):
            values.pop(dynamic)
        return all(values.values())


class ExecutorBackend(Closed):
    kind: Literal["oci_docker"] = "oci_docker"
    context: str
    client_version: str
    server_version: str
    api_version: str
    operating_system: str
    architecture: str
    image_digest: Digest
    runner_digest: Digest
    controls: ExecutorControls


class ExecutorResourceRecord(Closed):
    wall_time_ms: int = Field(ge=0)
    exit_code: int | None
    oom_killed: bool
    output_bytes: int = Field(ge=0)
    artifact_bytes: int = Field(ge=0)


class ExecutorArtifact(Closed):
    path: str
    digest: Digest
    size: int = Field(ge=0)
    content_base64: str

    def content(self) -> bytes:
        value = base64.b64decode(self.content_base64, validate=True)
        if len(value) != self.size or f"sha256:{hashlib.sha256(value).hexdigest()}" != self.digest:
            raise ValueError("artifact content does not match its receipt")
        return value


class ExecutorCleanup(Closed):
    container_removed: bool
    orphan_check_passed: bool


class ExecutorResult(Closed):
    schema_version: Literal["phase1b-1"] = "phase1b-1"
    status: Literal["completed", "failed", "timeout", "cancelled", "unsupported"]
    accepted: bool
    manifest_digest: Digest
    backend: ExecutorBackend | None = None
    resources: ExecutorResourceRecord
    stdout_preview: str
    stderr_preview: str
    stdout_digest: Digest
    stderr_digest: Digest
    artifacts: list[ExecutorArtifact]
    error: ExecutorError | None
    cleanup: ExecutorCleanup


class ExecutorAcceptanceReport(Closed):
    schema_version: Literal["phase1b-acceptance-1"] = "phase1b-acceptance-1"
    accepted: bool
    context: Literal["orbstack"] = "orbstack"
    image_digest: Digest
    runner_digest: Digest
    backend: ExecutorBackend | None
    probes: dict[str, bool]
    profile_digest: Digest
    wall_time_ms: int = Field(ge=0)
    error: ExecutorError | None = None


class DependencyAcquisitionResult(Closed):
    schema_version: Literal["phase1b-1"] = "phase1b-1"
    status: Literal["unsupported"] = "unsupported"
    manifest_digest: Digest
    error: ExecutorError
    network_opened: Literal[False] = False
    process_started: Literal[False] = False
