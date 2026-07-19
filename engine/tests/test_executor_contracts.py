from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from promptectomy.executor import OciExecutor
from promptectomy.executor_contracts import (
    DependencyAcquisitionManifest,
    ExecutorLimits,
    ExecutorManifest,
    manifest_digest,
)


IMAGE = "sha256:" + "1" * 64
SNAPSHOT = "sha256:" + "2" * 64


def _manifest(**overrides: object) -> ExecutorManifest:
    values: dict[str, object] = {
        "image_digest": IMAGE,
        "snapshot_digest": SNAPSHOT,
        "command": ["/usr/local/bin/python3", "-I", "/workspace/probe.py"],
        "environment": {"PT_ALLOWED": "visible"},
        "expected_artifacts": ["result.json"],
        "limits": ExecutorLimits(),
    }
    values.update(overrides)
    return ExecutorManifest.model_validate(values)


def test_manifest_is_closed_offline_and_digest_pinned() -> None:
    manifest = _manifest()

    assert manifest.network == "none"
    assert manifest.root_read_only is True
    assert manifest.source_read_only is True
    assert manifest.dependency_policy.mode == "prebuilt_image"
    assert manifest.dependency_policy.install_scripts is False
    assert manifest.image_digest == IMAGE
    assert manifest_digest(manifest) == manifest_digest(
        ExecutorManifest.model_validate_json(manifest.model_dump_json())
    )

    with pytest.raises(ValidationError):
        _manifest(image_digest="python:3.12")
    with pytest.raises(ValidationError):
        _manifest(network="bridge")
    with pytest.raises(ValidationError):
        ExecutorManifest.model_validate({**manifest.model_dump(), "unknown": True})


@pytest.mark.parametrize(
    "environment",
    [
        {"OPENAI_API_KEY": "not-a-real-key"},
        {"GH_TOKEN": "not-a-real-token"},
        {"AWS_SECRET_ACCESS_KEY": "not-a-real-secret"},
        {"PT_ALLOWED": "sk-abcdefghijklmnopqrstuvwxyz"},
        {"LD_PRELOAD": "/workspace/attack.so"},
        {"PATH": "/workspace/bin"},
    ],
)
def test_manifest_rejects_credential_and_runtime_control_environment(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ValidationError):
        _manifest(environment=environment)


@pytest.mark.parametrize(
    "artifact",
    ["../escape", "/absolute", "nested/../../escape", "a\\b", "", ".", "x\nname"],
)
def test_manifest_rejects_unsafe_artifact_paths(artifact: str) -> None:
    with pytest.raises(ValidationError):
        _manifest(expected_artifacts=[artifact])


def test_manifest_rejects_duplicate_artifacts_and_unbounded_values() -> None:
    with pytest.raises(ValidationError):
        _manifest(expected_artifacts=["result.json", "result.json"])
    with pytest.raises(ValidationError):
        _manifest(command=["/usr/local/bin/python3", "x" * 4097])
    with pytest.raises(ValidationError):
        _manifest(limits={"memory_bytes": 1})


def test_manifest_serialization_contains_no_ambient_state() -> None:
    encoded = json.loads(_manifest().model_dump_json())

    assert set(encoded) == {
        "schema_version",
        "operation",
        "image_digest",
        "snapshot_digest",
        "command",
        "working_directory",
        "environment",
        "network",
        "root_read_only",
        "source_read_only",
        "expected_artifacts",
        "limits",
        "dependency_policy",
    }
    assert encoded["environment"] == {"PT_ALLOWED": "visible"}


def test_dependency_acquisition_is_separate_and_fails_closed_without_egress_control() -> None:
    acquisition = DependencyAcquisitionManifest(
        image_digest=IMAGE,
        snapshot_digest=SNAPSHOT,
        package_manager="uv",
        lockfile="uv.lock",
        lock_digest="sha256:" + "3" * 64,
        registry_hosts=["pypi.org", "files.pythonhosted.org"],
        max_download_bytes=100_000_000,
        wall_time_seconds=300,
    )

    result = OciExecutor.acquire_dependencies(acquisition)

    assert result.status == "unsupported"
    assert result.error.code == "dependency_network_policy_unavailable"
    assert result.network_opened is False
    assert result.process_started is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"lockfile": "../uv.lock"},
        {"registry_hosts": ["https://pypi.org"]},
        {"registry_hosts": ["pypi.org", "pypi.org"]},
        {"install_scripts": True},
    ],
)
def test_dependency_acquisition_rejects_widened_authority(overrides: dict[str, object]) -> None:
    values: dict[str, object] = {
        "image_digest": IMAGE,
        "snapshot_digest": SNAPSHOT,
        "package_manager": "uv",
        "lockfile": "uv.lock",
        "lock_digest": "sha256:" + "3" * 64,
        "registry_hosts": ["pypi.org"],
        "max_download_bytes": 100_000_000,
        "wall_time_seconds": 300,
    }
    values.update(overrides)

    with pytest.raises(ValidationError):
        DependencyAcquisitionManifest.model_validate(values)
