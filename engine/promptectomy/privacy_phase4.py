from __future__ import annotations

import hashlib
import hmac
import base64
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

import rfc8785
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .contracts_v2 import ContractError, parse_json_strict


class PrivacyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class KeyStoreUnavailable(RuntimeError):
    pass


class WrappingKeyStore(Protocol):
    def current_key(self, installation_id: str) -> tuple[str, bytes]: ...

    def load_key(self, installation_id: str, key_id: str) -> bytes: ...


@dataclass(frozen=True)
class SourceSlice:
    relative_path: str
    start_line: int
    end_line: int
    content: bytes


@dataclass(frozen=True)
class MinimizedSlice:
    relative_path: str
    start_line: int
    end_line: int
    byte_count: int
    content_digest: str


@dataclass(frozen=True)
class EgressAuthority:
    authority_id: str
    run_id: str
    action_id: str
    snapshot_digest: str
    selected_roots_digest: str
    destination: str
    endpoint_class: str
    transport: Literal["https"]
    endpoint_path: str
    region: str
    purpose: str
    model: str
    prompt_bundle_digest: str
    adapter_version: str
    policy_digest: str
    expires_at_unix: int
    maximum_files: int
    maximum_bytes: int
    maximum_requests: int
    maximum_tokens: int
    maximum_cost_microusd: int
    local_retention_days: int
    external_retention_days: int
    reusable: bool = False


@dataclass(frozen=True)
class EgressPreview:
    manifest_digest: str
    destination: str
    purpose: str
    slices: tuple[MinimizedSlice, ...]
    total_bytes: int
    secret_scan_version: str
    content_classes: tuple[str, ...]


@dataclass(frozen=True)
class CaptureDecision:
    mode: Literal["metadata_only", "session_only", "persistent_protected"]
    retention_days: int
    encrypted_persistence_required: bool


@dataclass(frozen=True)
class RetentionPolicy:
    safe_metadata_days: int = 30
    pinned_source_days: int = 7
    protected_content_days: int = 0
    diagnostics_days: int = 7


@dataclass(frozen=True)
class DeletionInventory:
    artifact_ids: tuple[str, ...]
    shared_references: tuple[str, ...]
    pinned_references: tuple[str, ...]
    external_copy_labels: tuple[str, ...]


@dataclass(frozen=True)
class DeletionPlan:
    deletable_artifact_ids: tuple[str, ...]
    blocked_artifact_ids: tuple[str, ...]
    external_copy_labels: tuple[str, ...]


@dataclass(frozen=True)
class DeletionReceipt:
    version: Literal["phase4-deletion-receipt-1"]
    deleted_artifact_ids: tuple[str, ...]
    blocked_artifact_ids: tuple[str, ...]
    external_copy_labels: tuple[str, ...]
    residual_artifact_ids: tuple[str, ...]
    completed_at_unix: int
    receipt_digest: str


@dataclass(frozen=True)
class ProtectedEnvelope:
    version: Literal["phase4-protected-envelope-1"]
    algorithm: Literal["AES-256-GCM"]
    artifact_id: str
    data_class: Literal["D2_protected_evidence"]
    installation_id: str
    wrapping_key_id: str
    content_nonce: bytes
    wrapping_nonce: bytes
    wrapped_data_key: bytes
    ciphertext: bytes


SECRET_SCAN_VERSION = "phase4-secret-scan-1"
_MAX_SLICE_BYTES = 256 * 1024
_MAX_PATH_BYTES = 1_024
_SECRET_PATTERNS = (
    re.compile(rb"(?i)authorization\s*[:=]\s*bearer\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(rb"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[a-z0-9._~+/=-]{12,}"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(rb"\bgh[opsu]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_OPAQUE_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}_[0-9a-f]{64}$")
_ENDPOINT_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,511}$")
_APPROVED_EGRESS_DESTINATIONS = {"api.openai.com"}


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _valid_path(value: str) -> bool:
    if not value or value.startswith(('/', '\\')) or "\\" in value or "\0" in value:
        return False
    if len(value.encode()) > _MAX_PATH_BYTES:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} and not any(ord(character) < 32 for character in part) for part in parts)


def scan_secret(content: bytes, *, canaries: tuple[bytes, ...] = ()) -> tuple[str, ...]:
    findings = [f"pattern_{index}" for index, pattern in enumerate(_SECRET_PATTERNS, start=1) if pattern.search(content)]
    for index, canary in enumerate(canaries, start=1):
        if not canary:
            raise PrivacyError("invalid_canary", "Privacy canaries must be non-empty bytes")
        if canary in content:
            findings.append(f"canary_{index}")
    return tuple(findings)


def _validate_authority(authority: EgressAuthority) -> None:
    if not all(_OPAQUE_ID.fullmatch(value) for value in (authority.authority_id, authority.run_id, authority.action_id)):
        raise PrivacyError("invalid_egress_authority", "Egress authority identities are invalid")
    if not all(
        _DIGEST.fullmatch(value)
        for value in (
            authority.snapshot_digest,
            authority.selected_roots_digest,
            authority.prompt_bundle_digest,
            authority.policy_digest,
        )
    ):
        raise PrivacyError("invalid_egress_authority", "Egress authority digest binding is invalid")
    if (
        not _HOST.fullmatch(authority.destination)
        or ".." in authority.destination
        or authority.destination.lower() != authority.destination
        or authority.destination not in _APPROVED_EGRESS_DESTINATIONS
    ):
        raise PrivacyError("invalid_egress_authority", "Egress destination must be one explicit host")
    if not _TOKEN.fullmatch(authority.endpoint_class) or not _TOKEN.fullmatch(authority.purpose):
        raise PrivacyError("invalid_egress_authority", "Egress endpoint class or purpose is invalid")
    if authority.transport != "https" or not _ENDPOINT_PATH.fullmatch(authority.endpoint_path):
        raise PrivacyError("invalid_egress_authority", "Egress transport or endpoint path is invalid")
    if not _TOKEN.fullmatch(authority.region) or not _TOKEN.fullmatch(authority.adapter_version):
        raise PrivacyError("invalid_egress_authority", "Egress region or adapter version is invalid")
    if not authority.model or len(authority.model) > 256 or any(ord(character) < 32 for character in authority.model):
        raise PrivacyError("invalid_egress_authority", "Egress model identity is invalid")
    if authority.expires_at_unix <= int(time.time()):
        raise PrivacyError("egress_authority_expired", "Egress authority has expired")
    if (
        authority.maximum_files <= 0
        or authority.maximum_cost_microusd < 0
        or authority.local_retention_days < 0
        or authority.external_retention_days < 0
    ):
        raise PrivacyError("invalid_egress_authority", "Egress count, cost, or retention budget is invalid")


def build_egress_preview(
    slices: tuple[SourceSlice, ...],
    authority: EgressAuthority,
    *,
    local_only: bool,
    canaries: tuple[bytes, ...] = (),
) -> EgressPreview:
    _validate_authority(authority)
    if local_only:
        raise PrivacyError("local_only_model_stage_unavailable", "Local-only mode prohibits external model egress")
    if not slices:
        raise PrivacyError("empty_egress_manifest", "An egress manifest requires at least one source slice")
    if len(slices) > authority.maximum_files:
        raise PrivacyError("egress_budget_exceeded", "Source slice count exceeds the approved egress budget")
    if any(value <= 0 for value in (authority.maximum_bytes, authority.maximum_requests, authority.maximum_tokens)):
        raise PrivacyError("invalid_egress_authority", "Egress byte, request, and token budgets must be positive")
    minimized: list[MinimizedSlice] = []
    seen: set[tuple[str, int, int]] = set()
    total = 0
    for source in slices:
        if not _valid_path(source.relative_path):
            raise PrivacyError("invalid_source_path", "Egress source path is not repository-relative")
        if source.start_line < 1 or source.end_line < source.start_line:
            raise PrivacyError("invalid_source_range", "Egress source range is invalid")
        if len(source.content) > _MAX_SLICE_BYTES:
            raise PrivacyError("source_slice_too_large", "One source slice exceeds the minimization bound")
        identity = (source.relative_path, source.start_line, source.end_line)
        if identity in seen:
            raise PrivacyError("duplicate_source_slice", "Egress manifest contains a duplicate source range")
        seen.add(identity)
        findings = scan_secret(source.content, canaries=canaries)
        if findings:
            raise PrivacyError("policy_denied_content", "Secret or protected canary detected before egress")
        total += len(source.content)
        minimized.append(
            MinimizedSlice(
                relative_path=source.relative_path,
                start_line=source.start_line,
                end_line=source.end_line,
                byte_count=len(source.content),
                content_digest=_sha256(source.content),
            )
        )
    if total > authority.maximum_bytes:
        raise PrivacyError("egress_budget_exceeded", "Source bytes exceed the approved egress budget")
    manifest = {
        "authority_id": authority.authority_id,
        "run_id": authority.run_id,
        "action_id": authority.action_id,
        "snapshot_digest": authority.snapshot_digest,
        "selected_roots_digest": authority.selected_roots_digest,
        "destination": authority.destination,
        "endpoint_class": authority.endpoint_class,
        "transport": authority.transport,
        "endpoint_path": authority.endpoint_path,
        "region": authority.region,
        "purpose": authority.purpose,
        "model": authority.model,
        "prompt_bundle_digest": authority.prompt_bundle_digest,
        "adapter_version": authority.adapter_version,
        "policy_digest": authority.policy_digest,
        "expires_at_unix": authority.expires_at_unix,
        "budgets": {
            "files": authority.maximum_files,
            "bytes": authority.maximum_bytes,
            "requests": authority.maximum_requests,
            "tokens": authority.maximum_tokens,
            "cost_microusd": authority.maximum_cost_microusd,
        },
        "local_retention_days": authority.local_retention_days,
        "external_retention_days": authority.external_retention_days,
        "reusable": authority.reusable,
        "slices": [item.__dict__ for item in minimized],
        "secret_scan_version": SECRET_SCAN_VERSION,
        "content_classes": ["D1_source_confidential"],
    }
    return EgressPreview(
        manifest_digest=_sha256(rfc8785.dumps(manifest)),
        destination=authority.destination,
        purpose=authority.purpose,
        slices=tuple(minimized),
        total_bytes=total,
        secret_scan_version=SECRET_SCAN_VERSION,
        content_classes=("D1_source_confidential",),
    )


def authorize_capture(
    *,
    protected_content_requested: bool,
    persistent: bool,
    key_store_available: bool,
    explicit_session_grant: bool,
    retention_days: int,
) -> CaptureDecision:
    if retention_days < 0:
        raise PrivacyError("invalid_retention", "Retention cannot be negative")
    if not protected_content_requested:
        if retention_days > 30:
            raise PrivacyError("invalid_retention", "Safe metadata retention exceeds the stable default ceiling")
        return CaptureDecision("metadata_only", retention_days, False)
    if persistent:
        if not key_store_available:
            raise PrivacyError("secure_store_unavailable", "Persistent protected capture requires a supported key store")
        if retention_days <= 0:
            raise PrivacyError("invalid_retention", "Persistent protected capture requires an explicit retention period")
        return CaptureDecision("persistent_protected", retention_days, True)
    if not explicit_session_grant or retention_days != 0:
        raise PrivacyError("protected_capture_not_authorized", "Session-only protected capture requires an exact grant and zero persistence")
    return CaptureDecision("session_only", 0, False)


def _envelope_metadata(
    *,
    artifact_id: str,
    installation_id: str,
    wrapping_key_id: str,
) -> bytes:
    if not _DIGEST.fullmatch(artifact_id):
        raise PrivacyError("protected_envelope_invalid", "Protected artifact identity is invalid")
    if not installation_id or len(installation_id) > 128 or not wrapping_key_id or len(wrapping_key_id) > 128:
        raise PrivacyError("protected_envelope_invalid", "Protected installation or key identity is invalid")
    return rfc8785.dumps(
        {
            "version": "phase4-protected-envelope-1",
            "algorithm": "AES-256-GCM",
            "artifact_id": artifact_id,
            "data_class": "D2_protected_evidence",
            "installation_id": installation_id,
            "wrapping_key_id": wrapping_key_id,
        }
    )


def _wrapping_key(store: WrappingKeyStore, installation_id: str, key_id: str | None = None) -> tuple[str, bytes]:
    try:
        if key_id is None:
            resolved_id, key = store.current_key(installation_id)
        else:
            resolved_id, key = key_id, store.load_key(installation_id, key_id)
    except KeyStoreUnavailable as exc:
        raise PrivacyError("secure_store_unavailable", "Protected capture key store is unavailable") from exc
    if len(key) != 32:
        raise PrivacyError("secure_store_invalid", "Protected capture key store returned an invalid key")
    return resolved_id, key


def encrypt_protected(
    plaintext: bytes,
    *,
    artifact_id: str,
    installation_id: str,
    key_store: WrappingKeyStore,
) -> ProtectedEnvelope:
    key_id, wrapping_key = _wrapping_key(key_store, installation_id)
    metadata = _envelope_metadata(
        artifact_id=artifact_id,
        installation_id=installation_id,
        wrapping_key_id=key_id,
    )
    data_key = AESGCM.generate_key(bit_length=256)
    content_nonce = secrets.token_bytes(12)
    wrapping_nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(data_key).encrypt(content_nonce, plaintext, metadata)
    wrapped_data_key = AESGCM(wrapping_key).encrypt(wrapping_nonce, data_key, metadata + b"\0wrapped_data_key")
    return ProtectedEnvelope(
        version="phase4-protected-envelope-1",
        algorithm="AES-256-GCM",
        artifact_id=artifact_id,
        data_class="D2_protected_evidence",
        installation_id=installation_id,
        wrapping_key_id=key_id,
        content_nonce=content_nonce,
        wrapping_nonce=wrapping_nonce,
        wrapped_data_key=wrapped_data_key,
        ciphertext=ciphertext,
    )


def decrypt_protected(envelope: ProtectedEnvelope, *, key_store: WrappingKeyStore) -> bytes:
    if envelope.version != "phase4-protected-envelope-1" or envelope.algorithm != "AES-256-GCM":
        raise PrivacyError("protected_envelope_invalid", "Protected envelope version or algorithm is unsupported")
    if len(envelope.content_nonce) != 12 or len(envelope.wrapping_nonce) != 12:
        raise PrivacyError("protected_envelope_invalid", "Protected envelope nonce is invalid")
    metadata = _envelope_metadata(
        artifact_id=envelope.artifact_id,
        installation_id=envelope.installation_id,
        wrapping_key_id=envelope.wrapping_key_id,
    )
    _, wrapping_key = _wrapping_key(key_store, envelope.installation_id, envelope.wrapping_key_id)
    try:
        data_key = AESGCM(wrapping_key).decrypt(
            envelope.wrapping_nonce,
            envelope.wrapped_data_key,
            metadata + b"\0wrapped_data_key",
        )
        return AESGCM(data_key).decrypt(envelope.content_nonce, envelope.ciphertext, metadata)
    except InvalidTag as exc:
        raise PrivacyError("protected_envelope_authentication_failed", "Protected envelope failed authentication") from exc


def rotate_protected(envelope: ProtectedEnvelope, *, key_store: WrappingKeyStore) -> ProtectedEnvelope:
    plaintext = decrypt_protected(envelope, key_store=key_store)
    return encrypt_protected(
        plaintext,
        artifact_id=envelope.artifact_id,
        installation_id=envelope.installation_id,
        key_store=key_store,
    )


def encode_protected_envelope(envelope: ProtectedEnvelope) -> bytes:
    document = {
        "version": envelope.version,
        "algorithm": envelope.algorithm,
        "artifact_id": envelope.artifact_id,
        "data_class": envelope.data_class,
        "installation_id": envelope.installation_id,
        "wrapping_key_id": envelope.wrapping_key_id,
        "content_nonce": base64.b64encode(envelope.content_nonce).decode("ascii"),
        "wrapping_nonce": base64.b64encode(envelope.wrapping_nonce).decode("ascii"),
        "wrapped_data_key": base64.b64encode(envelope.wrapped_data_key).decode("ascii"),
        "ciphertext": base64.b64encode(envelope.ciphertext).decode("ascii"),
    }
    return rfc8785.dumps(document)


def decode_protected_envelope(encoded: bytes) -> ProtectedEnvelope:
    if len(encoded) > 96 * 1024 * 1024:
        raise PrivacyError("protected_envelope_invalid", "Protected envelope exceeds its byte bound")
    try:
        document = parse_json_strict(encoded)
    except ContractError as exc:
        raise PrivacyError("protected_envelope_invalid", "Protected envelope is not strict JSON") from exc
    expected = {
        "version",
        "algorithm",
        "artifact_id",
        "data_class",
        "installation_id",
        "wrapping_key_id",
        "content_nonce",
        "wrapping_nonce",
        "wrapped_data_key",
        "ciphertext",
    }
    if not isinstance(document, dict) or set(document) != expected or any(
        not isinstance(document[field], str) for field in expected
    ):
        raise PrivacyError("protected_envelope_invalid", "Protected envelope fields are invalid")
    try:
        content_nonce = base64.b64decode(document["content_nonce"], validate=True)
        wrapping_nonce = base64.b64decode(document["wrapping_nonce"], validate=True)
        wrapped_data_key = base64.b64decode(document["wrapped_data_key"], validate=True)
        ciphertext = base64.b64decode(document["ciphertext"], validate=True)
    except ValueError as exc:
        raise PrivacyError("protected_envelope_invalid", "Protected envelope binary field is invalid") from exc
    if len(ciphertext) > 64 * 1024 * 1024 + 16 or len(wrapped_data_key) != 48:
        raise PrivacyError("protected_envelope_invalid", "Protected envelope ciphertext size is invalid")
    if document["version"] != "phase4-protected-envelope-1" or document["algorithm"] != "AES-256-GCM":
        raise PrivacyError("protected_envelope_invalid", "Protected envelope version or algorithm is unsupported")
    if document["data_class"] != "D2_protected_evidence":
        raise PrivacyError("protected_envelope_invalid", "Protected envelope data class is invalid")
    return ProtectedEnvelope(
        version="phase4-protected-envelope-1",
        algorithm="AES-256-GCM",
        artifact_id=document["artifact_id"],
        data_class="D2_protected_evidence",
        installation_id=document["installation_id"],
        wrapping_key_id=document["wrapping_key_id"],
        content_nonce=content_nonce,
        wrapping_nonce=wrapping_nonce,
        wrapped_data_key=wrapped_data_key,
        ciphertext=ciphertext,
    )


def restrict_retention(previous: RetentionPolicy, requested: RetentionPolicy) -> RetentionPolicy:
    fields = (
        "safe_metadata_days",
        "pinned_source_days",
        "protected_content_days",
        "diagnostics_days",
    )
    for field in fields:
        before = getattr(previous, field)
        after = getattr(requested, field)
        if after < 0:
            raise PrivacyError("invalid_retention", "Retention cannot be negative")
        if after > before:
            raise PrivacyError("retention_expansion_requires_authority", "Retention cannot expand under an existing policy")
    return requested


def plan_deletion(inventory: DeletionInventory) -> DeletionPlan:
    identities = inventory.artifact_ids + inventory.shared_references + inventory.pinned_references
    if any(not _DIGEST.fullmatch(item) for item in identities):
        raise PrivacyError("invalid_deletion_inventory", "Deletion inventory contains an invalid artifact identity")
    if len(set(inventory.artifact_ids)) != len(inventory.artifact_ids):
        raise PrivacyError("invalid_deletion_inventory", "Deletion inventory contains duplicate artifacts")
    if any(not _TOKEN.fullmatch(item) for item in inventory.external_copy_labels):
        raise PrivacyError("invalid_deletion_inventory", "Deletion inventory contains an invalid external copy label")
    shared = set(inventory.shared_references)
    pinned = set(inventory.pinned_references)
    blocked = tuple(sorted(item for item in inventory.artifact_ids if item in shared or item in pinned))
    deletable = tuple(sorted(item for item in inventory.artifact_ids if item not in shared and item not in pinned))
    return DeletionPlan(deletable, blocked, tuple(sorted(inventory.external_copy_labels)))


def execute_deletion(
    root: Path,
    inventory: DeletionInventory,
    *,
    completed_at_unix: int,
) -> DeletionReceipt:
    plan = plan_deletion(inventory)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise PrivacyError("invalid_deletion_root", "Deletion root must be an existing absolute tool-owned directory")
    if completed_at_unix < 0:
        raise PrivacyError("invalid_deletion_time", "Deletion completion time is invalid")
    artifacts_root = root / "artifacts"
    receipts_root = root / "deletion-receipts"
    if artifacts_root.is_symlink() or (artifacts_root.exists() and not artifacts_root.is_dir()):
        raise PrivacyError("invalid_deletion_root", "Artifact storage root is invalid")
    artifacts_root.mkdir(mode=0o700, exist_ok=True)
    receipts_root.mkdir(mode=0o700, exist_ok=True)
    if receipts_root.is_symlink():
        raise PrivacyError("invalid_deletion_root", "Deletion receipt root is invalid")

    for artifact_id in plan.deletable_artifact_ids:
        path = artifacts_root / f"{artifact_id.removeprefix('sha256:')}.blob"
        try:
            stat = path.lstat()
        except FileNotFoundError:
            continue
        if path.is_symlink() or not path.is_file() or stat.st_nlink != 1:
            raise PrivacyError("deletion_artifact_unsafe", "Deletion artifact storage entry is unsafe")
        if _sha256(path.read_bytes()) != artifact_id:
            raise PrivacyError("deletion_artifact_tampered", "Deletion artifact content does not match its identity")
        path.unlink()
    directory = os.open(artifacts_root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

    residual = tuple(
        sorted(
            artifact_id
            for artifact_id in inventory.artifact_ids
            if (artifacts_root / f"{artifact_id.removeprefix('sha256:')}.blob").exists()
        )
    )
    document = {
        "version": "phase4-deletion-receipt-1",
        "deleted_artifact_ids": list(plan.deletable_artifact_ids),
        "blocked_artifact_ids": list(plan.blocked_artifact_ids),
        "external_copy_labels": list(plan.external_copy_labels),
        "residual_artifact_ids": list(residual),
        "completed_at_unix": completed_at_unix,
    }
    digest = _sha256(rfc8785.dumps(document))
    encoded = rfc8785.dumps({**document, "receipt_digest": digest})
    with tempfile.NamedTemporaryFile(dir=receipts_root, prefix=".pending-", delete=False) as pending:
        pending_path = Path(pending.name)
        pending.write(encoded)
        pending.flush()
        os.fsync(pending.fileno())
    final_path = receipts_root / f"{digest.removeprefix('sha256:')}.json"
    try:
        os.replace(pending_path, final_path)
        directory = os.open(receipts_root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if pending_path.exists():
            pending_path.unlink()
    return DeletionReceipt(
        version="phase4-deletion-receipt-1",
        deleted_artifact_ids=plan.deletable_artifact_ids,
        blocked_artifact_ids=plan.blocked_artifact_ids,
        external_copy_labels=plan.external_copy_labels,
        residual_artifact_ids=residual,
        completed_at_unix=completed_at_unix,
        receipt_digest=digest,
    )


def preview_matches_authority(preview: EgressPreview, approved_digest: str) -> bool:
    return hmac.compare_digest(preview.manifest_digest, approved_digest)
