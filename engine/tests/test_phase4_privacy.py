from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from promptectomy.privacy_phase4 import (
    CaptureDecision,
    DeletionInventory,
    EgressAuthority,
    PrivacyError,
    KeyStoreUnavailable,
    RetentionPolicy,
    SourceSlice,
    authorize_capture,
    build_egress_preview,
    decode_protected_envelope,
    decrypt_protected,
    encode_protected_envelope,
    encrypt_protected,
    execute_deletion,
    plan_deletion,
    preview_matches_authority,
    restrict_retention,
    rotate_protected,
    scan_secret,
)


class _KeyStore:
    def __init__(self) -> None:
        self.current = "key-1"
        self.keys = {"key-1": b"1" * 32}
        self.available = True

    def current_key(self, installation_id: str) -> tuple[str, bytes]:
        if not self.available or installation_id != "install-1":
            raise KeyStoreUnavailable
        return self.current, self.keys[self.current]

    def load_key(self, installation_id: str, key_id: str) -> bytes:
        if not self.available or installation_id != "install-1" or key_id not in self.keys:
            raise KeyStoreUnavailable
        return self.keys[key_id]


def _authority() -> EgressAuthority:
    return EgressAuthority(
        authority_id="authority_" + "1" * 64,
        run_id="run_" + "2" * 64,
        action_id="action_" + "3" * 64,
        snapshot_digest="sha256:" + "4" * 64,
        selected_roots_digest="sha256:" + "5" * 64,
        exclusions_digest="sha256:" + "7" * 64,
        revision="0123456789abcdef0123456789abcdef01234567",
        mode="audit",
        stage="source_classification",
        destination="api.openai.com",
        destination_organization="openai",
        destination_service="responses_api",
        data_policy_url="https://openai.com/policies/privacy-policy/",
        endpoint_class="openai_responses",
        transport="https",
        endpoint_path="/v1/responses",
        region="global",
        purpose="classify_supported_callsite",
        model="gpt-5.1-codex",
        prompt_bundle_digest="sha256:" + "a" * 64,
        adapter_version="responses_v1",
        agent_runtime="trusted_connector",
        minimization_version="source_slices_v1",
        redaction_version="secret_scan_v1",
        policy_digest="sha256:" + "6" * 64,
        expires_at_unix=4_000_000_000,
        maximum_files=2,
        maximum_bytes=1_000,
        maximum_requests=1,
        maximum_tokens=2_000,
        maximum_cost_microusd=50_000,
        maximum_duration_seconds=120,
        local_retention_days=0,
        external_retention_days=30,
        destination_deletion_supported=False,
        cancellation_behavior="stop_before_next_request",
        revocation_behavior="stop_before_next_request",
        cleanup_behavior="delete_unpinned_source_after_run",
    )


def test_egress_preview_is_exact_content_free_and_digest_bound() -> None:
    content = b"client.responses.create(model=model, input=user_input)"
    preview = build_egress_preview(
        (SourceSlice("src/client.py", 10, 10, content),),
        _authority(),
        local_only=False,
    )
    assert preview.total_bytes == len(content)
    assert preview.slices[0].content_digest.startswith("sha256:")
    assert not hasattr(preview.slices[0], "content")
    assert preview.destination_organization == "openai"
    assert preview.destination_service == "responses_api"
    assert preview.sample_preview.endswith("content omitted")
    assert "cannot delete" in preview.external_copy_warning
    assert preview_matches_authority(preview, preview.manifest_digest)
    assert not preview_matches_authority(preview, "sha256:" + "0" * 64)


@pytest.mark.parametrize(
    "content",
    [
        b"Authorization: Bearer abcdefghijklmnop",
        b"api_key = 'abcdefghijklmnop'",
        b"sk-abcdefghijklmnopqrstuv",
        b"ghp_abcdefghijklmnopqrstuvwxyz",
        b"-----BEGIN PRIVATE KEY-----",
    ],
)
def test_secret_patterns_are_denied_before_egress(content: bytes) -> None:
    assert scan_secret(content)
    with pytest.raises(PrivacyError) as caught:
        build_egress_preview(
            (SourceSlice("src/client.py", 1, 1, content),),
            _authority(),
            local_only=False,
        )
    assert caught.value.code == "policy_denied_content"
    assert content.decode(errors="replace") not in str(caught.value)


def test_unique_privacy_canary_never_reaches_preview_or_error() -> None:
    canary = b"PHASE4_UNIQUE_PROTECTED_CANARY"
    with pytest.raises(PrivacyError) as caught:
        build_egress_preview(
            (SourceSlice("src/client.py", 1, 1, b"safe prefix " + canary),),
            _authority(),
            local_only=False,
            canaries=(canary,),
        )
    assert caught.value.code == "policy_denied_content"
    assert canary.decode() not in str(caught.value)


@pytest.mark.parametrize(
    ("slices", "authority", "local_only", "code"),
    [
        ((SourceSlice("../escape.py", 1, 1, b"x"),), _authority(), False, "invalid_source_path"),
        ((SourceSlice("src/a.py", 0, 1, b"x"),), _authority(), False, "invalid_source_range"),
        ((SourceSlice("src/a.py", 1, 1, b"x"),), _authority(), True, "local_only_model_stage_unavailable"),
        (
            (SourceSlice("src/a.py", 1, 1, b"1234"),),
            replace(_authority(), maximum_bytes=3),
            False,
            "egress_budget_exceeded",
        ),
    ],
)
def test_egress_path_budget_and_local_only_fail_closed(
    slices: tuple[SourceSlice, ...],
    authority: EgressAuthority,
    local_only: bool,
    code: str,
) -> None:
    with pytest.raises(PrivacyError) as caught:
        build_egress_preview(slices, authority, local_only=local_only)
    assert caught.value.code == code


def test_egress_authority_rejects_url_credentials_queries_and_unbound_prompt() -> None:
    for authority in (
        replace(_authority(), destination="https://api.openai.com"),
        replace(_authority(), destination="user@example.com"),
        replace(_authority(), destination="api.openai.com?token=canary"),
        replace(_authority(), destination="localhost"),
        replace(_authority(), destination="127.0.0.1"),
        replace(_authority(), destination="attacker.example"),
        replace(_authority(), destination="API.OPENAI.COM"),
        replace(_authority(), prompt_bundle_digest="latest"),
    ):
        with pytest.raises(PrivacyError) as caught:
            build_egress_preview(
                (SourceSlice("src/a.py", 1, 1, b"safe"),),
                authority,
                local_only=False,
            )
        assert caught.value.code == "invalid_egress_authority"


def test_egress_preview_binds_context_and_rejects_ambiguous_external_controls() -> None:
    slices = (SourceSlice("src/a.py", 1, 1, b"safe"),)
    baseline = build_egress_preview(slices, _authority(), local_only=False).manifest_digest
    variants = (
        replace(_authority(), revision="fedcba9876543210fedcba9876543210fedcba98"),
        replace(_authority(), mode="draft"),
        replace(_authority(), stage="candidate_synthesis"),
        replace(_authority(), destination_organization="openai_platform"),
        replace(_authority(), destination_service="responses_api_v2"),
        replace(_authority(), data_policy_url="https://openai.com/policies/usage-policies/"),
        replace(_authority(), agent_runtime="codex_sdk"),
        replace(_authority(), minimization_version="source_slices_v2"),
        replace(_authority(), redaction_version="secret_scan_v2"),
        replace(_authority(), maximum_duration_seconds=60),
        replace(_authority(), cancellation_behavior="cancel_active_request"),
        replace(_authority(), revocation_behavior="deny_active_request"),
        replace(_authority(), cleanup_behavior="delete_all_unpinned_after_run"),
    )
    assert all(
        build_egress_preview(slices, authority, local_only=False).manifest_digest != baseline
        for authority in variants
    )

    invalid = (
        replace(_authority(), revision="main\nother"),
        replace(_authority(), data_policy_url="https://openai.com/privacy?token=secret"),
        replace(_authority(), destination_deletion_supported=True),
        replace(_authority(), maximum_duration_seconds=0),
    )
    for authority in invalid:
        with pytest.raises(PrivacyError) as caught:
            build_egress_preview(slices, authority, local_only=False)
        assert caught.value.code == "invalid_egress_authority"


def test_protected_capture_requires_exact_grant_and_secure_store() -> None:
    assert authorize_capture(
        protected_content_requested=False,
        persistent=False,
        key_store_available=False,
        explicit_session_grant=False,
        retention_days=30,
    ) == CaptureDecision("metadata_only", 30, False)
    with pytest.raises(PrivacyError) as caught:
        authorize_capture(
            protected_content_requested=True,
            persistent=True,
            key_store_available=False,
            explicit_session_grant=True,
            retention_days=1,
        )
    assert caught.value.code == "secure_store_unavailable"
    assert authorize_capture(
        protected_content_requested=True,
        persistent=False,
        key_store_available=False,
        explicit_session_grant=True,
        retention_days=0,
    ) == CaptureDecision("session_only", 0, False)


def test_retention_can_shrink_but_cannot_expand_without_new_authority() -> None:
    current = RetentionPolicy()
    shorter = RetentionPolicy(7, 1, 0, 1)
    assert restrict_retention(current, shorter) == shorter
    with pytest.raises(PrivacyError) as caught:
        restrict_retention(shorter, current)
    assert caught.value.code == "retention_expansion_requires_authority"


def test_deletion_inventory_reports_shared_pinned_and_external_copies() -> None:
    a = "sha256:" + "a" * 64
    b = "sha256:" + "b" * 64
    c = "sha256:" + "c" * 64
    plan = plan_deletion(
        DeletionInventory(
            artifact_ids=(a, b, c),
            shared_references=(b,),
            pinned_references=(c,),
            external_copy_labels=("provider_retention", "backup_1"),
        )
    )
    assert plan.deletable_artifact_ids == (a,)
    assert plan.blocked_artifact_ids == (b, c)
    assert plan.external_copy_labels == ("backup_1", "provider_retention")


def test_deletion_executes_in_tool_storage_and_writes_content_bound_receipt(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    deletable = b"delete me"
    blocked = b"keep me"
    deletable_id = "sha256:" + hashlib.sha256(deletable).hexdigest()
    blocked_id = "sha256:" + hashlib.sha256(blocked).hexdigest()
    (artifacts / f"{deletable_id.removeprefix('sha256:')}.blob").write_bytes(deletable)
    (artifacts / f"{blocked_id.removeprefix('sha256:')}.blob").write_bytes(blocked)
    receipt = execute_deletion(
        tmp_path,
        DeletionInventory(
            artifact_ids=(deletable_id, blocked_id),
            shared_references=(blocked_id,),
            pinned_references=(),
            external_copy_labels=("provider_retention",),
        ),
        completed_at_unix=1_000,
    )
    assert receipt.deleted_artifact_ids == (deletable_id,)
    assert receipt.residual_artifact_ids == (blocked_id,)
    assert not (artifacts / f"{deletable_id.removeprefix('sha256:')}.blob").exists()
    assert (artifacts / f"{blocked_id.removeprefix('sha256:')}.blob").read_bytes() == blocked
    receipts = list((tmp_path / "deletion-receipts").glob("*.json"))
    assert len(receipts) == 1
    assert receipts[0].read_bytes().startswith(b'{"blocked_artifact_ids"')


def test_protected_envelope_encrypts_binds_metadata_and_rotates_keys() -> None:
    store = _KeyStore()
    plaintext = b"PROTECTED_CANARY_PROMPT_AND_COMPLETION"
    artifact_id = "sha256:" + "a" * 64
    first = encrypt_protected(
        plaintext,
        artifact_id=artifact_id,
        installation_id="install-1",
        key_store=store,
    )
    assert plaintext not in first.ciphertext
    assert plaintext not in first.wrapped_data_key
    assert decrypt_protected(first, key_store=store) == plaintext
    encoded = encode_protected_envelope(first)
    assert plaintext not in encoded
    assert decrypt_protected(decode_protected_envelope(encoded), key_store=store) == plaintext
    store.keys["key-2"] = b"2" * 32
    store.current = "key-2"
    rotated = rotate_protected(first, key_store=store)
    assert rotated.wrapping_key_id == "key-2"
    assert rotated.ciphertext != first.ciphertext
    assert decrypt_protected(rotated, key_store=store) == plaintext


def test_protected_envelope_rejects_tamper_wrong_key_and_missing_store() -> None:
    store = _KeyStore()
    envelope = encrypt_protected(
        b"protected",
        artifact_id="sha256:" + "b" * 64,
        installation_id="install-1",
        key_store=store,
    )
    tampered = replace(envelope, ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]))
    with pytest.raises(PrivacyError) as caught:
        decrypt_protected(tampered, key_store=store)
    assert caught.value.code == "protected_envelope_authentication_failed"
    rebound = replace(envelope, artifact_id="sha256:" + "d" * 64)
    with pytest.raises(PrivacyError) as caught:
        decrypt_protected(rebound, key_store=store)
    assert caught.value.code == "protected_envelope_authentication_failed"
    store.keys["key-1"] = b"3" * 32
    with pytest.raises(PrivacyError) as caught:
        decrypt_protected(envelope, key_store=store)
    assert caught.value.code == "protected_envelope_authentication_failed"
    store.available = False
    with pytest.raises(PrivacyError) as caught:
        decrypt_protected(envelope, key_store=store)
    assert caught.value.code == "secure_store_unavailable"
    with pytest.raises(PrivacyError) as caught:
        encrypt_protected(
            b"protected",
            artifact_id="sha256:" + "b" * 64,
            installation_id="install-1",
            key_store=store,
        )
    assert caught.value.code == "secure_store_unavailable"


def test_protected_envelope_uses_unique_content_and_wrapping_nonces() -> None:
    store = _KeyStore()
    envelopes = [
        encrypt_protected(
            b"same-content",
            artifact_id="sha256:" + "c" * 64,
            installation_id="install-1",
            key_store=store,
        )
        for _ in range(128)
    ]
    assert len({item.content_nonce for item in envelopes}) == 128
    assert len({item.wrapping_nonce for item in envelopes}) == 128
    assert len({item.ciphertext for item in envelopes}) == 128
