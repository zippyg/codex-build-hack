from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from promptectomy.cli import app
from promptectomy.connector import ConnectorCancelled, ConnectorFailure, ResponsesConnector
from promptectomy.reference import execute, load_run, render_report


def _write_repo(root: Path, *, python: bool = True, typescript: bool = True) -> None:
    root.mkdir(parents=True)
    if python:
        (root / "app.py").write_text(
            "from openai import OpenAI\nclient = OpenAI()\nresponse = client.responses.create(model='gpt-5', input='hello')\n",
            encoding="utf-8",
        )
    if typescript:
        (root / "worker.ts").write_text(
            "import OpenAI from 'openai';\nconst client = new OpenAI();\nawait client.responses.create({model: 'gpt-5', input: 'hello'});\n",
            encoding="utf-8",
        )


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative)
        if path.is_symlink():
            digest.update(b"symlink")
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(b"file")
            digest.update(path.read_bytes())
        elif path.is_dir():
            digest.update(b"dir")
    return digest.hexdigest()


def _init_dirty_git_repo(root: Path) -> None:
    _write_repo(root, typescript=False)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Fixture"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
    (root / "app.py").write_text((root / "app.py").read_text(encoding="utf-8") + "# unstaged\n", encoding="utf-8")
    (root / "staged.txt").write_text("staged\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "staged.txt"], check=True)
    (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")


def _git_state(root: Path) -> dict[str, str]:
    commands = {
        "index": ["git", "-C", str(root), "diff", "--cached", "--binary"],
        "worktree": ["git", "-C", str(root), "diff", "--binary"],
        "refs": ["git", "-C", str(root), "for-each-ref", "--format=%(refname)%00%(objectname)"],
        "config": ["git", "-C", str(root), "config", "--local", "--null", "--list"],
        "worktrees": ["git", "-C", str(root), "worktree", "list", "--porcelain"],
        "untracked": ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"],
    }
    state = {"tree": _tree_digest(root)}
    for name, command in commands.items():
        state[name] = subprocess.run(command, check=True, capture_output=True).stdout.hex()
    return state


def _policy(source_digest: str, source_file: Path) -> dict[str, object]:
    content = source_file.read_bytes()
    return {
        "schema_version": "1",
        "operation": "draft",
        "approved": True,
        "source_digest": source_digest,
        "destination": "https://api.openai.com/v1/responses",
        "model": "gpt-5.3-codex",
        "reasoning_effort": "medium",
        "max_input_bytes": len(content),
        "max_output_tokens": 1200,
        "timeout_seconds": 30,
        "retention_days": 30,
        "slices": [
            {
                "path": source_file.name,
                "start_line": 1,
                "end_line": len(content.decode().splitlines()),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        ],
    }


@pytest.mark.parametrize("operation", ["inspect", "audit"])
def test_general_static_modes_are_non_mutating_and_do_not_execute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    source = tmp_path / "dirty"
    _init_dirty_git_repo(source)
    before = _tree_digest(source)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("general static mode attempted process execution")

    monkeypatch.setattr(subprocess, "run", forbidden)
    result = execute(operation, source, state_root=tmp_path / "state")

    assert result.status == "completed"
    assert result.mode == operation
    assert result.work.performed >= 2
    assert result.support.callsites == 1
    assert result.support.highest_level == "L1"
    assert _tree_digest(source) == before


def test_inspect_accounts_for_python_typescript_unsupported_and_zero_findings(tmp_path: Path) -> None:
    mixed = tmp_path / "mixed"
    _write_repo(mixed)
    (mixed / "main.go").write_text("package main\n", encoding="utf-8")

    result = execute("inspect", mixed, state_root=tmp_path / "state")

    assert result.status == "completed_with_unsupported"
    assert result.support.callsites == 2
    assert result.support.languages == {"python": 1, "typescript": 1, "go": 1}
    assert [item.code for item in result.unsupported] == ["unsupported_language"]

    empty = tmp_path / "empty"
    empty.mkdir()
    no_findings = execute("audit", empty, state_root=tmp_path / "state")
    assert no_findings.status == "completed_no_findings"
    assert no_findings.work.performed >= 2
    assert no_findings.work.zero_work is False


def test_mixed_provider_sdk_and_dynamic_surfaces_are_not_silently_dropped(tmp_path: Path) -> None:
    source = tmp_path / "mixed-surfaces"
    _write_repo(source, typescript=False)
    (source / "legacy.py").write_text(
        "import anthropic\n"
        "client.chat.completions.create(model='gpt-4', messages=[])\n"
        "openai.ChatCompletion.create(model='gpt-3.5-turbo', messages=[])\n"
        "getattr(client, 'responses').create(model='gpt-5', input='dynamic')\n",
        encoding="utf-8",
    )

    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "completed_with_unsupported"
    assert result.support.callsites == 1
    assert {item.code for item in result.unsupported} == {
        "ambiguous_dynamic_callsite",
        "unsupported_operation",
        "unsupported_provider",
        "unsupported_sdk_version",
    }


def test_typescript_comments_and_strings_do_not_create_false_callsites(tmp_path: Path) -> None:
    source = tmp_path / "typescript-false-positive"
    source.mkdir()
    (source / "fixture.ts").write_text(
        "// client.responses.create({ model: 'fake' })\n"
        "const text = \"client.responses.create({ model: 'fake' })\";\n"
        "/* client.chat.completions.create({ model: 'fake' }) */\n",
        encoding="utf-8",
    )

    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "completed_no_findings"
    assert result.support.callsites == 0
    assert result.unsupported == []


def test_typescript_block_comment_does_not_create_provider_surface(tmp_path: Path) -> None:
    source = tmp_path / "typescript-provider-comment"
    source.mkdir()
    (source / "fixture.ts").write_text("/*\nimport Anthropic from 'anthropic';\n*/\n", encoding="utf-8")

    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "completed_no_findings"
    assert result.unsupported == []


def test_symlink_nested_repository_and_malformed_source_are_typed(tmp_path: Path) -> None:
    source = tmp_path / "hostile"
    _write_repo(source, typescript=False)
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET_OUTSIDE = True\n", encoding="utf-8")
    (source / "escape.py").symlink_to(outside)
    nested = source / "nested"
    nested.mkdir()
    (nested / ".git").write_text("gitdir: ../external-git-dir\n", encoding="utf-8")
    (nested / "evil.py").write_text(
        "from openai import OpenAI\nOpenAI().responses.create(model='gpt-5', input='nested')\n",
        encoding="utf-8",
    )
    (source / "broken.py").write_bytes(b"\xff\xfe")

    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "completed_with_unsupported"
    assert {item.code for item in result.unsupported} == {
        "malformed_source",
        "nested_repository",
        "unsafe_symlink",
    }
    assert "SECRET_OUTSIDE" not in result.model_dump_json()
    assert result.support.callsites == 1


def test_permission_denied_source_fails_without_raw_path_or_mutation(tmp_path: Path) -> None:
    source = tmp_path / "permission-canary"
    _write_repo(source, typescript=False)
    source_file = source / "app.py"
    before = _tree_digest(source)
    source_file.chmod(0)
    try:
        result = execute("inspect", source, state_root=tmp_path / "state")
    finally:
        source_file.chmod(0o600)

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "source_unreadable"
    assert "permission-canary" not in result.model_dump_json()
    assert _tree_digest(source) == before


def test_remote_source_is_explicitly_unsupported_without_locator_leak(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["inspect", "https://example.invalid/private.git", "--json"])

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "remote_source_unsupported"
    assert "example.invalid" not in result.stdout

    credentialed = runner.invoke(app, ["inspect", "https://user:PT_TOKEN_CANARY@example.invalid/private.git", "--json"])
    assert credentialed.exit_code == 2
    assert json.loads(credentialed.stdout)["error"]["code"] == "source_credentials_forbidden"
    assert "PT_TOKEN_CANARY" not in credentialed.stdout


def test_source_digest_rejects_oversized_sparse_file_before_reading_it(tmp_path: Path) -> None:
    source = tmp_path / "oversized"
    source.mkdir()
    oversized = source / "large.bin"
    with oversized.open("wb") as handle:
        handle.seek(100_000_000)
        handle.write(b"x")

    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "source_quota_exceeded"
    assert result.candidate is None


def test_git_object_database_is_excluded_from_source_digest_quota(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    _init_dirty_git_repo(source)
    oversized = source / ".git" / "objects" / "oversized-pack"
    with oversized.open("wb") as handle:
        handle.seek(100_000_000)
        handle.write(b"x")

    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "completed"
    assert result.error is None


def test_forged_git_pointer_fails_before_external_tree_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "forged-worktree"
    _write_repo(source, typescript=False)
    external = tmp_path / "unrelated"
    external.mkdir()
    oversized = external / "oversized-canary"
    with oversized.open("wb") as handle:
        handle.seek(100_000_000)
        handle.write(b"x")
    (source / ".git").write_text(f"gitdir: {external}\n", encoding="utf-8")
    monkeypatch.setenv("PROMPTECTOMY_HOME", str(tmp_path / "state"))

    result = CliRunner().invoke(app, ["inspect", str(source), "--json"])

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "git_metadata_invalid"


@pytest.mark.parametrize("command", [["doctor", "--json"], ["inspect", ".", "--json"]])
def test_invalid_state_root_is_a_typed_json_failure(
    monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    monkeypatch.setenv("PROMPTECTOMY_HOME", "relative-state")

    result = CliRunner().invoke(app, command)

    assert result.exit_code == 9
    assert json.loads(result.stdout)["error"]["code"] == "invalid_state_root"


def test_privacy_canaries_do_not_enter_safe_state_events_or_reports(tmp_path: Path) -> None:
    canary = "PT_PRIVACY_CANARY_93e67c"
    source = tmp_path / canary
    source.mkdir()
    (source / f"{canary}.py").write_text(
        f"# {canary}\nfrom openai import OpenAI\nOpenAI().responses.create(model='gpt-5', input='safe')\n",
        encoding="utf-8",
    )

    result = execute("audit", source, state_root=tmp_path / "state")
    run_dir = tmp_path / "state" / "runs" / result.run_id
    safe_bytes = b"".join(path.read_bytes() for path in run_dir.rglob("*") if path.is_file())

    assert canary not in result.model_dump_json()
    assert canary.encode() not in safe_bytes
    assert canary not in render_report(result, "json")
    assert canary not in render_report(result, "md")


def test_draft_requires_exact_manifest_and_confines_unverified_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    (source / "unapproved.py").write_text("# PT_UNAPPROVED_CONTEXT_CANARY\n", encoding="utf-8")
    inspect_result = execute("inspect", source, state_root=tmp_path / "state")
    before = _tree_digest(source)

    missing = execute("draft", source, state_root=tmp_path / "state")
    assert missing.status == "failed"
    assert missing.error is not None
    assert missing.error.code == "missing_egress_manifest"
    assert missing.candidate is None

    policy = _policy(inspect_result.snapshot_digest, source / "app.py")
    before = _tree_digest(source)
    monkeypatch.setenv("PT_AMBIENT_CANARY", "PT_AMBIENT_ENV_MUST_NOT_EGRESS")

    class FakeTransport:
        def __init__(self) -> None:
            self.request: dict[str, object] | None = None
            self.headers: dict[str, str] | None = None

        def send(
            self,
            endpoint: str,
            headers: dict[str, str],
            payload: dict[str, object],
            timeout_seconds: int,
        ) -> dict[str, object]:
            assert endpoint == "https://api.openai.com/v1/responses"
            assert timeout_seconds == 30
            self.request = payload
            self.headers = headers
            proposal = {
                "schema_version": "1",
                "patch": "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-old\n+new\n",
                "affected_paths": ["app.py"],
                "proposed_tests": ["Verify the Responses call remains schema-compatible."],
                "rationale": "Reduce repeated static work.",
                "evidence": ["The selected callsite is a direct Responses invocation."],
                "limitations": ["Not executed or evaluated."],
            }
            return {
                "id": "resp_fixture",
                "status": "completed",
                "model": "gpt-5.3-codex-2026-07-01",
                "usage": {"input_tokens": 50, "output_tokens": 40, "total_tokens": 90},
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(proposal)}],
                    }
                ],
            }

    transport = FakeTransport()
    connector = ResponsesConnector(api_key="connector-secret", transport=transport)
    drafted = execute("draft", source, state_root=tmp_path / "state", policy=policy, connector=connector)

    assert drafted.status == "completed"
    assert drafted.candidate is not None
    assert drafted.candidate.state == "unverified"
    assert drafted.candidate.patch_artifact.startswith("sha256:")
    assert drafted.candidate.tests_artifact.startswith("sha256:")
    assert _tree_digest(source) == before
    assert transport.request is not None
    assert "tools" not in transport.request
    assert "tool_choice" not in transport.request
    assert transport.request["text"]["format"]["strict"] is True
    assert "connector-secret" not in json.dumps(transport.request)
    assert transport.headers == {"Authorization": "Bearer connector-secret", "Content-Type": "application/json"}
    request_text = json.dumps(transport.request)
    assert "client.responses.create" in request_text
    assert "untracked" not in request_text
    assert "staged" not in request_text
    assert "PT_UNAPPROVED_CONTEXT_CANARY" not in request_text
    assert "PT_AMBIENT_ENV_MUST_NOT_EGRESS" not in request_text
    run_dir = tmp_path / "state" / "runs" / drafted.run_id
    assert run_dir.is_dir()
    assert source not in run_dir.parents
    assert not (run_dir / "snapshot").exists()
    assert drafted.cleanup.status == "completed"
    assert drafted.connector is not None
    assert drafted.connector.response_id == "resp_fixture"
    for reference in (drafted.candidate.patch_artifact, drafted.candidate.tests_artifact):
        digest = reference.removeprefix("sha256:")
        artifact = run_dir / "artifacts" / digest
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == digest
    assert drafted.receipt is not None
    receipt = run_dir / "receipts" / drafted.receipt.receipt_id.removeprefix("receipt_")
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_payload["candidate_patch"] == drafted.candidate.patch_artifact
    assert receipt_payload["candidate_tests"] == drafted.candidate.tests_artifact


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda policy: policy.update(source_digest="sha256:" + "0" * 64), "stale_egress_manifest"),
        (lambda policy: policy["slices"][0].update(sha256="0" * 64), "stale_egress_slice"),
        (lambda policy: policy["slices"][0].update(path="../app.py"), "policy_path_outside_snapshot"),
        (lambda policy: policy["slices"].append(dict(policy["slices"][0])), "duplicate_egress_slice"),
        (lambda policy: policy.update(destination="https://example.invalid/v1/responses"), "invalid_egress_manifest"),
        (lambda policy: policy.update(model="gpt-4.1"), "invalid_egress_manifest"),
        (lambda policy: policy.update(max_input_bytes=1), "agent_input_budget_exceeded"),
    ],
)
def test_draft_manifest_widening_fails_closed(
    tmp_path: Path, mutate, code: str
) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    inspected = execute("inspect", source, state_root=tmp_path / "state")
    policy = _policy(inspected.snapshot_digest, source / "app.py")
    mutate(policy)

    class MustNotSend:
        def send(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("invalid manifest reached the connector")

    result = execute(
        "draft",
        source,
        state_root=tmp_path / "state",
        policy=policy,
        connector=ResponsesConnector(api_key="secret", transport=MustNotSend()),
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == code
    assert result.candidate is None
    run_dir = tmp_path / "state" / "runs" / result.run_id
    assert not (run_dir / "artifacts").exists()
    assert not (run_dir / "snapshot").exists()


def test_draft_rejects_unapproved_patch_target(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    inspected = execute("inspect", source, state_root=tmp_path / "state")
    policy = _policy(inspected.snapshot_digest, source / "app.py")

    class WrongPathTransport:
        def send(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            proposal = {
                "schema_version": "1",
                "patch": "--- a/unapproved.py\n+++ b/unapproved.py\n@@ -1 +1 @@\n-old\n+new\n",
                "affected_paths": ["unapproved.py"],
                "proposed_tests": ["test"],
                "rationale": "rationale",
                "evidence": ["selected static callsite"],
                "limitations": ["unverified"],
            }
            return {
                "id": "resp_wrong_path",
                "status": "completed",
                "model": "gpt-5.3-codex",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps(proposal)}]}],
            }

    result = execute(
        "draft",
        source,
        state_root=tmp_path / "state",
        policy=policy,
        connector=ResponsesConnector(api_key="secret", transport=WrongPathTransport()),
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "unexpected_patch_target"
    assert result.candidate is None


def test_draft_with_no_supported_callsite_is_typed_without_connector_use(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    source.mkdir()
    source_file = source / "plain.py"
    source_file.write_text("VALUE = 1\n", encoding="utf-8")
    inspected = execute("inspect", source, state_root=tmp_path / "state")
    policy = _policy(inspected.snapshot_digest, source_file)

    class MustNotSend:
        def send(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            raise AssertionError("zero-callsite Draft reached the connector")

    result = execute(
        "draft",
        source,
        state_root=tmp_path / "state",
        policy=policy,
        connector=ResponsesConnector(api_key="secret", transport=MustNotSend()),
    )

    assert result.status == "completed_no_findings"
    assert result.work.zero_work is False
    assert result.candidate is None


def test_configured_policy_without_connector_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    inspected = execute("inspect", source, state_root=tmp_path / "state")
    policy = _policy(inspected.snapshot_digest, source / "app.py")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = execute("draft", source, state_root=tmp_path / "state", policy=policy)

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "safe_agent_transport_unavailable"
    assert result.candidate is None


@pytest.mark.parametrize(
    ("failure", "code", "status"),
    [
        (ConnectorFailure("agent_response_schema_invalid"), "agent_response_schema_invalid", "failed"),
        (ConnectorFailure("agent_budget_exceeded"), "agent_budget_exceeded", "failed"),
        (ConnectorCancelled(), "cancelled", "cancelled"),
    ],
)
def test_draft_connector_failures_are_typed_and_create_no_candidate(
    tmp_path: Path, failure: Exception, code: str, status: str
) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    inspected = execute("inspect", source, state_root=tmp_path / "state")
    policy = _policy(inspected.snapshot_digest, source / "app.py")

    class FailingTransport:
        def send(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            raise failure

    connector = ResponsesConnector(api_key="secret", transport=FailingTransport())
    result = execute("draft", source, state_root=tmp_path / "state", policy=policy, connector=connector)

    assert result.status == status
    assert result.error is not None
    assert result.error.code == code
    assert result.candidate is None


@pytest.mark.parametrize(
    ("response_change", "code"),
    [
        (lambda response: response["output"][0]["content"][0].update(text="not json"), "agent_response_schema_invalid"),
        (
            lambda response: response["output"][0]["content"][0].update(
                text=response["output"][0]["content"][0]["text"].replace(
                    '"schema_version": "1"', '"schema_version": "1", "schema_version": "1"', 1
                )
            ),
            "agent_response_schema_invalid",
        ),
        (
            lambda response: response["output"][0]["content"][0].update(
                text=json.dumps(
                    {
                        "schema_version": "2",
                        "patch": "--- a/app.py\n+++ b/app.py\n",
                        "affected_paths": ["app.py"],
                        "proposed_tests": ["test"],
                        "rationale": "rationale",
                        "evidence": ["evidence"],
                        "limitations": ["unverified"],
                    }
                )
            ),
            "agent_response_schema_invalid",
        ),
        (lambda response: response["usage"].update(output_tokens=1201), "agent_budget_exceeded"),
        (lambda response: response.update(status="incomplete"), "agent_response_incomplete"),
    ],
)
def test_connector_enforces_response_schema_completion_and_budget(
    tmp_path: Path, response_change, code: str
) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    inspected = execute("inspect", source, state_root=tmp_path / "state")
    policy = _policy(inspected.snapshot_digest, source / "app.py")
    proposal = {
        "schema_version": "1",
        "patch": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n",
        "affected_paths": ["app.py"],
        "proposed_tests": ["test"],
        "rationale": "rationale",
        "evidence": ["evidence"],
        "limitations": ["unverified"],
    }
    response = {
        "id": "resp_schema_fixture",
        "status": "completed",
        "model": "gpt-5.3-codex",
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps(proposal)}]}],
    }
    response_change(response)

    class ResponseTransport:
        def send(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            return response

    result = execute(
        "draft",
        source,
        state_root=tmp_path / "state",
        policy=policy,
        connector=ResponsesConnector(api_key="secret", transport=ResponseTransport()),
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == code
    assert result.candidate is None


def test_cli_json_status_report_and_legacy_run_migration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    state = tmp_path / "state"
    monkeypatch.setenv("PROMPTECTOMY_HOME", str(state))
    runner = CliRunner()

    inspected = runner.invoke(app, ["inspect", str(source), "--json"])
    assert inspected.exit_code == 0
    payload = json.loads(inspected.stdout)
    assert payload["mode"] == "inspect"
    assert payload["status"] == "completed"

    status = runner.invoke(app, ["status", payload["run_id"], "--json"])
    assert status.exit_code == 0
    assert json.loads(status.stdout)["run_id"] == payload["run_id"]

    report = runner.invoke(app, ["report", payload["run_id"], "--format", "md"])
    assert report.exit_code == 0
    assert "# PROMPTECTOMY Inspect report" in report.stdout

    before = _tree_digest(source)
    legacy = runner.invoke(app, ["run", str(source)])
    assert legacy.exit_code == 4
    assert "legacy_run_disabled" in legacy.output
    assert _tree_digest(source) == before

    failed = runner.invoke(app, ["draft", str(source), "--json"])
    assert failed.exit_code == 4
    failed_payload = json.loads(failed.stdout)
    failed_status = runner.invoke(app, ["status", failed_payload["run_id"], "--json"])
    assert failed_status.exit_code == 0
    assert json.loads(failed_status.stdout)["status"] == "failed"


def test_keyboard_interrupt_becomes_a_typed_cancelled_terminal_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)

    def interrupt(*_args: object, **_kwargs: object):
        raise KeyboardInterrupt

    monkeypatch.setattr("promptectomy.reference._inventory", interrupt)
    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "cancelled"
    assert result.error is not None
    assert result.error.code == "cancelled"
    events = (tmp_path / "state" / "runs" / result.run_id / "events.ndjson").read_text(encoding="utf-8")
    assert '"status":"cancelled"' in events


def test_unexpected_trusted_value_error_becomes_typed_internal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)

    def fail(*_args: object, **_kwargs: object):
        raise ValueError("PT_INTERNAL_EXCEPTION_CANARY")

    monkeypatch.setattr("promptectomy.reference._inventory", fail)
    result = execute("inspect", source, state_root=tmp_path / "state")

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "internal_failure"
    assert "PT_INTERNAL_EXCEPTION_CANARY" not in result.model_dump_json()


def test_run_files_are_owner_only_and_loading_rejects_path_ids(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    result = execute("inspect", source, state_root=tmp_path / "state")
    run_dir = tmp_path / "state" / "runs" / result.run_id

    assert run_dir.stat().st_mode & 0o077 == 0
    for path in run_dir.rglob("*"):
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="invalid run ID"):
        load_run(tmp_path / "state", "../../escape")


def test_state_root_inside_source_or_git_metadata_is_rejected_before_write(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    _init_dirty_git_repo(source)
    worktree = tmp_path / "linked-worktree"
    subprocess.run(["git", "-C", str(source), "worktree", "add", "-q", "--detach", str(worktree), "HEAD"], check=True)
    git_pointer = (worktree / ".git").read_text(encoding="utf-8").removeprefix("gitdir: ").strip()
    git_metadata = Path(git_pointer)
    if not git_metadata.is_absolute():
        git_metadata = (worktree / git_metadata).resolve()

    with pytest.raises(ValueError, match="outside the source"):
        execute("inspect", source, state_root=source / ".promptectomy-state")
    with pytest.raises(ValueError, match="outside Git metadata"):
        execute("inspect", worktree, state_root=git_metadata / "promptectomy-state")

    assert not (source / ".promptectomy-state").exists()
    assert not (git_metadata / "promptectomy-state").exists()


def test_dirty_git_state_is_exact_across_all_phase1a_terminal_paths(tmp_path: Path) -> None:
    source = tmp_path / "dirty"
    _init_dirty_git_repo(source)
    state = tmp_path / "state"
    before = _git_state(source)

    inspected = execute("inspect", source, state_root=state)
    assert inspected.status == "completed"
    assert _git_state(source) == before

    audited = execute("audit", source, state_root=state)
    assert audited.status == "completed"
    assert _git_state(source) == before

    missing = execute("draft", source, state_root=state)
    assert missing.status == "failed"
    assert _git_state(source) == before

    policy = _policy(inspected.snapshot_digest, source / "app.py")

    class CancelTransport:
        def send(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            raise ConnectorCancelled()

    cancelled = execute(
        "draft",
        source,
        state_root=state,
        policy=policy,
        connector=ResponsesConnector(api_key="secret", transport=CancelTransport()),
    )
    assert cancelled.status == "cancelled"
    assert _git_state(source) == before

    class SuccessTransport:
        def send(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            proposal = {
                "schema_version": "1",
                "patch": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n",
                "affected_paths": ["app.py"],
                "proposed_tests": ["Run the declared static contract checks."],
                "rationale": "Use a bounded deterministic candidate.",
                "evidence": ["The manifest selects a supported Responses callsite."],
                "limitations": ["The candidate is unverified."],
            }
            return {
                "id": "resp_dirty_fixture",
                "status": "completed",
                "model": "gpt-5.3-codex",
                "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
                "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps(proposal)}]}],
            }

    drafted = execute(
        "draft",
        source,
        state_root=state,
        policy=policy,
        connector=ResponsesConnector(api_key="secret", transport=SuccessTransport()),
    )
    assert drafted.status == "completed"
    assert drafted.candidate is not None
    assert _git_state(source) == before


def test_events_artifacts_reports_and_receipt_are_digest_bound(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    _write_repo(source, typescript=False)
    state = tmp_path / "state"
    inspected = execute("inspect", source, state_root=state)
    run_dir = state / "runs" / inspected.run_id
    events_path = run_dir / "events.ndjson"
    before_events = events_path.read_bytes()
    events = [json.loads(line) for line in before_events.splitlines()]

    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert events[0]["type"] == "run.created"
    assert events[-1]["type"] == "run.terminal"
    assert all(event["run_id"] == inspected.run_id for event in events)

    for group, references in (("reports", inspected.report_artifacts.values()),):
        for reference in references:
            digest = reference.removeprefix("sha256:")
            artifact = run_dir / group / digest
            assert hashlib.sha256(artifact.read_bytes()).hexdigest() == digest

    assert inspected.receipt is not None
    receipt_digest = inspected.receipt.receipt_id.removeprefix("receipt_")
    receipt = run_dir / "receipts" / receipt_digest
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == receipt_digest
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_payload["snapshot_digest"] == inspected.snapshot_digest
    assert receipt_payload["authority_manifest_digest"] == inspected.authority.manifest_digest
    assert receipt_payload["semantics"] == "digest_bound_local_consistency"

    reloaded = load_run(state, inspected.run_id)
    assert render_report(reloaded, "json")
    assert render_report(reloaded, "md")
    assert events_path.read_bytes() == before_events


def test_legacy_commands_are_gated_and_scan_is_only_an_inspect_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "dirty"
    _init_dirty_git_repo(source)
    state = tmp_path / "state"
    monkeypatch.setenv("PROMPTECTOMY_HOME", str(state))
    before = _git_state(source)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("legacy command attempted process execution")

    monkeypatch.setattr(subprocess, "run", forbidden)
    runner = CliRunner()
    scanned = runner.invoke(app, ["scan", str(source), "--json"])
    assert scanned.exit_code == 0
    assert json.loads(scanned.stdout)["mode"] == "inspect"
    for command in (
        ["run", str(source)],
        ["accept", "callsite", "--repo", str(source)],
        ["disable", "callsite", "--repo", str(source)],
        ["serve", str(source)],
    ):
        result = runner.invoke(app, command)
        assert result.exit_code == 4
        assert "disabled" in result.output
    assert _tree_digest(source) == before["tree"]


def test_cli_import_does_not_load_legacy_execution_modules() -> None:
    script = (
        "import sys; import promptectomy.cli; "
        "blocked={'promptectomy.scan','promptectomy.synthesize','promptectomy.replay','promptectomy.worktrees'}; "
        "assert not blocked.intersection(sys.modules)"
    )
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
