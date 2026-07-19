from __future__ import annotations

import importlib.util
import json
from importlib.resources import files
from pathlib import Path

import promptectomy
from typer.testing import CliRunner

from promptectomy.cli import app


LEGACY_MODULES = (
    "contracts",
    "events",
    "guard",
    "ledger",
    "pricing",
    "replay",
    "scan",
    "schemas",
    "scoring",
    "server",
    "shim",
    "splitting",
    "synthesize",
    "verify",
    "worktrees",
)


def test_distribution_is_installed_outside_the_source_checkout() -> None:
    package = Path(promptectomy.__file__).resolve()

    assert "site-packages" in package.parts
    assert "codex-build-hack" not in package.as_posix()
    assert importlib.util.find_spec("promptectomy.generated") is None
    for module in LEGACY_MODULES:
        assert importlib.util.find_spec(f"promptectomy.{module}") is None


def test_distribution_contains_only_declared_runtime_assets() -> None:
    schemas = files("promptectomy.schema_assets")
    executor = files("promptectomy.executor_image")

    for name in (
        "audit-v1.json",
        "draft-candidate-v1.json",
        "synthesis-result-v1.json",
        "verdict-v1.json",
    ):
        assert (
            json.loads(schemas.joinpath(name).read_text(encoding="utf-8"))["type"]
            == "object"
        )
    assert executor.joinpath("Dockerfile").is_file()
    assert executor.joinpath("runner.py").is_file()


def test_default_capabilities_are_local_and_fail_closed(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("PROMPTECTOMY_OCI_IMAGE", raising=False)
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(
        "from openai import OpenAI\nOpenAI().responses.create(model='gpt-5', input='hello')\n",
        encoding="utf-8",
    )
    before = (source / "app.py").read_bytes()

    doctor = CliRunner().invoke(app, ["doctor", str(source), "--json"])
    inspect = CliRunner().invoke(app, ["inspect", str(source), "--json"])

    assert doctor.exit_code == 0
    checks = json.loads(doctor.stdout)["checks"]
    assert checks["responses_connector_configured"] is False
    assert checks["executor_configured"] is False
    assert checks["executor_accepted"] is False
    assert checks["protected_key_store_enabled"] is False
    assert checks["local_api_available"] is False
    assert inspect.exit_code == 0
    payload = json.loads(inspect.stdout)
    assert payload["authority"]["executes"] == []
    assert payload["authority"]["destinations"] == []
    assert payload["support"]["callsites"] == 1
    assert (source / "app.py").read_bytes() == before
