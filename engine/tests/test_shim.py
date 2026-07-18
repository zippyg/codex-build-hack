from __future__ import annotations

import json
from pathlib import Path

from openai.resources.responses.responses import Responses
from openai.types.responses.response import Response

from promptectomy import shim
from promptectomy.ledger import load


def test_compiled_hot_swap_returns_sdk_response_without_template(tmp_path: Path, monkeypatch) -> None:
    generated = tmp_path / "engine" / "promptectomy" / "generated"
    generated.mkdir(parents=True)
    module = generated / "extract.py"
    module.write_text("def run(payload, params):\n    return {'ticket': payload['ticket']}\n", encoding="utf-8")
    state = tmp_path / ".promptectomy"
    state.mkdir()
    registry_path = state / "registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "callsites": {
                    "extract": {
                        "enabled": True,
                        "kind": "structured",
                        "module_path": "../engine/promptectomy/generated/extract.py",
                        "response_template": None,
                        "shadow_rate": 0,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    ledger_path = state / "ledger.jsonl"
    monkeypatch.setattr(shim, "_callsite_id", lambda _repo: ("extract", None, None))
    monkeypatch.setattr(shim, "_config", (tmp_path, ledger_path, registry_path))
    monkeypatch.setattr(shim, "_original_create", lambda *_args, **_kwargs: None)

    response = shim._wrapped(object(), model="gpt-4.1-mini", input={"ticket": "DEMO-1"})

    assert isinstance(response, Response)
    assert response.output_text == '{"ticket":"DEMO-1"}'
    assert response.id.startswith("resp_promptectomy_")
    assert response.status == "completed"
    [event] = load(ledger_path)
    assert event.mode == "compiled"
    assert event.response_normalized == {"ticket": "DEMO-1"}
    assert isinstance(event.response_raw, dict)


def test_shadow_disables_registry_on_normalized_drift(tmp_path: Path) -> None:
    registry_path = tmp_path / "registry.json"
    registry = {
        "callsites": {
            "extract": {
                "enabled": True,
                "kind": "structured",
                "unrelated": "preserved",
            }
        }
    }
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    ledger_path = tmp_path / "ledger.jsonl"
    config = registry["callsites"]["extract"]

    def original(_self, **_kwargs):
        return shim._compiled_response(None, {"b": 2, "a": 1}, "gpt-4.1-mini")

    shim._shadow(
        original,
        object(),
        (),
        {"model": "gpt-4.1-mini", "input": "same"},
        ledger_path,
        registry_path,
        "extract",
        config,
        {"a": 1, "b": 2},
    )
    assert json.loads(registry_path.read_text(encoding="utf-8"))["callsites"]["extract"]["enabled"] is True

    shim._shadow(
        original,
        object(),
        (),
        {"model": "gpt-4.1-mini", "input": "drift"},
        ledger_path,
        registry_path,
        "extract",
        config,
        {"a": 9, "b": 2},
    )

    entry = json.loads(registry_path.read_text(encoding="utf-8"))["callsites"]["extract"]
    assert entry["enabled"] is False
    assert entry["disabled_reason"] == "shadow_output_drift"
    assert entry["disabled_at"]
    assert entry["unrelated"] == "preserved"
    assert [event.status for event in load(ledger_path)] == ["ok", "ok"]


def test_uninstall_restores_sdk_and_clears_state(tmp_path: Path) -> None:
    shim.uninstall()
    original = Responses.create
    try:
        shim.install(tmp_path, tmp_path / "ledger.jsonl", tmp_path / "registry.json")
        assert Responses.create is shim._wrapped
        assert shim._config is not None
    finally:
        shim.uninstall()

    assert Responses.create is original
    assert shim._original_create is None
    assert shim._config is None
