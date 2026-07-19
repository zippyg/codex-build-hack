from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from promptectomy import discovery_javascript
from promptectomy.discovery_javascript import ADAPTER_VERSION as TYPESCRIPT_ADAPTER_VERSION
from promptectomy.discovery_javascript import discover_javascript
from promptectomy.discovery_python import ADAPTER_VERSION as PYTHON_ADAPTER_VERSION
from promptectomy.discovery_python import discover_python
from promptectomy.reference import execute


FIXTURES = Path(__file__).parent / "fixtures" / "phase4_discovery"


def _tree_sitter_available() -> bool:
    return importlib.util.find_spec("tree_sitter") is not None and importlib.util.find_spec("tree_sitter_typescript") is not None


def _discover(relative: str):
    path = FIXTURES / relative
    source = path.read_bytes()
    if path.suffix == ".py":
        return discover_python(source)
    language = "typescript" if path.suffix == ".ts" else "javascript"
    return discover_javascript(source, language, relative=relative)


def test_golden_true_false_positive_and_ambiguity_corpus() -> None:
    expected = json.loads((FIXTURES / "golden.json").read_text(encoding="utf-8"))
    observed = {}
    for relative, outcome in expected.items():
        if not relative.startswith("python/") and not _tree_sitter_available():
            continue
        result = _discover(relative)
        observed[relative] = {
            "calls": len(result.calls),
            "gaps": sorted(gap.code for gap in result.gaps),
        }
        assert observed[relative] == outcome
    assert set(observed) >= {
        "python/sync_alias.py",
        "python/full_surface.py",
        "python/structured_parse.py",
        "python/false_positive.py",
        "python/dynamic.py",
        "python/unsupported.py",
    }
    if _tree_sitter_available():
        assert observed == expected


def test_python_declared_feature_cells_are_covered() -> None:
    full = _discover("python/full_surface.py").calls[0]
    assert set(full.features) == {
        "asynchronous",
        "cancellation_bounded",
        "cancellation_handled",
        "errors_handled",
        "resource_alias",
        "retries_configured",
        "streaming",
        "structured_output",
        "tools",
        "wrapper_body",
    }
    sync = _discover("python/sync_alias.py").calls[0]
    assert set(sync.features) == {"client_alias", "synchronous"}
    parsed = _discover("python/structured_parse.py").calls[0]
    assert parsed.operation == "responses.parse"
    assert "structured_output" in parsed.features


def test_python_local_shadow_does_not_inherit_a_global_openai_binding() -> None:
    result = discover_python(
        b"from openai import OpenAI\n"
        b"client = OpenAI()\n"
        b"def unrelated():\n"
        b"    client = object()\n"
        b"    return client.responses.create()\n"
    )

    assert result.calls == ()
    assert [gap.code for gap in result.gaps] == ["ambiguous_dynamic_callsite"]


def test_python_with_options_retry_alias_is_statically_supported() -> None:
    result = discover_python(
        b"from openai import OpenAI\n"
        b"client = OpenAI()\n"
        b"client.with_options(max_retries=4).responses.create(input='fixture')\n"
    )

    assert len(result.calls) == 1
    assert "retries_configured" in result.calls[0].features
    assert result.gaps == ()


def test_identical_calls_in_one_symbol_receive_distinct_stable_ordinals(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def run():\n"
        "    client.responses.create(input='same')\n"
        "    client.responses.create(input='same')\n",
        encoding="utf-8",
    )

    result = execute("inspect", source, state_root=tmp_path / "state")

    assert len(result.callsites) == 2
    assert len({call.callsite_id for call in result.callsites}) == 2
    assert {call.ast_ordinal for call in result.callsites} == {0, 1}


@pytest.mark.skipif(not _tree_sitter_available(), reason="pinned Tree-sitter adapter is not installed")
def test_typescript_and_javascript_declared_feature_cells_are_covered() -> None:
    full = _discover("typescript/full_surface.ts").calls[0]
    assert set(full.features) == {
        "asynchronous",
        "cancellation_bounded",
        "client_alias",
        "errors_handled",
        "resource_alias",
        "retries_configured",
        "streaming",
        "structured_output",
        "tools",
        "wrapper_body",
    }
    parsed = _discover("typescript/structured_parse.ts").calls[0]
    assert parsed.operation == "responses.parse"
    commonjs = _discover("javascript/commonjs.js").calls[0]
    assert set(commonjs.features) >= {"asynchronous", "tools", "wrapper_body"}


def test_missing_tree_sitter_fails_closed_with_typed_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery_javascript, "_load_parser", lambda _relative: None)
    source = b'import OpenAI from "openai";\nconst client = new OpenAI();\nclient.responses.create({});\n'

    result = discover_javascript(source, "typescript", relative="fixture.ts")

    assert result.calls == ()
    assert [gap.code for gap in result.gaps] == ["unsupported_toolchain"]


@pytest.mark.skipif(not _tree_sitter_available(), reason="pinned Tree-sitter adapter is not installed")
def test_integrated_callsites_have_stable_digest_bound_identity_and_safe_coverage(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_bytes((FIXTURES / "python/full_surface.py").read_bytes())
    (source / "worker.ts").write_bytes((FIXTURES / "typescript/full_surface.ts").read_bytes())
    before = hashlib.sha256(b"".join(path.read_bytes() for path in sorted(source.iterdir()))).hexdigest()

    first = execute("inspect", source, state_root=tmp_path / "state")
    second = execute("inspect", source, state_root=tmp_path / "state")

    assert [call.callsite_id for call in first.callsites] == [call.callsite_id for call in second.callsites]
    assert {call.adapter_version for call in first.callsites} == {PYTHON_ADAPTER_VERSION, TYPESCRIPT_ADAPTER_VERSION}
    assert {call.stability for call in first.callsites} == {"stable"}
    assert all(call.normalized_ast_digest.startswith("sha256:") for call in first.callsites)
    assert all(call.enclosing_symbol_ref.startswith("symbol_") for call in first.callsites)
    assert first.support.feature_coverage["streaming"] == 2
    after = hashlib.sha256(b"".join(path.read_bytes() for path in sorted(source.iterdir()))).hexdigest()
    assert after == before


@pytest.mark.skipif(not _tree_sitter_available(), reason="pinned Tree-sitter adapter is not installed")
def test_safe_outputs_never_include_source_path_symbol_or_content_canaries(tmp_path: Path) -> None:
    canary = "PT_DISCOVERY_CANARY_4a62d9"
    source = tmp_path / canary
    source.mkdir()
    (source / f"{canary}.ts").write_text(
        f'import OpenAI from "openai";\nconst client = new OpenAI();\n'
        f'async function {canary}() {{ return client.responses.create({{ input: "{canary}" }}); }}\n',
        encoding="utf-8",
    )

    result = execute("inspect", source, state_root=tmp_path / "state")
    safe = result.model_dump_json()
    run_dir = tmp_path / "state" / "runs" / result.run_id
    stored = b"".join(path.read_bytes() for path in run_dir.rglob("*") if path.is_file())

    assert result.support.callsites == 1
    assert canary not in safe
    assert canary.encode() not in stored
