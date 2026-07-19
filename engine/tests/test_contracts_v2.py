from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path

import pytest

from promptectomy.contracts_v2 import (
    ContractError,
    canonical_json,
    digest_json,
    parse_json_strict,
    receipt_id,
    typed_id,
    validate_contract,
    validate_relative_path,
    validate_schema_document,
)
from scripts.generate_contract_bindings import OUTPUT_ROOT, SCHEMA_PATH, generate
from v2_fixtures import run_contract


SCHEMA_EXAMPLES = Path(__file__).resolve().parents[1] / "schemas" / "v2" / "examples"


def test_canonical_schema_is_valid_and_run_is_strict() -> None:
    validate_schema_document()
    run = run_contract()
    validate_contract(run)

    extra = copy.deepcopy(run)
    extra["unknown"] = True
    with pytest.raises(ContractError, match="validation failed"):
        validate_contract(extra)

    wrong_version = copy.deepcopy(run)
    wrong_version["schema_version"] = "3.0.0"
    with pytest.raises(ContractError, match="unsupported schema version"):
        validate_contract(wrong_version)


def test_tracked_positive_and_negative_contract_examples() -> None:
    for path in sorted(SCHEMA_EXAMPLES.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if path.name.endswith(".invalid.json"):
            with pytest.raises(ContractError):
                validate_contract(value)
        else:
            validate_contract(value)


def test_strict_json_rejects_ambiguous_and_non_ijson_values() -> None:
    with pytest.raises(ContractError, match="duplicate JSON member"):
        parse_json_strict('{"a":1,"a":2}')
    with pytest.raises(ContractError, match="non-finite"):
        parse_json_strict('{"a":NaN}')
    with pytest.raises(ContractError, match="I-JSON range"):
        parse_json_strict('{"a":9007199254740992}')
    with pytest.raises(ContractError, match="binary float"):
        canonical_json({"a": 1.5})
    with pytest.raises(ContractError, match="byte-order mark"):
        parse_json_strict("\ufeff{}")


def test_canonical_json_and_domain_separation_are_deterministic() -> None:
    left = canonical_json({"z": 1, "a": "x"})
    right = canonical_json({"a": "x", "z": 1})
    assert left == right == b'{"a":"x","z":1}'
    first = digest_json(
        {"a": 1},
        purpose="report",
        schema_uri="https://promptectomy.invalid/schemas/v2/run.schema.json",
    )
    second = digest_json(
        {"a": 1},
        purpose="snapshot",
        schema_uri="https://promptectomy.invalid/schemas/v2/run.schema.json",
    )
    assert first != second


def test_uuid7_and_receipt_identifiers_have_the_declared_shape() -> None:
    run_id = typed_id("run")
    parsed = uuid.UUID(run_id.removeprefix("run_"))
    assert parsed.version == 7
    assert parsed.variant == uuid.RFC_4122
    receipt = {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/receipt.schema.json",
        "schema_version": "2.0.0",
        "receipt_kind": "evaluation",
    }
    assert receipt_id(receipt) == receipt_id({**receipt, "receipt_id": "ignored"})


def test_generated_bindings_are_reproducible_and_bound_to_schema() -> None:
    paths = (
        OUTPUT_ROOT / "python" / "promptectomy_contracts_v2.py",
        OUTPUT_ROOT / "typescript" / "contracts-v2.ts",
        OUTPUT_ROOT / "rust" / "src" / "lib.rs",
    )
    before = {path: path.read_bytes() for path in paths}
    generate()
    digest = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest().encode()
    for path in paths:
        assert path.read_bytes() == before[path]
        assert digest in before[path]


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ("src/main.py", True),
        ("../secret", False),
        ("/absolute", False),
        ("C:/windows", False),
        ("a\\b", False),
        ("a\x00b", False),
    ],
)
def test_relative_path_boundary(value: str, accepted: bool) -> None:
    if accepted:
        assert validate_relative_path(value).as_posix() == value
    else:
        with pytest.raises(ContractError):
            validate_relative_path(value)
