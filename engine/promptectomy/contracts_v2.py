from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


SCHEMA_BASE = "https://promptectomy.invalid/schemas/v2/"
SCHEMA_VERSION = "2.0.0"
ENTITY_DEFINITIONS = {
    "repository.schema.json": "Repository",
    "snapshot.schema.json": "Snapshot",
    "authority.schema.json": "Authority",
    "run.schema.json": "Run",
    "stage.schema.json": "Stage",
    "event.schema.json": "Event",
    "callsite.schema.json": "Callsite",
    "observation.schema.json": "Observation",
    "finding.schema.json": "Finding",
    "candidate.schema.json": "Candidate",
    "evaluation.schema.json": "Evaluation",
    "patch.schema.json": "Patch",
    "artifact.schema.json": "Artifact",
    "receipt.schema.json": "Receipt",
    "error.schema.json": "Error",
}
ID_PREFIXES = {
    "repository": "repo",
    "authority": "auth",
    "run": "run",
    "stage": "stage",
    "event": "evt",
    "finding": "finding",
    "candidate": "candidate",
    "evaluation": "eval",
    "patch": "patch",
    "error": "err",
}


class ContractError(ValueError):
    pass


def _schema() -> dict[str, Any]:
    try:
        content = files("promptectomy.schema_v2").joinpath("contract.schema.json").read_bytes()
    except ModuleNotFoundError:
        content = (Path(__file__).resolve().parents[1] / "schemas" / "v2" / "contract.schema.json").read_bytes()
    return parse_json_strict(content)


def parse_json_strict(content: bytes | str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"duplicate JSON member: {key!r}")
            result[key] = value
        return result

    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError("contract JSON is not valid UTF-8") from exc
    if content.startswith("\ufeff"):
        raise ContractError("contract JSON must not contain a byte-order mark")
    try:
        value = json.loads(
            content,
            object_pairs_hook=object_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ContractError(f"non-finite JSON number: {token}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise ContractError("contract JSON is syntactically invalid") from exc
    _check_ijson(value)
    return value


def _check_ijson(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise ContractError(f"binary float is prohibited at {path}")
    if isinstance(value, int):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise ContractError(f"integer is outside the I-JSON range at {path}")
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ContractError(f"unpaired Unicode surrogate at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_ijson(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"non-string object key at {path}")
            _check_ijson(key, f"{path}.<key>")
            _check_ijson(item, f"{path}.{key}")
        return
    if value is not None and not isinstance(value, bool):
        raise ContractError(f"unsupported JSON value at {path}: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    _check_ijson(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeEncodeError) as exc:
        raise ContractError("contract value cannot be RFC 8785 canonicalized") from exc


def digest_json(value: Any, *, purpose: str, schema_uri: str) -> str:
    if not purpose or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for character in purpose):
        raise ContractError(f"invalid digest purpose: {purpose!r}")
    if schema_uri not in {f"{SCHEMA_BASE}{name}" for name in ENTITY_DEFINITIONS}:
        raise ContractError(f"unknown schema URI for digest: {schema_uri!r}")
    domain = f"PROMPTECTOMY\0v2\0{purpose}\0{schema_uri}\0".encode()
    return f"sha256:{hashlib.sha256(domain + canonical_json(value)).hexdigest()}"


def validate_contract(value: Any) -> None:
    if not isinstance(value, dict):
        raise ContractError("contract root must be an object")
    uri = value.get("schema_uri")
    version = value.get("schema_version")
    if version != SCHEMA_VERSION:
        raise ContractError("unsupported schema version")
    if not isinstance(uri, str) or not uri.startswith(SCHEMA_BASE):
        raise ContractError("unknown schema URI")
    name = uri.removeprefix(SCHEMA_BASE)
    definition = ENTITY_DEFINITIONS.get(name)
    if definition is None:
        raise ContractError("unknown schema URI")
    contract = _schema()
    validator = Draft202012Validator(
        {
            "$schema": contract["$schema"],
            "$ref": f"#/$defs/{definition}",
            "$defs": contract["$defs"],
        }
    )
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
    if errors:
        error = errors[0]
        raise ContractError(f"contract validation failed ({error.validator})")


def validate_schema_document() -> None:
    try:
        Draft202012Validator.check_schema(_schema())
    except ValidationError as exc:
        raise ContractError(f"invalid canonical schema: {exc.message}") from exc


def uuid7() -> uuid.UUID:
    milliseconds = int(time.time_ns() // 1_000_000)
    if milliseconds >= 1 << 48:
        raise OverflowError("current timestamp cannot be represented by UUIDv7")
    random_bits = secrets.randbits(74)
    value = milliseconds << 80
    value |= 0x7 << 76
    value |= ((random_bits >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    return uuid.UUID(int=value)


def typed_id(kind: str) -> str:
    try:
        prefix = ID_PREFIXES[kind]
    except KeyError as exc:
        raise ContractError(f"unknown entity ID kind: {kind!r}") from exc
    return f"{prefix}_{uuid7()}"


def artifact_id(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def snapshot_id(manifest: Any) -> str:
    digest = digest_json(
        manifest,
        purpose="snapshot_manifest",
        schema_uri=f"{SCHEMA_BASE}snapshot.schema.json",
    ).removeprefix("sha256:")
    return f"snap_sha256_{digest}"


def receipt_id(receipt: dict[str, Any]) -> str:
    unsigned = dict(receipt)
    unsigned.pop("receipt_id", None)
    digest = digest_json(
        unsigned,
        purpose="receipt_manifest",
        schema_uri=f"{SCHEMA_BASE}receipt.schema.json",
    ).removeprefix("sha256:")
    return f"receipt_sha256_{digest}"


def validate_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\0" in value:
        raise ContractError(f"invalid repository-relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ContractError(f"invalid repository-relative path: {value!r}")
    if path.parts and ":" in path.parts[0]:
        raise ContractError(f"invalid repository-relative path: {value!r}")
    return path
