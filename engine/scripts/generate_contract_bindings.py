from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


ENGINE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ENGINE_ROOT.parent
SCHEMA_PATH = ENGINE_ROOT / "schemas" / "v2" / "contract.schema.json"
OUTPUT_ROOT = ENGINE_ROOT / "generated" / "contracts_v2"
ENTITIES = (
    "Repository",
    "Snapshot",
    "Authority",
    "Run",
    "Stage",
    "Event",
    "Callsite",
    "Observation",
    "Finding",
    "Candidate",
    "Evaluation",
    "Patch",
    "Artifact",
    "Receipt",
    "Error",
)


def _python_type(schema: dict[str, Any]) -> str:
    reference = schema.get("$ref", "").rsplit("/", 1)[-1]
    if reference in {"ArtifactRefs"}:
        return "list[str]"
    if reference in {"StringMap"}:
        return "dict[str, str]"
    if reference:
        return "str"
    if "const" in schema:
        return f"Literal[{schema['const']!r}]"
    if "enum" in schema:
        return "Literal[" + ", ".join(repr(item) for item in schema["enum"]) + "]"
    value_type = schema.get("type")
    if isinstance(value_type, list):
        non_null = [item for item in value_type if item != "null"]
        inner = _python_type({**schema, "type": non_null[0]}) if non_null else "None"
        return f"{inner} | None" if "null" in value_type else inner
    if value_type == "string":
        return "str"
    if value_type == "integer":
        return "int"
    if value_type == "boolean":
        return "bool"
    if value_type == "array":
        return f"list[{_python_type(schema.get('items', {}))}]"
    if value_type == "object":
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            return f"dict[str, {_python_type(additional)}]"
        return "dict[str, Any]"
    return "Any"


def _typescript_type(schema: dict[str, Any]) -> str:
    reference = schema.get("$ref", "").rsplit("/", 1)[-1]
    if reference == "ArtifactRefs":
        return "string[]"
    if reference == "StringMap":
        return "Record<string, string>"
    if reference:
        return "string"
    if "const" in schema:
        return json.dumps(schema["const"], ensure_ascii=False)
    if "enum" in schema:
        return " | ".join(json.dumps(item, ensure_ascii=False) for item in schema["enum"])
    value_type = schema.get("type")
    if isinstance(value_type, list):
        return " | ".join(_typescript_type({**schema, "type": item}) for item in value_type)
    if value_type == "null":
        return "null"
    if value_type == "string":
        return "string"
    if value_type == "integer":
        return "number"
    if value_type == "boolean":
        return "boolean"
    if value_type == "array":
        return f"Array<{_typescript_type(schema.get('items', {}))}>"
    if value_type == "object":
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            return f"Record<string, {_typescript_type(additional)}>"
        return "Record<string, unknown>"
    return "unknown"


def _rust_type(schema: dict[str, Any]) -> str:
    reference = schema.get("$ref", "").rsplit("/", 1)[-1]
    if reference == "ArtifactRefs":
        return "Vec<String>"
    if reference == "StringMap":
        return "BTreeMap<String, String>"
    if reference:
        return "String"
    if "const" in schema or "enum" in schema:
        return "String"
    value_type = schema.get("type")
    if isinstance(value_type, list):
        non_null = [item for item in value_type if item != "null"]
        inner = _rust_type({**schema, "type": non_null[0]}) if non_null else "Value"
        return f"Option<{inner}>" if "null" in value_type else inner
    if value_type == "string":
        return "String"
    if value_type == "integer":
        return "i64" if schema.get("minimum", 0) < 0 else "u64"
    if value_type == "boolean":
        return "bool"
    if value_type == "array":
        return f"Vec<{_rust_type(schema.get('items', {}))}>"
    if value_type == "object":
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            return f"BTreeMap<String, {_rust_type(additional)}>"
        return "BTreeMap<String, Value>"
    return "Value"


def generate() -> None:
    raw = SCHEMA_PATH.read_bytes()
    schema = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    definitions = schema["$defs"]

    python_lines = [
        "from __future__ import annotations",
        "",
        "from typing import Any, Literal, NotRequired, TypedDict",
        "",
        f'SCHEMA_SHA256 = "{digest}"',
        "",
    ]
    typescript_lines = [
        f'export const SCHEMA_SHA256 = "{digest}" as const;',
        "",
    ]
    rust_lines = [
        "use serde::{Deserialize, Serialize};",
        "use serde_json::Value;",
        "use std::collections::BTreeMap;",
        "",
        f'pub const SCHEMA_SHA256: &str = "{digest}";',
        "",
    ]

    for entity in ENTITIES:
        definition = definitions[entity]
        required = set(definition["required"])
        python_fields: list[str] = []
        typescript_lines.append(f"export interface {entity} {{")
        rust_lines.extend(
            [
                "#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]",
                "#[serde(deny_unknown_fields)]",
                f"pub struct {entity} {{",
            ]
        )
        for name, field_schema in definition["properties"].items():
            python_type = _python_type(field_schema)
            if name not in required:
                python_type = f"NotRequired[{python_type}]"
            python_fields.append(f"    {name!r}: {python_type},")
            optional = "" if name in required else "?"
            typescript_lines.append(
                f"  {json.dumps(name)}{optional}: {_typescript_type(field_schema)};"
            )
            rust_name = f"r#{name}" if name in {"class", "type"} else name
            rust_type = _rust_type(field_schema)
            if name not in required and not rust_type.startswith("Option<"):
                rust_type = f"Option<{rust_type}>"
            if rust_name != name:
                rust_lines.append(f'    #[serde(rename = "{name}")]')
            if name not in required:
                rust_lines.append("    #[serde(default, skip_serializing_if = \"Option::is_none\")]")
            rust_lines.append(f"    pub {rust_name}: {rust_type},")
        python_lines.extend(
            [
                f'{entity} = TypedDict("{entity}", {{',
                *python_fields,
                "})",
                "",
            ]
        )
        typescript_lines.extend(["}", ""])
        rust_lines.extend(["}", ""])

    python_path = OUTPUT_ROOT / "python" / "promptectomy_contracts_v2.py"
    typescript_path = OUTPUT_ROOT / "typescript" / "contracts-v2.ts"
    rust_path = (
        REPOSITORY_ROOT
        / "rust"
        / "crates"
        / "promptectomy-contracts"
        / "src"
        / "generated.rs"
    )
    rust_schema = rust_path.parent.parent / "schema" / "contract.schema.json"
    rust_examples = rust_schema.parent / "examples"
    for path in (python_path, typescript_path, rust_path, rust_schema):
        path.parent.mkdir(parents=True, exist_ok=True)
    python_path.write_text("\n".join(python_lines), encoding="utf-8")
    typescript_path.write_text("\n".join(typescript_lines), encoding="utf-8")
    rust_path.write_text("\n".join(rust_lines), encoding="utf-8")
    rust_schema.write_bytes(raw)
    if rust_examples.exists():
        shutil.rmtree(rust_examples)
    shutil.copytree(SCHEMA_PATH.parent / "examples", rust_examples)


if __name__ == "__main__":
    generate()
