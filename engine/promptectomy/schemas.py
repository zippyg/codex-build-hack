"""Generate Codex output schemas from the frozen Pydantic contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .contracts import AuditReport, Verdict


class SynthesisResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    callsite_id: str
    status: Literal["completed", "needs_resume", "failed"]
    module_path: str | None = None
    summary: str = ""


def _strictify(node: object) -> object:
    """Rewrite a Pydantic JSON Schema into OpenAI strict structured-output form.

    Strict mode requires every object to set additionalProperties=false and to list EVERY property
    in `required` (optional fields stay nullable so null satisfies them), and rejects `default`.
    """
    if isinstance(node, dict):
        node.pop("default", None)
        if node.get("type") == "object" and isinstance(node.get("properties"), dict):
            node["additionalProperties"] = False
            node["required"] = list(node["properties"].keys())
        for value in node.values():
            _strictify(value)
    elif isinstance(node, list):
        for value in node:
            _strictify(value)
    return node


def write_schemas(destination: str | Path | None = None) -> list[Path]:
    target = Path(destination) if destination is not None else Path(__file__).parents[1] / "schemas"
    target.mkdir(parents=True, exist_ok=True)
    schemas = {
        "audit-v1.json": _strictify(AuditReport.model_json_schema()),
        "synthesis-result-v1.json": _strictify(SynthesisResultV1.model_json_schema()),
        "verdict-v1.json": _strictify(Verdict.model_json_schema()),
    }
    written: list[Path] = []
    for name, schema in schemas.items():
        path = target / name
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":
    write_schemas()
