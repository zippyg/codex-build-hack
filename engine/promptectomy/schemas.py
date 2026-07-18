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


def write_schemas(destination: str | Path | None = None) -> list[Path]:
    target = Path(destination) if destination is not None else Path(__file__).parents[1] / "schemas"
    target.mkdir(parents=True, exist_ok=True)
    schemas = {
        "audit-v1.json": AuditReport.model_json_schema(),
        "synthesis-result-v1.json": SynthesisResultV1.model_json_schema(),
        "verdict-v1.json": Verdict.model_json_schema(),
    }
    written: list[Path] = []
    for name, schema in schemas.items():
        path = target / name
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":
    write_schemas()
