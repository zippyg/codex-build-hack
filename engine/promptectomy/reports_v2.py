from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .artifacts_v2 import ArtifactStore
from .contracts_v2 import canonical_json
from .state_v2 import StateError, StateStore


@dataclass(frozen=True)
class FrozenReport:
    snapshot_artifact_id: str
    markdown_artifact_id: str
    snapshot_digest: str
    markdown_digest: str


def freeze_report(
    state: StateStore, artifacts: ArtifactStore, run_id: str
) -> FrozenReport:
    run = state.get_run(run_id)
    if run is None:
        raise StateError(f"run does not exist: {run_id}")
    events = state.events_after(run_id, 0, limit=1000)
    if len(events) != run["last_sequence"]:
        raise StateError(
            f"report cannot freeze an incomplete event history for {run_id}: "
            f"expected {run['last_sequence']}, found {len(events)}"
        )
    snapshot: dict[str, Any] = {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/report-snapshot.schema.json",
        "schema_version": "2.0.0",
        "run": run,
        "events": [
            {
                "event_id": event["event_id"],
                "sequence": event["sequence"],
                "occurred_at": event["occurred_at"],
                "type": event["type"],
                "artifact_refs": event["artifact_refs"],
            }
            for event in events
        ],
    }
    snapshot_bytes = canonical_json(snapshot)
    snapshot_artifact = artifacts.put(
        snapshot_bytes,
        artifact_class="safe",
        media_type="application/json",
        pinned=True,
    )
    markdown_bytes = _render_markdown(snapshot).encode("utf-8")
    markdown_artifact = artifacts.put(
        markdown_bytes,
        artifact_class="safe",
        media_type="text/markdown",
        pinned=True,
    )
    artifacts.add_reference(
        snapshot_artifact.artifact_id, owner_type="report", owner_id=run_id
    )
    artifacts.add_reference(
        markdown_artifact.artifact_id, owner_type="report", owner_id=run_id
    )
    return FrozenReport(
        snapshot_artifact_id=snapshot_artifact.artifact_id,
        markdown_artifact_id=markdown_artifact.artifact_id,
        snapshot_digest=f"sha256:{hashlib.sha256(snapshot_bytes).hexdigest()}",
        markdown_digest=f"sha256:{hashlib.sha256(markdown_bytes).hexdigest()}",
    )


def _render_markdown(snapshot: dict[str, Any]) -> str:
    run = snapshot["run"]
    lines = [
        "# PROMPTECTOMY run report",
        "",
        f"- Run: `{run['run_id']}`",
        f"- Mode: `{run['mode']}`",
        f"- Status: `{run['status']}`",
        f"- Snapshot: `{run['snapshot_id']}`",
        f"- Highest support: `{run['highest_support_level']}`",
        f"- Cleanup: `{run['cleanup_state']}`",
        f"- Events: `{run['last_sequence']}`",
        "",
        "## Event timeline",
        "",
        "| Sequence | Time | Type | Artifacts |",
        "| ---: | --- | --- | ---: |",
    ]
    for event in snapshot["events"]:
        lines.append(
            f"| {event['sequence']} | `{event['occurred_at']}` | "
            f"`{event['type']}` | {len(event['artifact_refs'])} |"
        )
    lines.extend(
        [
            "",
            "This report is a deterministic view of the frozen safe event snapshot. ",
            "Protected, source, diagnostic, and executable artifact bodies are not embedded.",
            "",
        ]
    )
    return "\n".join(lines)
