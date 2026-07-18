"""Parent-owned sealed holdout verification. Codex never calls this module."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .contracts import LedgerEventV1, Verdict
from .replay import replay


@dataclass
class HoldoutVerifier:
    """A verifier instance may grade each callsite's sealed holdout exactly once."""

    verified: set[str] = field(default_factory=set)

    def verify(
        self,
        module_path: str | Path,
        events: list[LedgerEventV1],
        kind: Literal["structured", "classifier", "freeform"],
    ) -> Verdict:
        callsite_id = events[0].callsite_id if events else Path(module_path).stem
        if callsite_id in self.verified:
            raise RuntimeError(f"sealed holdout for {callsite_id} was already run")
        self.verified.add(callsite_id)
        if kind == "freeform":
            return Verdict(
                callsite_id=callsite_id,
                status="NOT_COMPILABLE",
                reason="freeform_generation_requires_model",
                holdout_n=len(events),
            )
        result = replay(module_path, events, kind)
        if result.error:
            return Verdict(
                callsite_id=callsite_id,
                status="ERROR",
                reason=result.error,
                holdout_n=len(events),
                module_path=str(module_path),
            )
        assert result.score is not None
        agreement = result.score.agreement or 0.0
        qualifies = agreement >= 0.95 and (kind != "classifier" or (result.score.macro_f1 or 0.0) >= 0.90)
        status = "COMPILED" if agreement == 1.0 else "COMPILED_WITH_DIFFS" if qualifies else "NOT_COMPILABLE"
        return Verdict(
            callsite_id=callsite_id,
            status=status,
            reason="recorded_model_behaviour_preservation",
            agreement=agreement,
            holdout_n=len(events),
            diffs=result.score.diffs,
            module_path=str(module_path),
            median_latency_ms=result.median_latency_ms,
        )
