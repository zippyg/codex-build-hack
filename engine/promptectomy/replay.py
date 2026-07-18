"""Offline replay of a generated engine against recorded traffic."""

from __future__ import annotations

import importlib.util
import signal
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal

from .contracts import LedgerEventV1
from .guard import assert_pure
from .scoring import Score, score

CALL_TIMEOUT_SECONDS = 0.100


@dataclass(frozen=True)
class ReplayResult:
    score: Score | None
    passed: int
    total: int
    median_latency_ms: float | None
    error: str = ""


def load_engine(module_path: str | Path) -> Callable[[Any, dict[str, Any]], Any]:
    path = Path(module_path)
    assert_pure(path)
    spec = importlib.util.spec_from_file_location(f"promptectomy_generated_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load generated module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = getattr(module, "run", None)
    if not callable(run):
        raise TypeError(f"generated module {path} does not expose run(input, params)")
    return run


class EngineTimeout(TimeoutError):
    pass


def _raise_timeout(_signum: int, _frame: Any) -> None:
    raise EngineTimeout(f"generated engine exceeded {CALL_TIMEOUT_SECONDS * 1000:.0f}ms per-call limit")


def run_with_timeout(run: Callable[[Any, dict[str, Any]], Any], input_value: Any, params: dict[str, Any]) -> tuple[Any, float]:
    """Run one engine call under the Unix wall-clock budget used by the verifier."""
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, CALL_TIMEOUT_SECONDS)
    started = time.perf_counter()
    try:
        result = run(input_value, params)
        elapsed_ms = (time.perf_counter() - started) * 1000
        return result, elapsed_ms
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def replay(
    module_path: str | Path,
    events: list[LedgerEventV1],
    kind: Literal["structured", "classifier", "freeform"],
) -> ReplayResult:
    if kind == "freeform":
        return ReplayResult(score=score(kind, []), passed=0, total=0, median_latency_ms=None)
    try:
        run = load_engine(module_path)
        cases: list[tuple[LedgerEventV1, Any]] = []
        latencies: list[float] = []
        for event in events:
            got, elapsed_ms = run_with_timeout(run, event.request_input, event.request_params)
            cases.append((event, got))
            latencies.append(elapsed_ms)
        result = score(kind, cases)
        return ReplayResult(
            score=result,
            passed=len(cases) - len(result.diffs),
            total=len(cases),
            median_latency_ms=statistics.median(latencies) if latencies else None,
        )
    except Exception as exc:
        return ReplayResult(score=None, passed=0, total=len(events), median_latency_ms=None, error=f"{type(exc).__name__}: {exc}")
