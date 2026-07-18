"""Authoritative behavioural-preservation scorers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .contracts import Diff, LedgerEventV1
from .splitting import canonical_json


@dataclass(frozen=True)
class Score:
    agreement: float | None
    diffs: list[Diff]
    macro_f1: float | None = None


def expected_output(event: LedgerEventV1) -> Any:
    return event.response_normalized if event.response_normalized is not None else event.response_raw


def _label(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip().lower()
    if isinstance(value, dict):
        for key in ("label", "route", "category", "classification"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate.strip().lower()
    return None


def _diff(event: LedgerEventV1, expected: Any, got: Any, summary: str) -> Diff:
    return Diff(event_id=event.event_id, input=event.request_input, expected=expected, got=got, summary=summary)


def score_structured(cases: list[tuple[LedgerEventV1, Any]]) -> Score:
    diffs = [
        _diff(event, expected_output(event), got, "canonical_json_mismatch")
        for event, got in cases
        if canonical_json(expected_output(event)) != canonical_json(got)
    ]
    agreement = (len(cases) - len(diffs)) / len(cases) if cases else 0.0
    return Score(agreement=agreement, diffs=diffs)


def score_classifier(cases: list[tuple[LedgerEventV1, Any]]) -> Score:
    labels = sorted(
        {
            label
            for event, got in cases
            for label in (_label(expected_output(event)), _label(got))
            if label is not None
        }
    )
    diffs: list[Diff] = []
    expected_labels: list[str | None] = []
    actual_labels: list[str | None] = []
    for event, got in cases:
        expected = expected_output(event)
        expected_label, actual_label = _label(expected), _label(got)
        expected_labels.append(expected_label)
        actual_labels.append(actual_label)
        if expected_label != actual_label:
            diffs.append(_diff(event, expected, got, "top_label_mismatch"))
    agreement = (len(cases) - len(diffs)) / len(cases) if cases else 0.0
    if not labels:
        return Score(agreement=agreement, diffs=diffs, macro_f1=0.0)
    f1_values: list[float] = []
    for label in labels:
        true_positive = sum(expected == label and actual == label for expected, actual in zip(expected_labels, actual_labels))
        false_positive = sum(expected != label and actual == label for expected, actual in zip(expected_labels, actual_labels))
        false_negative = sum(expected == label and actual != label for expected, actual in zip(expected_labels, actual_labels))
        denominator = 2 * true_positive + false_positive + false_negative
        f1_values.append(2 * true_positive / denominator if denominator else 0.0)
    return Score(agreement=agreement, diffs=diffs, macro_f1=sum(f1_values) / len(f1_values))


def score(kind: Literal["structured", "classifier", "freeform"], cases: list[tuple[LedgerEventV1, Any]]) -> Score:
    if kind == "structured":
        return score_structured(cases)
    if kind == "classifier":
        return score_classifier(cases)
    return Score(agreement=None, diffs=[])
