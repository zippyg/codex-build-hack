"""Leakage-resistant traffic splitting grouped by canonical requests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .contracts import LedgerEventV1


@dataclass(frozen=True)
class Splits:
    train: list[LedgerEventV1]
    dev: list[LedgerEventV1]
    holdout: list[LedgerEventV1]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def request_hash(event: LedgerEventV1) -> str:
    request = {"input": event.request_input, "params": event.request_params}
    return hashlib.sha256(f"{event.callsite_id}:{canonical_json(request)}".encode()).hexdigest()


def bucket(event: LedgerEventV1) -> int:
    return int(request_hash(event), 16) % 100


def split(events: list[LedgerEventV1]) -> Splits:
    train: list[LedgerEventV1] = []
    dev: list[LedgerEventV1] = []
    holdout: list[LedgerEventV1] = []
    for event in events:
        value = bucket(event)
        if value < 60:
            train.append(event)
        elif value < 80:
            dev.append(event)
        else:
            holdout.append(event)
    return Splits(train=train, dev=dev, holdout=holdout)
