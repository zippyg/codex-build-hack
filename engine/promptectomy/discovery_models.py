from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Language = Literal["python", "typescript", "javascript"]
Operation = Literal["responses.create", "responses.parse"]


@dataclass(frozen=True)
class DiscoveredCall:
    line: int
    language: Language
    operation: Operation
    normalized_ast_digest: str
    enclosing_symbol: str
    features: tuple[str, ...]
    ast_ordinal: int = 0
    adapter_version: str = ""
    stability: Literal["reference", "stable"] = "stable"


@dataclass(frozen=True)
class DiscoveryGap:
    code: str
    highest_level: Literal["L0", "L1"]
    next_action: str


@dataclass(frozen=True)
class DiscoveryResult:
    calls: tuple[DiscoveredCall, ...]
    gaps: tuple[DiscoveryGap, ...]
