"""Pinned, deliberately small token pricing table used for ledger estimates."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import Usage


@dataclass(frozen=True)
class ModelPrice:
    input_per_million: float
    output_per_million: float


# Update this table only as an explicit versioned product decision. Unknown models
# intentionally produce no estimate rather than a plausible-looking number.
PRICING_VERSION = "2026-07-18"
PRICES: dict[str, ModelPrice] = {
    "gpt-4.1": ModelPrice(2.00, 8.00),
    "gpt-4.1-mini": ModelPrice(0.40, 1.60),
    "gpt-4.1-nano": ModelPrice(0.10, 0.40),
    "gpt-4o": ModelPrice(2.50, 10.00),
    "gpt-4o-mini": ModelPrice(0.15, 0.60),
}


def estimate_cost(usage: Usage, model: str) -> float | None:
    """Return the pinned USD estimate for a single request, or ``None`` if unknown."""
    price = next(
        (value for prefix, value in sorted(PRICES.items(), key=lambda item: len(item[0]), reverse=True) if model == prefix or model.startswith(f"{prefix}-")),
        None,
    )
    if price is None:
        return None
    return round(
        (usage.input_tokens * price.input_per_million + usage.output_tokens * price.output_per_million) / 1_000_000,
        9,
    )
