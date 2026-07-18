"""Deterministic synthetic support-ticket traffic. It contains no real PII."""

from __future__ import annotations

import random
from collections.abc import Iterator

_PRODUCTS = ("wireless headphones", "smart kettle", "travel adapter", "desk lamp")
_TIERS = ("basic", "plus", "premium")
_CURRENCIES = ("GBP", "USD", "EUR")
_TEMPLATES = (
    "Order {order_id}: my {product} arrived damaged. I am {tier} and paid {currency} {amount:.2f}.",
    "I need help with order {order_id}. The {product} charge of {currency} {amount:.2f} looks wrong, not a shipping issue.",
    "My {product} for order {order_id} has a bug after delivery. Please do not cancel my {tier} account.",
    "Where is order {order_id}? I am not disputing the {currency} {amount:.2f} payment, it is a shipping question.",
)


def tickets(count: int, *, seed: int = 7) -> Iterator[str]:
    rng = random.Random(seed)
    for number in range(count):
        yield rng.choice(_TEMPLATES).format(
            order_id=f"DEMO-{number + 1000:05d}",
            product=rng.choice(_PRODUCTS),
            tier=rng.choice(_TIERS),
            currency=rng.choice(_CURRENCIES),
            amount=rng.uniform(8, 180),
        )
