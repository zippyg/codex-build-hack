"""Deterministically extract ticket facts from the captured ticket format."""

import re


_ORDER_ID = re.compile(r"\bDEMO-\d+\b")
_TIER = re.compile(r"\b(basic|plus|premium)\b", re.IGNORECASE)
_PRODUCT = re.compile(
    r"\b(wireless headphones|smart kettle|travel adapter|desk lamp)\b",
    re.IGNORECASE,
)
_MONEY = re.compile(r"\b(USD|EUR|GBP)\s+(\d+(?:\.\d+)?)\b", re.IGNORECASE)


def run(input, params):
    """Return the normalized facts contained in a support ticket prompt."""
    order_id = _ORDER_ID.search(input)
    tier = _TIER.search(input)
    product = _PRODUCT.search(input)
    money = _MONEY.search(input)
    return {
        "order_id": order_id.group(0) if order_id else None,
        "tier": tier.group(1).lower() if tier else None,
        "product": product.group(1).lower() if product else None,
        "amount": float(money.group(2)) if money else None,
        "currency": money.group(1).upper() if money else None,
    }
