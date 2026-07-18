"""Build a keyless synthetic ledger with text-derivable ground truth.

No OPENAI_API_KEY is required. Each recorded output is exactly what a faithful model would return
for the ticket text, so a synthesized parser/classifier can match it. Ground truth reflects only the
fields actually present in each template, so absent fields are None (the honest structured target).
Run: uv run python -m demo.triager.capture [count]
"""

from __future__ import annotations

import random
import sys
import uuid
from pathlib import Path

from promptectomy.contracts import LedgerEventV1, Usage
from promptectomy.ledger import append

_PRODUCTS = ("wireless headphones", "smart kettle", "travel adapter", "desk lamp")
_TIERS = ("basic", "plus", "premium")
_CURRENCIES = ("GBP", "USD", "EUR")

# (route_label, present_fields, template)
_TEMPLATES = (
    ("shipping", {"order_id", "product", "tier", "amount", "currency"},
     "Order {order_id}: my {product} arrived damaged. I am {tier} and paid {currency} {amount:.2f}."),
    ("billing", {"order_id", "product", "amount", "currency"},
     "I need help with order {order_id}. The {product} charge of {currency} {amount:.2f} looks wrong, not a shipping issue."),
    ("bug", {"order_id", "product", "tier"},
     "My {product} for order {order_id} has a bug after delivery. Please do not cancel my {tier} account."),
    ("shipping", {"order_id", "amount", "currency"},
     "Where is order {order_id}? I am not disputing the {currency} {amount:.2f} payment, it is a shipping question."),
)

_EXTRACT_PROMPT = "Extract order_id, tier, product, amount, and currency as a JSON object. Ticket: {ticket}"
_ROUTE_PROMPT = (
    "Classify this support ticket as exactly billing, account, shipping, or bug. "
    "Respect negation and ambiguity: 'not a billing issue' is not billing. Ticket: {ticket}"
)
_REPLY_PROMPT = "Draft a concise, empathetic reply for this {route} support ticket. Ticket: {ticket}"


def _ledger_path() -> Path:
    return Path(__file__).resolve().parents[3] / ".promptectomy" / "ledger.jsonl"


def _event(callsite_id: str, kind: str, request_input: str, output: object, latency_ms: float, cost: float) -> LedgerEventV1:
    return LedgerEventV1(
        event_id=uuid.uuid4().hex,
        recorded_at="2026-07-18T09:00:00+00:00",
        repo_sha="synthetic",
        callsite_id=callsite_id,
        model="gpt-4.1-mini",
        request_input=request_input,
        request_params={"temperature": 0},
        response_normalized=output,
        usage=Usage(input_tokens=180, output_tokens=24, total_tokens=204),
        latency_ms=latency_ms,
        estimated_cost_usd=cost,
    )


def build(count: int = 240, seed: int = 7) -> int:
    rng = random.Random(seed)
    path = _ledger_path()
    if path.exists():
        path.unlink()
    written = 0
    for number in range(count):
        route_label, present, template = _TEMPLATES[rng.randrange(len(_TEMPLATES))]
        order_id = f"DEMO-{number + 1000:05d}"
        product = rng.choice(_PRODUCTS)
        tier = rng.choice(_TIERS)
        currency = rng.choice(_CURRENCIES)
        amount = round(rng.uniform(8, 180), 2)
        ticket = template.format(order_id=order_id, product=product, tier=tier, currency=currency, amount=amount)
        facts = {
            "order_id": order_id if "order_id" in present else None,
            "tier": tier if "tier" in present else None,
            "product": product if "product" in present else None,
            "amount": amount if "amount" in present else None,
            "currency": currency if "currency" in present else None,
        }
        append(path, _event("extract_ticket_facts", "structured", _EXTRACT_PROMPT.format(ticket=ticket), facts, rng.uniform(760, 1080), 0.0041))
        append(path, _event("route_ticket", "classifier", _ROUTE_PROMPT.format(ticket=ticket), route_label, rng.uniform(700, 980), 0.0032))
        append(path, _event("draft_empathetic_reply", "freeform", _REPLY_PROMPT.format(ticket=ticket, route=route_label), f"Thanks for reaching out about {order_id}. We're on it.", rng.uniform(1050, 1420), 0.0090))
        written += 3
    return written


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 240
    total = build(n)
    print(f"wrote {total} ledger events ({n} tickets x 3 callsites) to {_ledger_path()}")
