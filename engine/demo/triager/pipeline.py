"""A deliberately small triager containing two low-entropy and one generative callsite."""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field


class Ticket(BaseModel):
    body: str = Field(min_length=1)


class TicketFacts(BaseModel):
    order_id: str | None = None
    tier: str | None = None
    product: str | None = None
    amount: float | None = None
    currency: str | None = None


def extract_ticket_facts(client: Any, ticket: str) -> dict[str, Any]:
    # promptectomy:callsite_id=extract_ticket_facts kind=structured
    response = client.responses.create(
        model="gpt-4.1-mini",
        input=("Extract order_id, tier, product, amount, and currency as a JSON object. " f"Ticket: {ticket}"),
        text={"format": {"type": "json_object"}},
    )
    return TicketFacts.model_validate(json.loads(response.output_text)).model_dump()


def route_ticket(client: Any, ticket: str) -> str:
    # promptectomy:callsite_id=route_ticket kind=classifier
    response = client.responses.create(
        model="gpt-4.1-mini",
        input=("Classify this support ticket as exactly billing, account, shipping, or bug. "
               "Respect negation and ambiguity: 'not a billing issue' is not billing. "
               f"Ticket: {ticket}"),
    )
    return response.output_text.strip().lower()


def draft_empathetic_reply(client: Any, ticket: str, route: str) -> str:
    # promptectomy:callsite_id=draft_empathetic_reply kind=freeform
    response = client.responses.create(
        model="gpt-4.1-mini",
        input=f"Draft a concise, empathetic reply for this {route} support ticket. Ticket: {ticket}",
    )
    return response.output_text


def triage(client: Any, ticket: str) -> dict[str, Any]:
    facts = extract_ticket_facts(client, ticket)
    route = route_ticket(client, ticket)
    return {"facts": facts, "route": route, "reply": draft_empathetic_reply(client, ticket, route)}


app = FastAPI(title="PROMPTECTOMY triager")


@app.post("/triage")
def triage_ticket(ticket: Ticket) -> dict[str, Any]:
    from openai import OpenAI

    return triage(OpenAI(max_retries=0, timeout=15.0), ticket.body)
