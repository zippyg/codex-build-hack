import asyncio
import openai
from openai import AsyncOpenAI

client = AsyncOpenAI(max_retries=3)
responses = client.responses


async def declared_wrapper() -> object:
    try:
        return await responses.create(
            model="gpt-5",
            input="fixture",
            stream=True,
            tools=[],
            text={"format": {"type": "json_schema"}},
            timeout=10,
        )
    except (openai.APIError, asyncio.CancelledError):
        raise
