import OpenAI from "openai";

const client = new OpenAI({ maxRetries: 3 });
const alias = client;
const responses = alias.responses;

export async function declaredWrapper(signal: AbortSignal) {
  try {
    return await responses.create({
      model: "gpt-5",
      input: "fixture",
      stream: true,
      tools: [],
      text: { format: { type: "json_schema" } },
      signal,
    });
  } catch (error) {
    throw error;
  }
}
