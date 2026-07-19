import { OpenAI as Client } from "openai";

const client = new Client();
client.responses.parse({ model: "gpt-5", input: "fixture", text_format: {} });
