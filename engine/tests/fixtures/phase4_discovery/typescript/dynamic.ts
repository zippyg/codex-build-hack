import OpenAI from "openai";

const client = new OpenAI();
const operation = "create";
client.responses[operation]({ model: "gpt-5", input: "fixture" });
