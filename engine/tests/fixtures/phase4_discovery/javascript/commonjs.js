const OpenAI = require("openai");
const client = new OpenAI();

module.exports = async function run() {
  return client.responses.create({ model: "gpt-5", input: "fixture", tools: [] });
};
