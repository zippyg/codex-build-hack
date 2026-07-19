class LocalClient {
  responses = { create: (value: string) => value };
}

const local = new LocalClient();
local.responses.create("not OpenAI");
const text = "client.responses.create({ model: 'not code' })";
// client.responses.create({ model: "not code" });
