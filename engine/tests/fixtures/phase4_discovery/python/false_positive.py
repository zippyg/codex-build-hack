class LocalResponses:
    def create(self, value: str) -> str:
        return value


local = LocalResponses()
local.responses.create("not OpenAI")
text = "client.responses.create(model='not code')"
