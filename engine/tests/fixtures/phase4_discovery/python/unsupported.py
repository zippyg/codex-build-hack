import anthropic  # noqa: F401 - unsupported provider fixture
import openai

client = openai.OpenAI()
client.chat.completions.create(model="gpt-4", messages=[])
openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=[])
