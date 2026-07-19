from openai import OpenAI

client = OpenAI()
client.responses.parse(model="gpt-5", input="fixture", text_format=dict)
