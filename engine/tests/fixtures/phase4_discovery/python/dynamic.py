from openai import OpenAI

client = OpenAI()
getattr(client, "responses").create(model="gpt-5", input="fixture")
