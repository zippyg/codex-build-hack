from openai import OpenAI as Client

client = Client()
alias = client
alias.responses.create(model="gpt-5", input="fixture")
