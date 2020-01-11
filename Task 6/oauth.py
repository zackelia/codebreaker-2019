import base64
import requests

token_url = "https://register.terrortime.app/oauth2/token"
client_id = "natalie--vhost-32@terrortime.app"
client_secret = "dKtjzdmMcGaH9I"

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization":"Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode(),
    "X-Server-Select": "oauth"
}
data = {
    "audience": "",
    "grant_type": "client_credentials",
    "scope": "chat"
}

response = requests.post(token_url, headers=headers, data=data)
access_token = response.json()["access_token"]

print(access_token)
