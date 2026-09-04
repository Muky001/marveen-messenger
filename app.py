import os
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

VERIFY_TOKEN = os.environ.get("VERIFY_TOKEN", "marveen123")
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

@app.route("/webhook", methods=["GET"])
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json
    if data.get("object") == "page":
        for entry in data.get("entry", []):
            for event in entry.get("messaging", []):
                if "message" in event:
                    sender_id = event["sender"]["id"]
                    text = event["message"].get("text", "")
                    if text:
                        reply = get_claude_reply(text)
                        send_message(sender_id, reply)
    return "OK", 200

def get_claude_reply(text):
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    body = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": text}]
    }
    r = requests.post("https://api.anthropic.com/v1/messages", json=body, headers=headers)
    return r.json()["content"][0]["text"]

def send_message(recipient_id, text):
    url = f"https://graph.facebook.com/v19.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }
    requests.post(url, json=payload)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
