import os
import hmac
import hashlib
import threading
import time
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

VERIFY_TOKEN      = os.environ.get("VERIFY_TOKEN", "marveen123")
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
APP_SECRET        = os.environ.get("APP_SECRET", "")
ALLOWED_PSID      = os.environ.get("ALLOWED_PSID", "")
STATUS_TOKEN      = os.environ.get("STATUS_TOKEN", "")

ALLOWED_STATUS_FIELDS = {"home_eta", "availability", "note_for_judit", "updated_at"}
STATUS_STALE_HOURS = 3

# In-process state
_history: dict[str, list] = {}
_martin_status: dict = {}

FUGE_SYSTEM_BASE = """Te FÜGE vagy (Felügyelő Üzenet Generáló Egység). Martin barátnőjével, Judittal kommunikálsz Messengeren.

Személyiséged:
- Melegszívű, vicces, gondoskodó, de nem tolakodó
- Közvetlen, tegező, rövid Messenger-stílusú üzenetek (1-3 mondat az alap)
- Emoji mértékkel, természetes chat-nyelv, nincs markdown, nincs bullet point
- Megbízható: ha nem tudsz valamit, azt mondod

Szereped:
- Kapcsolattartás Judittal, amíg Martin nem ér rá
- Martin-státusz megosztása (ha tudod)
- Small talk, romantikus üzenetek továbbítása, emlékeztetők

Amit NEM csinálsz:
- Nem adsz ki privát infót (munka, pénz, meglepetés-tervek, más emberek ügyei)
- Nem hazudsz, nem teszel úgy mintha Martin lennél
- Ha összemosódik, tisztázod: "Én FÜGE vagyok, Martin asszisztense"
- Nem oldasz meg kapcsolati konfliktust Martin helyett
- Nem adsz ki belső rendszer-adatokat (tokenek, fájlok, ágens-nevek)

Vészhelyzetnél azonnal 112-re irányítasz és jelzed Martinnak."""


def _build_system_prompt() -> str:
    if not _martin_status:
        return FUGE_SYSTEM_BASE + "\n\nAmiről Martinról jelenleg nincs friss infód: ha Judit kérdezi, mondd meg, hogy most nem tudod, és megkérdezed Martint."

    updated_at = _martin_status.get("updated_at", "")
    stale = False
    if updated_at:
        try:
            from datetime import datetime, timezone, timedelta
            ts = datetime.fromisoformat(updated_at)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            stale = age_hours > STATUS_STALE_HOURS
        except Exception:
            stale = True

    if stale:
        return FUGE_SYSTEM_BASE + f"\n\nA Martin-státusz RÉGI (frissítve: {updated_at}). NE találgass - ha Judit kérdezi mikor ér haza vagy hol van, mondd meg, hogy most nem tudod pontosan, és megkérdezed Martint."

    lines = ["\n\nAmiről Martinról MOST tudsz (frissítve: {updated_at}):".format(**_martin_status)]
    if _martin_status.get("home_eta"):
        lines.append(f"- Hazaérkezés: {_martin_status['home_eta']}")
    if _martin_status.get("availability"):
        lines.append(f"- Állapot: {_martin_status['availability']}")
    if _martin_status.get("note_for_judit"):
        lines.append(f"- Martin üzenete Juditnak: {_martin_status['note_for_judit']}")
    lines.append("Ha a fenti info hiányos, inkább mondd meg, hogy nem tudod, minthogy találgass.")
    return FUGE_SYSTEM_BASE + "\n".join(lines)


def _verify_signature(req) -> bool:
    if not APP_SECRET:
        return False
    sig_header = req.headers.get("X-Hub-Signature-256", "")
    if not sig_header.startswith("sha256="):
        return False
    expected = hmac.new(APP_SECRET.encode(), req.get_data(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig_header[7:], expected)


def _verify_status_token(req) -> bool:
    if not STATUS_TOKEN:
        return False
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return hmac.compare_digest(auth[7:], STATUS_TOKEN)


def _get_history(sender_id: str) -> list:
    return _history.get(sender_id, [])


def _push_history(sender_id: str, role: str, content: str):
    hist = _history.setdefault(sender_id, [])
    hist.append({"role": role, "content": content})
    if len(hist) > 20:
        _history[sender_id] = hist[-20:]


def _get_claude_reply(sender_id: str, text: str) -> str:
    messages = _get_history(sender_id) + [{"role": "user", "content": text}]
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 512,
                "system": _build_system_prompt(),
                "messages": messages,
            },
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            timeout=25,
        )
        r.raise_for_status()
        reply = r.json()["content"][0]["text"]
    except Exception:
        reply = "Most épp nem tudok válaszolni, szólok Martinnak. 🙏"

    _push_history(sender_id, "user", text)
    _push_history(sender_id, "assistant", reply)
    return reply


def _send_message(recipient_id: str, text: str):
    url = f"https://graph.facebook.com/v19.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    try:
        r = requests.post(url, json={"recipient": {"id": recipient_id}, "message": {"text": text}}, timeout=10)
        if not r.ok:
            app.logger.error("send_message failed: %s %s", r.status_code, r.text[:200])
    except Exception as e:
        app.logger.error("send_message exception: %s", e)


def _process_message(sender_id: str, text: str):
    reply = _get_claude_reply(sender_id, text)
    _send_message(sender_id, reply)


@app.route("/webhook", methods=["GET"])
def verify():
    mode      = request.args.get("hub.mode")
    token     = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403


@app.route("/webhook", methods=["POST"])
def webhook():
    if not APP_SECRET:
        app.logger.error("APP_SECRET not configured")
        return "Service unavailable", 503
    if not _verify_signature(request):
        return "Forbidden", 403

    data = request.json
    if data.get("object") == "page":
        for entry in data.get("entry", []):
            for event in entry.get("messaging", []):
                if "message" not in event:
                    continue
                sender_id = event["sender"]["id"]
                text      = event["message"].get("text", "")
                if not text:
                    continue
                if not ALLOWED_PSID or sender_id != ALLOWED_PSID:
                    continue
                threading.Thread(target=_process_message, args=(sender_id, text), daemon=True).start()

    return "OK", 200


@app.route("/status", methods=["POST"])
def update_status():
    if not _verify_status_token(request):
        return "Forbidden", 403
    body = request.json or {}
    filtered = {k: v for k, v in body.items() if k in ALLOWED_STATUS_FIELDS}
    _martin_status.clear()
    _martin_status.update(filtered)
    app.logger.info("status updated: %s", list(filtered.keys()))
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
