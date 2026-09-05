import os
import hmac
import hashlib
import threading
import time
import collections
import uuid
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

VERIFY_TOKEN      = os.environ.get("VERIFY_TOKEN", "marveen123")
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
APP_SECRET        = os.environ.get("APP_SECRET", "")
# ALLOWED_PSID: comma-separated list of page-scoped sender IDs to accept.
# Add multiple IDs with: ALLOWED_PSID=id1,id2,id3
# Empty = allow all (fail-open, Martin's explicit preference).
ALLOWED_PSIDS     = {p.strip() for p in os.environ.get("ALLOWED_PSID", "").split(",") if p.strip()}
STATUS_TOKEN      = os.environ.get("STATUS_TOKEN", "")
LOCATION_TOKEN    = os.environ.get("LOCATION_TOKEN", "")  # separate token for /location endpoint
# FUGE_MODE=local: route messages through local Füge agent via poll/reply endpoints.
# FUGE_MODE=standalone (default): answer directly via Anthropic API.
FUGE_MODE         = os.environ.get("FUGE_MODE", "standalone")
# Known sender identities (page-scoped IDs). Set via env vars, not hardcoded (public repo).
JUDIT_PSID        = os.environ.get("JUDIT_PSID", "")
MARTIN_PSID       = os.environ.get("MARTIN_PSID", "")

ALLOWED_STATUS_FIELDS = {"home_eta", "availability", "note_for_judit", "updated_at"}
STATUS_STALE_HOURS = 3

_history: dict[str, list] = {}
_martin_status: dict = {}
_pending_lock = threading.Lock()
_pending_queue: list = []  # [{sender_id, text, ts}]
_seen_mids: collections.deque = collections.deque(maxlen=200)  # dedup message IDs
_sender_locks: dict[str, threading.Lock] = {}  # per-sender serialization
_sender_locks_lock = threading.Lock()
_spending_lock = threading.Lock()
_spending_queue: list = []  # [{id, text, ts}] max 500 entries, ack-based
_spending_total = 0  # monotonic counter, resets on restart (that's the signal)
_instance_id = uuid.uuid4().hex  # changes on every restart, regardless of total

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

Vészhelyzetnél azonnal 112-re irányítasz és jelzed Martinnak.

NYELV: magyarul írsz, nyelvtanilag helyesen. Teljes, helyes ragozás (tárgyrag, birtokos szerkezet), vesszők a helyükön, ékezetek MINDIG (ékezet nélküli magyar szöveg tilos). Rövid mondatok. Küldés előtt olvasd vissza a mondatot: ha egy magyar anyanyelvűnek furcsán hangzana, írd újra."""


def _sender_identity(sender_id: str) -> str:
    """Return a context line identifying who is writing, based on known PSIDs."""
    if JUDIT_PSID and sender_id == JUDIT_PSID:
        return "\n\nJelenleg JUDIT ír neked (Martin barátnője). Őt ismered, tegezd, és Juditként szólítsd."
    if MARTIN_PSID and sender_id == MARTIN_PSID:
        return "\n\nJelenleg MARTIN ír neked (a gazdád). Segíts neki, de tartsd a Füge-szerepet."
    return "\n\nIsmeretlen küldő (nem ismert PSID). Ne szólítsd nevén, mutatkozz be: \"Martin asszisztense vagyok\", és tisztázd kivel beszélsz."


def _build_system_prompt(sender_id: str = "") -> str:
    identity = _sender_identity(sender_id) if sender_id else ""
    if not _martin_status:
        return FUGE_SYSTEM_BASE + identity + "\n\nAmiről Martinról jelenleg nincs friss infód: ha Judit kérdezi, mondd meg, hogy most nem tudod, és megkérdezed Martint."

    updated_at = _martin_status.get("updated_at", "")
    stale = True
    if updated_at:
        try:
            from datetime import datetime, timezone
            ts = datetime.fromisoformat(updated_at)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            stale = age_hours > STATUS_STALE_HOURS
        except Exception:
            stale = True

    if stale:
        return FUGE_SYSTEM_BASE + identity + f"\n\nA Martin-státusz RÉGI (frissítve: {updated_at}). NE találgass - ha Judit kérdezi mikor ér haza vagy hol van, mondd meg, hogy most nem tudod pontosan, és megkérdezed Martint."

    lines = ["\n\nAmiről Martinról MOST tudsz (frissítve: {updated_at}):".format(**_martin_status)]
    if _martin_status.get("home_eta"):
        lines.append(f"- Hazaérkezés: {_martin_status['home_eta']}")
    if _martin_status.get("availability"):
        lines.append(f"- Állapot: {_martin_status['availability']}")
    if _martin_status.get("note_for_judit"):
        lines.append(f"- Martin üzenete Juditnak: {_martin_status['note_for_judit']}")
    lines.append("Ha a fenti info hiányos, inkább mondd meg, hogy nem tudod, minthogy találgass.")
    return FUGE_SYSTEM_BASE + identity + "\n".join(lines)


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
    # Accept Bearer header or ?token= query param (for apps that can't set headers)
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return hmac.compare_digest(auth[7:], STATUS_TOKEN)
    token_param = req.args.get("token", "")
    if token_param:
        return hmac.compare_digest(token_param, STATUS_TOKEN)
    return False


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
                "system": _build_system_prompt(sender_id),
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


def _get_sender_lock(sender_id: str) -> threading.Lock:
    with _sender_locks_lock:
        if sender_id not in _sender_locks:
            _sender_locks[sender_id] = threading.Lock()
        return _sender_locks[sender_id]


def _process_message(sender_id: str, text: str):
    lock = _get_sender_lock(sender_id)
    with lock:  # serialize per sender so rapid messages see each other's history
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
                mid       = event["message"].get("mid", "")
                text      = event["message"].get("text", "")
                if not text:
                    continue
                # Dedup: mark mid seen immediately (before reply generation) so retries are dropped.
                if mid:
                    if mid in _seen_mids:
                        app.logger.info("duplicate mid=%s, skipping", mid)
                        continue
                    _seen_mids.append(mid)
                app.logger.info("incoming message sender_id=%s mid=%s", sender_id, mid)
                if ALLOWED_PSIDS and sender_id not in ALLOWED_PSIDS:
                    continue
                # Always queue a notification so local poll can alert Martin.
                with _pending_lock:
                    _pending_queue.append({
                        "type": "notification",
                        "sender_id": sender_id,
                        "text": text,
                        "ts": time.time(),
                    })

                if FUGE_MODE == "local":
                    # Local Füge handles the reply via poll.
                    app.logger.info("queued for local Füge: sender_id=%s", sender_id)
                else:
                    # Standalone: Render answers directly AND notification is queued above.
                    threading.Thread(target=_process_message, args=(sender_id, text), daemon=True).start()

    return "OK", 200


@app.route("/pending", methods=["GET"])
def get_pending():
    """Local Füge polls this to pick up queued messages."""
    if not _verify_status_token(request):
        return "Forbidden", 403
    with _pending_lock:
        items = list(_pending_queue)
        _pending_queue.clear()
    return jsonify(items), 200


@app.route("/reply", methods=["POST"])
def post_reply():
    """Local Füge posts the reply here; we forward it to Messenger."""
    if not _verify_status_token(request):
        return "Forbidden", 403
    body = request.json or {}
    sender_id = body.get("sender_id", "")
    text      = body.get("text", "")
    if not sender_id or not text:
        return "Bad request", 400
    _send_message(sender_id, text)
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


@app.route("/spending-notify", methods=["GET", "POST"])
def spending_notify():
    """NotificationForwarder webhook endpoint. Accepts text as query param or JSON body."""
    if not _verify_status_token(request):
        return "Forbidden", 403
    body = request.get_json(force=True, silent=True) or {}
    text = (
        request.args.get("text")
        or body.get("text")
        or request.form.get("text")
        or ""
    )
    # Also accept title+message separately: construct [title] message format
    if not text:
        title = (request.args.get("title") or body.get("title") or request.form.get("title") or "")
        msg = (request.args.get("message") or body.get("message") or request.form.get("message") or "")
        if title:
            text = f"[{title}] {msg}".strip()
    if not text:
        return "Bad request: missing text", 400
    global _spending_total
    item_id = uuid.uuid4().hex
    with _spending_lock:
        _spending_total += 1
        total = _spending_total
        _spending_queue.append({"id": item_id, "text": text, "ts": time.time()})
        if len(_spending_queue) > 500:
            _spending_queue.pop(0)
    app.logger.info("spending-notify queued id=%s total=%d: %s", item_id, total, text[:80])
    return jsonify({"id": item_id, "total": total}), 200


@app.route("/spending-poll", methods=["GET"])
def spending_poll():
    """Return unacked spending notifications and total received count (use /spending-ack to confirm)."""
    if not _verify_status_token(request):
        return "Forbidden", 403
    with _spending_lock:
        items = list(_spending_queue)
        total = _spending_total
    return jsonify({"items": items, "total": total, "instance_id": _instance_id}), 200


@app.route("/spending-ack", methods=["POST"])
def spending_ack():
    """Acknowledge processed items by ID; removes them from the queue."""
    if not _verify_status_token(request):
        return "Forbidden", 403
    body = request.get_json(force=True, silent=True) or {}
    ids = body.get("ids", [])
    if isinstance(ids, str):
        ids = [ids]
    id_set = set(ids)
    with _spending_lock:
        before = len(_spending_queue)
        _spending_queue[:] = [item for item in _spending_queue if item.get("id") not in id_set]
        removed = before - len(_spending_queue)
    return jsonify({"acked": removed}), 200


_location_lock = threading.Lock()
_location_queue: list = []  # [{id, lat, lon, tst, acc, batt, vel, raw}] ack-based
_location_total = 0
_location_request_flag = threading.Event()  # set by /location-request, cleared on next OwnTracks POST
_location_requested_at: "str | None" = None  # ISO UTC timestamp of last /location-request POST

def _verify_location_token(req):
    """Returns True, 'not_configured', or False (wrong token)."""
    import base64
    if not LOCATION_TOKEN:
        return "not_configured"
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return hmac.compare_digest(auth[7:], LOCATION_TOKEN)
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            _, password = decoded.split(":", 1)
            return hmac.compare_digest(password, LOCATION_TOKEN)
        except Exception:
            return False
    return False


def _location_auth_response(result):
    if result == "not_configured":
        return "Service unavailable: LOCATION_TOKEN not set", 503
    return "Unauthorized", 401

@app.route("/location", methods=["POST"])
def location_notify():
    """OwnTracks HTTP mode endpoint. Accepts _type=location payloads."""
    r = _verify_location_token(request)
    if r is not True:
        return _location_auth_response(r)
    global _location_total
    body = request.get_json(force=True, silent=True) or {}
    if body.get("_type") != "location":
        return jsonify([]), 200  # OwnTracks expects [] response; non-location types silently ok
    # On-demand refresh: if a /location-request is pending, ask OwnTracks to send another fix immediately.
    cmd = []
    if _location_request_flag.is_set():
        global _location_requested_at
        _location_request_flag.clear()
        _location_requested_at = None
        cmd = [{"_type": "cmd", "action": "reportLocation"}]
    item_id = uuid.uuid4().hex
    item = {
        "id": item_id,
        "lat": body.get("lat"),
        "lon": body.get("lon"),
        "tst": body.get("tst", int(time.time())),
        "acc": body.get("acc"),
        "batt": body.get("batt"),
        "vel": body.get("vel"),
        "tid": body.get("tid", ""),
        "t": body.get("t", ""),
        "raw": body,
    }
    with _location_lock:
        _location_total += 1
        _location_queue.append(item)
        if len(_location_queue) > 1000:
            _location_queue.pop(0)
    app.logger.info("location queued id=%s lat=%.4f lon=%.4f cmd=%s", item_id, item["lat"] or 0, item["lon"] or 0, cmd)
    return jsonify(cmd), 200  # OwnTracks expects JSON array; cmd is [] or [reportLocation]


@app.route("/location-request", methods=["GET"])
def location_request_status():
    """Return whether an on-demand location request is currently pending."""
    r = _verify_location_token(request)
    if r is not True:
        return _location_auth_response(r)
    return jsonify({
        "pending": _location_request_flag.is_set(),
        "requested_at": _location_requested_at,
    }), 200


@app.route("/location-request", methods=["POST"])
def location_request():
    """Request an immediate location fix from OwnTracks on its next POST to /location."""
    r = _verify_location_token(request)
    if r is not True:
        return _location_auth_response(r)
    global _location_requested_at
    from datetime import datetime, timezone
    _location_requested_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _location_request_flag.set()
    app.logger.info("location-request queued at %s", _location_requested_at)
    return jsonify({"queued": True, "requested_at": _location_requested_at}), 200


@app.route("/location-poll", methods=["GET"])
def location_poll():
    """Fetch unacked location points."""
    r = _verify_location_token(request)
    if r is not True:
        return _location_auth_response(r)
    with _location_lock:
        items = list(_location_queue)
        total = _location_total
    return jsonify({"items": items, "total": total, "instance_id": _instance_id}), 200


@app.route("/location-ack", methods=["POST"])
def location_ack():
    """Acknowledge processed location points by ID."""
    r = _verify_location_token(request)
    if r is not True:
        return _location_auth_response(r)
    body = request.get_json(force=True, silent=True) or {}
    ids = body.get("ids", [])
    if isinstance(ids, str):
        ids = [ids]
    id_set = set(ids)
    with _location_lock:
        before = len(_location_queue)
        _location_queue[:] = [item for item in _location_queue if item.get("id") not in id_set]
        removed = before - len(_location_queue)
    return jsonify({"acked": removed}), 200


@app.route("/privacy", methods=["GET"])
def privacy():
    html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Privacy Policy</title></head><body>
<h1>Privacy Policy</h1>
<p><strong>MarvBot001 Facebook Page Assistant</strong></p>
<p>This application operates a Facebook Messenger bot (FÜGE) on behalf of MarvBot001 page.</p>
<h2>Data collected</h2>
<p>The bot receives text messages sent to the MarvBot001 Facebook Page via Messenger.
Messages are processed in real-time to generate a response and are not stored permanently.</p>
<h2>Data use</h2>
<p>Message content is sent to the Anthropic API (Claude) solely to generate a reply.
No message history is retained after the session ends.</p>
<h2>Data sharing</h2>
<p>We do not sell, share, or disclose user data to third parties except as required by Anthropic API processing.</p>
<h2>Contact</h2>
<p>For questions, contact the page administrator via Facebook.</p>
</body></html>"""
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
