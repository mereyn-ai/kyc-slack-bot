import os
import sys
import time
import hmac
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from difflib import SequenceMatcher

# ── Config ─────────────────────────────────────────────────────────────────────

SUMSUB_APP_TOKEN  = os.environ.get("SUMSUB_APP_TOKEN")
SUMSUB_SECRET_KEY = os.environ.get("SUMSUB_SECRET_KEY")
SLACK_BOT_TOKEN   = os.environ.get("SLACK_BOT_TOKEN")

if not all([SUMSUB_APP_TOKEN, SUMSUB_SECRET_KEY, SLACK_BOT_TOKEN]):
    print("CRITICAL: Missing required environment variables (SUMSUB_APP_TOKEN, SUMSUB_SECRET_KEY, SLACK_BOT_TOKEN).")
    sys.exit(1)

SUMSUB_BASE_URL   = "https://api.sumsub.com"
SLACK_CHANNEL     = os.environ.get("SLACK_CHANNEL", "kyc-alerts")

EXPIRY_WARN_DAYS = 30
FUZZY_THRESHOLD  = 0.72

# Reusable session to improve performance and stability
sumsub_session = requests.Session()

# ── Sumsub API ─────────────────────────────────────────────────────────────────

def sumsub_headers(method, path, body=b""):
    ts  = str(int(time.time()))
    msg = (ts + method.upper() + path).encode() + body
    sig = hmac.new(SUMSUB_SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()
    return {
        "X-App-Token":      SUMSUB_APP_TOKEN,
        "X-App-Access-Sig": sig,
        "X-App-Access-Ts":  ts,
        "Accept":           "application/json",
    }

def sumsub_get(path, params=None):
    url = SUMSUB_BASE_URL + path
    req = requests.Request("GET", url, params=params)
    prepared = req.prepare()
    prepared.headers.update(sumsub_headers("GET", prepared.path_url))

    resp = sumsub_session.send(prepared, timeout=30)
    if resp.status_code != 200:
        print(f"DEBUG: Sumsub API Error {resp.status_code}: {resp.text}")
    resp.raise_for_status()
    return resp.json()

def get_all_applicants():
    applicants = []
    offset, limit = 0, 100
    while True:
        path = "/resources/applicants/-/main"
        params = {"limit": limit, "offset": offset, "reviewStatus": "completed"}
        try:
            data = sumsub_get(path, params=params)
            items = data.get("list", {}).get("items", [])
            if not items:
                break
            applicants.extend(items)
            if offset >= data.get("list", {}).get("totalCount", 0) or len(items) < limit:
                break
            offset += limit
        except Exception as e:
            print(f"    Error loading list: {e}")
            break
    return applicants

# ── Expiry check ───────────────────────────────────────────────────────────────

def parse_date(value):
    if not value:
        return None
    if isinstance(value, str) and "-" in value:
        try:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, TypeError):
        return None

def check_expiry(applicant):
    now      = datetime.now(tz=timezone.utc)
    deadline = now + timedelta(days=EXPIRY_WARN_DAYS)
    info      = applicant.get("info", {})
    full_name = f"{(info.get('firstName') or '').strip()} {(info.get('lastName') or '').strip()}".strip() or "—"

    id_docs = info.get("idDocs", [])
    worst_expiry, worst_doc = None, None

    for doc in id_docs:
        exp = parse_date(doc.get("validUntil") or doc.get("expiry"))
        if exp is None:
            continue
        if worst_expiry is None or exp < worst_expiry:
            worst_expiry, worst_doc = exp, doc

    if worst_expiry is None or worst_expiry > deadline:
        return None

    days_left = (worst_expiry - now).days
    return {
        "full_name":    full_name,
        "doc_type":     worst_doc.get("idDocType", "UNKNOWN") if worst_doc else "UNKNOWN",
        "doc_number":   worst_doc.get("number", "—") if worst_doc else "—",
        "expiry_date":  worst_expiry.strftime("%d.%m.%Y"),
        "days_left":    days_left,
        "expired":      days_left < 0,
    }

# ── Slack API ──────────────────────────────────────────────────────────────────

def slack_get(method, params=None):
    resp = requests.get(
        f"https://slack.com/api/{method}",
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        params=params,
        timeout=30,
    )
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"Slack error [{method}]: {data.get('error')}")
    return data

def slack_post(method, payload):
    resp = requests.post(
        f"https://slack.com/api/{method}",
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"Slack error [{method}]: {data.get('error')}")
    return data

def get_slack_users():
    users, cursor = [], None
    while True:
        params = {"limit": 200}
        if cursor: params["cursor"] = cursor
        data = slack_get("users.list", params=params)
        users.extend([u for u in data.get("members", []) if not u.get("is_bot") and not u.get("deleted")])
        cursor = data.get("response_metadata", {}).get("next_cursor")
        if not cursor: break
    return users

def get_channel_id(name):
    clean_name = name.lstrip("#").lower()
    cursor = None
    while True:
        params = {"limit": 1000, "types": "public_channel,private_channel"}
        if cursor: params["cursor"] = cursor
        data = slack_get("conversations.list", params=params)
        for ch in data.get("channels", []):
            if ch.get("name").lower() == clean_name: return ch["id"]
        cursor = data.get("response_metadata", {}).get("next_cursor")
        if not cursor: break
    raise RuntimeError(f"Channel #{name} not found.")

# ── Matching & Report ──────────────────────────────────────────────────────────

def similarity(a, b):
    return SequenceMatcher(None, a.lower().strip(), b.lower().strip()).ratio()

def find_slack_user(full_name, slack_users):
    if not full_name or full_name == "—": return None
    best_score, best_user = 0.0, None
    for user in slack_users:
        profile = user.get("profile", {})
        score = max(similarity(full_name, profile.get("real_name", "")), similarity(full_name, profile.get("display_name", "")))
        if score > best_score: best_score, best_user = score, user
    return best_user if best_score >= FUZZY_THRESHOLD else None

def build_block(alert, slack_user):
    name_str = f"<@{slack_user['id']}>" if slack_user else f"*{alert['full
