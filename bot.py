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

# Reusable session to prevent opening/closing TCP connections on every request
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
    
    headers = sumsub_headers("GET", prepared.path_url)
    prepared.headers.update(headers)

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
        params = {
            "limit": limit,
            "offset": offset,
            "reviewStatus": "completed",
        }

        try:
            data  = sumsub_get(path, params=params)
            list_data = data.get("list", {})
            items = list_data.get("items", [])

            if not items:
                break
            
            applicants.extend(items)
            total = list_data.get("totalCount", 0)
            
            offset += limit
            if offset >= total or len(items) < limit:
                break
                
        except Exception as e:
            print(f"    Ошибка при загрузке списка: {e}")
            break

    return applicants

def get_applicant_detail(applicant_id):
    return sumsub_get(f"/resources/applicants/{applicant_id}/one")

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
    first     = (info.get("firstName") or "").strip()
    last      = (info.get("lastName")  or "").strip()
    full_name = f"{first} {last}".strip() or "—"

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
        "applicant_id": applicant.get("id"),
        "full_name":    full_name,
        "doc_type":      worst_doc.get("idDocType", "UNKNOWN") if worst_doc else "UNKNOWN",
        "doc_number":    worst_doc.get("number", "—") if worst_doc else "—",
        "expiry_date":  worst_expiry.strftime("%d.%m.%Y"),
        "days_left":     days_left,
        "expired":       days_left < 0,
    }

# ── Slack API ──────────────────────────────────────────────────────────────────

def slack_get(method,
