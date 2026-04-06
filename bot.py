import os
import time
import hmac
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from difflib import SequenceMatcher

# ── Config ─────────────────────────────────────────────────────────────────────

SUMSUB_APP_TOKEN  = os.environ["SUMSUB_APP_TOKEN"]
SUMSUB_SECRET_KEY = os.environ["SUMSUB_SECRET_KEY"]
SUMSUB_BASE_URL   = "https://api.sumsub.com"

SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_CHANNEL   = os.environ.get("SLACK_CHANNEL", "kyc-alerts")

EXPIRY_WARN_DAYS = 30
FUZZY_THRESHOLD  = 0.72

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
    
    # Sign using the path + query string (e.g. /resources/applicants?limit=100)
    headers = sumsub_headers("GET", prepared.path_url)
    prepared.headers.update(headers)

    with requests.Session() as s:
        resp = s.send(prepared, timeout=30)
    
    if resp.status_code != 200:
        print(f"DEBUG: Sumsub API Error {resp.status_code}: {resp.text}")
        
    resp.raise_for_status()
    return resp.json()

def get_all_applicants():
    applicants = []
    offset, limit = 0, 100

    while True:
        # Changed to the standard resources/applicants endpoint
        path = "/resources/applicants"
        params = {
            "limit": limit,
            "offset": offset,
            "reviewStatus": "completed",
        }

        try:
            data  = sumsub_get(path, params=params)
            # Standard Sumsub search response is a list or contains a 'list' object
            items = []
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("list", {}).get("items", data.get("items", []))

            if not items:
                break
            
            applicants.extend(items)
            
            # Pagination logic
            total = 0
            if isinstance(data, dict):
                total = data.get("list", {}).get("totalCount", data.get("total", 0))
            
            offset += limit
            if total > 0 and offset >= total:
                break
            if len(items) < limit: # Safety break if we get less than a full page
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

def slack_get(method, params=None):
    resp = requests.get(
        f"https://slack.com/api/{method}",
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
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
    resp.raise_for_status()
    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"Slack error [{method}]: {data.get('error')}")
    return data

def get_slack_users():
    users, cursor = [], None
    while True:
        params = {"limit": 200}
        if cursor:
            params["cursor"] = cursor
        data = slack_get("users.list", params=params)
        users.extend([
            u for u in data.get("members", [])
            if not u.get("is_bot") and not u.get("deleted") and u["id"] != "USLACKBOT"
        ])
        cursor = data.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    return users

def get_channel_id(name):
    clean_name = name.lstrip("#").lower()
    cursor = None
    while True:
        # types MUST include public and private for the bot to see them
        params = {"limit": 1000, "types": "public_channel,private_channel"}
        if cursor:
            params["cursor"] = cursor
        data = slack_get("conversations.list", params=params)
        for ch in data.get("channels", []):
            if ch.get("name").lower() == clean_name:
                return ch["id"]
        
        cursor = data.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
            
    raise RuntimeError(f"Канал #{name} не найден. Убедись, что: 1. Имя верное. 2. БОТ ДОБАВЛЕН В КАНАЛ (/invite @bot).")

# ── Name matching ──────────────────────────────────────────────────────────────

def normalize(name):
    return " ".join(name.lower().strip().split())

def similarity(a, b):
    return SequenceMatcher(None, normalize(a), normalize(b)).ratio()

def find_slack_user(full_name, slack_users):
    if not full_name or full_name == "—":
        return None
    best_score, best_user = 0.0, None
    for user in slack_users:
        profile = user.get("profile", {})
        score   = max(
            similarity(full_name, profile.get("real_name",    "")),
            similarity(full_name, profile.get("display_name", "")),
        )
        if score > best_score:
            best_score, best_user = score, user
    return best_user if best_score >= FUZZY_THRESHOLD else None

# ── Report ─────────────────────────────────────────────────────────────────────

def build_block(alert, slack_user):
    name_str = f"<@{slack_user['id']}>" if slack_user else f"*{alert['full_name']}* _(не найден в Slack)_"

    if alert["expired"]:
        status = f"🔴 Истёк *{abs(alert['days_left'])} дн. назад* ({alert['expiry_date']})"
    elif alert["days_left"] <= 7:
        status = f"🚨 Истекает через *{alert['days_left']} дн.* ({alert['expiry_date']})"
    else:
        status = f"🟡 Истекает через *{alert['days_left']} дн.* ({alert['expiry_date']})"

    text = f"{name_str}\nДокумент: `{alert['doc_type']}` | №: `{alert['doc_number']}`\n{status}"
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}

def post_report(alerts, slack_users):
    now_str  = datetime.now(tz=timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    expired  = sorted([a for a in alerts if a["expired"]],     key=lambda x: x["days_left"])
    expiring = sorted([a for a in alerts if not a["expired"]], key=lambda x: x["days_left"])

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🛂 KYC Document Expiry Report", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": (
            f"📅 {now_str}  |  🔴 Истекло: *{len(expired)}* |  🟡 Скоро: *{len(expiring)}*"
        )}]},
        {"type": "divider"},
    ]

    if expired:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*🔴 Уже истекли:*"}})
        for a in expired:
            blocks.append(build_block(a, find_slack_user(a["full_name"], slack_users)))
            blocks.append({"type": "divider"})

    if expiring:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*🟡 Истекают в течение {EXPIRY_WARN_DAYS} дней:*"}})
        for a in expiring:
            blocks.append(build_block(a, find_slack_user(a["full_name"], slack_users)))
            blocks.append({"type": "divider"})

    if not alerts:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "✅ Все документы актуальны."}})

    channel_id = get_channel_id(SLACK_CHANNEL)
    slack_post("chat.postMessage", {
        "channel": channel_id,
        "blocks":  blocks,
        "text":    f"KYC Report: {len(alerts)} записей требуют внимания",
    })

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("1/4 Загружаем Slack юзеров...")
    slack_users = get_slack_users()
    print(f"    Найдено: {len(slack_users)}")

    print("2/4 Загружаем applicants из Sumsub...")
    applicants = get_all_applicants()
    print(f"    Найдено: {len(applicants)}")

    print("3/4 Проверяем документы...")
    alerts = []
    for app in applicants:
        try:
            # Optimize: use data from list if available
            if "info" in app and app["info"].get("idDocs"):
                detail = app
            else:
                detail = get_applicant_detail(app["id"])
                
            result = check_expiry(detail)
            if result:
                alerts.append(result)
                flag = "🔴" if result["expired"] else "🟡"
                print(f"    {flag} {result['full_name']} — {result['doc_type']} — {result['expiry_date']}")
        except Exception as e:
            print(f"    ⚠️  Ошибка для ID {app.get('id')}: {e}")
            continue

    print(f"4/4 Отправляем в #{SLACK_CHANNEL}... ({len(alerts)} записей)")
    post_report(alerts, slack_users)
    print("✅ Готово!")

if __name__ == "__main__":
    main()
