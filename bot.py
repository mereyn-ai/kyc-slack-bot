import os
import sys
import csv
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
    print("CRITICAL: Missing environment variables.")
    sys.exit(1)

SUMSUB_BASE_URL  = "https://api.sumsub.com"
SLACK_CHANNEL    = os.environ.get("SLACK_CHANNEL", "kyc-alerts")
CSV_FILE         = os.environ.get("CSV_FILE", "applicants.csv")

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
    resp = requests.get(
        SUMSUB_BASE_URL + path,
        headers=sumsub_headers("GET", path),
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()

def get_applicant_detail(applicant_id):
    return sumsub_get(f"/resources/applicants/{applicant_id}/one")

# ── Read CSV ───────────────────────────────────────────────────────────────────

def load_applicants_from_csv(filepath):
    """
    Читает CSV из Sumsub Dashboard экспорта.
    Берём только GREEN + completed applicants у которых есть реальное имя.
    """
    applicants = []

    with open(filepath, encoding="utf-8") as f:
        # Sumsub использует ; как разделитель
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            # Пропускаем не завершённых
            if row.get("result") != "GREEN":
                continue
            if row.get("status") not in ("completed", "init"):
                continue

            name = row.get("applicantName", "").strip()
            # Пропускаем applicants без имени (незавершённые)
            if not name or name.startswith("Applicant '"):
                continue

            applicants.append({
                "applicantId": row["applicantId"].strip('"'),
                "name":        name.strip('"'),
                "email":       row.get("applicantEmail", "").strip('"'),
                "sourceKey":   row.get("sourceKey", "").strip('"'),
            })

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

def check_expiry(detail, csv_name):
    now      = datetime.now(tz=timezone.utc)
    deadline = now + timedelta(days=EXPIRY_WARN_DAYS)

    info      = detail.get("info", {})
    first     = (info.get("firstName") or "").strip()
    last      = (info.get("lastName")  or "").strip()
    full_name = f"{first} {last}".strip() or csv_name

    id_docs = info.get("idDocs", [])
    worst_expiry, worst_doc = None, None

    for doc in id_docs:
        exp = parse_date(doc.get("validUntil") or doc.get("expiry"))
        if exp is None:
            continue
        # Пропускаем "вечные" документы (2099)
        if exp.year >= 2099:
            continue
        if worst_expiry is None or exp < worst_expiry:
            worst_expiry, worst_doc = exp, doc

    if worst_expiry is None or worst_expiry > deadline:
        return None

    days_left = (worst_expiry - now).days
    return {
        "applicant_id": detail.get("id"),
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
    name, cursor = name.lstrip("#").lower(), None
    while True:
        params = {"limit": 200, "types": "public_channel,private_channel"}
        if cursor:
            params["cursor"] = cursor
        data = slack_get("conversations.list", params=params)
        for ch in data.get("channels", []):
            if ch.get("name", "").lower() == name:
                return ch["id"]
        cursor = data.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    raise RuntimeError(f"Канал #{name} не найден. Добавь бота в канал!")

# ── Name matching ──────────────────────────────────────────────────────────────

def similarity(a, b):
    return SequenceMatcher(None, a.lower().strip(), b.lower().strip()).ratio()

def find_slack_user(full_name, slack_users):
    if not full_name or full_name == "—":
        return None
    best_score, best_user = 0.0, None
    for user in slack_users:
        profile = user.get("profile", {})
        score = max(
            similarity(full_name, profile.get("real_name", "")),
            similarity(full_name, profile.get("display_name", "")),
        )
        if score > best_score:
            best_score, best_user = score, user
    return best_user if best_score >= FUZZY_THRESHOLD else None

# ── Report ─────────────────────────────────────────────────────────────────────

def build_block(alert, slack_user):
    if slack_user:
        name_str = f"<@{slack_user['id']}>"
    else:
        name_str = f"*{alert['full_name']}* _(не найден в Slack)_"

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
    expired  = sorted([a for a in alerts if a["expired"]],      key=lambda x: x["days_left"])
    expiring = sorted([a for a in alerts if not a["expired"]], key=lambda x: x["days_left"])

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🛂 KYC Document Expiry Report", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": (
            f"📅 {now_str}  |  🔴 Истекло: *{len(expired)}*  |  🟡 Скоро: *{len(expiring)}*"
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

    print(f"2/4 Читаем CSV: {CSV_FILE}")
    if not os.path.exists(CSV_FILE):
        print(f"    ОШИБКА: файл {CSV_FILE} не найден!")
        sys.exit(1)
    applicants = load_applicants_from_csv(CSV_FILE)
    print(f"    GREEN+completed applicants: {len(applicants)}")

    print("3/4 Проверяем документы через Sumsub API...")
    alerts = []
    for i, app in enumerate(applicants):
        try:
            detail = get_applicant_detail(app["applicantId"])
            result = check_expiry(detail, app["name"])
            if result:
                alerts.append(result)
                flag = "🔴" if result["expired"] else "🟡"
                print(f"    {flag} {result['full_name']} — {result['doc_type']} — {result['expiry_date']}")
            # Небольшая пауза чтобы не превысить rate limit
            if i % 10 == 0:
                time.sleep(0.5)
        except Exception as e:
            print(f"    ⚠️  {app['name']} ({app['applicantId']}): {e}")
            continue

    print(f"4/4 Отправляем в #{SLACK_CHANNEL}... ({len(alerts)} записей)")
    post_report(alerts, slack_users)
    print("✅ Готово!")

if __name__ == "__main__":
    main()
