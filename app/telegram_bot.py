"""
Telegram bot for Amharic Phishing Shield
-----------------------------------------
Send or forward a suspicious message to the bot and it replies with a verdict
(Safe / Suspicious / Dangerous), the reasons, and advice in English + Amharic.

Uses ONLY Python's standard library, so there is nothing to install (and
nothing a security policy such as Smart App Control can block). It asks
Telegram for new messages ("long polling"), so it needs no public web address:
it works on any Wi-Fi, as long as this script is running.

Setup
  1. In Telegram, chat with @BotFather -> /newbot -> copy the token it gives you.
  2. Put the token in a file named .env next to this script:
         TELEGRAM_BOT_TOKEN=123456789:your-token-here
     (or, for this terminal only:  $env:TELEGRAM_BOT_TOKEN="123456789:...")
  3. Run, from the app/ folder:
         python telegram_bot.py
  Stop with Ctrl+C (it can take a few seconds).

KEEP THE TOKEN SECRET. Anyone with it controls your bot. Never paste it in a
chat, a screenshot or GitHub. If it leaks, send /revoke to @BotFather.
"""

import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from scoring import get_verdict

try:  # make sure printing never crashes on Windows consoles
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

API_BASE = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org")
MAX_CHARS = 2000        # longest message we analyze (same limit as the web page)
POLL_SECONDS = 15       # long-poll length; also how long Ctrl+C may take
MAX_REASONS = 6         # reasons shown in a reply
MAX_PER_MINUTE = 8      # analyses per chat per minute (basic abuse protection)
WORKERS = 4             # messages handled at the same time

# ---------------------------------------------------------------- texts ----

WELCOME = (
    "\U0001F6E1\uFE0F Amharic Phishing Shield\n\n"
    "Send or forward me any suspicious SMS, Telegram or email message and I will "
    "tell you how risky it looks. I understand Amharic, English, or a mix of both.\n\n"
    "የተጠራጠሩትን መልእክት ወደዚህ ይላኩ ወይም ፎርዋርድ ያድርጉ፤ ምን ያህል አደገኛ እንደሆነ እነግርዎታለሁ።\n\n"
    "Never click links or share a PIN, password or code from a message you are unsure about.\n"
    "I am a detection aid, not a guarantee. Messages are not saved."
)
NOT_TEXT = (
    "I can only read text. Please paste the message as text.\n"
    "ጽሑፍ ብቻ ነው ማንበብ የምችለው። እባክዎ መልእክቱን እንደ ጽሑፍ ይለጥፉ።"
)
UNKNOWN_CMD = (
    "Unknown command. Just send me the message you want checked.\n"
    "ያልታወቀ ትዕዛዝ። መፈተሽ የሚፈልጉትን መልእክት ብቻ ይላኩ።"
)
SLOW_DOWN = (
    "Please wait a moment before sending more messages.\n"
    "እባክዎ ትንሽ ይጠብቁ።"
)
FAILED = "Sorry, something went wrong while checking that message. Please try again."

LABELS = {
    "Safe": ("\U0001F7E2", "Looks safe", "ደህንነቱ የተጠበቀ"),
    "Suspicious": ("\U0001F7E0", "Be careful", "አጠራጣሪ"),
    "Dangerous": ("\U0001F534", "Very likely a scam", "አደገኛ"),
}
ADVICE = {
    "Safe": (
        "No clear scam signals were found. Still be careful with links and with requests for money or codes.",
        "ግልጽ የማጭበርበር ምልክት አልተገኘም። ስለ ሊንኮች እና ገንዘብ ወይም ኮድ ጥያቄዎች ጥንቃቄ ያድርጉ።",
    ),
    "Suspicious": (
        "This message has some scam signals. Do not click links or share codes. Confirm with the sender through another channel.",
        "ይህ መልእክት አንዳንድ የማጭበርበር ምልክቶች አሉት። ሊንኮችን አይጫኑ፣ ኮድ አይላኩ። ላኪውን በሌላ መንገድ ያረጋግጡ።",
    ),
    "Dangerous": (
        "Do not click any link or send any PIN, password or code. Delete the message.",
        "ማንኛውንም ሊንክ አይጫኑ፣ ፒን፣ የይለፍ ቃል ወይም ኮድ አይላኩ። መልእክቱን ይሰርዙ።",
    ),
}

# ------------------------------------------------------------- settings ----


def _read_env_file(path):
    values = {}
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def load_token():
    """Token from the environment, else from a .env file (here or one folder up)."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if token:
        return token
    here = os.path.dirname(os.path.abspath(__file__))
    for folder in (here, os.path.dirname(here)):
        token = _read_env_file(os.path.join(folder, ".env")).get("TELEGRAM_BOT_TOKEN", "")
        if token:
            return token
    return ""


# ------------------------------------------------------- telegram calls ----


class TelegramError(Exception):
    def __init__(self, code, description):
        super().__init__(f"{code}: {description}")
        self.code = code
        self.description = description


def api_call(token, method, payload=None, timeout=20):
    """Call a Telegram Bot API method. Returns the 'result' part of the answer."""
    url = f"{API_BASE}/bot{token}/{method}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload or {}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"ok": False, "error_code": e.code, "description": "HTTP error"}
    if not body.get("ok"):
        raise TelegramError(body.get("error_code"), body.get("description", "unknown error"))
    return body["result"]


def send(token, chat_id, text, reply_to=None):
    """
    Send a text message. With reply_to, it appears as a reply to that exact
    message, so when someone sends several messages quickly each verdict stays
    attached to the message it is about (replies can finish out of order).
    """
    payload = {
        "chat_id": chat_id,
        "text": text,
        "link_preview_options": {"is_disabled": True},
    }
    if reply_to is not None:
        payload["reply_parameters"] = {"message_id": reply_to,
                                       "allow_sending_without_reply": True}
    api_call(token, "sendMessage", payload)


def send_typing(token, chat_id):
    try:
        api_call(token, "sendChatAction", {"chat_id": chat_id, "action": "typing"}, timeout=5)
    except Exception:
        pass  # purely cosmetic


# ------------------------------------------------------------- replying ----


def defang(text):
    """
    Make links harmless in the reply: Telegram turns anything that looks like a
    web address into a tappable link, and we must never help someone tap a
    scam site.   http://evil.com  ->  hxxp://evil[.]com
    """
    text = re.sub(r"(?i)\bhttp", "hxxp", text)
    return re.sub(r"(?<=\w)\.(?=\w)", "[.]", text)


def build_reply(verdict, truncated=False):
    emoji, label_en, label_am = LABELS.get(verdict["verdict"], LABELS["Safe"])
    lines = [
        f"{emoji} {label_en}",
        f"{label_am} \u00b7 {verdict['verdict']}",
        f"Risk score: {round(verdict['final_score'])}/100",
    ]
    reasons = verdict.get("reasons", [])
    if reasons:
        lines += ["", "Why:"]
        lines += ["\u2022 " + defang(r) for r in reasons[:MAX_REASONS]]
        if len(reasons) > MAX_REASONS:
            lines.append(f"\u2022 (+{len(reasons) - MAX_REASONS} more)")
    advice_en, advice_am = ADVICE.get(verdict["verdict"], ADVICE["Safe"])
    lines += ["", advice_en, advice_am]
    if truncated:
        lines += ["", f"(Only the first {MAX_CHARS} characters were checked.)"]
    return "\n".join(lines)


_recent = defaultdict(deque)
_recent_lock = threading.Lock()


def too_fast(chat_id):
    """True if this chat already used its analyses for the current minute."""
    now = time.monotonic()
    with _recent_lock:
        history = _recent[chat_id]
        while history and now - history[0] > 60:
            history.popleft()
        if len(history) >= MAX_PER_MINUTE:
            return True
        history.append(now)
        return False


def handle_update(token, update):
    message = update.get("message")
    if not message:
        return
    chat_id = message["chat"]["id"]
    reply_to = message.get("message_id")
    text = message.get("text")

    # Photos, stickers, voice... Captions are NOT analyzed on purpose: a photo of
    # a scam with the caption "is this real?" must not be answered "Safe".
    if text is None:
        send(token, chat_id, NOT_TEXT, reply_to)
        return

    if text.startswith("/"):
        command = text.split()[0].split("@")[0].lower()
        send(token, chat_id, WELCOME if command in ("/start", "/help") else UNKNOWN_CMD, reply_to)
        return

    if too_fast(chat_id):
        send(token, chat_id, SLOW_DOWN, reply_to)
        return

    truncated = len(text) > MAX_CHARS
    send_typing(token, chat_id)
    verdict = get_verdict(text[:MAX_CHARS])
    send(token, chat_id, build_reply(verdict, truncated), reply_to)
    # Privacy: log only the outcome, never the message or who sent it.
    print(f"[bot] analyzed one message -> {verdict['verdict']} ({round(verdict['final_score'])})")


def safe_handle(token, update):
    """Run handle_update so that one bad message can never stop the bot."""
    try:
        handle_update(token, update)
    except Exception as e:
        print(f"[bot] error while handling a message: {type(e).__name__}: "
              f"{str(e).replace(token, '***')}")
        try:
            msg = update.get("message", {})
            chat_id = msg.get("chat", {}).get("id")
            if chat_id is not None:
                send(token, chat_id, FAILED, msg.get("message_id"))
        except Exception:
            pass


# ------------------------------------------------------------------ main ----


def main():
    token = load_token()
    if not token:
        print("No bot token found.\n"
              "  1. In Telegram, chat with @BotFather, send /newbot and copy the token.\n"
              "  2. Create a file named .env in this folder containing one line:\n"
              "         TELEGRAM_BOT_TOKEN=your-token-here\n"
              "     or, for this terminal only:  $env:TELEGRAM_BOT_TOKEN=\"your-token-here\"")
        sys.exit(1)
    if not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", token):
        print("That does not look like a Telegram bot token. It should look like\n"
              "  123456789:ABCdef... (digits, a colon, then letters and digits).\n"
              "Copy it again from @BotFather without spaces or quotes.")
        sys.exit(1)

    try:
        me = api_call(token, "getMe", timeout=15)
    except TelegramError as e:
        print(f"Telegram rejected the token ({e}). Check it in @BotFather (it may have been revoked).")
        sys.exit(1)
    except Exception as e:
        print(f"Could not reach Telegram ({type(e).__name__}). Check your internet connection.")
        sys.exit(1)

    # Long polling cannot work while a webhook is set, so make sure none is.
    try:
        api_call(token, "deleteWebhook", {"drop_pending_updates": False}, timeout=15)
    except Exception:
        pass

    # Skip messages that arrived while the bot was off, so a restart does not
    # answer a pile of stale chats.
    offset = None
    try:
        stale = api_call(token, "getUpdates", {"offset": -1, "timeout": 0}, timeout=15)
        if stale:
            offset = stale[-1]["update_id"] + 1
    except Exception:
        pass

    username = me.get("username", "your_bot")
    print(f"Bot @{username} is running. Chat with it at https://t.me/{username}")
    print("Press Ctrl+C to stop (it can take a few seconds).")

    pool = ThreadPoolExecutor(max_workers=WORKERS)
    try:
        while True:
            params = {"timeout": POLL_SECONDS, "allowed_updates": ["message"]}
            if offset is not None:
                params["offset"] = offset
            try:
                updates = api_call(token, "getUpdates", params, timeout=POLL_SECONDS + 10)
            except TelegramError as e:
                if e.code == 409:
                    print("Another copy of this bot is already running. Close it first.")
                else:
                    print(f"[bot] Telegram error ({e}); retrying.")
                time.sleep(5)
                continue
            except Exception as e:
                print(f"[bot] network problem ({type(e).__name__}); retrying.")
                time.sleep(3)
                continue
            for update in updates:
                offset = update["update_id"] + 1
                pool.submit(safe_handle, token, update)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
