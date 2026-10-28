"""
Rule-Based Phishing Detection Engine
-------------------------------------
Fast, explainable first layer. Scores a normalized message against
categories of phishing signals commonly seen in Ethiopian scam messages.

Design rules (they keep real bank/telecom messages from being flagged):
- Patterns look for scam ACTIONS ("send your PIN"), not bare words ("password").
- Warnings are not requests: "never share your PIN" is checked clause by
  clause and ignored when negated.
- Mentioning a bank or telecom brand is NOT suspicious by itself. It only
  counts when something else is also suspicious.
- "Congratulations" is normal in everyday messages. It only counts together
  with other scam signals.
- Links to a trusted official domain (see link_analyzer.TRUSTED_LINK_DOMAINS)
  are not a warning sign.

The result is combined with the link analyzer and ML scores in scoring.py.
"""

import re
from typing import List, Dict

from normalizer import normalize
from link_analyzer import extract_urls, get_domain, is_trusted_domain

# ---- Rule categories -------------------------------------------------

URGENCY_PATTERNS = [
    # Amharic
    r"አሁኑኑ", r"ወዲያውኑ", r"በአስቸኳይ", r"ይታገዳል", r"ይዘጋል", r"ታግዷል", r"ተዘግቷል",
    r"የመጨረሻ ማስጠንቀቂያ",
    # English
    r"\burgent(?:ly)?\b", r"\bimmediately\b", r"\bright now\b", r"\bact now\b",
    r"\bexpires? (?:today|soon|tonight)\b", r"\blast warning\b",
    r"\bwithin (?:24|48) hours\b", r"\bsuspend(?:ed)?\b", r"\bdeactivat\w*",
    r"\bwill be (?:blocked|closed|locked|suspended|terminated|deactivated)\b",
    r"\baccount (?:has been |is )?(?:locked|blocked|suspended|limited)\b",
]

MONEY_PRIZE_PATTERNS = [
    # Amharic
    r"አሸንፈዋል", r"አሸነፉ", r"ተሸላሚ", r"ሽልማት", r"ሎተሪ", r"ነጻ ገንዘብ", r"ቦነስ",
    # English (typo-tolerant: "you win", "you won", ...)
    r"\byou(?:'ve|\s+have)?\s+(?:won|win)\b", r"\bwinner\b",
    r"\bprize\b", r"\blottery\b", r"\bgift card\b", r"\bclaim\b",
    r"\bfree (?:gift|bonus|data|airtime|bundle|money|cash)\b",
    r"\byou (?:are|have been) selected\b",
    r"\b(?:refund|reward|payment) (?:is )?(?:pending|waiting|available)\b",
    r"\bpending (?:refund|reward|payment)\b",
]

# Normal in everyday messages ("Congratulations on your graduation!"),
# so these only count when combined with another scam signal.
WEAK_CELEBRATION_PATTERNS = [r"\bcongratulation\w*", r"ደስ አለዎት"]

CREDENTIAL_REQUEST_PATTERNS = [
    # Amharic: asking you to ENTER / SEND / CONFIRM a secret
    r"የይለፍ ቃል\S* (?:ያስገቡ|ይላኩ|ያረጋግጡ|ይንገሩ\S*)",
    r"ፒን ኮድ\S* (?:ያስገቡ|ይላኩ|ያረጋግጡ|ይንገሩ\S*)",
    r"ኮድዎን (?:ያስገቡ|ይላኩ|ያረጋግጡ|ይንገሩ\S*)",
    r"አካውንት ቁጥር\S* (?:ያስገቡ|ይላኩ|ያረጋግጡ|ይንገሩ\S*)",
    # English
    r"\b(?:send|share|enter|confirm|verify|give|provide|submit|update)\b[^.!?\n]{0,30}\byour (?:\w+ )?(?:password|pin|otp|cvv|passcode)\b",
    r"\bone.?time (?:code|password|pin)\b", r"\bcvv\b",
    r"\bverify (?:your )?(?:account|identity|details)\b",
    r"\bconfirm your (?:identity|account|details|number)\b",
    r"\bupdate your (?:account|details)\b",
    r"\breply with your\b",
    r"\breply with the (?:otp|code|pin)\b", r"\bsend the (?:otp|code|pin)\b",
]

IMPERSONATION_PATTERNS = [
    r"telebirr", r"ቴሌብር", r"ኢትዮ ቴሌኮም", r"ethio ?telecom",
    r"\bcbe\b", r"commercial bank", r"dashen bank", r"awash bank",
    r"bank of abyssinia", r"\bnib bank\b", r"\bzemen bank\b", r"\bchapa\b",
]

# A warning, not a request: a negation right before the action ("never share
# your PIN", "do not give your OTP"). The negation must sit within a few
# characters of the verb, so scam wording such as "send the OTP to avoid
# suspension" or "do not ignore this and send your PIN" is still caught.
_NEGATED_ACTION = re.compile(
    r"\b(?:never|don'?t|do not|dont|no one|nobody)\b[^.!?\n]{0,12}"
    r"\b(?:share|send|give|tell|reveal|enter|provide|submit|disclose)\b",
    re.IGNORECASE)


def _matches_any(patterns: List[str], text: str) -> bool:
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


def _clauses(text: str) -> List[str]:
    return [c for c in re.split(r"[.!?\n,;:።፣፤]+", text) if c.strip()]


def _credential_request(text: str) -> bool:
    """True if some clause ASKS for a secret. Negated clauses ("never share your
    PIN") are warnings, not requests, and are skipped."""
    for clause in _clauses(text):
        if _NEGATED_ACTION.search(clause):
            continue
        if _matches_any(CREDENTIAL_REQUEST_PATTERNS, clause):
            return True
    return False


def contains_link(text: str) -> bool:
    return bool(extract_urls(text))


def evaluate(raw_text: str) -> Dict:
    """
    Run the rule engine on a raw message.
    Returns a dict: rule_score (0-100), triggered reasons, normalized info, has_link.
    """
    norm = normalize(raw_text)
    text = norm["normalized"]

    links = extract_urls(text)
    external_links = [u for u in links if not is_trusted_domain(get_domain(u))]

    urgency = _matches_any(URGENCY_PATTERNS, text)
    prize = _matches_any(MONEY_PRIZE_PATTERNS, text)
    credential = _credential_request(text)
    brand = _matches_any(IMPERSONATION_PATTERNS, text)
    celebrate = _matches_any(WEAK_CELEBRATION_PATTERNS, text)

    # "something else is suspicious" -> brand names and celebrations then matter
    other_signal = urgency or prize or credential or bool(external_links)

    score = 0
    reasons = []
    if urgency:
        score += 20; reasons.append("Uses urgent/pressure language typical of scams")
    if prize:
        score += 25; reasons.append("Promises money or a prize, a common phishing lure")
    if credential:
        score += 30; reasons.append("Asks for a password, PIN, OTP, or account number")
    if brand and other_signal:
        score += 15; reasons.append("Mentions a bank or telecom brand — check if it's really from them")
    if celebrate and other_signal:
        score += 10; reasons.append("Congratulation wording combined with other scam signals")
    if external_links:
        score += 10; reasons.append("Message contains a link — links will be checked separately")

    return {
        "script": norm["script"],
        "normalized_text": text,
        "rule_score": min(score, 100),
        "reasons": reasons,
        "has_link": bool(links),
    }


if __name__ == "__main__":
    tests = [
        "ሰላም! ሂሳብዎ ይታገዳል!!! አሁኑኑ የይለፍ ቃልዎን ያስገቡ http://telebirr-verify.com",
        "Hi, are we still meeting tomorrow at 5?",
        "Congratulations on your graduation!",
        "Never share your PIN with anyone.",
    ]
    for t in tests:
        result = evaluate(t)
        print(f"\nMessage: {t}")
        print(f"Score: {result['rule_score']}  Script: {result['script']}")
        print("Reasons:", result["reasons"])
