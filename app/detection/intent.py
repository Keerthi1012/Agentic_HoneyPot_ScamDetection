import re
from typing import Dict, List

# -----------------------------
# Keyword sets (easy to extend)
# -----------------------------

URGENCY_KEYWORDS = [
    "immediately", "urgent", "today", "now", "within", "24 hours", "limited time"
]

THREAT_KEYWORDS = [
    "blocked", "suspended", "terminated", "legal action", "penalty", "frozen"
]

ACTION_KEYWORDS = [
    "verify", "click", "login", "pay", "transfer", "update", "confirm"
]

AUTHORITY_KEYWORDS = [
    "bank", "government", "support", "customer care", "admin", "official"
]

SENSITIVE_INFO_KEYWORDS = [
    "otp", "pin", "password", "cvv", "account number", "upi"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".info", ".click", ".link"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl", "goo.gl", "t.co"
]

# -----------------------------
# Helper functions
# -----------------------------

def extract_urls(text: str) -> List[str]:
    return re.findall(r'(https?://[^\s]+)', text.lower())


def has_grammar_anomaly(text: str) -> bool:
    """
    Lightweight heuristic:
    - ALL CAPS
    - Excessive punctuation
    - Very short but urgent messages
    """
    if text.isupper():
        return True
    if "!!!" in text or "???" in text:
        return True
    if len(text.split()) < 5 and any(w in text.lower() for w in URGENCY_KEYWORDS):
        return True
    return False


# -----------------------------
# Main intent detection logic
# -----------------------------

def detect_intent(text: str) -> Dict:
    text_lower = text.lower()
    confidence = 0.0
    signals = []

    # 1. Urgency
    if any(word in text_lower for word in URGENCY_KEYWORDS):
        confidence += 0.15
        signals.append("urgency")

    # 2. Threat / Fear
    if any(word in text_lower for word in THREAT_KEYWORDS):
        confidence += 0.15
        signals.append("threat")

    # 3. Action demand
    if any(word in text_lower for word in ACTION_KEYWORDS):
        confidence += 0.15
        signals.append("action_request")

    # 4. Authority impersonation
    if any(word in text_lower for word in AUTHORITY_KEYWORDS):
        confidence += 0.10
        signals.append("authority_impersonation")

    # 5. Sensitive information request
    if any(word in text_lower for word in SENSITIVE_INFO_KEYWORDS):
        confidence += 0.15
        signals.append("sensitive_info_request")

    # 6. Suspicious URLs
    urls = extract_urls(text)
    for url in urls:
        if any(tld in url for tld in SUSPICIOUS_TLDS) or any(s in url for s in URL_SHORTENERS):
            confidence += 0.15
            signals.append("suspicious_url")
            break

    # 7. Grammar / style anomaly
    if has_grammar_anomaly(text):
        confidence += 0.10
        signals.append("grammar_anomaly")

    # Cap confidence
    confidence = min(confidence, 1.0)

    # Decision bucket
    if confidence >= 0.7:
        decision = "scam"
    elif confidence >= 0.4:
        decision = "uncertain"
    else:
        decision = "safe"

    return {
        "decision": decision,
        "confidence": round(confidence, 2),
        "signals": signals
    }
