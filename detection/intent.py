import re
from typing import Dict, List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
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

# Scam keywords/ML (train simple model once)
scam_keywords = ["urgent", "verify", "blocked", "upi", "share"]
vectorizer = TfidfVectorizer()
clf = LogisticRegression()  # Train on sample data

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

    # Stage 2: ML model
    # Fix ML - Train ONCE at module level (put this at TOP of file)
    global vectorizer, clf
    if not hasattr(detect_intent, 'is_trained') or not detect_intent.is_trained:
        # ✅ FIXED TRAINING DATA - BOTH CLASSES
        training_texts = [
            # SCAM examples (label=1)
            "your account blocked urgent verify now", 
            "upi payment required immediately", 
            "click here account suspended",
            "verify otp within 24 hours",
            
            # SAFE examples (label=0) - CRITICAL!
            "hello how are you", 
            "meeting tomorrow 10am", 
            "thanks for your email",
            "lunch at 1pm office"
        ]

        training_labels = [1, 1, 1, 1, 0, 0, 0, 0]  # 4 scam + 4 safe

        # Train models
        vectorizer.fit(training_texts)
        clf.fit(vectorizer.transform(training_texts), training_labels)


    # ML prediction
    vec = vectorizer.transform([text_lower])
    ml_score = clf.predict_proba(vec)[0][1]

    # Stage 3: Length + urgency patterns
    urgency_patterns = len(re.findall(r'\b(urgent|immediately|now|today)\b', text.lower()))
    msg_length_score = 1 if 20 < len(text) < 200 else 0  # Typical scam length
    
    # FINAL SCORE: Weighted ensemble
    final_score = (confidence * 0.4 + ml_score * 0.4 + urgency_patterns * 0.1 + msg_length_score * 0.1)
    
    print(f"Score: {final_score}")

    # Decision bucket
    if confidence >= 0.7:
        decision = "scam"
    else:
        decision = "safe"

    return {
        "decision": decision,
        "confidence": round(final_score, 2),
        "signals": signals
    }



    
    
    
    