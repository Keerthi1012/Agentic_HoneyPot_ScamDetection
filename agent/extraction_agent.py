import re
import spacy
from urllib.parse import urlparse

# -------------------------------------------------
# Load SpaCy model ONCE
# -------------------------------------------------
nlp = spacy.load("en_core_web_sm")

# -------------------------------------------------
# Constants
# -------------------------------------------------

KNOWN_BANK_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "canara"
]

COMMON_UPI_PROVIDERS = [
    "paytm", "phonepe", "googlepay", "gpay", "bhim"
]

SUSPICIOUS_TERMS = [
    "urgent", "verify", "blocked", "immediately", "suspension",
    "penalty", "freeze", "debit", "credit", "charge", "security"
]

THREAT_PATTERNS = {
    "account_blocked": ["blocked", "suspended", "freeze"],
    "legal_threat": ["legal", "court", "penalty", "case"],
    "payment_pressure": ["pay", "immediately", "today"]
}

IMPERSONATION_TERMS = [
    "bank", "rbi", "government", "kyc",
    "customer care", "support", "income tax"
]

# -------------------------------------------------
# Core Extraction
# -------------------------------------------------

def extract_intel(text: str) -> dict:
    """
    Extract raw scam indicators from text using regex + spaCy.
    """
    text = text.lower()
    doc = nlp(text)

    # -------------------------
    # URLs / Phishing links
    # -------------------------
    phishing_links = []

    for token in doc:
        if token.like_url:
            phishing_links.append(token.text)

    regex_urls = re.findall(
        r'\[([^\]]*(?:http|www)[^\]]*)\]|https?://[^\s<>"]+|www\.[^\s<>"]+',
        text
    )
    phishing_links.extend(regex_urls)

    unique_links = list(
        set([link.strip('[]()<>') for link in phishing_links if len(link) > 5])
    )

    # -------------------------
    # UPI IDs
    # -------------------------
    upi_patterns = [
        r'\b([a-z][a-z0-9]*@[a-z0-9]{4,15})\b',
        r'\b([a-z0-9]{3,}@paytm)\b',
        r'\b([a-z0-9]{3,}@phonepe)\b',
        r'\b([a-z0-9]{3,}@[a-z]+bank)\b',
    ]

    upi_ids = []
    for pattern in upi_patterns:
        upi_ids.extend(re.findall(pattern, text))

    # -------------------------
    # Phone Numbers
    # -------------------------
    phone_numbers = re.findall(r'\+91\d{10}|\b\d{10}\b', text)

    # -------------------------
    # Bank Account Numbers
    # -------------------------
    bank_accounts = re.findall(r'\b\d{4}-\d{4}-\d{4}\b', text)

    # -------------------------
    # Amounts
    # -------------------------
    amounts = re.findall(
        r'(?:rs\.?|₹|inr)\s?\d{1,7}', text
    )

    # -------------------------
    # Suspicious Keywords
    # -------------------------
    suspicious_keywords = [
        word for word in SUSPICIOUS_TERMS if word in text
    ]

    # -------------------------
    # Threat Classification
    # -------------------------
    threat_types = []
    for threat, words in THREAT_PATTERNS.items():
        if any(w in text for w in words):
            threat_types.append(threat)

    # -------------------------
    # Impersonation Terms
    # -------------------------
    impersonated_entities = [
        term for term in IMPERSONATION_TERMS if term in text
    ]

    intel = {
        "bankAccounts": bank_accounts,
        "upiIds": list(set(upi_ids)),
        "phishingLinks": list(
            set([link for link in unique_links if 'http' in link or 'www' in link])
        ),
        "phoneNumbers": phone_numbers,
        "amounts": list(set(amounts)),
        "suspiciousKeywords": suspicious_keywords,
        "threatTypes": threat_types,
        "impersonatedEntities": impersonated_entities
    }

    # Return only non-empty values
    return {k: v for k, v in intel.items() if v}

# -------------------------------------------------
# Enrichment Functions
# -------------------------------------------------

def enrich_domains(urls: list) -> dict:
    """
    Domain enrichment for phishing links.
    """
    domains = set()
    impersonation_flags = []

    for url in urls:
        try:
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            domain = parsed.netloc.lower()
            domains.add(domain)

            for bank in KNOWN_BANK_BRANDS:
                if bank in domain and not domain.endswith(".co.in"):
                    impersonation_flags.append(
                        f"Domain '{domain}' may impersonate {bank.upper()}"
                    )
        except Exception:
            continue

    return {
        "domains": list(domains),
        "domainImpersonation": impersonation_flags
    }

def enrich_upi(upi_ids: list) -> dict:
    """
    UPI enrichment
    """
    providers = set()
    bank_impersonation = []

    for upi in upi_ids:
        if "@" not in upi:
            continue

        handle = upi.split("@")[1].lower()
        providers.add(handle)

        for bank in KNOWN_BANK_BRANDS:
            if bank in handle and handle not in COMMON_UPI_PROVIDERS:
                bank_impersonation.append(
                    f"UPI handle '{handle}' may impersonate {bank.upper()}"
                )

    return {
        "upiProviders": list(providers),
        "upiImpersonation": bank_impersonation
    }

# -------------------------------------------------
# Master Pipeline
# -------------------------------------------------

def extract_and_enrich(text: str) -> dict:
    """
    Full extraction + enrichment pipeline.
    """
    raw = extract_intel(text)
    enriched = {}

    if "phishingLinks" in raw:
        enriched.update(enrich_domains(raw["phishingLinks"]))

    if "upiIds" in raw:
        enriched.update(enrich_upi(raw["upiIds"]))

    return {**raw, **enriched}
