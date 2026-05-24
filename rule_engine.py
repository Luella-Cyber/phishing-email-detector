"""
rule_engine.py
--------------
Layer 1: Rule-based phishing detection.

Each rule checks a specific indicator of compromise and returns
a score (0.0 - 1.0) and a human-readable explanation.

Rules are grouped into categories:
  - Sender Analysis
  - URL Analysis
  - Content Analysis
  - Attachment Analysis
  - Header Analysis
"""

import re
from urllib.parse import urlparse
from detector.email_parser import get_sender_domain, get_display_name


# ---------------------------------------------------------------------------
# Known data
# ---------------------------------------------------------------------------

TRUSTED_BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "netflix",
    "facebook", "instagram", "linkedin", "twitter", "chase", "bankofamerica",
    "wellsfargo", "irs", "usps", "fedex", "ups", "dropbox", "docusign",
    "zoom", "slack", "adobe"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".click", ".download", ".loan", ".win", ".racing"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.link", "rebrand.ly", "cutt.ly"
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "act now", "limited time",
    "expires", "expiring", "last chance", "final notice", "critical",
    "important notice", "account suspended", "verify now", "confirm now",
    "unusual activity", "suspicious activity", "unauthorized", "locked",
    "disabled", "compromised", "security alert", "24 hours", "48 hours"
]

CREDENTIAL_KEYWORDS = [
    "password", "username", "login", "sign in", "verify your account",
    "confirm your identity", "update your information", "click here to confirm",
    "enter your details", "provide your", "social security", "ssn",
    "credit card", "bank account", "routing number", "pin number"
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "bitcoin", "gift card", "western union",
    "money order", "send money", "payment required", "invoice attached",
    "overdue", "refund", "claim your prize", "winner", "lottery",
    "inheritance", "million dollars", "unclaimed funds"
]

THREAT_KEYWORDS = [
    "legal action", "lawsuit", "arrest", "authorities", "police",
    "fbi", "irs audit", "tax fraud", "deportation", "court order",
    "penalty", "fine", "sue", "criminal charges"
]


# ---------------------------------------------------------------------------
# Individual rule functions
# ---------------------------------------------------------------------------

def check_sender_spoofing(parsed: dict) -> tuple[float, str]:
    """
    Check if the sender display name impersonates a trusted brand
    but the actual email domain doesn't match.

    Example: 'PayPal <billing@paypa1-support.com>'
    """
    sender = parsed.get("sender", "")
    display_name = get_display_name(sender).lower()
    domain = get_sender_domain(sender).lower()

    for brand in TRUSTED_BRANDS:
        if brand in display_name and brand not in domain:
            return (0.95, f"Sender display name '{display_name}' impersonates '{brand}' "
                          f"but email comes from '{domain}'")
    return (0.0, "")


def check_reply_to_mismatch(parsed: dict) -> tuple[float, str]:
    """
    Check if the Reply-To address differs from the From address domain.
    Attackers use this to receive replies at a different address.
    """
    sender_domain = get_sender_domain(parsed.get("sender", ""))
    reply_to_domain = get_sender_domain(parsed.get("reply_to", ""))

    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        return (0.75, f"Reply-To domain '{reply_to_domain}' differs from "
                      f"sender domain '{sender_domain}'")
    return (0.0, "")


def check_free_email_provider(parsed: dict) -> tuple[float, str]:
    """
    Check if email is from a free provider (e.g. gmail, yahoo) but
    claims to be from a business or government entity.
    """
    FREE_PROVIDERS = ["gmail.com", "yahoo.com", "hotmail.com",
                      "outlook.com", "aol.com", "protonmail.com"]
    sender = parsed.get("sender", "").lower()
    domain = get_sender_domain(sender)
    display = get_display_name(sender).lower()

    corporate_signals = ["inc", "corp", "llc", "bank", "gov", "support",
                         "security", "billing", "account", "service"]

    if domain in FREE_PROVIDERS:
        if any(signal in display for signal in corporate_signals):
            return (0.80, f"Corporate/official display name but sent from free email provider '{domain}'")
        return (0.20, f"Email sent from free provider '{domain}'")
    return (0.0, "")


def check_suspicious_urls(parsed: dict) -> tuple[float, str]:
    """
    Analyze URLs in the email for phishing indicators:
    - IP address instead of domain
    - Suspicious TLDs
    - URL shorteners
    - Domain lookalikes (e.g. paypa1.com, amaz0n.com)
    - Excessive subdomains
    """
    urls = parsed.get("urls", [])
    if not urls:
        return (0.0, "")

    findings = []
    max_score = 0.0

    for url in urls[:20]:  # Check first 20 URLs
        try:
            parsed_url = urlparse(url if url.startswith("http") else "http://" + url)
            netloc = parsed_url.netloc.lower()
            path = parsed_url.path.lower()

            # IP address in URL
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', netloc):
                findings.append(f"IP address used as domain in URL: {url[:60]}")
                max_score = max(max_score, 0.90)

            # URL shortener
            if any(shortener in netloc for shortener in URL_SHORTENERS):
                findings.append(f"URL shortener detected: {netloc}")
                max_score = max(max_score, 0.65)

            # Suspicious TLD
            if any(netloc.endswith(tld) for tld in SUSPICIOUS_TLDS):
                findings.append(f"Suspicious TLD in URL: {netloc}")
                max_score = max(max_score, 0.75)

            # Brand name in subdomain/path but different domain (e.g. paypal.phishing.com)
            for brand in TRUSTED_BRANDS:
                if brand in netloc and not netloc.endswith(f"{brand}.com"):
                    if f"{brand}." not in netloc.split("/")[0].split(".")[-2:]:
                        findings.append(f"Brand '{brand}' in URL but domain is '{netloc}'")
                        max_score = max(max_score, 0.85)
                        break

            # Excessive subdomains (e.g. secure.login.verify.paypal.ru)
            parts = netloc.split(".")
            if len(parts) > 4:
                findings.append(f"Excessive subdomains in URL: {netloc}")
                max_score = max(max_score, 0.60)

            # Login/security keywords in URL path
            if re.search(r'(login|verify|secure|account|update|confirm|signin)', path):
                max_score = max(max_score, 0.40)

        except Exception:
            continue

    if findings:
        return (max_score, "Suspicious URLs: " + "; ".join(findings[:3]))
    return (max_score, "")


def check_urgency_language(parsed: dict) -> tuple[float, str]:
    """Check for urgency/pressure tactics in subject and body."""
    text = (parsed.get("subject", "") + " " + parsed.get("body_text", "")).lower()
    found = [kw for kw in URGENCY_KEYWORDS if kw in text]

    if len(found) >= 3:
        return (0.75, f"High-urgency language detected: {', '.join(found[:5])}")
    elif len(found) >= 1:
        return (0.40, f"Urgency language detected: {', '.join(found[:3])}")
    return (0.0, "")


def check_credential_harvesting(parsed: dict) -> tuple[float, str]:
    """Check for language designed to harvest credentials or personal info."""
    text = (parsed.get("subject", "") + " " + parsed.get("body_text", "")).lower()
    found = [kw for kw in CREDENTIAL_KEYWORDS if kw in text]

    if len(found) >= 2:
        return (0.80, f"Credential harvesting language detected: {', '.join(found[:4])}")
    elif len(found) == 1:
        return (0.45, f"Possible credential request: '{found[0]}'")
    return (0.0, "")


def check_financial_scam_language(parsed: dict) -> tuple[float, str]:
    """Check for financial scam indicators (gift cards, wire transfers, prize claims)."""
    text = (parsed.get("subject", "") + " " + parsed.get("body_text", "")).lower()
    found = [kw for kw in FINANCIAL_KEYWORDS if kw in text]

    if len(found) >= 2:
        return (0.85, f"Financial scam indicators: {', '.join(found[:4])}")
    elif len(found) == 1:
        return (0.50, f"Financial scam keyword: '{found[0]}'")
    return (0.0, "")


def check_threat_language(parsed: dict) -> tuple[float, str]:
    """Check for threats (legal action, arrest, penalties) used to coerce action."""
    text = (parsed.get("subject", "") + " " + parsed.get("body_text", "")).lower()
    found = [kw for kw in THREAT_KEYWORDS if kw in text]

    if found:
        return (0.75, f"Threatening language detected: {', '.join(found[:3])}")
    return (0.0, "")


def check_suspicious_attachments(parsed: dict) -> tuple[float, str]:
    """Check for dangerous attachment types commonly used in phishing."""
    DANGEROUS_EXTENSIONS = [
        ".exe", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".scr",
        ".jar", ".hta", ".iso", ".img"
    ]
    MEDIUM_RISK_EXTENSIONS = [
        ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm"
    ]

    if not parsed.get("has_attachments"):
        return (0.0, "")

    for name in parsed.get("attachment_names", []):
        name_lower = name.lower()
        if any(name_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            return (0.90, f"High-risk attachment: '{name}'")
        if any(name_lower.endswith(ext) for ext in MEDIUM_RISK_EXTENSIONS):
            return (0.55, f"Potentially risky attachment: '{name}'")

    return (0.20, "Email contains attachment(s)")


def check_subject_anomalies(parsed: dict) -> tuple[float, str]:
    """Check for suspicious subject line patterns."""
    subject = parsed.get("subject", "").strip()

    if not subject:
        return (0.30, "Email has no subject line")

    # All caps subject
    if subject.isupper() and len(subject) > 5:
        return (0.45, f"Subject line is ALL CAPS: '{subject}'")

    # Re: or Fwd: without prior thread context (can't fully verify, flag lightly)
    if re.match(r'^(re:|fwd:)\s', subject.lower()):
        return (0.15, "Subject suggests reply/forward thread — verify legitimacy")

    # Excessive punctuation
    if len(re.findall(r'[!?]{2,}', subject)) > 0:
        return (0.35, f"Excessive punctuation in subject: '{subject}'")

    return (0.0, "")


# ---------------------------------------------------------------------------
# Main rule engine runner
# ---------------------------------------------------------------------------

ALL_RULES = [
    ("Sender Spoofing",         check_sender_spoofing),
    ("Reply-To Mismatch",       check_reply_to_mismatch),
    ("Free Email Provider",     check_free_email_provider),
    ("Suspicious URLs",         check_suspicious_urls),
    ("Urgency Language",        check_urgency_language),
    ("Credential Harvesting",   check_credential_harvesting),
    ("Financial Scam Language", check_financial_scam_language),
    ("Threat Language",         check_threat_language),
    ("Suspicious Attachments",  check_suspicious_attachments),
    ("Subject Anomalies",       check_subject_anomalies),
]


def run_rules(parsed: dict) -> dict:
    """
    Run all rules against a parsed email.

    Returns:
        {
            "rule_score": float (0.0 - 1.0),
            "triggered_rules": list of {name, score, explanation},
            "clean_rules": list of rule names that passed
        }
    """
    triggered = []
    clean = []

    for name, rule_fn in ALL_RULES:
        score, explanation = rule_fn(parsed)
        if score > 0.0:
            triggered.append({
                "rule": name,
                "score": round(score, 2),
                "explanation": explanation
            })
        else:
            clean.append(name)

    # Weighted aggregate: take the highest score, then add 10% for each additional hit
    if not triggered:
        rule_score = 0.0
    else:
        sorted_scores = sorted([r["score"] for r in triggered], reverse=True)
        rule_score = sorted_scores[0]
        for s in sorted_scores[1:]:
            rule_score = min(1.0, rule_score + s * 0.10)

    return {
        "rule_score": round(rule_score, 3),
        "triggered_rules": triggered,
        "clean_rules": clean
    }
