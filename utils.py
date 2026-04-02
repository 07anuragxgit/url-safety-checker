import re
import validators
from urllib.parse import urlparse

# ---------- VALIDATION ----------
def is_valid_url(url):
    return validators.url(url)


# ---------- IP DETECTION ----------
def is_ip_url(url):
    pattern = r"http[s]?://\d{1,3}(\.\d{1,3}){3}"
    return bool(re.search(pattern, url))


# ---------- SHORTENERS ----------
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "shorturl.at"
]

def is_shortened(url):
    return any(short in url for short in SHORTENERS)


# ---------- KEYWORDS ----------
KEYWORDS = [
    "login", "verify", "bank", "secure", "account",
    "update", "free", "offer", "urgent", "password"
]

def has_suspicious_keywords(url):
    return any(word in url.lower() for word in KEYWORDS)


# ---------- DOMAIN ----------
def get_domain(url):
    return urlparse(url).netloc


# ---------- SUSPICIOUS TLD ----------
SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga"]

def has_suspicious_tld(domain):
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


# ---------- MAIN ANALYSIS ----------
def analyze_url(url):
    if not is_valid_url(url):
        return {
            "url": url,
            "verdict": "Invalid URL",
            "confidence": 0,
            "risk_level": "Unknown",
            "reasons": ["URL format is not valid"],
            "explanation": "This doesn't even look like a proper URL 😅",
            "precautions": ["Check the URL format"]
        }

    score = 0
    reasons = []
    explanation_parts = []

    # IP check
    if is_ip_url(url):
        score += 2
        reasons.append("Uses IP address instead of domain")
        explanation_parts.append(
            "This URL uses an IP address instead of a domain, which is often used to hide identity."
        )

    # Shortener check
    if is_shortened(url):
        score += 2
        reasons.append("Shortened URL detected")
        explanation_parts.append(
            "Shortened URLs can hide the real destination, commonly used in phishing attacks."
        )

    # Keyword check
    if has_suspicious_keywords(url):
        score += 1
        reasons.append("Contains suspicious keywords")
        explanation_parts.append(
            "Words like 'login', 'free', or 'verify' are often used to trick users."
        )

    # Domain check
    domain = get_domain(url)
    if has_suspicious_tld(domain):
        score += 1
        reasons.append("Suspicious domain extension")
        explanation_parts.append(
            "This domain extension is commonly used in spam or malicious websites."
        )

    # ---------- SCORING ----------
    max_score = 6
    safety_percent = max(0, 100 - (score / max_score) * 100)

    # ---------- VERDICT ----------
    if score >= 3:
        verdict = "Suspicious"
        risk = "High Risk"
    elif score == 2:
        verdict = "Moderate Risk"
        risk = "Medium Risk"
    else:
        verdict = "Safe"
        risk = "Low Risk"

    # ---------- PRECAUTIONS ----------
    if score >= 3:
        precautions = [
            "Do NOT enter personal information",
            "Avoid clicking further links",
            "Check URL using VirusTotal",
            "Use trusted official websites only"
        ]
    elif score == 2:
        precautions = [
            "Double-check the website authenticity",
            "Avoid logging in unless sure",
            "Verify domain spelling carefully"
        ]
    else:
        precautions = [
            "Looks safe, but always verify the domain carefully"
        ]

    # ---------- FINAL OUTPUT ----------
    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "confidence": round(safety_percent, 2),
        "risk_level": risk,
        "reasons": reasons,
        "explanation": " ".join(explanation_parts),
        "precautions": precautions
    }