"""Explainable phishing URL detector: rule-based scoring + lookalike detection."""
import re, ipaddress
from urllib.parse import urlparse

# Brands people impersonate: label -> legit registered domains (extend for Indian banks/govt/e-commerce)
BRANDS = {
    "paypal": ["paypal.com"], "google": ["google.com"], "amazon": ["amazon.com", "amazon.in"],
    "flipkart": ["flipkart.com"], "sbi": ["sbi.co.in", "onlinesbi.sbi"], "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "paytm": ["paytm.com"],
    "irctc": ["irctc.co.in"], "microsoft": ["microsoft.com"], "apple": ["apple.com"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"], "netflix": ["netflix.com"],
    "incometax": ["incometax.gov.in"], "uidai": ["uidai.gov.in"],
}
LEGIT = {d for v in BRANDS.values() for d in v}
MULTI_SUFFIX = {"co.in", "gov.in", "org.in", "net.in", "ac.in", "co.uk", "com.au", "org.uk", "co.jp"}
BAD_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "support", "loan", "icu", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "confirm", "banking",
            "password", "kyc", "suspend", "wallet", "otp", "refund", "prize", "free"]
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a", "rn": "m", "vv": "w", "cl": "d"}

def registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def normalize(label):
    label = label.lower()
    for k, v in HOMOGLYPHS.items():
        label = label.replace(k, v)
    return label

def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def analyze(url):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    factors = []  # each: {name, points, detail}
    def add(name, pts, detail): factors.append({"name": name, "points": pts, "detail": detail})

    reg = registered_domain(host)
    label = reg.split(".")[0]

    # 1. Trusted allowlist -> avoids false positives
    if reg in LEGIT and not re.search(r"[^a-z0-9.-]", host):
        return {"url": url, "host": host, "score": 0, "verdict": "Legitimate",
                "factors": [{"name": "Known trusted domain", "points": 0,
                             "detail": f"{reg} is on the verified brand allowlist"}]}

    # 2. Structural features
    try:
        ipaddress.ip_address(host); add("IP address as host", 25, "Real sites use domain names, not raw IPs")
    except ValueError:
        pass
    if p.scheme != "https": add("No HTTPS", 10, "Connection is not encrypted")
    if "@" in p.netloc: add("'@' in URL", 15, "Text before '@' is ignored by browsers - used to disguise the real host")
    if host.startswith("xn--") or ".xn--" in host or re.search(r"[^\x00-\x7f]", host):
        add("Punycode / non-ASCII domain", 25, "May use look-alike Unicode characters (IDN homograph)")
    if len(url) > 75: add("Very long URL", 5, f"{len(url)} characters")
    subs = host.count(".") - reg.count(".")
    if subs >= 3: add("Many subdomains", 10, f"{subs} subdomain levels used to hide the real domain")
    if host.count("-") >= 3: add("Many hyphens in domain", 8, "Common in throwaway phishing domains")
    tld = host.rsplit(".", 1)[-1]
    if tld in BAD_TLDS: add("High-abuse TLD", 12, f".{tld} is frequently used in phishing")
    if reg in SHORTENERS: add("URL shortener", 10, "Final destination is hidden")
    hits = [k for k in KEYWORDS if k in (host + p.path + p.query).lower()]
    if hits: add("Sensitive keywords", min(4 * len(hits), 14), "Found: " + ", ".join(hits))

    # 3. Lookalike / brand impersonation
    norm = normalize(label)
    for brand, domains in BRANDS.items():
        d = edit_distance(norm, brand)
        if label != brand and d <= 1 + (len(brand) > 7):
            add("Lookalike domain", 55, f"'{label}' imitates '{brand}' (edit distance {d}, official: {domains[0]})")
            break
        if brand in host.replace(reg, "") or brand in p.path.lower():
            add("Brand in subdomain/path", 30, f"'{brand}' appears but the real domain is {reg}, not {domains[0]}")
            break
        if brand in norm.replace("-", "") and label != brand:
            add("Brand + extra words", 40, f"'{label}' embeds '{brand}' but is not the official site ({domains[0]})")
            break

    score = min(sum(f["points"] for f in factors), 100)
    verdict = "Phishing" if score >= 60 else "Suspicious" if score >= 30 else "Legitimate"
    if not factors: factors.append({"name": "No risk signals", "points": 0, "detail": "Nothing unusual found"})
    return {"url": url, "host": host, "score": score, "verdict": verdict, "factors": factors}
