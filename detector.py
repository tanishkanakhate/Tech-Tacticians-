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
LEGIT |= set("""google.com youtube.com facebook.com instagram.com whatsapp.com twitter.com x.com linkedin.com wikipedia.org
amazon.com amazon.in flipkart.com myntra.com swiggy.com zomato.com paytm.com phonepe.com npci.org.in sbi.co.in onlinesbi.sbi
hdfcbank.com icicibank.com axisbank.com kotak.com bankofbaroda.in pnbindia.in canarabank.com unionbankofindia.co.in indusind.com
yesbank.in rbi.org.in irctc.co.in incometax.gov.in uidai.gov.in india.gov.in digilocker.gov.in gst.gov.in epfindia.gov.in
passportindia.gov.in mygov.in nic.in github.com microsoft.com office.com live.com outlook.com apple.com icloud.com netflix.com
spotify.com paypal.com ebay.com dropbox.com zoom.us slack.com adobe.com yahoo.com bing.com reddit.com stackoverflow.com medium.com
openai.com anthropic.com claude.ai telegram.org naukri.com jio.com airtel.in hotstar.com bookmyshow.com olacabs.com uber.com
makemytrip.com cleartrip.com nykaa.com ajio.com meesho.com snapdeal.com tatacliq.com bigbasket.com blinkit.com cloudflare.com wordpress.com""".split())
LABELS = {d.split(".")[0]: d for d in LEGIT if len(d.split(".")[0]) >= 6}
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s", "ј": "j", "ο": "o", "ρ": "p", "α": "a"}
WHY = {
 "High-abuse TLD": "Cheap domain endings like .top, .xyz and .tk are used by most throwaway scam sites, so they add risk.",
 "Brand + extra words": "Scammers put words like 'support' or 'secure' next to a real brand name to look official. The real company only uses its own domain.",
 "Lookalike domain": "The name is a near-copy of a real brand with a swapped or changed character, meant to fool a quick glance.",
 "Lookalike of popular site": "The name is one character away from a well-known site, a typical typo-squatting trick.",
 "Brand in subdomain/path": "The brand name appears in the link, but the real domain (the part before the last dot) belongs to someone else.",
 "Brand used as fake username": "Browsers ignore everything before '@', so the real destination is the part after it.",
 "IP address as host": "Genuine services use domain names. A raw IP address is often used to hide who owns the server.",
 "No HTTPS": "The connection is not encrypted, so anything typed here can be read in transit.",
 "Punycode / non-ASCII domain": "Letters from other alphabets can look identical to English letters and fake a real brand.",
 "Sensitive keywords": "Words like login, verify and kyc are used to pressure users into entering credentials.",
 "URL shortener": "A shortened link hides the final destination.",
 "Many subdomains": "Long subdomain chains push the real domain out of view.",
 "Many hyphens in domain": "Domains like secure-bank-login-update are common in scam sites.",
 "Very long URL": "Long URLs can hide the suspicious part of the address.",
 "Known trusted domain": "This domain is on the verified list of genuine sites, so it is not flagged.",
}
SUMMARY = {
 "Phishing": "This link shows strong signs of imitating a trusted site to steal your data. Do not open it or enter any details.",
 "Suspicious": "This link has some risky signs. It may be harmless, but verify the sender before opening it.",
 "Legitimate": "No meaningful risk signals were found.",
}
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
    label = "".join(CONFUSABLES.get(c, c) for c in label.lower())
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
    try: uni = host.encode("ascii").decode("idna")
    except Exception: uni = host
    ulabel = registered_domain(uni).split(".")[0]

    # 1. Trusted allowlist -> avoids false positives
    if reg in LEGIT and not re.search(r"[^a-z0-9.-]", host):
        return {"url": url, "host": host, "score": 0, "verdict": "Legitimate",
                "factors": [{"name": "Known trusted domain", "points": 0, "why": WHY["Known trusted domain"],
                             "detail": f"{reg} is on the verified brand allowlist"}],
                "summary": SUMMARY["Legitimate"], "formula": "0 = 0"}

    # 2. Structural features
    try:
        ipaddress.ip_address(host); add("IP address as host", 25, "Real sites use domain names, not raw IPs")
    except ValueError:
        pass
    if p.scheme != "https": add("No HTTPS", 10, "Connection is not encrypted")
    if "@" in p.netloc: add("'@' in URL", 15, "Text before '@' is ignored by browsers - used to disguise the real host")
    if host.startswith("xn--") or ".xn--" in host or re.search(r"[^\x00-\x7f]", host):
        add("Punycode / non-ASCII domain", 25, "May use look-alike Unicode characters (IDN homograph)")
    ui = p.netloc.rsplit("@", 1)[0].lower() if "@" in p.netloc else ""
    if any(b in ui for b in BRANDS): add("Brand used as fake username", 30, "A brand name sits before '@' to trick the reader")
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
    norm = normalize(ulabel)
    for brand, domains in BRANDS.items():
        d = edit_distance(norm, brand)
        if ulabel != brand and d <= 1 + (len(brand) > 7):
            add("Lookalike domain", 55, f"'{ulabel}' imitates '{brand}' (edit distance {d}, official: {domains[0]})")
            break
        if brand in host.replace(reg, "") or brand in p.path.lower():
            add("Brand in subdomain/path", 30, f"'{brand}' appears but the real domain is {reg}, not {domains[0]}")
            break
        if brand in norm.replace("-", "") and ulabel != brand:
            add("Brand + extra words", 48, f"'{ulabel}' embeds '{brand}' but is not the official site ({domains[0]})")
            break

    if not any("ookalike" in f["name"] or "Brand" in f["name"] for f in factors):
        for lab, dom in LABELS.items():
            if ulabel != lab and abs(len(norm) - len(lab)) <= 1 and edit_distance(norm, lab) == 1:
                add("Lookalike of popular site", 50, f"'{ulabel}' is one character away from {dom}"); break
    score = min(sum(f["points"] for f in factors), 100)
    verdict = "Phishing" if score >= 60 else "Suspicious" if score >= 30 else "Legitimate"
    if not factors: factors.append({"name": "No risk signals", "points": 0, "detail": "Nothing unusual found"})
    for f in factors: f["why"] = WHY.get(f["name"], "")
    formula = " + ".join(str(f["points"]) for f in factors) + f" = {score}"
    return {"url": url, "host": host, "score": score, "verdict": verdict, "factors": factors,
            "summary": SUMMARY[verdict], "formula": formula}
