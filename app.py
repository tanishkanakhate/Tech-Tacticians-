import datetime
import json
import re
import socket
import unicodedata
import urllib.request
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()
extract = tldextract.TLDExtract(suffix_list_urls=())  # works offline

# Brands to protect -> their REAL domains
BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "facebook": ["facebook.com", "fb.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "sbi": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "paytm": ["paytm.com"],
}
# Trusted sites (brand domains are trusted automatically). Add more here.
SAFE = {"wikipedia.org", "github.com", "stackoverflow.com", "python.org"}
SAFE |= {d for v in BRANDS.values() for d in v}

KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "bank", "confirm", "password", "wallet"]
SCAM_WORDS = ["free", "gift", "prize", "winner", "claim", "bonus", "lottery", "reward", "cashback", "refund", "kyc", "offer"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "work", "buzz", "icu", "cam", "shop", "live"}

# letters that scammers swap to imitate others (0->o, 1->l, rn->m, Cyrillic a->a ...)
SWAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "i": "l", "|": "l",
                      "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c"})


def skeleton(s):
    s = unicodedata.normalize("NFKD", s.lower()).translate(SWAP)
    return s.replace("rn", "m").replace("vv", "w").replace("-", "")


def readable(s):  # turn punycode (xn--...) back into the real characters
    try:
        return s.encode("ascii").decode("idna")
    except UnicodeError:
        return s


def distance(a, b):  # number of single-letter edits between two words
    prev = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        cur = [i]
        for j, y in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (x != y)))
        prev = cur
    return prev[-1]


# ---- live checks (need internet; if anything fails they quietly return None) ----------
@lru_cache(maxsize=2000)
def domain_exists(host):
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return None  # could not tell


@lru_cache(maxsize=2000)
def domain_age_days(domain):
    """Age of the domain in days, from the public RDAP registry. None if unknown."""
    try:
        req = urllib.request.Request("https://rdap.org/domain/" + domain, headers={"User-Agent": "PhishGuard"})
        data = json.load(urllib.request.urlopen(req, timeout=4))
        for e in data.get("events", []):
            if e.get("eventAction") == "registration":
                born = datetime.datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                return (datetime.datetime.now(datetime.timezone.utc) - born).days
    except Exception:
        pass
    return None


def analyze(url, live=False):
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    try:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
    except ValueError:
        host = ""
    if not host:
        return {"verdict": "Suspicious", "score": 30, "domain": "", "verified": False,
                "note": "", "reasons": [["Link is not readable", 30]]}

    t = extract(host.encode("idna").decode("ascii"))
    domain = t.top_domain_under_public_suffix if hasattr(t, "top_domain_under_public_suffix") else t.registered_domain
    domain = domain or host
    label = readable(t.domain)
    is_ip = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host))

    # Genuine sites: matched on the REGISTERED domain, so microsoft.evil.com does NOT pass
    if domain in SAFE and not p.username and not is_ip:
        return {"verdict": "Legitimate", "score": 0, "domain": domain, "verified": True,
                "note": "This domain is on the verified trusted list.",
                "reasons": [[domain + " is a verified trusted domain", 0]]}

    reasons = []
    if is_ip:
        reasons.append(["Uses a raw IP address instead of a domain name", 40])
    if p.username:
        reasons.append(["Contains '@' which can hide the real destination", 25])
        if "." in p.username:
            reasons.append(["Text before '@' is made to look like a website", 20])
    if p.scheme == "http":
        reasons.append(["Connection is not encrypted (http)", 10])
    if domain in SHORTENERS:
        reasons.append(["Link shortener hides the real destination", 20])
    if t.suffix.split(".")[-1] in RISKY_TLDS:
        reasons.append(["Domain ending often used by scammers (." + t.suffix + ")", 10])
    if "xn--" in host:
        reasons.append(["Uses disguised international characters", 20])
    if len([s for s in t.subdomain.split(".") if s and s != "www"]) >= 3:
        reasons.append(["Too many subdomain levels", 15])
    if label.count("-") >= 2:
        reasons.append(["Many hyphens in the domain name", 8])
    if len(label) >= 8 and re.search(r"[^aeiou\d\-]{6,}", label):
        reasons.append(["Domain name looks random or machine-generated", 10])
    words = [k for k in KEYWORDS if k in host.replace("-", "")]
    if words:
        reasons.append(["Sensitive words in the domain: " + ", ".join(words[:3]), min(16, 8 * len(words))])
    words = [k for k in SCAM_WORDS if k in host.replace("-", "")]
    if words:
        reasons.append(["Scam-style words in the domain: " + ", ".join(words[:3]), min(25, 10 * len(words))])
    words = [k for k in KEYWORDS if k in (p.path + p.query).lower()]
    if words:
        reasons.append(["Sensitive words in the path: " + ", ".join(words[:3]), min(8, 4 * len(words))])

    # Lookalike / brand impersonation: keep only the strongest finding
    found = []
    parts = label.split("-")
    subs = re.split(r"[-.]", readable(t.subdomain))
    for b in BRANDS:
        if len(b) >= 5 and skeleton(label) == skeleton(b) and label != b:
            found.append(["Lookalike of '" + b + "': " + domain + " imitates it with swapped letters", 65])
        elif label == b:
            found.append(["Uses the name '" + b + "' but not on its official domain", 30])
        elif len(b) >= 6 and distance(label.replace("-", ""), b) <= (2 if len(b) >= 9 else 1):
            found.append(["Looks like a misspelling of '" + b + "'", 50])
        if len(parts) > 1 and b in parts:
            found.append(["Domain name contains the brand '" + b + "' but is not the official site", 55])
        if b in subs:
            found.append(["'" + b + "' is in the subdomain, but the real site is " + domain, 60])
    if found:
        reasons.append(max(found, key=lambda f: f[1]))

    # Live checks: does the domain exist, and how new is it?
    if live and not is_ip:
        if domain_exists(host) is False:
            reasons.append(["This domain does not exist right now (cannot be reached)", 20])
        else:
            age = domain_age_days(domain)
            if age is not None and age < 30:
                reasons.append(["Domain was registered only %d days ago" % age, 40])
            elif age is not None and age < 90:
                reasons.append(["Domain is very new (%d days old)" % age, 25])
            elif age is not None and age < 365:
                reasons.append(["Domain is less than a year old", 10])

    reasons.sort(key=lambda r: -r[1])
    score = min(100, sum(r[1] for r in reasons))
    verdict = "Phishing" if score >= 60 else "Suspicious" if score >= 25 else "Legitimate"
    note = ""
    if verdict == "Legitimate":
        note = ("Not on the trusted list. 'Legitimate' here only means no warning signs were found "
                "in the link. Be careful before logging in or paying.")
    return {"verdict": verdict, "score": score, "domain": domain, "verified": False,
            "note": note, "reasons": reasons}


@app.get("/analyze")
def analyze_api(url: str):
    return analyze(url, live=True)


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>PhishGuard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
input{width:70%;padding:10px;font-size:16px} button{padding:10px 16px;font-size:16px}
.badge{display:inline-block;padding:4px 14px;border-radius:99px;color:#fff;font-weight:700;font-size:20px}
.Legitimate{background:#1a7f45}.Suspicious{background:#b36b00}.Phishing{background:#c62828}.Unverified{background:#5f6a76}
li{margin:6px 0} .note{background:#f1f3f5;padding:10px;border-radius:8px}
</style>
<h1>PhishGuard</h1>
<input id=u placeholder="https://example.com/login"> <button onclick=check()>Check</button>
<div id=out></div>
<script>
async function check(){
  const out=document.getElementById('out'); out.textContent='Checking...';
  try{
    const r=await (await fetch('/analyze?url='+encodeURIComponent(document.getElementById('u').value))).json();
    out.innerHTML='';
    const unver=(r.verdict==='Legitimate' && !r.verified);
    const b=document.createElement('p'); b.innerHTML='<span class="badge '+(unver?'Unverified':r.verdict)+'"></span> &nbsp; Score: '+r.score+'/100';
    b.firstChild.textContent=unver?'No warning signs (not verified)':r.verdict; out.append(b);
    const d=document.createElement('p'); d.textContent='Domain checked: '+r.domain; out.append(d);
    if(r.note){const n=document.createElement('p'); n.className='note'; n.textContent=r.note; out.append(n);}
    const ul=document.createElement('ul');
    r.reasons.forEach(x=>{const li=document.createElement('li'); li.textContent=x[0]+(x[1]?' (+'+x[1]+')':''); ul.append(li)});
    out.append(ul);
  }catch(e){out.textContent='Cannot reach the server. Is it running?'}
}
document.getElementById('u').addEventListener('keydown',e=>{if(e.key==='Enter')check()});
</script>"""


@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
