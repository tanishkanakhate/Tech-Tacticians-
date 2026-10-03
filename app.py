import re
import unicodedata
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
# Trusted sites (brand domains are trusted automatically)
SAFE = {"wikipedia.org", "github.com", "stackoverflow.com", "python.org"}
SAFE |= {d for v in BRANDS.values() for d in v}

KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "bank", "confirm", "password", "wallet"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "work", "buzz"}

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


def analyze(url):
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    try:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
    except ValueError:
        host = ""
    if not host:
        return {"verdict": "Suspicious", "score": 30, "domain": "", "reasons": [["Link is not readable", 30]]}

    t = extract(host.encode("idna").decode("ascii"))
    domain = t.top_domain_under_public_suffix if hasattr(t, "top_domain_under_public_suffix") else t.registered_domain
    domain = domain or host
    label = readable(t.domain)
    is_ip = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host))

    # Genuine sites: matched on the REGISTERED domain, so microsoft.evil.com does NOT pass
    if domain in SAFE and not p.username and not is_ip:
        return {"verdict": "Legitimate", "score": 0, "domain": domain,
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
    words = [k for k in KEYWORDS if k in host.replace("-", "")]
    if words:
        reasons.append(["Sensitive words in the domain: " + ", ".join(words[:3]), min(16, 8 * len(words))])
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

    reasons.sort(key=lambda r: -r[1])
    score = min(100, sum(r[1] for r in reasons))
    verdict = "Phishing" if score >= 60 else "Suspicious" if score >= 25 else "Legitimate"
    return {"verdict": verdict, "score": score, "domain": domain, "reasons": reasons}


@app.get("/analyze")
def analyze_api(url: str):
    return analyze(url)


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>PhishGuard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
input{width:70%;padding:10px;font-size:16px} button{padding:10px 16px;font-size:16px}
.badge{display:inline-block;padding:4px 14px;border-radius:99px;color:#fff;font-weight:700;font-size:20px}
.Legitimate{background:#1a7f45}.Suspicious{background:#b36b00}.Phishing{background:#c62828}
li{margin:6px 0}
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
    const b=document.createElement('p'); b.innerHTML='<span class="badge '+r.verdict+'"></span> &nbsp; Score: '+r.score+'/100';
    b.firstChild.textContent=r.verdict; out.append(b);
    const d=document.createElement('p'); d.textContent='Real domain: '+r.domain; out.append(d);
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
