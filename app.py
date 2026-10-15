from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
from datetime import datetime
import re
import ipaddress

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "account", "update",
    "confirm", "signin", "bank", "password", "credential", "wallet",
    "payment", "unlock", "support", "free", "bonus"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy"
}

BRANDS = {
    "paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com",
    "apple": "apple.com", "icloud": "icloud.com", "amazon": "amazon.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "netflix": "netflix.com",
    "linkedin": "linkedin.com", "whatsapp": "whatsapp.com", "dropbox": "dropbox.com",
}

ACTIONS = {
    "safe": "No strong configured indicators were found. Verify independently before trusting it.",
    "warning": "Several warning signs were found. Do not enter passwords or personal details until you confirm the sender another way.",
    "danger": "Do not open this link or enter any details. If it arrived by email or message, report it and delete it.",
}


def analyze_url(url):
    original = url.strip()
    if not original:
        return {"error": "Please enter a URL."}

    # Allow users to type example.com without the scheme.
    normalized = original if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original) else "http://" + original
    try:
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return {"error": "Invalid URL format."}
    if not hostname:
        return {"error": "Could not find a valid domain in the URL."}

    evidence = []

    def add(title, detail, points, status="risk"):
        evidence.append({"title": title, "detail": detail, "points": points, "status": status})

    # HTTPS
    is_https = parsed.scheme.lower() == "https"
    if is_https:
        add("HTTPS", "HTTPS is present; malicious sites can also use HTTPS.", 0, "ok")
    else:
        add("No HTTPS", "The connection is not encrypted.", 15)

    # IP address instead of domain
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        add("Raw IP host", "Uses an IP address instead of a domain name.", 25)
    except ValueError:
        pass

    # URL length
    if len(original) > 100:
        add("URL length", f"Unusually long URL ({len(original)} characters).", 15)

    # @ symbol
    if "@" in original:
        add("@ symbol", "Can hide the real destination of the link.", 20)

    # Hyphens and subdomains
    if hostname.count("-") >= 3:
        add("Hyphens", "The domain contains many hyphens.", 10)
    dot_count = hostname.count(".")
    if dot_count >= 4:
        add("Subdomains", "Unusually high number of subdomains.", 10)

    # Suspicious keywords
    lowered = original.lower()
    found = [k for k in SUSPICIOUS_KEYWORDS if k in lowered]
    if found:
        add("Suspicious keywords", "Found: " + ", ".join(found[:6]) + ".", min(20, 5 * len(found)))

    # URL shortener
    is_short = hostname.removeprefix("www.") in SHORTENER_DOMAINS
    if is_short:
        add("URL shortener", "Hides the final destination behind a short link.", 15)

    # Punycode / IDN
    is_puny = "xn--" in hostname
    if is_puny:
        add("Punycode", "Look-alike international characters may be used.", 15)

    # Deep path
    if parsed.path.count("/") >= 6:
        add("Deep path", "Unusually deep URL path.", 5)

    # Brand similarity: brand name in the host, but not on the brand's real domain
    brand_hit = None
    if not is_ip:
        tokens = re.split(r"[.\-]", hostname.translate(str.maketrans("0135", "oles")))
        for brand, official in BRANDS.items():
            if brand in tokens and hostname != official and not hostname.endswith("." + official):
                brand_hit = brand
                break
    if brand_hit:
        add("Brand similarity", f"Mentions \"{brand_hit}\" but is not on {BRANDS[brand_hit]}.", 25)

    score = min(100, sum(e["points"] for e in evidence))
    if score >= 60:
        verdict, level = "Potential Phishing", "danger"
    elif score >= 30:
        verdict, level = "Suspicious", "warning"
    else:
        verdict, level = "Likely Legitimate", "safe"

    return {
        "url": original,
        "domain": hostname,
        "score": score,
        "verdict": verdict,
        "level": level,
        "evidence": evidence,
        "action": ACTIONS[level],
        "analyzed_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "features": {
            "protocol": parsed.scheme.upper(),
            "hostname": hostname,
            "length": len(original),
            "subdomains": max(0, dot_count - 1),
            "keyword_count": len(found),
            "raw_ip": is_ip,
            "shortener": is_short,
            "punycode": is_puny,
            "brand": brand_hit,
        },
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    result = analyze_url(data.get("url", ""))
    return jsonify(result), (400 if "error" in result else 200)


if __name__ == "__main__":
    app.run(debug=True)
