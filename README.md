
# PhishGuard — Phishing Website Detection & Analysis System

## 1. Requirements
- Python 3.10 or newer
- VS Code (recommended)

## 2. Setup on Windows

Open this folder in VS Code, then open Terminal:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

You should see a local address such as:
`http://127.0.0.1:5000`

Open that address in Chrome.

## 3. Demo URLs

### Safe-style demonstration
https://www.wikipedia.org

### Suspicious demonstration
http://192.168.1.10/login/verify/account

The second URL is intentionally fake and is only for demonstrating detection logic. Do not visit unknown real phishing links.

## 4. What the system checks
- HTTPS vs HTTP
- IP address used instead of a domain
- URL length
- `@` symbol
- excessive hyphens
- excessive subdomains
- suspicious keywords
- URL-shortening services
- Punycode/IDN indicator
- unusually deep paths

## 5. Important academic limitation
This is a rule-based educational detector. A website receiving a low score is NOT guaranteed to be safe. Real phishing detection systems can use threat intelligence, DNS/WHOIS data, browser reputation services, machine learning, and other signals.

## 6. Suggested project title
**PhishGuard: Phishing Website Detection and Analysis System**

## 7. Suggested team division
Member 1 — Backend and detection logic
Member 2 — Frontend/UI and history
Member 3 — Testing, screenshots, report and presentation

## 8. Suggested 7–8 minute demo
1. Problem statement — 45 sec
2. Phishing concept — 45 sec
3. System architecture — 1 min
4. Analyze safe URL — 1 min
5. Analyze suspicious URL — 2 min
6. Explain detection features — 1 min
7. Results, limitations and future scope — 1 min
