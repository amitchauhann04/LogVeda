from flask import Flask, render_template, request, jsonify
import requests, ssl, socket
from datetime import datetime
import re

app = Flask(__name__)

PATTERNS = {
    "SQL Injection": r"(\%27)|(\')|(\-\-)|(union.*select)",
    "XSS Attack": r"(<script>)|(alert\()|(onerror=)",
    "LFI/RFI": r"(\.\./)|(%2e%2e)",
    "Brute Force": r" 401 | 403 | 429 ",
    "Sensitive File": r"(\.env)|(\.git)|(\.bak)|(wp-config)"
}

def pro_scan(domain):
    clean_domain = domain.replace("https://","").replace("http://","").split('/')[0]
    if not domain.startswith("http"):
        domain = "https://" + domain

    report = []
    try:
        r = requests.get(domain, timeout=6)
        # SSL Check
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=clean_domain) as s:
                s.settimeout(3)
                s.connect((clean_domain, 443))
                cert = s.getpeercert()
                exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days = (exp - datetime.now()).days
                report.append({"level": "Info", "title": "SSL Valid", "msg": f"{days} din baaki hain expire hone me"})
        except:
            report.append({"level": "High", "title": "SSL Error", "msg": "SSL certificate nahi mila ya invalid hai"})

        # Tech Stack
        if "wp-content" in r.text: report.append({"level": "Info", "title": "Tech Stack", "msg": "WordPress detected"})
        if "react" in r.text.lower(): report.append({"level": "Info", "title": "Tech Stack", "msg": "React.js detected"})
        if "cloudflare" in str(r.headers).lower(): report.append({"level": "Info", "title": "WAF", "msg": "Cloudflare protection ON hai"})

        # Headers
        if "Content-Security-Policy" not in r.headers:
            report.append({"level": "Medium", "title": "Missing CSP", "msg": "Content-Security-Policy header missing"})
        if "Strict-Transport-Security" not in r.headers:
            report.append({"level": "Medium", "title": "Missing HSTS", "msg": "HSTS header missing"})

        # Sensitive Files
        for path in ["/.env", "/.git/HEAD", "/.DS_Store", "/config.php"]:
            try:
                c = requests.get(domain + path, timeout=2)
                if c.status_code == 200 and len(c.text) > 0 and len(c.text) < 5000:
                    report.append({"level": "Critical", "title": "Sensitive File Exposed", "msg": f"{path} publically accessible hai"})
            except: pass

    except Exception as e:
        report.append({"level": "Critical", "title": "Domain Down", "msg": str(e)})

    return report

@app.route("/")
def home(): return render_template("index.html")
@app.route("/scan", methods=["POST"])
def scan(): return jsonify(pro_scan(request.json.get("domain")))
@app.route("/logscan", methods=["POST"])
def logscan():
    file = request.files['logfile']
    content = file.read().decode('utf-8', errors='ignore')
    findings = []
    for i, line in enumerate(content.splitlines()[:3000]):
        for name, pat in PATTERNS.items():
            if re.search(pat, line, re.IGNORECASE):
                findings.append({"line": i+1, "attack": name, "log": line[:250]})
    return jsonify(findings)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)
