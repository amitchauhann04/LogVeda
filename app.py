from flask import Flask, render_template, request, jsonify
import requests
import re

app = Flask(__name__)

PATTERNS = {
    "SQL Injection": r"(\%27)|(\')|(\-\-)|(union.*select)",
    "XSS Attempt": r"(<script>)|(alert\()",
    "Brute Force": r" 401 | 403 ",
    "Sensitive File": r"(\.env)|(\.git)|(\.bak)"
}

def scan_domain(domain):
    if not domain.startswith("http"):
        domain = "https://" + domain
    report = []
    try:
        r = requests.get(domain, timeout=5)
        if "Content-Security-Policy" not in r.headers:
            report.append({"level": "Medium", "msg": "CSP Header missing - XSS risk"})
        if "X-Frame-Options" not in r.headers:
            report.append({"level": "Low", "msg": "X-Frame-Options missing - Clickjacking possible"})
        for path in ["/.env", "/robots.txt", "/.git/HEAD"]:
            try:
                c = requests.get(domain + path, timeout=3)
                if c.status_code == 200 and len(c.text) > 5:
                    report.append({"level": "High", "msg": f"Exposed file found: {path}"})
            except: pass
    except Exception as e:
        report.append({"level": "Error", "msg": str(e)})
    return report

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    domain = request.json.get("domain")
    return jsonify(scan_domain(domain))

@app.route("/logscan", methods=["POST"])
def logscan():
    file = request.files['logfile']
    content = file.read().decode('utf-8', errors='ignore')
    findings = []
    for i, line in enumerate(content.splitlines()[:2000]):
        for name, pat in PATTERNS.items():
            if re.search(pat, line, re.IGNORECASE):
                findings.append({"line": i+1, "attack": name, "log": line[:200]})
    return jsonify(findings)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000)
