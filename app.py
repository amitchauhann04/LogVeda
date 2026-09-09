from flask import Flask, render_template, request, jsonify
import requests, ssl, socket, re
from datetime import datetime
from urllib.parse import urljoin

app = Flask(__name__)

def get_evidence_scan(domain):
    clean_domain = domain.replace("https://","").replace("http://","").split('/')[0]
    if not domain.startswith("http"): domain = "https://" + domain

    findings = []
    try:
        r = requests.get(domain, timeout=8)
        html = r.text

        # 1. SSL - Location dikhao
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=clean_domain) as s:
                s.settimeout(3); s.connect((clean_domain, 443))
                cert = s.getpeercert()
                exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                findings.append({"level":"Info","title":"SSL Valid","location":f"{clean_domain}:443","evidence":f"Issuer: {cert['issuer'][0][0][1]} | Expires in {(exp-datetime.now()).days} days","fix":"Kuch karne ki zarurat nahi","url":domain})
        except:
            findings.append({"level":"Critical","title":"SSL Invalid","location":f"{clean_domain}:443","evidence":"No valid SSL found","fix":"Let's Encrypt se SSL install karo","url":domain})

        # 2. CSP - Kaha missing hai, exact proof
        if "Content-Security-Policy" not in r.headers:
            findings.append({
                "level":"Medium","title":"Missing CSP Header","location":f"Response Header of {domain}",
                "evidence": str(dict(r.headers))[:400],
                "fix":"Server me header add karo: Content-Security-Policy: default-src 'self'",
                "url": domain,
                "poc_url": f"https://securityheaders.com/?q={domain}"
            })

        # 3. Exposed Files - Open karne layak link ke saath
        for path in ["/.env","/.git/HEAD","/robots.txt","/.DS_Store"]:
            try:
                test_url = urljoin(domain, path)
                c = requests.get(test_url, timeout=3)
                if c.status_code == 200 and len(c.text) > 10 and len(c.text) < 5000:
                    findings.append({
                        "level":"Critical","title":f"Sensitive File Exposed: {path}",
                        "location": test_url,
                        "evidence": c.text[:300],
                        "fix": f"{path} ko public access se hatao,.htaccess me deny karo",
                        "url": test_url,
                        "poc_url": test_url
                    })
            except: pass

        # 4. Source me inline script dhoondo - Line number ke saath
        for m in re.finditer(r"<script[^>]*>.*?</script>", html, re.DOTALL | re.IGNORECASE):
            line_no = html[:m.start()].count('\n') + 1
            findings.append({
                "level":"Low","title":"Inline Script Found (XSS Surface)","location":f"{domain} -> Line No: {line_no}",
                "evidence": m.group(0)[:200],
                "fix":"Inline JS ko external file me daalo aur CSP lagao",
                "url": domain,
                "poc_url": f"view-source:{domain}"
            })
            if len(findings) > 15: break

    except Exception as e:
        findings.append({"level":"Critical","title":"Scan Failed","location":domain,"evidence":str(e),"fix":"Domain check karo","url":domain})
    return findings

@app.route("/")
def home(): return render_template("index.html")
@app.route("/scan", methods=["POST"])
def scan(): return jsonify(get_evidence_scan(request.json.get("domain")))

@app.route("/logscan", methods=["POST"])
def logscan():
    file = request.files['logfile']
    content = file.read().decode('utf-8', errors='ignore')
    findings=[]
    for i,line in enumerate(content.splitlines()[:3000]):
        if " 401 " in line or "' OR" in line or "<script" in line:
            findings.append({"line":i+1,"attack":"Suspicious","log":line[:250],"location":f"Log Line {i+1}","ip":line.split()[0] if line.split() else "N/A"})
    return jsonify(findings)

if __name__ == "__main__": app.run(host='0.0.0.0', port=10000)
