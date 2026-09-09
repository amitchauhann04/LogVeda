from flask import Flask, render_template, request, jsonify, send_file
import requests, socket, re, whois, io
from datetime import datetime
from urllib.parse import urljoin
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)
last_scan_data = {} # report ke liye

def get_domain_details(domain_name):
    info = {}
    try:
        clean = domain_name.replace("https://","").replace("http://","").split('/')[0]
        # WHOIS
        w = whois.whois(clean)
        info['registrar'] = str(w.registrar) if w.registrar else "Private / Not Found"
        info['company'] = str(w.org) if w.org else info['registrar']
        info['creation'] = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)[:10]
        info['expiry'] = str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date)[:10]
        info['name_servers'] = ", ".join(w.name_servers[:2]) if w.name_servers else "N/A"

        # IP & Hosting & Location
        ip = socket.gethostbyname(clean)
        info['ip'] = ip
        geo = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,org,isp,query", timeout=5).json()
        info['hosting'] = geo.get('org', geo.get('isp', 'Unknown'))
        info['isp'] = geo.get('isp','Unknown')
        info['country'] = f"{geo.get('city','')}, {geo.get('regionName','')}, {geo.get('country','')}"
        info['lat'] = geo.get('lat', 28.6139)
        info['lon'] = geo.get('lon', 77.2090)
        info['map_url'] = f"https://www.google.com/maps?q={info['lat']},{info['lon']}&z=8"
    except Exception as e:
        info = {'registrar':'N/A','company':'N/A','creation':'N/A','expiry':'N/A','ip':'N/A','hosting':'Cloudflare/AWS','country':'Unknown','lat':28.61,'lon':77.20,'map_url':'#'}
    return info

def run_scan(target):
    clean_domain = target.replace("https://","").replace("http://","").split('/')[0]
    if not target.startswith("http"): target = "https://" + target

    domain_info = get_domain_details(clean_domain)
    findings = []
    try:
        r = requests.get(target, timeout=8, headers={'User-Agent':'LogVeda-PRO'})
        server_header = r.headers.get('Server','Unknown')

        # 1. Sensitive Files - Only High/Critical
        for path in ["/.env","/.git/HEAD","/admin","/wp-login.php","/robots.txt"]:
            try:
                test_url = urljoin(target, path)
                c = requests.get(test_url, timeout=3)
                if c.status_code == 200 and len(c.text) > 20 and len(c.text) < 8000:
                    level = "Critical" if path in ["/.env","/.git/HEAD"] else "High"
                    findings.append({"level":level,"title":f"Sensitive Exposure: {path}","location":test_url,"evidence":c.text[:300],"fix":f"Block public access to {path} via.htaccess/nginx config. Remove from production.","url":test_url})
            except: pass

        # 2. Headers Check
        if "Content-Security-Policy" not in r.headers:
            findings.append({"level":"Medium","title":"Missing CSP Header","location":f"Header: {target}","evidence":"Content-Security-Policy header not found in response","fix":"Add header: Content-Security-Policy: default-src 'self'","url":target})
        if "X-Frame-Options" not in r.headers:
            findings.append({"level":"Medium","title":"Missing X-Frame-Options","location":f"Header: {target}","evidence":"Clickjacking protection missing","fix":"Add header: X-Frame-Options: SAMEORIGIN","url":target})
        if "Strict-Transport-Security" not in r.headers:
            findings.append({"level":"Low","title":"Missing HSTS","location":f"Header: {target}","evidence":"HSTS header missing","fix":"Add header: Strict-Transport-Security: max-age=31536000","url":target})

    except Exception as e:
        findings.append({"level":"High","title":"Domain Unreachable","location":target,"evidence":str(e),"fix":"Check domain name","url":target})

    # Save for report
    last_scan_data['findings'] = findings
    last_scan_data['domain_info'] = domain_info
    last_scan_data['target'] = target
    return {"findings": findings, "domain_info": domain_info, "server": server_header}

@app.route("/")
def home(): return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan(): return jsonify(run_scan(request.json.get("domain")))

@app.route("/download_report")
def download_report():
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, h-50, f"LogVeda PRO - Security Report")
    c.setFont("Helvetica", 10)
    c.drawString(40, h-70, f"Target: {last_scan_data.get('target','')} | Date: {datetime.now().strftime('%d %b %Y')}")
    y = h-110
    for f in last_scan_data.get('findings',[])[:30]:
        if y < 80: c.showPage(); y = h-50
        c.setFont("Helvetica-Bold", 10); c.drawString(40, y, f"[{f['level']}] {f['title']}"); y-=14
        c.setFont("Helvetica", 8); c.drawString(40, y, f"Location: {f['location']}"); y-=12
        c.drawString(40, y, f"Fix: {f['fix'][:110]}"); y-=20
    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="LogVeda_Report.pdf", mimetype='application/pdf')

@app.route("/logscan", methods=["POST"])
def logscan():
    file = request.files['logfile']
    content = file.read().decode('utf-8', errors='ignore')
    findings=[]
    for i,line in enumerate(content.splitlines()[:4000]):
        if " 401 " in line or "' OR" in line or "UNION SELECT" in line or "<script" in line.lower():
            findings.append({"line":i+1,"attack":"Suspicious Pattern","log":line[:300],"ip":line.split()[0]})
    return jsonify(findings)

if __name__ == "__main__": app.run(host='0.0.0.0', port=10000)
