import io
import json
from flask import Flask, render_template, request, send_file, jsonify, session, redirect, url_for
from urllib.parse import urlparse
import threading
from functools import wraps

from modules.report import add_finding
from modules.port_scan import tcp_port_scan, get_host_ip
from modules.headers import check_security_headers
from modules.sqli import check_sqli
from modules.xss import check_xss
from modules.database_scan import check_databases
from modules.admin_panel_scan import check_admin_panels
# from modules.sniffer import sniff
# from modules.bruteforce import ssh_bruteforce
from modules.sitemapper import map_site
# from modules.find_connected import get_active_hosts, get_interfaces
from modules.user_recon import find_username
from modules.version_scan import check_version

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

findings = []
scan_progress = 0
scan_running = False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # Replace with your actual authentication logic
        if username == "admin" and password == "password":
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
def index():
    if "logged_in" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    global findings, scan_progress, scan_running
    if request.method == "POST":
        target = request.form.get("target")
        aggressive = request.form.get("aggressive")
        deep = request.form.get("deep")
        permission = request.form.get("permission")

        if not target:
            return render_template("scanner.html", error="Target URL is required.")

        if aggressive and not permission:
            return render_template("scanner.html", error="Aggressive scans require permission.")

        findings = []
        scan_progress = 0
        scan_running = True
        scan_thread = threading.Thread(target=run_scan, args=(target, aggressive, deep))
        scan_thread.start()

        return render_template("scanner.html", scan_started=True)

    return render_template("scanner.html", findings=findings)

@app.route("/progress")
def progress():
    global scan_progress, scan_running
    if not scan_running:
        return jsonify({"progress": 100, "status": "Done"})
    return jsonify({"progress": scan_progress})

@app.route("/results")
def results():
    global findings
    return jsonify(findings)

@app.route("/download")
def download():
    global findings
    if not findings:
        return "No findings to download.", 404

    # Create a file in memory
    mem_file = io.BytesIO()
    mem_file.write(json.dumps(findings, indent=4).encode('utf-8'))
    mem_file.seek(0)

    return send_file(
        mem_file,
        as_attachment=True,
        download_name='scan_results.json',
        mimetype='application/json'
    )

# @app.route("/sniffer", methods=["GET", "POST"])
# def sniffer():
#     if request.method == "POST":
#         target = request.form.get("target")
#         duration = int(request.form.get("duration", 10))
# 
#         if not target:
#             return render_template("sniffer.html", error="Target is required.")
# 
#         output = sniff(target, duration)
#         return render_template("sniffer.html", output=output, target=target, duration=duration)
# 
#     return render_template("sniffer.html")

# @app.route("/bruteforce", methods=["GET", "POST"])
# def bruteforce():
#     if request.method == "POST":
#         target = request.form.get("target")
#         usernames_text = request.form.get("usernames")
#         passwords_text = request.form.get("passwords")
#         user_file = request.files.get("user_file")
#         pass_file = request.files.get("pass_file")
# 
#         if not target:
#             return render_template("bruteforce.html", error="Target is required.")
# 
#         usernames = []
#         if usernames_text:
#             usernames = [u.strip() for u in usernames_text.split(",")]
#         elif user_file:
#             usernames = [line.decode("utf-8").strip() for line in user_file.readlines()]
# 
#         if not usernames:
#             return render_template("bruteforce.html", error="Usernames are required.")
# 
#         passwords = []
#         if passwords_text:
#             passwords = [p.strip() for p in passwords_text.split(",")]
#         elif pass_file:
#             passwords = [line.decode("utf-8").strip() for line in pass_file.readlines()]
# 
#         if not passwords:
#             return render_template("bruteforce.html", error="Passwords are required.")
# 
#         credentials = ssh_bruteforce(target, usernames, passwords)
#         return render_template("bruteforce.html", credentials=credentials, target=target)
# 
#     return render_template("bruteforce.html")

@app.route("/sitemap", methods=["GET", "POST"])
def sitemap():
    if request.method == "POST":
        target = request.form.get("target")
        wordlist_text = request.form.get("wordlist")
        wordlist_file = request.files.get("wordlist_file")
        extensions_text = request.form.get("extensions")

        if not target:
            return render_template("sitemap.html", error="Target is required.")

        wordlist = []
        if wordlist_text:
            wordlist = [w.strip() for w in wordlist_text.split("\n")]
        elif wordlist_file:
            wordlist = [line.decode("utf-8").strip() for line in wordlist_file.readlines()]

        if not wordlist:
            return render_template("sitemap.html", error="Wordlist is required.")

        extensions = []
        if extensions_text:
            extensions = [e.strip() for e in extensions_text.split(",")]
        else:
            extensions = ["", ".html", ".php", ".js", ".txt"]

        found_urls = map_site(target, wordlist, extensions)
        return render_template("sitemap.html", found_urls=found_urls, target=target)

    return render_template("sitemap.html")

# @app.route("/find_connected", methods=["GET", "POST"])
# def find_connected():
#     interfaces = get_interfaces()
#     if request.method == "POST":
#         interface = request.form.get("interface")
#         if not interface:
#             return render_template("find_connected.html", interfaces=interfaces, error="Please select an interface.")
# 
#         hosts, error = get_active_hosts(interface)
#         if error:
#             return render_template("find_connected.html", interfaces=interfaces, error=error)
#         
#         return render_template("find_connected.html", interfaces=interfaces, hosts=hosts, selected_interface=interface)
# 
#     return render_template("find_connected.html", interfaces=interfaces)

@app.route("/user_recon", methods=["GET", "POST"])
def user_recon():
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return render_template("user_recon.html", error="Username is required.")

        found_urls = find_username(username)
        return render_template("user_recon.html", found_urls=found_urls, username=username)

    return render_template("user_recon.html")

@app.route("/version_scan", methods=["GET", "POST"])
def version_scan():
    if request.method == "POST":
        target = request.form.get("target")
        if not target:
            return render_template("version_scan.html", error="Target is required.")

        findings = []
        check_version(target, findings, 1.0)
        return render_template("version_scan.html", versions=findings, target=target)

    return render_template("version_scan.html")

@app.route("/internal")
@login_required
def internal():
    return render_template("internal.html")

def run_scan(target, aggressive, deep):
    global findings, scan_progress, scan_running
    scan_progress = 10
    parsed_url = urlparse(target)
    host = parsed_url.hostname or target
    ip = get_host_ip(host)
    if not ip:
        add_finding(findings, "Host Unreachable", "Info", f"Could not resolve hostname: {host}")
        scan_running = False
        return

    scan_progress = 20
    check_version(target, findings, 1.0)

    scan_progress = 25
    open_ports = tcp_port_scan(ip, DEFAULT_PORTS, 1.0)
    if open_ports:
        add_finding(findings, "Open Ports", "Info", f"Open ports found: {open_ports}")

    scan_progress = 50
    check_security_headers(target, findings, 1.0)

    if deep:
        scan_progress = 60
        check_databases(ip, findings, 1.0)
        scan_progress = 70
        check_admin_panels(target, findings, 1.0)

    if aggressive:
        scan_progress = 85
        check_sqli(target, findings, 1.0, aggressive)
        check_xss(target, findings, 1.0, aggressive)
    
    scan_progress = 100
    scan_running = False

def main():
    app.run(debug=True, host="0.0.0.0", port=5001)

if __name__ == "__main__":
    main()