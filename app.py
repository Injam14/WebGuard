from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from scanner import scan_website
from database import init_db, save_scan, get_scans, get_scan
from report import create_pdf
from urllib.parse import urlparse
import io, json

app = Flask(__name__)
app.secret_key = "change-this-development-secret"
init_db()

def normalize_url(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Please enter a website URL.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")
    return value

@app.route("/")
def index():
    scans = get_scans()
    latest = scans[0] if scans else None
    return render_template("index.html", scans=scans[:6], latest=latest)

@app.route("/scan", methods=["POST"])
def scan():
    if request.form.get("authorized") != "yes":
        flash("Please confirm that you have permission to assess this website.", "error")
        return redirect(url_for("index"))
    try:
        target = normalize_url(request.form.get("url"))
        result = scan_website(target)
        scan_id = save_scan(target, result)
        return redirect(url_for("results", scan_id=scan_id))
    except Exception as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

@app.route("/results/<int:scan_id>")
def results(scan_id):
    item = get_scan(scan_id)
    if not item:
        return "Scan not found", 404
    result = json.loads(item["result_json"])
    return render_template("results.html", item=item, result=result)

@app.route("/report/<int:scan_id>")
def report(scan_id):
    item = get_scan(scan_id)
    if not item:
        return "Scan not found", 404
    result = json.loads(item["result_json"])
    pdf = create_pdf(item["target"], result, item["created_at"])
    return send_file(io.BytesIO(pdf), mimetype="application/pdf",
                     as_attachment=True, download_name=f"webguard-report-{scan_id}.pdf")

if __name__ == "__main__":
    app.run(debug=True)
