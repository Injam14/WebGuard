
import os
import io
import json
import hmac
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, Response
)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from scanner import scan_website
from database import init_db, save_scan, get_scans, get_scan
from report import create_pdf

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required.")

# Rate limiter: maximum 5 scans per visitor in 10 minutes.
# Memory storage is suitable for an initial single-instance demo.
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://"
)

init_db()


@app.before_request
def require_login():
    username = os.environ.get("WEBGUARD_USERNAME")
    password = os.environ.get("WEBGUARD_PASSWORD")

    if not username or not password:
        return "WebGuard login is not configured.", 503

    auth = request.authorization

    if not auth:
        return login_required_response()

    supplied_username = auth.username or ""
    supplied_password = auth.password or ""

    username_ok = hmac.compare_digest(
        supplied_username.encode("utf-8"),
        username.encode("utf-8")
    )

    password_ok = hmac.compare_digest(
        supplied_password.encode("utf-8"),
        password.encode("utf-8")
    )

    if not (username_ok and password_ok):
        return login_required_response()

    return None


def login_required_response():
    return Response(
        "Login required. Enter your WebGuard username and password.",
        401,
        {"WWW-Authenticate": 'Basic realm="WebGuard Login"'}
    )


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

    return render_template(
        "index.html",
        scans=scans[:6],
        latest=latest
    )


@app.route("/scan", methods=["POST"])
@limiter.limit("5 per 10 minutes")
def scan():
    if request.form.get("authorized") != "yes":
        flash(
            "Please confirm that you have permission to assess this website.",
            "error"
        )
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

    return render_template(
        "results.html",
        item=item,
        result=result
    )


@app.route("/report/<int:scan_id>")
def report(scan_id):
    item = get_scan(scan_id)

    if not item:
        return "Scan not found", 404

    result = json.loads(item["result_json"])

    pdf = create_pdf(
        item["target"],
        result,
        item["created_at"]
    )

    return send_file(
        io.BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"webguard-report-{scan_id}.pdf"
    )


if __name__ == "__main__":
    app.run(debug=False)
