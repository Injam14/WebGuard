import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime, timezone

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("High", "Add Strict-Transport-Security on HTTPS sites."),
    "Content-Security-Policy": ("High", "Define a Content-Security-Policy suited to your application."),
    "X-Content-Type-Options": ("Medium", "Set X-Content-Type-Options: nosniff."),
    "X-Frame-Options": ("Medium", "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."),
    "Referrer-Policy": ("Low", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
    "Permissions-Policy": ("Low", "Define a Permissions-Policy that disables unneeded browser features.")
}
WEIGHTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}

def finding(title, severity, details, recommendation):
    return {"title": title, "severity": severity, "details": details,
            "recommendation": recommendation}

def scan_website(target):
    parsed = urlparse(target)
    host = parsed.hostname
    findings = []
    response = None
    try:
        response = requests.get(target, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "WebGuard/1.0 (authorized passive assessment)"},
                                stream=True)
        status = response.status_code
        headers = response.headers
        final_url = response.url
    except requests.RequestException as exc:
        raise ValueError(f"Could not reach the target: {exc}")

    is_https = urlparse(final_url).scheme == "https"
    if not is_https:
        findings.append(finding("HTTPS is not enforced", "High",
            "The final page was reached over plain HTTP.",
            "Enable HTTPS and redirect all HTTP traffic to HTTPS."))

    for header, (severity, recommendation) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(finding(f"Missing {header}", severity,
                f"The response did not include the {header} header.", recommendation))

    cookies = response.cookies
    set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not set_cookie_headers and cookies:
        set_cookie_headers = [str(c) for c in cookies]
    for cookie in set_cookie_headers:
        low = cookie.lower()
        if is_https and "secure" not in low:
            findings.append(finding("Cookie missing Secure attribute", "Medium",
                "A response cookie may be sent over an unencrypted connection.",
                "Set the Secure attribute on session and sensitive cookies."))
            break
    for cookie in set_cookie_headers:
        low = cookie.lower()
        if "httponly" not in low:
            findings.append(finding("Cookie missing HttpOnly attribute", "Medium",
                "A response cookie may be accessible to client-side scripts.",
                "Set HttpOnly on session cookies unless JavaScript access is required."))
            break
    for cookie in set_cookie_headers:
        low = cookie.lower()
        if "samesite" not in low:
            findings.append(finding("Cookie missing SameSite attribute", "Low",
                "A response cookie did not declare a SameSite policy.",
                "Set SameSite=Lax or Strict where compatible with the application."))
            break

    server_header = headers.get("Server")
    if server_header:
        findings.append(finding("Server banner disclosed", "Info",
            f"The response disclosed the Server header: {server_header[:120]}",
            "Consider minimizing unnecessary server and version disclosure."))

    # Check the certificate validity using the system TLS trust store.
    if is_https:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    expiry = cert.get("notAfter")
                    if expiry:
                        expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (expiry_dt - datetime.now(timezone.utc)).days
                        if days < 0:
                            findings.append(finding("TLS certificate expired", "High",
                                "The TLS certificate appears to be expired.",
                                "Renew and correctly install the TLS certificate."))
                        elif days <= 30:
                            findings.append(finding("TLS certificate expires soon", "Medium",
                                f"The TLS certificate expires in approximately {days} days.",
                                "Renew the certificate before its expiration date."))
        except Exception as exc:
            findings.append(finding("TLS certificate check incomplete", "Info",
                f"Could not independently inspect the certificate: {str(exc)[:160]}",
                "Verify certificate chain, hostname, and expiry using your hosting provider."))

    response.close()
    score_deduction = sum(WEIGHTS.get(x["severity"], 0) for x in findings)
    score = max(0, 100 - score_deduction)
    counts = {level: sum(1 for x in findings if x["severity"] == level)
              for level in ("Critical", "High", "Medium", "Low", "Info")}
    return {
        "target": target, "final_url": final_url, "status_code": status,
        "https": is_https, "score": score, "counts": counts,
        "findings": findings,
        "note": "This is a limited passive assessment, not a full penetration test. A clean result does not prove that a website is secure."
    }
