
import ipaddress
import socket
import ssl
import requests

from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone


SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "High",
        "Add Strict-Transport-Security on HTTPS sites."
    ),
    "Content-Security-Policy": (
        "High",
        "Define a Content-Security-Policy suited to your application."
    ),
    "X-Content-Type-Options": (
        "Medium",
        "Set X-Content-Type-Options: nosniff."
    ),
    "X-Frame-Options": (
        "Medium",
        "Set X-Frame-Options: DENY or SAMEORIGIN."
    ),
    "Referrer-Policy": (
        "Low",
        "Set a privacy-conscious Referrer-Policy."
    ),
    "Permissions-Policy": (
        "Low",
        "Define a Permissions-Policy for browser features."
    )
}

WEIGHTS = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
    "Info": 0
}

MAX_REDIRECTS = 5


def finding(title, severity, details, recommendation):
    return {
        "title": title,
        "severity": severity,
        "details": details,
        "recommendation": recommendation
    }


def validate_public_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("Invalid website address.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    port = parsed.port

    if port is not None and port not in (80, 443):
        raise ValueError("Only ports 80 and 443 are allowed.")

    host = parsed.hostname.lower().rstrip(".")

    blocked_names = (
        "localhost",
        "local",
        "internal",
        "test"
    )

    if host.endswith((".localhost", ".local", ".internal", ".test")):
        raise ValueError("Private network hostnames are not allowed.")

    if host in blocked_names:
        raise ValueError("Private network hostnames are not allowed.")

    try:
        addresses = socket.getaddrinfo(
            host,
            port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("Could not resolve the website address.")

    if not addresses:
        raise ValueError("No network address found.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError("Private or reserved IP addresses are not allowed.")

    return url


def fetch_target(target):
    session = requests.Session()
    session.trust_env = False

    current_url = target

    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            validate_public_url(current_url)

            response = session.get(
                current_url,
                timeout=(5, 8),
                allow_redirects=False,
                stream=True,
                headers={
                    "User-Agent": "WebGuard/1.0 (authorized passive assessment)"
                }
            )

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()

                if not location:
                    raise ValueError("Redirect location is missing.")

                if redirect_count == MAX_REDIRECTS:
                    raise ValueError("Too many redirects.")

                current_url = urljoin(current_url, location)
                continue

            return session, response

        raise ValueError("Too many redirects.")

    except Exception:
        session.close()
        raise


def scan_website(target):
    validate_public_url(target)

    session = None
    response = None

    try:
        session, response = fetch_target(target)

        status = response.status_code
        headers = response.headers
        final_url = response.url

        parsed = urlparse(final_url)
        host = parsed.hostname
        is_https = parsed.scheme == "https"

        findings = []

        if not is_https:
            findings.append(
                finding(
                    "HTTPS is not enforced",
                    "High",
                    "The final page was reached over plain HTTP.",
                    "Enable HTTPS and redirect HTTP traffic to HTTPS."
                )
            )

        for header, (severity, recommendation) in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    finding(
                        f"Missing {header}",
                        severity,
                        f"The response did not include {header}.",
                        recommendation
                    )
                )

        cookie_headers = []

        raw_headers = getattr(response.raw, "headers", None)

        if raw_headers and hasattr(raw_headers, "getlist"):
            cookie_headers = raw_headers.getlist("Set-Cookie")

        if not cookie_headers:
            cookie_value = headers.get("Set-Cookie")

            if cookie_value:
                cookie_headers = [cookie_value]

        if is_https:
            for cookie in cookie_headers:
                if "secure" not in cookie.lower():
                    findings.append(
                        finding(
                            "Cookie missing Secure attribute",
                            "Medium",
                            "A response cookie may lack the Secure attribute.",
                            "Set Secure on session and sensitive cookies."
                        )
                    )
                    break

        for cookie in cookie_headers:
            if "httponly" not in cookie.lower():
                findings.append(
                    finding(
                        "Cookie missing HttpOnly attribute",
                        "Medium",
                        "A response cookie may be accessible to scripts.",
                        "Set HttpOnly on session cookies where appropriate."
                    )
                )
                break

        for cookie in cookie_headers:
            if "samesite" not in cookie.lower():
                findings.append(
                    finding(
                        "Cookie missing SameSite attribute",
                        "Low",
                        "A response cookie did not declare SameSite.",
                        "Set SameSite=Lax or Strict where appropriate."
                    )
                )
                break

        server_header = headers.get("Server")

        if server_header:
            findings.append(
                finding(
                    "Server banner disclosed",
                    "Info",
                    f"The response disclosed: {server_header[:120]}",
                    "Consider minimizing unnecessary server disclosure."
                )
            )

        if is_https:
            try:
                context = ssl.create_default_context()

                with socket.create_connection(
                    (host, parsed.port or 443),
                    timeout=5
                ) as sock:
                    with context.wrap_socket(
                        sock,
                        server_hostname=host
                    ) as tls_sock:

                        cert = tls_sock.getpeercert()
                        expiry = cert.get("notAfter")

                        if expiry:
                            expiry_dt = datetime.strptime(
                                expiry,
                                "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=timezone.utc)

                            days = (
                                expiry_dt - datetime.now(timezone.utc)
                            ).days

                            if days < 0:
                                findings.append(
                                    finding(
                                        "TLS certificate expired",
                                        "High",
                                        "The TLS certificate appears expired.",
                                        "Renew and correctly install the certificate."
                                    )
                                )

                            elif days <= 30:
                                findings.append(
                                    finding(
                                        "TLS certificate expires soon",
                                        "Medium",
                                        f"The certificate expires in approximately {days} days.",
                                        "Renew the certificate before expiration."
                                    )
                                )

            except Exception as exc:
                findings.append(
                    finding(
                        "TLS certificate check incomplete",
                        "Info",
                        f"Could not inspect certificate: {str(exc)[:160]}",
                        "Verify the certificate using your hosting provider."
                    )
                )

        score_deduction = sum(
            WEIGHTS.get(item["severity"], 0)
            for item in findings
        )

        score = max(0, 100 - score_deduction)

        counts = {
            level: sum(
                1 for item in findings
                if item["severity"] == level
            )
            for level in ("Critical", "High", "Medium", "Low", "Info")
        }

        return {
            "target": target,
            "final_url": final_url,
            "status_code": status,
            "https": is_https,
            "score": score,
            "counts": counts,
            "findings": findings,
            "note": (
                "This is a limited passive assessment, not a full "
                "penetration test. A clean result does not prove "
                "that a website is secure."
            )
        }

    except requests.RequestException as exc:
        raise ValueError(f"Could not reach the target: {exc}")

    finally:
        if response is not None:
            response.close()

        if session is not None:
            session.close()
