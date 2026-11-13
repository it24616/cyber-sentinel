"""Live website security check.

Makes the same kind of GET request a browser makes (plus one per redirect), then
checks HTTPS, the TLS certificate, security headers, cookies and information
leaks. It never sends attack payloads or probes other paths.

SSRF protection: the hostname is resolved once, every resolved address must be
public, and the connection is pinned to that checked address (no DNS
rebinding). Every redirect hop is validated the same way.
"""

import http.client
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from backend.detection import risk_level_for

TIMEOUT_SECONDS = 8
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512 * 1024
MAX_URL_LENGTH = 2048
ALLOWED_PORTS = {80, 443, 8080, 8443}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
USER_AGENT = "CyberSentinel-SiteCheck/1.0 (passive security header check)"
HSTS_MIN_SECONDS = 15_552_000  # 180 days
CERT_WARN_DAYS = 14


class SiteCheckError(Exception):
    """A problem worth showing to the user as-is (bad URL, blocked address, unreachable site)."""


# ---------------------------------------------------------------------------
# URL validation and SSRF protection
# ---------------------------------------------------------------------------

def normalize_url(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise SiteCheckError("Enter a website address, for example https://example.com.")
    url = raw.strip()
    if len(url) > MAX_URL_LENGTH:
        raise SiteCheckError("The address is too long.")
    if "://" not in url:
        url = f"https://{url}"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SiteCheckError("Only http:// and https:// addresses can be checked.")
    if not parts.hostname:
        raise SiteCheckError("That doesn't look like a valid website address.")
    if parts.username or parts.password:
        raise SiteCheckError("Addresses with a username or password are not allowed.")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SiteCheckError(f"Port {port} is not allowed. Use 80, 443, 8080 or 8443.")
    return url


def _public(address):
    ip = ipaddress.ip_address(address)
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public_address(host, port, allow_private=False):
    """Resolve host and return one address to connect to, refusing private/reserved targets."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise SiteCheckError(f"Could not find the website “{host}”. Check the spelling.") from None
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise SiteCheckError(f"Could not find the website “{host}”.")
    if not allow_private and not all(_public(address) for address in addresses):
        raise SiteCheckError(
            f"“{host}” points to a private, local or reserved address. "
            "Only public websites can be checked."
        )
    # Prefer IPv4: it works on more networks.
    return sorted(addresses, key=lambda address: ":" in address)[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address
        self._tls_context = context

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def _tls_context(verify):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _certificate_info(sock):
    cert = sock.getpeercert() or {}
    info = {"version": sock.version()}
    if cert:
        def name(field):
            pairs = dict(item for group in cert.get(field, ()) for item in group)
            return pairs.get("organizationName") or pairs.get("commonName")
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        info.update(issuer=name("issuer"), subject=name("subject"),
                    expires_at=expires.isoformat(timespec="seconds"),
                    days_left=(expires - datetime.now(timezone.utc)).days)
    return info


def _fetch_once(url, allow_private, verify=True):
    parts = urlsplit(url)
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    address = resolve_public_address(parts.hostname, port, allow_private)
    connection = (_PinnedHTTPSConnection(parts.hostname, port, address, TIMEOUT_SECONDS, _tls_context(verify))
                  if https else _PinnedHTTPConnection(parts.hostname, port, address, TIMEOUT_SECONDS))
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    started = time.monotonic()
    try:
        connection.request("GET", path, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        # Capture TLS details while the pinned connection is still attached.
        # http.client may detach connection.sock as soon as getresponse() sees
        # a response that will close the connection.
        tls = _certificate_info(connection.sock) if https and connection.sock else None
        response = connection.getresponse()
        elapsed_ms = round((time.monotonic() - started) * 1000)
        headers = response.getheaders()
        body = b"" if response.status in REDIRECT_STATUSES else response.read(MAX_BODY_BYTES)
        return {"url": url, "address": address, "status": response.status, "reason": response.reason,
                "headers": headers, "body": body, "elapsed_ms": elapsed_ms, "tls": tls}
    finally:
        connection.close()


def fetch(url, allow_private=False):
    """Follow redirects (validating every hop) and return the final response plus the chain."""
    chain = []
    tls_error = None
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            try:
                response = _fetch_once(current, allow_private)
            except ssl.SSLCertVerificationError as error:
                # Keep going without verification so headers can still be checked; report the TLS failure.
                tls_error = getattr(error, "verify_message", None) or str(error)
                response = _fetch_once(current, allow_private, verify=False)
        except SiteCheckError:
            raise
        except (socket.timeout, TimeoutError):
            raise SiteCheckError(f"The website did not answer within {TIMEOUT_SECONDS} seconds.") from None
        except ssl.SSLError as error:
            raise SiteCheckError(f"Could not set up a secure (TLS) connection: {error.reason or error}.") from None
        except (ConnectionError, OSError, http.client.HTTPException) as error:
            raise SiteCheckError(f"Could not connect to the website ({error.__class__.__name__}).") from None

        chain.append({"url": current, "status": response["status"]})
        location = dict((k.lower(), v) for k, v in response["headers"]).get("location")
        if response["status"] in REDIRECT_STATUSES and location:
            current = normalize_url(urljoin(current, location))
            continue
        response["chain"] = chain
        response["tls_error"] = tls_error if urlsplit(current).scheme == "https" else None
        return response
    raise SiteCheckError(f"The website redirected more than {MAX_REDIRECTS} times.")


# ---------------------------------------------------------------------------
# Analysis (pure: easy to test without a network)
# ---------------------------------------------------------------------------

MIXED_CONTENT = re.compile(rb"<(?:script|iframe|link|img|audio|video|source)\b[^>]*\b(?:src|href)\s*=\s*[\"']http://", re.I)
VERSION_LIKE = re.compile(r"\d+(?:\.\d+)+")


def _check(check_id, title, status, detail, fix="", weight=0):
    return {"id": check_id, "title": title, "status": status, "detail": detail, "fix": fix,
            "weight": weight if status in ("fail", "warn") else 0}


def analyze(requested_url, response):
    """Turn a fetched response into graded checks."""
    headers = {}
    cookies = []
    for key, value in response["headers"]:
        key = key.lower()
        if key == "set-cookie":
            cookies.append(value)
        headers[key] = f"{headers[key]}, {value}" if key in headers else value

    final_url = response["chain"][-1]["url"]
    https = urlsplit(final_url).scheme == "https"
    tls = response.get("tls") or {}
    checks = []

    # HTTPS and redirects
    if https:
        checks.append(_check("WEB_HTTPS", "Uses HTTPS", "pass", "The page is served over an encrypted connection."))
    else:
        checks.append(_check("WEB_NO_HTTPS", "No HTTPS", "fail",
                             "The page is served over plain HTTP, so visitors' data can be read or changed in transit.",
                             "Install a TLS certificate (Let's Encrypt is free) and redirect all HTTP traffic to HTTPS.", 25))
    if urlsplit(requested_url).scheme == "http" and https:
        checks.append(_check("WEB_HTTPS_REDIRECT", "HTTP redirects to HTTPS", "pass",
                             "Visitors who type http:// are sent to the secure version."))

    # Certificate and protocol
    if https:
        if response.get("tls_error"):
            checks.append(_check("WEB_TLS_INVALID", "Certificate not trusted", "fail",
                                 f"Browsers will show a security warning: {response['tls_error']}.",
                                 "Use a certificate from a trusted authority that matches the domain and is not expired.", 25))
        elif "days_left" in tls:
            days = tls["days_left"]
            issuer = tls.get("issuer") or "a trusted authority"
            if days < 0:
                checks.append(_check("WEB_TLS_EXPIRED", "Certificate expired", "fail",
                                     f"The certificate expired {-days} days ago.", "Renew the certificate now.", 25))
            elif days < CERT_WARN_DAYS:
                checks.append(_check("WEB_TLS_EXPIRING", "Certificate expires soon", "warn",
                                     f"The certificate from {issuer} expires in {days} days.",
                                     "Renew it, and turn on automatic renewal.", 10))
            else:
                checks.append(_check("WEB_TLS_VALID", "Valid certificate", "pass",
                                     f"Issued by {issuer}; expires in {days} days."))
        version = tls.get("version")
        if version in ("TLSv1.2", "TLSv1.3"):
            checks.append(_check("WEB_TLS_VERSION", "Modern TLS version", "pass", f"Connection used {version}."))
        elif version:
            checks.append(_check("WEB_TLS_OLD", "Outdated TLS version", "fail",
                                 f"Connection used {version}, which has known weaknesses.",
                                 "Allow only TLS 1.2 and TLS 1.3 on the server.", 15))

    # Security headers
    csp = headers.get("content-security-policy", "")
    if https:
        hsts = headers.get("strict-transport-security", "")
        max_age = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if not hsts:
            checks.append(_check("WEB_HSTS_MISSING", "HSTS header missing", "warn",
                                 "Browsers are not told to always use HTTPS for this site.",
                                 "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", 10))
        elif not max_age or int(max_age.group(1)) < HSTS_MIN_SECONDS:
            checks.append(_check("WEB_HSTS_SHORT", "HSTS max-age is short", "warn",
                                 f"Current value: {hsts}", "Use max-age of at least 15552000 (180 days).", 5))
        else:
            checks.append(_check("WEB_HSTS", "HSTS enabled", "pass", f"Strict-Transport-Security: {hsts}"))

    if not csp:
        checks.append(_check("WEB_CSP_MISSING", "Content-Security-Policy missing", "warn",
                             "Without a CSP, an XSS bug can load and run scripts from anywhere.",
                             "Add a Content-Security-Policy header, starting with default-src 'self'.", 10))
    elif "'unsafe-inline'" in csp and "nonce-" not in csp and "strict-dynamic" not in csp:
        checks.append(_check("WEB_CSP_WEAK", "CSP allows inline scripts", "warn",
                             "'unsafe-inline' lets injected inline scripts run, which weakens XSS protection.",
                             "Replace 'unsafe-inline' with nonces or hashes.", 5))
    else:
        checks.append(_check("WEB_CSP", "Content-Security-Policy set", "pass", "A CSP limits where scripts can load from."))

    xfo = headers.get("x-frame-options", "")
    if xfo.upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp:
        checks.append(_check("WEB_FRAMING", "Clickjacking protection", "pass", "Other sites cannot embed this page in a frame."))
    else:
        checks.append(_check("WEB_FRAMING_MISSING", "No clickjacking protection", "warn",
                             "Other sites can embed this page invisibly and trick users into clicking.",
                             "Add X-Frame-Options: DENY, or CSP frame-ancestors 'self'.", 8))

    if headers.get("x-content-type-options", "").lower() == "nosniff":
        checks.append(_check("WEB_NOSNIFF", "MIME sniffing blocked", "pass", "X-Content-Type-Options: nosniff is set."))
    else:
        checks.append(_check("WEB_NOSNIFF_MISSING", "X-Content-Type-Options missing", "warn",
                             "Browsers may guess file types, which can turn uploads into scripts.",
                             "Add: X-Content-Type-Options: nosniff", 5))

    if headers.get("referrer-policy"):
        checks.append(_check("WEB_REFERRER", "Referrer-Policy set", "pass", f"Referrer-Policy: {headers['referrer-policy']}"))
    else:
        checks.append(_check("WEB_REFERRER_MISSING", "Referrer-Policy missing", "warn",
                             "Full page addresses (which can contain private data) may leak to other sites.",
                             "Add: Referrer-Policy: strict-origin-when-cross-origin", 3))

    if headers.get("permissions-policy"):
        checks.append(_check("WEB_PERMISSIONS", "Permissions-Policy set", "pass", "Browser features such as camera and location are restricted."))
    else:
        checks.append(_check("WEB_PERMISSIONS_MISSING", "Permissions-Policy missing", "info",
                             "Optional: restrict browser features (camera, microphone, location) the site doesn't use.",
                             "Add e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()"))

    # Information disclosure
    leaks = [f"{name}: {headers[name]}" for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
             if VERSION_LIKE.search(headers.get(name, ""))]
    if leaks:
        checks.append(_check("WEB_VERSION_LEAK", "Software versions exposed", "warn",
                             "Exact versions help attackers find known vulnerabilities: " + "; ".join(leaks),
                             "Hide version numbers in server and framework headers.", 5))
    else:
        checks.append(_check("WEB_NO_VERSION_LEAK", "No software versions exposed", "pass",
                             "Server headers don't reveal exact software versions."))

    # Cookies
    if cookies:
        problems = []
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            flags = cookie.lower()
            missing = [flag for flag, present in (
                ("Secure", "; secure" in flags or not https),
                ("HttpOnly", "httponly" in flags),
                ("SameSite", "samesite" in flags)) if not present]
            if missing:
                problems.append(f"{name} (no {', '.join(missing)})")
        if problems:
            checks.append(_check("WEB_COOKIE_FLAGS", "Cookies missing security flags", "warn",
                                 "; ".join(problems[:6]),
                                 "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.", 8))
        else:
            checks.append(_check("WEB_COOKIES", "Cookies are protected", "pass",
                                 f"{len(cookies)} cookie(s) have Secure, HttpOnly and SameSite."))

    # Mixed content
    if https:
        mixed = len(MIXED_CONTENT.findall(response.get("body") or b""))
        if mixed:
            checks.append(_check("WEB_MIXED_CONTENT", "Insecure resources on a secure page", "warn",
                                 f"{mixed} script, style, frame or media reference(s) load over http://.",
                                 "Load every resource over https://.", 8))

    # CORS
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        checks.append(_check("WEB_CORS_OPEN", "CORS allows any site with credentials", "fail",
                             "Any website may read responses on behalf of logged-in users.",
                             "Allow only your own origins, never '*' together with credentials.", 15))

    if response["status"] >= 400:
        checks.append(_check("WEB_HTTP_ERROR", f"Page returned HTTP {response['status']}", "info",
                             "The headers of an error page may differ from the real site; check the main page too."))

    penalty = sum(check["weight"] for check in checks)
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    risk_score = min(100, penalty)
    counts = {status: sum(check["status"] == status for check in checks) for status in ("fail", "warn", "pass", "info")}
    order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    checks.sort(key=lambda check: (order[check["status"]], -check["weight"]))

    return {
        "url": requested_url,
        "final_url": final_url,
        "status_code": response["status"],
        "response_ms": response["elapsed_ms"],
        "address": response["address"],
        "server": headers.get("server"),
        "redirects": response["chain"],
        "tls": ({**tls, "error": response.get("tls_error")} if https else None),
        "score": score,
        "grade": grade,
        "risk_score": risk_score,
        "risk_level": risk_level_for(risk_score),
        "counts": counts,
        "checks": checks,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def check_site(raw_url, allow_private=False):
    url = normalize_url(raw_url)
    return analyze(url, fetch(url, allow_private))


def as_assessment(report):
    """Shape a report like a rule-engine result so it can be stored as an event."""
    problems = [check for check in report["checks"] if check["status"] in ("fail", "warn")]
    return {
        "risk_score": report["risk_score"],
        "risk_level": report["risk_level"],
        "detected_threats": [check["title"] for check in problems] or ["No website security issues found"],
        "matched_rules": [check["id"] for check in problems],
        "recommendation": (problems[0]["fix"] if problems else "No action needed. Re-check after site changes."),
    }
