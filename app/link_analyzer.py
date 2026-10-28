"""
Link Analyzer
--------------
Extracts URLs from a message and checks them for common phishing signals:
- Known URL shorteners
- Lookalike domains impersonating major Ethiopian brands
- Basic TLS certificate presence/validity check (requires network access)

Safety rules (the analyzer can be reached by strangers through the web page
and the Telegram bot, so it must not be abusable):
- At most MAX_LINKS links per message are checked (each check can take seconds).
- The certificate check NEVER connects to private/internal addresses
  (127.x, 10.x, 192.168.x, 169.254.x, localhost ...). A message that points
  at one is flagged as suspicious instead of being visited.
- The connection goes to the exact IP address that was checked, so a domain
  cannot switch to an internal address between the check and the connection.

Note: certificate checks need outbound network access to the target domain on
port 443. Offline, they fail safe (valid=None) and the rest of the pipeline
still works.
"""

import ipaddress
import re
import socket
import ssl
from urllib.parse import urlparse

MAX_LINKS = 5   # links checked per message

# Top-level domains we recognise when a link has no http:// or www. in front.
# Includes shortener TLDs (.ly, .gl, .gd) and TLDs often abused in scams.
TLDS = (
    "com|net|org|et|ly|io|co|me|info|xyz|top|link|click|online|site|app|biz|"
    "gl|gd|ws|cc|tk|ml|ga|cf|gq|ru|cn"
)
URL_PATTERN = (
    r"(https?://[^\s]+"
    r"|www\.[^\s]+"
    r"|\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.(?:" + TLDS + r")\b(?:/[^\s]*)?)"
)

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly",
}

# Real brand domains you consider "legitimate" for comparison.
# Extend this list with the actual official domains you want to protect.
BRAND_DOMAINS = {
    "telebirr": ["telebirr.com", "ethiotelecom.et"],
    "cbe": ["cbe.com.et", "cbebirr.et"],
    "dashen": ["dashenbanksc.com"],
    "awash": ["awashbank.com"],
    "ethiotelecom": ["ethiotelecom.et"],
}


# Links to these domains are NOT treated as a warning sign by the rule engine.
# Only list domains you are CERTAIN belong to the organisation: verify each one
# before demo day. (A look-alike such as cbe.com.et.evil.com does not match.)
TRUSTED_LINK_DOMAINS = ["ethiotelecom.et", "cbe.com.et", "awashbank.com", "dashenbanksc.com"]


def extract_urls(text: str):
    """Find every link in the text (no duplicates, trailing punctuation removed)."""
    found = re.findall(URL_PATTERN, text, flags=re.IGNORECASE)
    urls = []
    for u in found:
        u = u.rstrip(".,;:!?)\"'")
        if u and u not in urls:
            urls.append(u)
    return urls


def _get_domain(url: str) -> str:
    if not re.match(r"(?i)https?://", url):
        url = "http://" + url
    try:
        host = urlparse(url).hostname      # handles :port, user@, [ipv6]
    except ValueError:
        host = None
    return (host or "").lower()


def get_domain(url: str) -> str:
    """Public name for the host-name parser (used by the rule engine)."""
    return _get_domain(url)


def is_trusted_domain(domain: str) -> bool:
    return any(domain == t or domain.endswith("." + t) for t in TRUSTED_LINK_DOMAINS)


def is_shortener(domain: str) -> bool:
    return any(domain == sh or domain.endswith("." + sh) for sh in KNOWN_SHORTENERS)


def is_lookalike(domain: str):
    """
    Very simple lookalike check: does the domain contain a brand keyword
    but NOT match any of that brand's real domains?
    Returns the brand name if suspicious, else None.
    """
    tokens = re.split(r"[^a-z0-9]+", domain)
    for brand, real_domains in BRAND_DOMAINS.items():
        is_official = any(domain == rd or domain.endswith("." + rd) for rd in real_domains)
        if not is_official and any(tok.startswith(brand) for tok in tokens):
            return brand
    return None


def _resolve_public(domain: str):
    """
    Look the host up and make sure it only points at public internet addresses.
    Returns (ip, None) if safe to connect to, (None, "private") if any address
    is private/internal, or (None, "unresolved") if it cannot be resolved.
    """
    if not domain:
        return None, "unresolved"
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return None, "unresolved"
    first = None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            return None, "private"
        first = first or str(ip)
    return (first, None) if first else (None, "unresolved")


# OpenSSL verification codes that mean the certificate ITSELF is wrong. Only
# these count against a site. Anything else (typically "can't link this
# certificate to a trusted root", codes 19-21) can be a gap in THIS computer's
# list of trusted roots or a network that inspects traffic, so it is reported
# as "could not be confirmed" and adds no risk points.
_BAD_CERT_FLAGS = {
    10: "Certificate has expired",
    9: "Certificate is not valid yet",
    62: "Certificate belongs to a different website",
    64: "Certificate belongs to a different address",
    18: "Certificate is self-signed (no trusted authority vouches for it)",
    7: "Certificate signature is invalid",
    23: "Certificate has been revoked",
}
_NOT_CONFIRMED = "Certificate could not be confirmed on this computer (not counted against the site)"

_ctx = None


def _tls_context():
    """
    Default TLS settings plus the certifi list of trusted roots when it is
    installed. Windows only learns some roots on demand, so Python alone can
    miss roots that a browser already knows. certifi is plain data (no compiled
    code), so security policies do not block it. Works without certifi too.
    """
    global _ctx
    if _ctx is None:
        ctx = ssl.create_default_context()
        try:
            import certifi
            ctx.load_verify_locations(cafile=certifi.where())
        except Exception:
            pass
        _ctx = ctx
    return _ctx


def _verify_tls(ip: str, server_name: str, timeout: float = 3.0, ctx=None, port: int = 443):
    """
    Open a TLS connection to ip and verify the certificate for server_name.
    Returns {"valid": True/False/None, "reason": technical text,
             "flag": short text for the user, "code": OpenSSL code (if any)}.
    """
    ctx = ctx or _tls_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                ssock.getpeercert()
        return {"valid": True, "reason": None, "flag": None}
    except ssl.SSLCertVerificationError as e:
        code = e.verify_code
        reason = f"Certificate verification failed (code {code}): {e.verify_message}"
        if code in _BAD_CERT_FLAGS:
            return {"valid": False, "code": code, "reason": reason, "flag": _BAD_CERT_FLAGS[code]}
        return {"valid": None, "code": code, "reason": reason, "flag": _NOT_CONFIRMED}
    except ssl.SSLError as e:   # e.g. the site does not speak TLS on this port
        return {"valid": None, "reason": f"TLS handshake failed ({e.reason or e})",
                "flag": "No secure (HTTPS) connection could be set up to check the certificate"}
    except Exception as e:      # timeouts, refused connections, resets ...
        return {"valid": None, "reason": f"Could not connect ({type(e).__name__})",
                "flag": "Could not connect to check this site's certificate"}


def check_certificate(domain: str, timeout: float = 3.0):
    """
    Check a domain's TLS certificate. Returns a dict with 'valid' (True / False /
    None), a 'flag' to show the user and a technical 'reason'.
    'private': True means the link points at an internal address and was
    deliberately NOT visited.
    """
    ip, problem = _resolve_public(domain)
    if problem == "private":
        return {"valid": None, "private": True,
                "reason": "Points to a private or internal address"}
    if problem == "unresolved":
        return {"valid": None, "reason": "Domain could not be resolved",
                "flag": "Domain could not be found (it may not exist, or you may be offline)"}
    return _verify_tls(ip, domain, timeout)


def analyze(text: str) -> dict:
    all_urls = extract_urls(text)
    urls = all_urls[:MAX_LINKS]
    findings = []
    score = 0

    for url in urls:
        domain = _get_domain(url)
        entry = {"url": url, "domain": domain, "flags": []}

        if is_shortener(domain):
            entry["flags"].append("Shortened link — real destination is hidden")
            score += 15

        brand = is_lookalike(domain)
        if brand:
            entry["flags"].append(f"Domain resembles '{brand}' but does not match its official domain")
            score += 30

        cert = check_certificate(domain)
        if cert.get("private"):
            entry["flags"].append("Link points to a private or internal network address (not visited)")
            score += 20
        elif cert["valid"] is False:
            entry["flags"].append(cert.get("flag") or "Invalid TLS certificate")
            score += 25
        elif cert["valid"] is None:
            entry["flags"].append(cert.get("flag") or "Certificate could not be verified")

        findings.append(entry)

    return {
        "urls_found": len(all_urls),
        "findings": findings,
        "link_score": min(score, 100),
    }


if __name__ == "__main__":
    sample = "Verify your account now at http://telebirr-verify.com or bit.ly/xyz123"
    print(analyze(sample))
