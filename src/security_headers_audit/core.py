"""HTTP security header analysis with an A-F grade. Works offline on header dumps or live via urllib."""
from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass

PENALTY = {"high": 20, "medium": 10, "low": 5}


@dataclass
class Issue:
    header: str
    severity: str
    message: str

    def as_dict(self):
        return self.__dict__.copy()


def parse_headers(raw: str) -> dict[str, str]:
    """Parse a raw header dump (optionally starting with a status line) into a lowercase dict."""
    out: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith(("HTTP/", " ", "\t")):
            k, v = line.split(":", 1)
            out[k.strip().lower()] = (out[k.strip().lower()] + ", " + v.strip()) if k.strip().lower() in out else v.strip()
    return out


def _csp(v: str) -> list[Issue]:
    out = []
    d = {p.split()[0].lower(): p.split()[1:] for p in (x.strip() for x in v.split(";")) if p}
    script = d.get("script-src", d.get("default-src", []))
    if "'unsafe-inline'" in script and not any(t.startswith(("'nonce-", "'sha")) for t in script):
        out.append(Issue("content-security-policy", "high", "script-src allows 'unsafe-inline' without nonce or hash"))
    if "'unsafe-eval'" in script:
        out.append(Issue("content-security-policy", "medium", "script-src allows 'unsafe-eval'"))
    if "*" in script or "http:" in script or "data:" in script:
        out.append(Issue("content-security-policy", "high", "script-src allows wildcard, http: or data: sources"))
    if "default-src" not in d and "script-src" not in d:
        out.append(Issue("content-security-policy", "medium", "no default-src or script-src"))
    if "object-src" not in d and "default-src" not in d:
        out.append(Issue("content-security-policy", "low", "object-src not restricted"))
    if "frame-ancestors" not in d:
        out.append(Issue("content-security-policy", "low", "no frame-ancestors (clickjacking relies on X-Frame-Options)"))
    return out


def _hsts(v: str) -> list[Issue]:
    m = re.search(r"max-age=(\d+)", v, re.I)
    out = []
    if not m:
        return [Issue("strict-transport-security", "high", "max-age missing")]
    if int(m.group(1)) < 15552000:
        out.append(Issue("strict-transport-security", "medium", f"max-age {m.group(1)} is below 180 days"))
    if "includesubdomains" not in v.lower():
        out.append(Issue("strict-transport-security", "low", "includeSubDomains not set"))
    return out


def _cookies(headers: dict[str, str], raw_cookies: list[str]) -> list[Issue]:
    out = []
    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        if "secure" not in low:
            out.append(Issue("set-cookie", "high", f"cookie '{name}' missing Secure"))
        if "httponly" not in low:
            out.append(Issue("set-cookie", "medium", f"cookie '{name}' missing HttpOnly"))
        if "samesite" not in low:
            out.append(Issue("set-cookie", "medium", f"cookie '{name}' missing SameSite"))
        elif "samesite=none" in low and "secure" not in low:
            out.append(Issue("set-cookie", "high", f"cookie '{name}' SameSite=None without Secure"))
    return out


def analyze(headers: dict[str, str], cookies: list[str] | None = None) -> list[Issue]:
    h = {k.lower(): v for k, v in headers.items()}
    out: list[Issue] = []
    if "strict-transport-security" not in h:
        out.append(Issue("strict-transport-security", "high", "missing HSTS"))
    else:
        out += _hsts(h["strict-transport-security"])
    if "content-security-policy" not in h:
        out.append(Issue("content-security-policy", "high", "missing Content-Security-Policy"))
    else:
        out += _csp(h["content-security-policy"])
    xfo = h.get("x-frame-options", "").lower()
    if not xfo and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(Issue("x-frame-options", "medium", "no clickjacking protection (X-Frame-Options or frame-ancestors)"))
    elif xfo and xfo not in ("deny", "sameorigin"):
        out.append(Issue("x-frame-options", "low", f"unusual value '{xfo}'"))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(Issue("x-content-type-options", "medium", "missing or not 'nosniff'"))
    if "referrer-policy" not in h:
        out.append(Issue("referrer-policy", "low", "missing Referrer-Policy"))
    elif h["referrer-policy"].lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        out.append(Issue("referrer-policy", "medium", f"weak policy '{h['referrer-policy']}'"))
    if "permissions-policy" not in h:
        out.append(Issue("permissions-policy", "low", "missing Permissions-Policy"))
    if "x-powered-by" in h:
        out.append(Issue("x-powered-by", "low", f"discloses technology: {h['x-powered-by']}"))
    if re.search(r"\d+\.\d+", h.get("server", "")):
        out.append(Issue("server", "low", f"discloses version: {h['server']}"))
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        out.append(Issue("access-control-allow-origin", "high", "wildcard origin combined with credentials"))
    out += _cookies(h, cookies or [])
    return out


def score(issues: list[Issue]) -> tuple[int, str]:
    s = max(0, 100 - sum(PENALTY[i.severity] for i in issues))
    grade = "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 65 else "D" if s >= 50 else "F"
    return s, grade


def fetch(url: str, timeout: float = 10.0) -> tuple[dict[str, str], list[str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "security-headers-audit/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - user supplied URL by design
        headers = {k.lower(): v for k, v in r.headers.items() if k.lower() != "set-cookie"}
        return headers, r.headers.get_all("Set-Cookie") or []
