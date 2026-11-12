import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from security_headers_audit.cli import main
from security_headers_audit.core import analyze, fetch, parse_headers, score

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def rules(issues):
    return {(i.header, i.severity) for i in issues}


def test_good_config_gets_grade_a():
    s, g = score(analyze(GOOD, ["sid=1; Secure; HttpOnly; SameSite=Lax"]))
    assert (s, g) == (100, "A")


def test_empty_headers_fail():
    s, g = score(analyze({}))
    assert g in ("D", "F") and s < 60


def test_csp_unsafe_inline_and_wildcard():
    h = dict(GOOD, **{"Content-Security-Policy": "script-src 'self' 'unsafe-inline' *"})
    r = rules(analyze(h))
    assert ("content-security-policy", "high") in r


def test_csp_nonce_neutralises_unsafe_inline():
    h = dict(GOOD, **{"Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'"})
    assert not [i for i in analyze(h) if "unsafe-inline" in i.message]


def test_hsts_short_max_age_and_missing_subdomains():
    h = dict(GOOD, **{"Strict-Transport-Security": "max-age=300"})
    msgs = [i.message for i in analyze(h)]
    assert any("below 180 days" in m for m in msgs) and any("includeSubDomains" in m for m in msgs)


def test_cookie_flags():
    issues = analyze(GOOD, ["a=1", "b=2; Secure; HttpOnly; SameSite=None"])
    msgs = " ".join(i.message for i in issues)
    assert "'a' missing Secure" in msgs and "'a' missing HttpOnly" in msgs and "'a' missing SameSite" in msgs
    assert "'b'" not in msgs


def test_information_disclosure_and_cors():
    h = dict(GOOD, **{"Server": "nginx/1.18.0", "X-Powered-By": "Express", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    r = {i.header for i in analyze(h)}
    assert {"server", "x-powered-by", "access-control-allow-origin"} <= r


def test_frame_ancestors_replaces_xfo():
    assert not [i for i in analyze(GOOD) if i.header == "x-frame-options"]
    h = {k: v for k, v in GOOD.items() if k != "Content-Security-Policy"}
    assert [i for i in analyze(h) if i.header == "x-frame-options"]


def test_parse_headers_dump():
    raw = "HTTP/1.1 200 OK\nServer: nginx\nSet-Cookie: a=1\nSet-Cookie: b=2\nX-Frame-Options: DENY\n"
    h = parse_headers(raw)
    assert h["x-frame-options"] == "DENY" and h["server"] == "nginx"


def test_cli_file_json_and_min_grade(tmp_path, capsys):
    f = tmp_path / "h.txt"
    f.write_text("HTTP/1.1 200 OK\nServer: Apache/2.4.1\nSet-Cookie: s=1\n")
    assert main([str(f), "--format", "json", "--min-grade", "B"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["grade"] in ("D", "F") and data["issues"]


def test_live_fetch_against_local_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", "sid=1; HttpOnly")
            self.end_headers()
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        headers, cookies = fetch(f"http://127.0.0.1:{srv.server_port}/")
    finally:
        srv.shutdown()
    assert headers["x-content-type-options"] == "nosniff" and cookies == ["sid=1; HttpOnly"]
