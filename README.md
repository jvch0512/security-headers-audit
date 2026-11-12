# security-headers-audit

Grade the HTTP security headers of a site (A to F) with actionable findings. Works **offline** on a header dump (`curl -sI` output, DevTools copy) or **live** against a URL using only the standard library.

## Checks

| Area | What is verified |
|------|------------------|
| HSTS | present, `max-age` >= 180 days, `includeSubDomains` |
| CSP | present, no `unsafe-inline` without nonce/hash, no `unsafe-eval`, no wildcard/`http:`/`data:` script sources, `object-src`, `frame-ancestors` |
| Clickjacking | `X-Frame-Options` or CSP `frame-ancestors` |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| Privacy | `Referrer-Policy` strength, `Permissions-Policy` |
| Disclosure | `Server` version, `X-Powered-By` |
| CORS | wildcard origin combined with credentials |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure` |

Scoring: 100 minus 20/10/5 per high/medium/low finding. A >= 90, B >= 80, C >= 65, D >= 50, otherwise F.

## Usage

```bash
pip install -e .
security-headers-audit https://example.org
curl -sI https://example.org | security-headers-audit -
security-headers-audit headers.txt --format json --min-grade B   # exits 2 below B, handy in CI
```

Only scan sites you own or are authorised to test. The tool sends a single GET request.

## Development

```bash
pip install -e .[dev] && pytest -q
```

The live-fetch test runs against a throwaway local HTTP server, so the suite needs no network access.

MIT licensed.
