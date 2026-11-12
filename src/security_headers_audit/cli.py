from __future__ import annotations

import argparse
import json
import sys

from .core import analyze, fetch, parse_headers, score

ORDER = {"high": 0, "medium": 1, "low": 2}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="security-headers-audit", description="Grade the HTTP security headers of a site or a header dump.")
    p.add_argument("target", help="URL (https://...) or path to a file with raw headers, '-' for stdin")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--min-grade", choices=list("ABCDF"), help="exit 2 if the grade is worse than this")
    a = p.parse_args(argv)

    if a.target.startswith(("http://", "https://")):
        headers, cookies = fetch(a.target)
    else:
        raw = sys.stdin.read() if a.target == "-" else open(a.target, encoding="utf-8").read()
        headers = parse_headers(raw)
        cookies = [l.split(":", 1)[1].strip() for l in raw.splitlines() if l.lower().startswith("set-cookie:")]
    issues = sorted(analyze(headers, cookies), key=lambda i: ORDER[i.severity])
    s, grade = score(issues)

    if a.format == "json":
        print(json.dumps({"score": s, "grade": grade, "issues": [i.as_dict() for i in issues]}, indent=2))
    else:
        print(f"Grade {grade}  (score {s}/100)")
        for i in issues:
            print(f"  [{i.severity.upper():6}] {i.header}: {i.message}")
    if a.min_grade and "ABCDF".index(grade) > "ABCDF".index(a.min_grade):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
