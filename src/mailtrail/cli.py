"""Command line interface for mailtrail."""

from __future__ import annotations

import argparse
import sys

from . import analyze_file, at_or_above, render_json, render_text

SAMPLE = """From: "PayPal Security" <alerts@paypal-secure.example>
Reply-To: recovery@mail-verify.example
Return-Path: <bounce@mail-verify.example>
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
Subject: Your account is limited
Content-Type: text/html; charset=utf-8

<html><body>
<p><a href="http://192.0.2.10/login">https://www.paypal.com/signin</a></p>
</body></html>
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailtrail",
        description="Triage a reported email from its headers and links, fully offline.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyse a raw .eml file")
    analyze.add_argument("path")
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--out", help="also write the report to this path")
    analyze.add_argument(
        "--fail-on",
        choices=["none", "low-risk", "suspicious", "likely-phishing"],
        default="suspicious",
        help="minimum verdict that exits 1 (default: suspicious)",
    )
    sub.add_parser("demo", help="analyse a built-in suspicious email")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "demo":
        from . import analyze_email

        print(render_text(analyze_email(SAMPLE), "<demo>"))
        return 0

    try:
        report = analyze_file(args.path)
    except OSError as exc:
        print(f"mailtrail: {exc}", file=sys.stderr)
        return 2

    output = render_json(report, args.path) if args.json else render_text(report, args.path)
    print(output)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")

    if args.fail_on != "none" and at_or_above(report, args.fail_on):
        print(f"mailtrail: verdict '{report.verdict}' meets --fail-on {args.fail_on}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
