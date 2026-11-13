import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from mailtrail import (
    analyze_email,
    at_or_above,
    domain_of,
    host_of,
    lookalike_reason,
    registered_domain,
    render_json,
    render_text,
    summarize,
)
from mailtrail.cli import main

CLEAN = """From: Alice Example <alice@example.com>
Reply-To: Alice Example <alice@example.com>
Return-Path: <alice@example.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Message-ID: <abc123@example.com>
Subject: Lunch on Friday
Content-Type: text/plain; charset=utf-8

Hi, see https://example.com/calendar for the details.
"""

PHISH = """From: "PayPal Security" <alerts@paypal-secure.example>
Reply-To: recovery@mail-verify.example
Return-Path: <bounce@mail-verify.example>
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
Subject: Your account is limited
Content-Type: text/html; charset=utf-8

<html><body>
<p><a href="http://192.0.2.10/login">https://www.paypal.com/signin</a></p>
</body></html>
"""


def test_clean_email_is_low_risk():
    report = analyze_email(CLEAN)
    assert report.verdict == "low-risk"
    assert report.score == 0
    assert report.signals == []
    assert report.from_domain == "example.com"


def test_phishing_email_accumulates_signals():
    report = analyze_email(PHISH)
    codes = {signal.code for signal in report.signals}
    assert {"dmarc-fail", "spf-fail", "dkim-fail", "lookalike-domain",
            "reply-to-mismatch", "return-path-mismatch", "ip-literal-link",
            "plaintext-link", "anchor-mismatch"} <= codes
    assert report.score >= 90
    assert report.verdict == "likely-phishing"
    assert at_or_above(report, "suspicious") is True


def test_missing_auth_results_is_flagged_low():
    raw = (
        "From: bob@example.com\nSubject: hi\nContent-Type: text/plain\n\nhello\n"
    )
    report = analyze_email(raw)
    codes = {signal.code for signal in report.signals}
    assert "no-auth-results" in codes
    assert "missing-message-id" in codes
    assert report.verdict == "low-risk"


def test_punycode_and_shortener_links():
    raw = (
        "From: news@example.com\nSubject: link\nMessage-ID: <x@example.com>\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "Content-Type: text/html\n\n"
        '<a href="https://xn--pple-43d.com/login">apple</a>'
        '<a href="https://bit.ly/abc">short</a>'
    )
    codes = {signal.code for signal in analyze_email(raw).signals}
    assert {"punycode-link", "shortener-link"} <= codes


def test_domain_helpers():
    assert registered_domain("mail.example.co.uk") == "example.co.uk"
    assert registered_domain("a.b.example.com") == "example.com"
    assert domain_of("Alice <alice@Example.COM>") == "example.com"
    assert domain_of("not-an-address") == ""
    assert host_of("https://user:pass@Example.com:8443/x") == "example.com"
    assert host_of("ftp://example.org") == "example.org"
    assert host_of("no-scheme") == ""


def test_lookalike_detection():
    assert lookalike_reason("paypal.com") is None
    assert lookalike_reason("paypal-secure.example") is not None
    assert lookalike_reason("paypa1.com") is not None
    assert lookalike_reason("paypal.example") is not None
    assert lookalike_reason("") is None


def test_summary_and_rendering():
    report = analyze_email(PHISH)
    summary = summarize(report)
    assert summary["signals"] == len(report.signals)
    assert summary["counts"]["high"] >= 1
    text = render_text(report, "phish.eml")
    assert "mailtrail report - phish.eml" in text and "likely-phishing" in text
    payload = json.loads(render_json(report, "phish.eml"))
    assert payload["summary"]["verdict"] == "likely-phishing"
    assert len(payload["signals"]) == len(report.signals)


def test_cli_analyze_and_exit_codes(tmp_path, capsys):
    clean = tmp_path / "clean.eml"
    clean.write_text(CLEAN, encoding="utf-8")
    assert main(["analyze", str(clean)]) == 0

    phish = tmp_path / "phish.eml"
    phish.write_text(PHISH, encoding="utf-8")
    assert main(["analyze", str(phish)]) == 1
    assert main(["analyze", str(phish), "--fail-on", "none"]) == 0

    capsys.readouterr()
    assert main(["analyze", str(phish), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "likely-phishing"

    assert main(["analyze", str(tmp_path / "missing.eml")]) == 2
    assert main(["demo"]) == 0
