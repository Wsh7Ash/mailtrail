# mailtrail

**Triage a reported phishing email from its headers and links — without opening
anything.**

## Why

A user forwards a suspicious email. The fastest useful questions are answerable
offline: did SPF, DKIM and DMARC pass? Does Reply-To leave the From domain? Is
the sender domain a lookalike? Do the links point at an IP literal, a punycode
host, a shortener, or somewhere other than their anchor text suggests?
`mailtrail` answers those from the raw `.eml` and returns a scored list of
signals for a human decision. It never fetches links or resolves DNS.

## Features

- Parses `Authentication-Results` / `Received-SPF` (spf, dkim, dmarc outcomes)
- Compares From, Reply-To and Return-Path registered domains
- Flags brand lookalikes (extra text, wrong TLD, one-edit distance)
- Reviews body links: HTTP, IP literals, punycode, shorteners, anchor mismatches
- Detects display names containing an email address or a brand the domain lacks
- Score, verdict (`low-risk` / `suspicious` / `likely-phishing`), text or JSON

## Example

`mailtrail demo`:

```text
mailtrail report - <demo>
==========================================================
Subject: Your account is limited
From:    "PayPal Security" <alerts@paypal-secure.example>  (paypal-secure.example)
Reply-To domain:    mail-verify.example
Return-Path domain: mail-verify.example
Signals: 10
  [HIGH  ] +40  dmarc-fail             DMARC returned fail
  [HIGH  ] +30  lookalike-domain       From domain paypal-secure.example contains the brand 'paypal' with extra text
  [HIGH  ] +20  ip-literal-link        link points at an IP address: 192.0.2.10
  [HIGH  ] +20  anchor-mismatch        link text host www.paypal.com does not match target 192.0.2.10
  ...
----------------------------------------------------------
score 100/100 -> likely-phishing
```

## Architecture

```text
src/mailtrail/__init__.py  header parsing, domain helpers, signals, verdict
src/mailtrail/cli.py       analyze / demo and exit codes
tests/test_mailtrail.py    clean vs phishing fixtures, links, domains, CLI
```

Each signal is independent and additive (capped at 100). The verdict is a
summary threshold, not an instruction to block; signals are listed so an analyst
can see why.

## Requirements

- Python 3.10+
- A raw `.eml` file (exported from the mail client)
- pytest for tests

## Installation

```shell
git clone https://github.com/Wsh7Ash/mailtrail.git
cd mailtrail
python -m pip install -e .
```

## Quick start

```shell
mailtrail demo
mailtrail analyze examples/phish.eml
```

## Usage

```shell
# Analyst report
mailtrail analyze report.eml

# JSON for a ticket system
mailtrail analyze report.eml --json --out results/report.json

# Only fail on a strong verdict
mailtrail analyze report.eml --fail-on likely-phishing
```

Exit codes: `0` below threshold, `1` verdict at/above `--fail-on`, `2` file
unreadable. Default threshold is `suspicious`.

## Configuration

Flags only: `--json`, `--out`, `--fail-on none|low-risk|suspicious|likely-phishing`.

## Testing

```shell
python -m pip install -e . pytest
python -m pytest tests -q
```

## Project structure

```text
mailtrail/
├─ src/mailtrail/       analyser + CLI
├─ tests/               pytest suite
├─ examples/            sample reported email
├─ docs/                architecture, usage, spec
├─ results/             generated reports
└─ .github/workflows/   CI
```

## Limitations

- Signals are heuristics; a legitimate sender can trip lookalike or mismatch
  rules (mailing-list infrastructure does this routinely).
- Header order and rewritten headers (forwarding) can hide original auth results.
- Registered-domain detection uses a small multi-part suffix list, not the full
  Public Suffix List.
- Does not inspect attachments beyond ignoring them, and never contacts URLs.
- Scores are fixed and intentionally simple; tune them by editing one table.

## Roadmap

- Public Suffix List support
- Attachment filename/extension mismatch checks
- Batch mode for a mailbox export

## Safety notes

The tool reads a local file, performs no network access, and does not execute or
fetch links. Treat the verdict as triage input, not a malware verdict, and never
forward the original message to untrusted systems.

## License

MIT — see `LICENSE`.
