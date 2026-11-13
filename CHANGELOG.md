# Changelog

## [1.0.0] - 2026-11-14

### Added

- Offline `.eml` triage: SPF/DKIM/DMARC results, From/Reply-To/Return-Path
  comparison, lookalike domains, display-name claims.
- Body link review: HTTP, IP literals, punycode, shorteners, anchor mismatches.
- Additive signal scoring with `low-risk` / `suspicious` / `likely-phishing`
  verdicts, text and JSON output, `--fail-on` gate.
- pytest suite with clean and phishing fixtures plus CLI exit-code coverage.
