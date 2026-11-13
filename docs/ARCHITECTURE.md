# Architecture

## Flow

```text
.eml bytes ──► BytesParser(policy=default)
                    │
     ┌──────────────┼────────────────┬───────────────────┐
     ▼              ▼                ▼                   ▼
auth headers   From/Reply-To/   display name        body parts
(spf/dkim/     Return-Path      brand claims        (html + plain)
 dmarc)         domains              │                   │
     │              │                │                   ▼
     │              │                │            link checks
     └──────────────┴────────────────┴───────────────────┘
                              ▼
                     Signal[] (code, severity, score, detail)
                              ▼
                   score = min(100, Σ scores)
                   verdict thresholds: 60 / 30
```

## Signal catalogue

| Code | Score | Severity |
|---|---|---|
| `dmarc-fail` | 40 | high |
| `lookalike-domain` | 30 | high |
| `punycode-link` | 25 | high |
| `spf-fail` / `spf-softfail` | 20 / 10 | high / medium |
| `ip-literal-link` | 20 | high |
| `anchor-mismatch` | 20 | high |
| `dkim-fail` | 15 | medium |
| `reply-to-mismatch` | 15 | medium |
| `email-in-display-name` | 15 | medium |
| `brand-display-name` | 15 | medium |
| `plaintext-link` / `shortener-link` | 10 | medium |
| `return-path-mismatch` | 10 | low |
| `no-auth-results` / `missing-message-id` | 5 | low |

Signals deduplicate by code: five shorteners are one signal, not five.

## Domain handling

`registered_domain` reduces a host to its registrable part using a small
multi-part suffix set (`co.uk`, `com.au`, …). This is enough to compare From and
Reply-To without pretending to be a Public Suffix List implementation.

`lookalike_reason` checks three patterns against a brand list: the exact brand on
a non-`.com` domain, the brand embedded with extra text, and edit distance 1.

## Link review

HTML is parsed with `html.parser` to keep anchor text; any `href` missed by the
parser and any plain-text URL is also reviewed. Anchor mismatch compares the
registrable domain of the visible text with the target.

## Limitations by design

No DNS, no HTTP, no attachment execution. Scores are fixed so two analysts get
the same output; tuning means editing the catalogue above.
