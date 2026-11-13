# PROJECT_SPEC — mailtrail

- **Name:** mailtrail
- **Category:** email-security
- **Target user:** SOC analyst or IT helper triaging a user-reported email
- **Problem:** header authentication results, domain mismatches and link tricks
  are spread across several headers and the HTML body, so triage is slow and
  inconsistent
- **Solution:** offline analyser that turns a raw `.eml` into scored, explained
  signals and a verdict
- **Core workflow:** `mailtrail analyze report.eml` → signals + verdict → ticket
- **Must-have features:** auth-result parsing, domain comparison, lookalike
  detection, link checks, display-name checks, text/JSON, threshold
- **Nice-to-have features:** Public Suffix List, attachment checks, batch mode
- **Stack:** Python 3.10+ standard library (`email`, `html.parser`)
- **Test strategy:** clean fixture (zero signals), phishing fixture (auth + domain
  + link signals), missing-header case, punycode/shortener, helper units, CLI codes
- **Demo/result strategy:** built-in demo plus `examples/phish.eml` reports
- **Safety considerations:** no network access, no link fetching, no attachment
  execution; outputs are triage aids, not verdicts
- **Definition of done:** tests pass, install works, demo recorded, docs accurate
