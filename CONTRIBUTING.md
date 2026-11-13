# Contributing

## Setup

```shell
python -m pip install -e . pytest
python -m pytest tests -q
```

## Rules

- Offline only: never add DNS, HTTP or attachment execution.
- Signals are independent and deduplicated by code.
- Scores live in one table per mechanism; changing one requires a test update and
  a changelog entry.
- A new rule needs a triggering fixture and a case that must stay clean.

## Style

- Standard library only.
- Detail strings state the observation, not the conclusion ("DMARC returned fail",
  not "this is phishing").
- Keep verdict thresholds (60/30) documented in one place.
