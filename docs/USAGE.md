# Usage

## Getting the raw message

- Outlook: *Save As* → `.eml` (or drag the message to a folder).
- Gmail: *Show original* → *Download original*.
- Thunderbird: *Save As* → *File*.

Analyse the saved file, never the rendered message, so the headers survive.

## First pass

```shell
mailtrail analyze report.eml
```

Read the signal list before the score. `dmarc-fail` plus an IP-literal link is a
different situation from a lookalike domain with no body links.

## Ticket integration

```shell
mailtrail analyze report.eml --json --out results/ticket-4711.json
```

The JSON contains the parsed domains, every signal, and the verdict.

## Choosing a threshold

- `--fail-on likely-phishing` for automated pipelines that should only alert on
  strong evidence.
- `--fail-on suspicious` (default) for analyst queues.
- `--fail-on low-risk` is effectively "any signal at all"; use it for testing.

## Interpreting common false positives

- **reply-to-mismatch**: mailing lists and ticketing systems legitimately set a
  different Reply-To.
- **no-auth-results**: internal relays often strip the header after evaluating it.
- **brand-display-name**: resellers and partners mention brands in display names.
- **lookalike-domain**: short brand names collide easily; read the detail text.

## Batch triage

```shell
for file in reports/*.eml; do
  mailtrail analyze "$file" --json >> results/batch.jsonl || true
done
```

Each line is a complete JSON report, suitable for a spreadsheet import.
