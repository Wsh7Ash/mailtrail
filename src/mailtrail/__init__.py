"""mailtrail - triage a reported email without opening its links.

Given a raw ``.eml`` file, the analyser reads authentication results, compares
the From/Reply-To/Return-Path domains, checks the sender domain against known
brand names, and inspects body links for IP literals, punycode, shorteners and
mismatched anchor text. Every signal carries a score; the verdict is a summary
for a human, never an automatic block.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import Iterable, Sequence

BRANDS = (
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "docusign",
    "github", "outlook", "office365", "dropbox", "linkedin", "facebook",
)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
MULTI_SUFFIXES = {"co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.za", "com.sa", "com.eg", "co.in"}

_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
_IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ANY_HREF = re.compile(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)


@dataclass(frozen=True)
class Signal:
    code: str
    severity: str
    score: int
    detail: str


@dataclass
class Report:
    subject: str
    from_header: str
    from_domain: str
    reply_to_domain: str
    return_path_domain: str
    signals: list[Signal] = field(default_factory=list)
    score: int = 0
    verdict: str = "low-risk"

    def to_dict(self) -> dict:
        return {**asdict(self), "signals": [asdict(signal) for signal in self.signals]}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []


def registered_domain(host: str) -> str:
    labels = [label for label in (host or "").lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of(address_header: str) -> str:
    _, address = parseaddr(address_header or "")
    return registered_domain(address.rsplit("@", 1)[-1]) if "@" in address else ""


def host_of(url: str) -> str:
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)", url.strip())
    if not match:
        return ""
    host = match.group(1).rsplit("@", 1)[-1]
    return host.split(":")[0].lower()


def _levenshtein(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
        previous = current
    return previous[-1]


def lookalike_reason(domain: str) -> str | None:
    if not domain:
        return None
    sld = domain.rsplit(".", 1)[0].split(".")[-1]
    for brand in BRANDS:
        if sld == brand and not domain.endswith(f"{brand}.com"):
            return f"uses the brand '{brand}' outside its usual .com domain"
        if sld != brand and brand in sld and len(sld) <= len(brand) + 12:
            return f"contains the brand '{brand}' with extra text"
        if sld != brand and _levenshtein(sld, brand, 1) <= 1:
            return f"is one edit away from '{brand}'"
    return None


def _add(signals: list[Signal], code: str, severity: str, score: int, detail: str) -> None:
    if any(signal.code == code for signal in signals):
        return
    signals.append(Signal(code, severity, score, detail))


def _authentication(signals: list[Signal], parser) -> None:
    headers = parser.get_all("Authentication-Results") or []
    headers += parser.get_all("Received-SPF") or []
    seen: dict[str, str] = {}
    for header in headers:
        for mechanism, result in _AUTH.findall(str(header)):
            seen.setdefault(mechanism.lower(), result.lower())

    if not seen:
        _add(signals, "no-auth-results", "low", 5, "no Authentication-Results header was found")
        return

    table = {
        "dmarc": {"fail": (40, "high")},
        "spf": {"fail": (20, "high"), "softfail": (10, "medium")},
        "dkim": {"fail": (15, "medium")},
    }
    for mechanism, result in seen.items():
        rule = table.get(mechanism, {}).get(result)
        if rule:
            score, severity = rule
            _add(signals, f"{mechanism}-{result}", severity, score, f"{mechanism.upper()} returned {result}")


def _link_checks(signals: list[Signal], html: str, plain: str) -> None:
    parser = _LinkParser()
    try:
        parser.feed(html or "")
    except Exception:  # malformed HTML should not abort triage
        pass

    links: list[tuple[str, str]] = list(parser.links)
    for href in _ANY_HREF.findall(html or ""):
        if not any(href == existing[0] for existing in links):
            links.append((href, ""))
    for href in re.findall(r"https?://[^\s<>\"')]+", plain or ""):
        links.append((href, ""))

    for href, text in links:
        host = host_of(href)
        if not host:
            continue
        if href.lower().startswith("http://"):
            _add(signals, "plaintext-link", "medium", 10, f"link uses HTTP: {href}")
        if _IP_HOST.match(host):
            _add(signals, "ip-literal-link", "high", 20, f"link points at an IP address: {host}")
        if "xn--" in host:
            _add(signals, "punycode-link", "high", 25, f"link uses punycode: {host}")
        if host in SHORTENERS:
            _add(signals, "shortener-link", "medium", 10, f"link uses a shortener: {host}")
        if text.lower().startswith(("http://", "https://", "www.")):
            text_host = host_of(text) if "://" in text else host_of("http://" + text)
            if text_host and registered_domain(text_host) != registered_domain(host):
                _add(
                    signals, "anchor-mismatch", "high", 20,
                    f"link text host {text_host} does not match target {host}",
                )


def analyze_email(raw: bytes | str) -> Report:
    data = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    message = BytesParser(policy=policy.default).parsebytes(data)

    from_header = str(message.get("From", ""))
    subject = str(message.get("Subject", ""))
    from_domain = domain_of(from_header)
    reply_domain = domain_of(str(message.get("Reply-To", "")))
    return_domain = domain_of(str(message.get("Return-Path", "")))

    signals: list[Signal] = []
    _authentication(signals, message)

    if reply_domain and from_domain and reply_domain != from_domain:
        _add(signals, "reply-to-mismatch", "medium", 15,
             f"Reply-To domain {reply_domain} differs from From domain {from_domain}")
    if return_domain and from_domain and return_domain != from_domain:
        _add(signals, "return-path-mismatch", "low", 10,
             f"Return-Path domain {return_domain} differs from From domain {from_domain}")

    reason = lookalike_reason(from_domain)
    if reason:
        _add(signals, "lookalike-domain", "high", 30, f"From domain {from_domain} {reason}")

    display_name, address = parseaddr(from_header)
    if "@" in display_name:
        _add(signals, "email-in-display-name", "medium", 15,
             "the display name contains an email address")
    if display_name and any(brand in display_name.lower() for brand in BRANDS) and \
            not any(brand in from_domain for brand in BRANDS):
        _add(signals, "brand-display-name", "medium", 15,
             "the display name claims a brand the domain does not use")

    if not message.get("Message-ID"):
        _add(signals, "missing-message-id", "low", 5, "the header has no Message-ID")

    html = ""
    plain = ""
    for part in message.walk():
        content_type = part.get_content_type()
        if content_type not in {"text/html", "text/plain"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = ""
        except Exception:
            content = ""
        if content_type == "text/html" and not html:
            html = str(content)
        elif content_type == "text/plain" and not plain:
            plain = str(content)

    _link_checks(signals, html, plain)

    score = min(100, sum(signal.score for signal in signals))
    verdict = "likely-phishing" if score >= 60 else "suspicious" if score >= 30 else "low-risk"

    return Report(
        subject=subject,
        from_header=from_header,
        from_domain=from_domain,
        reply_to_domain=reply_domain,
        return_path_domain=return_domain,
        signals=signals,
        score=score,
        verdict=verdict,
    )


def analyze_file(path: str) -> Report:
    with open(path, "rb") as handle:
        return analyze_email(handle.read())


def summarize(report: Report) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for signal in report.signals:
        counts[signal.severity] = counts.get(signal.severity, 0) + 1
    return {"score": report.score, "verdict": report.verdict, "counts": counts, "signals": len(report.signals)}


def at_or_above(report: Report, threshold: str) -> bool:
    ranking = {"none": 0, "low-risk": 1, "suspicious": 2, "likely-phishing": 3}
    if threshold == "none":
        return False
    return ranking.get(report.verdict, 0) >= ranking.get(threshold, 0)


def render_text(report: Report, target: str = "") -> str:
    lines = [f"mailtrail report{f' - {target}' if target else ''}", "=" * 58]
    lines.append(f"Subject: {report.subject or '<none>'}")
    lines.append(f"From:    {report.from_header or '<none>'}  ({report.from_domain or 'no domain'})")
    lines.append(f"Reply-To domain:    {report.reply_to_domain or '<none>'}")
    lines.append(f"Return-Path domain: {report.return_path_domain or '<none>'}")
    if not report.signals:
        lines.append("Signals: none")
    else:
        lines.append(f"Signals: {len(report.signals)}")
        for signal in sorted(report.signals, key=lambda item: -item.score):
            lines.append(f"  [{signal.severity.upper():6}] +{signal.score:<3} {signal.code:22} {signal.detail}")
    lines.append("-" * 58)
    lines.append(f"score {report.score}/100 -> {report.verdict}")
    return "\n".join(lines)


def render_json(report: Report, target: str = "") -> str:
    return json.dumps({"target": target, **report.to_dict(), "summary": summarize(report)}, indent=2)
