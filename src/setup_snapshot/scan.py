"""Secret scanning for collected text. Fail closed: any finding aborts the build.

Findings report `label:line: rule`, never the matched value. A line may opt out
of one rule with an inline `snapshot:allow <rule>` marker; overrides are
returned so the plan can list them.
"""
from __future__ import annotations

import re
from typing import Iterable

SECRET_RULES = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "secret-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?"
            r"[A-Za-z0-9/+_=-]{20,}"
        ),
    ),
    (
        # JSON/YAML style: "GITHUB_TOKEN": "value", MY_API_KEY: value
        "secret-keyed-value",
        re.compile(
            r"(?i)[\"']?[A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*[\"']?"
            r"\s*[:=]\s*[\"'][^\"'\s$<{]{8,}[\"']"
        ),
    ),
]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
ALLOW_RE = re.compile(r"snapshot:allow\s+([a-z0-9-]+)")

DEFAULT_ALLOWED_EMAIL_DOMAINS = frozenset({"example.com", "example.org", "example.net", "anthropic.com"})
RESERVED_TLDS = (".test", ".example", ".invalid", ".localhost")  # RFC 2606: never real addresses


def scan_text(text: str, label: str, allowed_email_domains: Iterable[str] = DEFAULT_ALLOWED_EMAIL_DOMAINS) -> tuple[list[str], list[str]]:
    """Return (findings, overrides) for one text. Both are `label:line: rule` strings."""
    domains = {d.lower() for d in allowed_email_domains}
    findings: list[str] = []
    overrides: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        allowed = set(ALLOW_RE.findall(line))
        hits = [rule for rule, pattern in SECRET_RULES if pattern.search(line)]
        if any(_is_real_email_domain(m.group(1).lower(), domains) for m in EMAIL_RE.finditer(line)):
            hits.append("email")
        for rule in hits:
            entry = f"{label}:{lineno}: {rule}"
            (overrides if rule in allowed else findings).append(entry)
    return findings, overrides


def _is_real_email_domain(domain: str, allowed: set) -> bool:
    return domain not in allowed and not domain.endswith(RESERVED_TLDS)


SECRET_NAME_RE = re.compile(r"(?i)(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH)")


def is_secret_name(name: str) -> bool:
    """True for env/header names that conventionally hold secrets."""
    return bool(SECRET_NAME_RE.search(name))
