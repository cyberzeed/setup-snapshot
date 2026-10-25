"""The ticket: the only thing a sender hands over.

A few strict `key: value` lines, parsed here and never interpreted by Claude.
Anything unexpected (extra keys, free text, credentials in the locator)
rejects the whole ticket.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from .errors import SnapshotError

COMMAND = "/setup-snapshot apply"
VERSION_KEY = "setup-snapshot-ticket"
VERSION = 1
KEYS = ("name", "locator", "sha256", "size")

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
LINE_RE = re.compile(r"^([a-z0-9-]+): (.+)$")
# Query parameters that carry credentials in presigned or tokenized URLs.
CREDENTIAL_PARAMS = re.compile(
    r"(?i)^(x-amz-signature|x-amz-credential|x-amz-security-token|signature|sig|token|access_token|key|api_key|apikey|password)$"
)


@dataclass(frozen=True)
class Ticket:
    name: str
    locator: str
    sha256: str
    size: int

    def render(self) -> str:
        return "\n".join(
            [
                COMMAND,
                f"{VERSION_KEY}: {VERSION}",
                f"name: {self.name}",
                f"locator: {self.locator}",
                f"sha256: {self.sha256}",
                f"size: {self.size}",
            ]
        ) + "\n"


def check_locator(locator: str, schemes: set[str], allow_presigned: bool = False) -> str:
    parts = urlsplit(locator)
    if parts.scheme not in schemes:
        raise SnapshotError(f"locator scheme {parts.scheme!r} is not enabled (enabled: {', '.join(sorted(schemes))})")
    if parts.password is not None or (parts.username and parts.scheme in ("https", "http", "s3")):
        raise SnapshotError("locator must not carry credentials")
    if any(ch.isspace() for ch in locator) or "\x00" in locator:
        raise SnapshotError("locator contains whitespace")
    params = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    if any(CREDENTIAL_PARAMS.match(k) for k in params) and not allow_presigned:
        raise SnapshotError("locator carries a credential in its query; pass --allow-presigned to accept a presigned URL")
    return locator


def parse(text: str, schemes: set[str], max_size: int, allow_presigned: bool = False) -> Ticket:
    lines = [ln.rstrip("\r") for ln in text.strip().splitlines()]
    if not lines or lines[0].strip() != COMMAND:
        raise SnapshotError(f"ticket must start with '{COMMAND}'")
    values: dict[str, str] = {}
    for ln in lines[1:]:
        m = LINE_RE.match(ln)
        if not m:
            raise SnapshotError("ticket has a line that is not 'key: value'")
        key, value = m.group(1), m.group(2).strip()
        if key in values:
            raise SnapshotError(f"ticket repeats key {key!r}")
        if key != VERSION_KEY and key not in KEYS:
            raise SnapshotError(f"ticket has unknown key {key!r}")
        values[key] = value
    if values.get(VERSION_KEY) != str(VERSION):
        raise SnapshotError(f"unsupported ticket version {values.get(VERSION_KEY)!r}")
    missing = [k for k in KEYS if k not in values]
    if missing:
        raise SnapshotError(f"ticket is missing {', '.join(missing)}")
    if not NAME_RE.match(values["name"]):
        raise SnapshotError("ticket name has unexpected characters")
    if not SHA_RE.match(values["sha256"]):
        raise SnapshotError("ticket sha256 must be 64 lowercase hex characters")
    if not values["size"].isdigit() or not 0 < int(values["size"]) <= max_size:
        raise SnapshotError(f"ticket size must be a positive integer up to {max_size}")
    check_locator(values["locator"], schemes, allow_presigned)
    return Ticket(values["name"], values["locator"], values["sha256"], int(values["size"]))
