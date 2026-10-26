"""Manifest schema (format_version 1) and validation.

The manifest describes what the archive holds: one entry per payload file,
plus plugins and MCP servers as metadata only (never vendored code or secrets).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .scan import is_secret_name

FORMAT = "setup-snapshot"
FORMAT_VERSION = 1
MANIFEST_NAME = "manifest.json"
PAYLOAD_DIR = "payload"
HOME_TOKEN = "{{HOME}}"

LOW, MEDIUM, HIGH = "low", "medium", "high"
RISKS = (LOW, MEDIUM, HIGH)

# category -> default risk. Skills are raised to HIGH when they carry scripts.
CATEGORIES = {
    "instructions": MEDIUM,
    "notes": MEDIUM,
    "skill": LOW,
    "agent": MEDIUM,
    "command": MEDIUM,
    "output-style": LOW,
    "settings": LOW,
    "hooks": HIGH,
    "keybindings": LOW,
}
# Metadata-only categories: the receiver gets commands to run, never files.
METADATA_CATEGORIES = {"plugin": HIGH, "mcp": HIGH}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FILE_MODES = ("0644", "0755")


@dataclass
class Item:
    path: str  # archive path, always under payload/
    category: str
    risk: str
    data: bytes = field(repr=False)
    mode: str = "0644"

    def entry(self, sha256: str) -> dict:
        return {
            "path": self.path,
            "category": self.category,
            "risk": self.risk,
            "sha256": sha256,
            "size": len(self.data),
            "mode": self.mode,
        }


def is_safe_relpath(path: str) -> bool:
    """Relative POSIX path with no empty, '.', '..' or hidden-escape parts and no backslashes."""
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def _fail(msg: str):
    from .errors import SnapshotError

    raise SnapshotError(f"invalid manifest: {msg}")


def validate(m: object) -> dict:
    """Check a manifest read from an untrusted archive. Returns it unchanged."""
    if not isinstance(m, dict):
        _fail("not a JSON object")
    if m.get("format") != FORMAT:
        _fail("format is not setup-snapshot")
    if m.get("format_version") != FORMAT_VERSION:
        _fail(f"unsupported format_version {m.get('format_version')!r} (this reader knows {FORMAT_VERSION})")
    for key in ("name", "created_at"):
        if not isinstance(m.get(key), str) or not m[key]:
            _fail(f"missing {key}")
    items = m.get("items")
    if not isinstance(items, list):
        _fail("items must be a list")
    seen = set()
    for it in items:
        if not isinstance(it, dict):
            _fail("item is not an object")
        path = it.get("path")
        if not isinstance(path, str) or not path.startswith(PAYLOAD_DIR + "/") or not is_safe_relpath(path):
            _fail(f"item path outside payload/: {path!r}")
        if path in seen:
            _fail(f"duplicate item {path}")
        seen.add(path)
        if it.get("category") not in CATEGORIES:
            _fail(f"{path}: unknown category {it.get('category')!r}")
        if it.get("risk") not in RISKS:
            _fail(f"{path}: unknown risk {it.get('risk')!r}")
        if not isinstance(it.get("sha256"), str) or not SHA256_RE.match(it["sha256"]):
            _fail(f"{path}: bad sha256")
        if not isinstance(it.get("size"), int) or it["size"] < 0:
            _fail(f"{path}: bad size")
        if it.get("mode") not in FILE_MODES:
            _fail(f"{path}: bad mode")
    for key in ("plugins", "mcp_servers", "warnings", "overrides"):
        if not isinstance(m.get(key, []), list):
            _fail(f"{key} must be a list")
    # Everything below ends up in printed commands or plan text: no control characters anywhere.
    _no_control(m)
    for p in m.get("plugins", []):
        if not isinstance(p, dict) or not all(isinstance(p.get(k), str) and NAME_RE.match(p[k]) for k in ("id", "name", "marketplace")):
            _fail("plugin entry needs plain id, name and marketplace")
    for s in m.get("mcp_servers", []):
        if not isinstance(s, dict) or not isinstance(s.get("name"), str) or not NAME_RE.match(s["name"]):
            _fail("mcp server entry needs a plain name")
        if not all(isinstance(a, str) for a in s.get("args", [])):
            _fail(f"mcp server {s['name']}: args must be strings")
        for k in s.get("env_keys", []) + s.get("header_keys", []):
            if not isinstance(k, str) or not NAME_RE.match(k):
                _fail(f"mcp server {s['name']}: bad env or header key")
        env = s.get("env", {})
        if not isinstance(env, dict) or not all(isinstance(k, str) and NAME_RE.match(k) and is_plain_env_value(k, v) for k, v in env.items()):
            _fail(f"mcp server {s['name']}: env may only carry plain flag values")
    return m


# MCP env values are dropped, except flags like NPM_CONFIG_IGNORE_SCRIPTS=true: losing those
# silently weakens the receiver. Only short booleans and numbers under non-secret names are kept.
PLAIN_ENV_VALUE_RE = re.compile(r"(?i)^(true|false|yes|no|on|off|[0-9]{1,6})$")


def is_plain_env_value(name: str, value) -> bool:
    return isinstance(value, str) and not is_secret_name(name) and bool(PLAIN_ENV_VALUE_RE.match(value))


NAME_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,200}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _no_control(o, where: str = "manifest") -> None:
    if isinstance(o, str):
        if CONTROL_RE.search(o):
            _fail(f"control character in {where}")
    elif isinstance(o, dict):
        for k, v in o.items():
            _no_control(k, where + ".key")
            _no_control(v, f"{where}.{k}" if isinstance(k, str) else where)
    elif isinstance(o, list):
        for v in o:
            _no_control(v, where + "[]")
