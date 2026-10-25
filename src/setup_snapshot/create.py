"""Build a snapshot: collect, describe, pack."""
from __future__ import annotations

import datetime as _dt
import platform
import re
import shutil
import subprocess
from pathlib import Path

from . import __version__
from . import manifest as mf
from .archive import pack, sha256_bytes
from .collect import Collected, Collector, Profile
from .errors import SnapshotError

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def claude_code_version() -> str | None:
    exe = shutil.which("claude")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out.split()[0] if out else None


def build_manifest(name: str, created: _dt.datetime, collected: Collected, cc_version: str | None) -> dict:
    return {
        "format": mf.FORMAT,
        "format_version": mf.FORMAT_VERSION,
        "name": name,
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": __version__,
        "source": {"os": platform.system().lower(), "claude_code_version": cc_version},
        "tokens": [mf.HOME_TOKEN],
        "items": [it.entry(sha256_bytes(it.data)) for it in collected.items],
        "plugins": collected.plugins,
        "mcp_servers": collected.mcp_servers,
        "warnings": collected.warnings,
        "overrides": collected.overrides,
    }


def collect(claude_dir: Path, claude_json: Path, home: Path, profile: Profile) -> Collected:
    return Collector(claude_dir, claude_json, home, profile).run()


def create(collected: Collected, name: str, out_dir: Path, now: _dt.datetime | None = None) -> tuple[Path, str, dict]:
    if not NAME_RE.match(name):
        raise SnapshotError("snapshot name may use letters, digits, '.', '_' and '-' (max 100)")
    now = (now or _dt.datetime.now(_dt.timezone.utc)).replace(microsecond=0)
    manifest = build_manifest(name, now, collected, claude_code_version())
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{name}.snap.tar.gz"
    if out.exists():
        raise SnapshotError(f"{out} already exists; snapshots are immutable, pick another name")
    digest = pack(collected.items, manifest, out, int(now.timestamp()))
    return out, digest, manifest
