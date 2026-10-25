"""Receiver side: back up, write approved items, roll back.

Approval rules:
- a category is applied only if named in `approve` ("all" = every category);
- an item with risk=high is applied only if its category is also named in `approve_high`;
  "all" never covers high-risk items.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest as mf
from .errors import SnapshotError
from .plan import MERGED, Plan, SAME, merged_settings

MODES = ("overwrite", "replace")
REPLACE_SCOPES = {"skill": 2, "agent": 1, "command": 1, "output-style": 1, "notes": 1}  # path depth that defines one unit
BACKUP_DIR = "backups"
BACKUP_PREFIX = "setup-snapshot-"
BLOCK_BEGIN = "<!-- setup-snapshot:begin name={name} sha256={sha} -->"
BLOCK_END = "<!-- setup-snapshot:end -->"


@dataclass
class Decisions:
    approve: set = field(default_factory=set)
    approve_high: set = field(default_factory=set)
    modes: dict = field(default_factory=dict)  # category -> overwrite | replace
    only: set = field(default_factory=set)  # optional item rel paths
    claude_md: str = "block"  # block | replace


@dataclass
class Result:
    backup: Path
    written: list
    removed: list
    skipped: list


def _approved(plan: Plan, d: Decisions) -> tuple[list, list]:
    present = plan.categories()
    approve = set(d.approve)
    if "all" in approve:
        approve |= set(present)  # high-risk items still need --approve-high below
    unknown = (approve | d.approve_high) - set(present) - {"all"}
    if unknown:
        raise SnapshotError(f"categories not in this snapshot: {', '.join(sorted(unknown))}")
    for cat, mode in d.modes.items():
        if mode not in MODES:
            raise SnapshotError(f"unknown mode {mode!r} for {cat} (use overwrite or replace)")
        if mode == "replace" and cat not in REPLACE_SCOPES:
            raise SnapshotError(f"replace mode is not supported for {cat}")
    take, skip = [], []
    for it in plan.items:
        ok = it.category in approve and (it.risk != mf.HIGH or it.category in d.approve_high)
        if d.only and it.rel not in d.only:
            ok = False
        (take if ok else skip).append(it)
    return take, skip


def _atomic_write(target: Path, data: bytes, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class Backup:
    def __init__(self, claude_dir: Path, manifest: dict, sha256: str, now: _dt.datetime):
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        self.root = claude_dir / BACKUP_DIR / f"{BACKUP_PREFIX}{stamp}"
        if self.root.exists():
            raise SnapshotError(f"backup {self.root} already exists; try again in a second")
        self.claude_dir = claude_dir
        self.record = {"snapshot": manifest["name"], "sha256": sha256, "applied_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "changes": []}
        self.seen: set = set()
        (self.root / "files").mkdir(parents=True)

    def save(self, target: Path) -> None:
        rel = target.relative_to(self.claude_dir).as_posix()
        if rel in self.seen:
            return
        self.seen.add(rel)
        existed = target.exists()
        if existed:
            dest = self.root / "files" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, dest)
        self.record["changes"].append({"path": rel, "existed": existed})
        self._flush()  # written before every change, so a crash still leaves a usable record

    def _flush(self) -> None:
        (self.root / "restore.json").write_text(json.dumps(self.record, indent=2) + "\n", encoding="utf-8")


def _claude_md(existing: bytes | None, incoming: bytes, name: str, sha: str, mode: str) -> bytes:
    if mode == "replace" or existing is None:
        return incoming
    text = existing.decode("utf-8")
    begin = BLOCK_BEGIN.format(name=name, sha=sha)
    block = f"{begin}\n{incoming.decode('utf-8').rstrip()}\n{BLOCK_END}\n"
    pattern = re.compile(
        re.escape("<!-- setup-snapshot:begin name=" + name + " ") + r"sha256=[0-9a-f]{64} -->\n.*?" + re.escape(BLOCK_END) + r"\n?",
        re.S,
    )
    if pattern.search(text):
        return pattern.sub(lambda _: block, text, count=1).encode("utf-8")
    return (text.rstrip("\n") + "\n\n" + block).encode("utf-8")


def _replace_extras(take: list, claude_dir: Path, modes: dict, backup: Backup) -> list:
    """For categories in replace mode, remove receiver files in each touched unit that the snapshot lacks."""
    removed = []
    units: dict = {}
    for it in take:
        depth = REPLACE_SCOPES.get(it.category)
        if modes.get(it.category) != "replace" or depth is None:
            continue
        unit = "/".join(it.rel.split("/")[:depth])
        units.setdefault(unit, set()).add(it.rel)
    for unit, keep in units.items():
        root = claude_dir / unit
        if not root.is_dir() or root.is_symlink():
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.is_symlink():
                rel = p.relative_to(claude_dir).as_posix()
                if rel not in keep:
                    backup.save(p)
                    p.unlink()
                    removed.append(rel)
    return removed


def apply(plan: Plan, claude_dir: Path, sha256: str, d: Decisions, now: _dt.datetime | None = None) -> Result:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    take, skip = _approved(plan, d)
    if not take:
        raise SnapshotError("nothing approved; pass --approve <categories>")
    backup = Backup(claude_dir, plan.manifest, sha256, now)
    written = []

    merges = [it for it in take if it.merge]
    for it in take:
        if it.merge or it.status == SAME:
            continue
        data = it.data
        if it.rel == "CLAUDE.md":
            existing = it.target.read_bytes() if it.target.exists() else None
            data = _claude_md(existing, it.data, plan.manifest["name"], sha256, d.claude_md)
        backup.save(it.target)
        _atomic_write(it.target, data, it.mode)
        written.append(it.rel)
    if merges and any(it.status != SAME for it in merges):
        target = claude_dir / "settings.json"
        backup.save(target)
        _atomic_write(target, merged_settings(claude_dir, [it.data for it in merges]), 0o644)
        written.append("settings.json (merged: " + ", ".join(sorted(MERGED[it.rel] for it in merges)) + ")")
    removed = _replace_extras(take, claude_dir, d.modes, backup)
    backup._flush()
    return Result(backup.root, written, removed, [it.rel for it in skip])


def list_backups(claude_dir: Path) -> list:
    root = claude_dir / BACKUP_DIR
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.name.startswith(BACKUP_PREFIX) and not p.name.endswith(".rolled-back") and (p / "restore.json").is_file())


def rollback(claude_dir: Path, stamp: str | None = None) -> tuple[Path, list]:
    backups = list_backups(claude_dir)
    if not backups:
        raise SnapshotError("no setup-snapshot backups found")
    if stamp:
        matches = [b for b in backups if b.name == BACKUP_PREFIX + stamp or b.name == stamp]
        if not matches:
            raise SnapshotError(f"no backup named {stamp}")
        root = matches[0]
    else:
        root = backups[-1]
    record = json.loads((root / "restore.json").read_text(encoding="utf-8"))
    restored = []
    for change in reversed(record["changes"]):
        rel = change["path"]
        if not mf.is_safe_relpath(rel):
            raise SnapshotError(f"unsafe path in backup record: {rel!r}")
        target = claude_dir / rel
        if change["existed"]:
            src = root / "files" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
        elif target.exists():
            target.unlink()
        restored.append(rel)
    done = root.with_name(root.name + ".rolled-back")
    root.rename(done)
    return done, restored
