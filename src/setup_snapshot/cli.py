"""setup-snapshot command line."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from . import apply as ap
from . import manifest as mf
from . import plan as pl
from . import transports
from .archive import Limits, safe_extract, sha256_file
from .collect import Profile
from .create import collect, create
from .errors import SnapshotError
from .ticket import Ticket, parse

PRIVATE_CATEGORIES = {"instructions", "notes"}
PRIVATE_TRANSPORTS = {"ssh", "rsync+ssh"}


def default_claude_dir() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(env).expanduser() if env else Path.home() / ".claude"


def default_profile_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "setup-snapshot" / "profile.json"


def load_profile(path: Path | None) -> Profile:
    p = path or default_profile_path()
    if not p.exists():
        if path:
            raise SnapshotError(f"profile not found: {p}")
        return Profile()
    try:
        return Profile.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except ValueError:
        raise SnapshotError(f"profile is not valid JSON: {p}") from None


def human(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ---- sender ----------------------------------------------------------------

def cmd_create(a) -> int:
    claude_dir = Path(a.claude_dir).expanduser() if a.claude_dir else default_claude_dir()
    home = Path(a.home).expanduser() if a.home else Path.home()
    claude_json = Path(a.claude_json).expanduser() if a.claude_json else home / ".claude.json"
    collected = collect(claude_dir, claude_json, home, load_profile(Path(a.profile) if a.profile else None))
    print(f"{len(collected.items)} files:")
    for it in collected.items:
        flag = "  HIGH" if it.risk == mf.HIGH else ""
        print(f"  {it.category:<13} {human(len(it.data)):>7}  {it.path}{flag}")
    if collected.plugins:
        print(f"{len(collected.plugins)} plugins (metadata only): " + ", ".join(p["id"] for p in collected.plugins))
    if collected.mcp_servers:
        print(f"{len(collected.mcp_servers)} MCP servers (env values dropped): " + ", ".join(s["name"] for s in collected.mcp_servers))
    for w in collected.warnings:
        print(f"warning: {w}")
    for o in collected.overrides:
        print(f"override: {o}")
    if a.dry_run:
        print("dry run: nothing written")
        return 0
    name = a.name or f"{os.uname().nodename.split('.')[0]}-{__import__('datetime').date.today().isoformat()}"
    out, digest, _ = create(collected, name, Path(a.out).expanduser())
    print(f"wrote {out}  ({human(out.stat().st_size)})")
    print(f"sha256 {digest}")
    print(f"next: setup-snapshot push {out} <dest>")
    return 0


def _archive_categories(path: Path) -> set:
    with tempfile.TemporaryDirectory(prefix="setup-snapshot-") as tmp:
        manifest = safe_extract(path, Path(tmp) / "x")
    return {it["category"] for it in manifest["items"]}


def cmd_push(a) -> int:
    local = Path(a.file).expanduser()
    if not local.is_file():
        raise SnapshotError(f"{local}: not a file")
    t = transports.get(a.dest)
    private = PRIVATE_CATEGORIES & _archive_categories(local)
    if t.scheme not in PRIVATE_TRANSPORTS and private and not a.confirm_plaintext:
        raise SnapshotError(
            f"this snapshot holds {', '.join(sorted(private))} and {t.scheme} stores it unencrypted on someone else's storage. "
            "Use ssh/rsync+ssh, or pass --confirm-plaintext."
        )
    locator = t.push(local, a.dest)
    ticket = Ticket(local.name.split(".snap.")[0], locator, sha256_file(local), local.stat().st_size)
    print(ticket.render(), end="")
    return 0


def cmd_ticket(a) -> int:
    local = Path(a.file).expanduser()
    transports.get(a.locator)
    print(Ticket(local.name.split(".snap.")[0], a.locator, sha256_file(local), local.stat().st_size).render(), end="")
    return 0


# ---- receiver --------------------------------------------------------------

def _read_ticket(a) -> Ticket:
    text = Path(a.ticket).read_text(encoding="utf-8") if a.ticket and a.ticket != "-" else sys.stdin.read()
    return parse(text, set(transports.TRANSPORTS), Limits().max_archive_bytes, a.allow_presigned)


def _fetch_verified(ticket: Ticket, work: Path) -> tuple[Path, dict]:
    dl_dir = work / "download"
    dl_dir.mkdir()
    path = transports.get(ticket.locator).fetch(ticket.locator, dl_dir, ticket.size)
    digest = sha256_file(path)
    if digest != ticket.sha256:
        path.unlink()
        raise SnapshotError("sha256 does not match the ticket; the file was deleted and nothing was unpacked")
    if path.stat().st_size != ticket.size:
        raise SnapshotError("size does not match the ticket")
    extracted = work / "extracted"
    manifest = safe_extract(path, extracted)
    if manifest["name"] != ticket.name:
        raise SnapshotError("snapshot name does not match the ticket")
    return extracted, manifest


def _plan(a, work: Path) -> tuple[Ticket, pl.Plan, Path]:
    ticket = _read_ticket(a)
    extracted, manifest = _fetch_verified(ticket, work)
    claude_dir = Path(a.claude_dir).expanduser() if a.claude_dir else default_claude_dir()
    home = Path(a.home).expanduser() if a.home else Path.home()
    return ticket, pl.build(extracted, manifest, claude_dir, home), claude_dir


def cmd_plan(a) -> int:
    with tempfile.TemporaryDirectory(prefix="setup-snapshot-") as tmp:
        _, plan, _ = _plan(a, Path(tmp))
        print("sha256 verified, archive checked.\n")
        print(pl.render(plan), end="")
        print("\nNothing changed. To apply: setup-snapshot apply --approve <categories> [--approve-high <categories>]")
    return 0


def _csv(values) -> set:
    out = set()
    for v in values or []:
        out |= {x.strip() for x in v.split(",") if x.strip()}
    return out


def cmd_apply(a) -> int:
    modes = {}
    for m in a.mode or []:
        cat, _, mode = m.partition("=")
        modes[cat.strip()] = mode.strip()
    d = ap.Decisions(_csv(a.approve), _csv(a.approve_high), modes, _csv(a.only), a.claude_md)
    with tempfile.TemporaryDirectory(prefix="setup-snapshot-") as tmp:
        ticket, plan, claude_dir = _plan(a, Path(tmp))
        result = ap.apply(plan, claude_dir, ticket.sha256, d)
    print(f"backup: {result.backup}")
    for w in result.written:
        print(f"wrote   {w}")
    for r in result.removed:
        print(f"removed {r}")
    if result.skipped:
        print(f"skipped {len(result.skipped)} items not approved")
    if plan.plugin_commands or plan.mcp_commands:
        print("\nRun these yourself after review (not executed):")
        for c in plan.plugin_commands + plan.mcp_commands:
            print(f"  {c}")
    print(f"\nundo: setup-snapshot rollback {result.backup.name[len(ap.BACKUP_PREFIX):]}")
    return 0


def cmd_rollback(a) -> int:
    claude_dir = Path(a.claude_dir).expanduser() if a.claude_dir else default_claude_dir()
    done, restored = ap.rollback(claude_dir, a.stamp)
    for r in restored:
        print(f"restored {r}")
    print(f"rolled back; backup kept at {done}")
    return 0


def cmd_status(a) -> int:
    claude_dir = Path(a.claude_dir).expanduser() if a.claude_dir else default_claude_dir()
    backups = ap.list_backups(claude_dir)
    if not backups:
        print("no snapshots applied")
    for b in backups:
        r = json.loads((b / "restore.json").read_text(encoding="utf-8"))
        print(f"{r['applied_at']}  {r['snapshot']}  sha256 {r['sha256'][:12]}…  {len(r['changes'])} files  rollback id {b.name[len(ap.BACKUP_PREFIX):]}")
    return 0


def main(argv: list | None = None) -> int:
    ap_ = argparse.ArgumentParser(prog="setup-snapshot", description="Pack a Claude Code setup into one verifiable archive and install it elsewhere.")
    ap_.add_argument("--version", action="version", version=f"setup-snapshot {__version__}")
    sub = ap_.add_subparsers(dest="cmd", required=True)

    def paths(p, home=True):
        p.add_argument("--claude-dir", help="default: $CLAUDE_CONFIG_DIR or ~/.claude")
        if home:
            p.add_argument("--home", help="home directory used for {{HOME}} (default: your home)")

    c = sub.add_parser("create", help="collect, scan and pack a snapshot")
    paths(c)
    c.add_argument("--claude-json", help="default: ~/.claude.json (MCP servers)")
    c.add_argument("--profile", help=f"default: {default_profile_path()}")
    c.add_argument("--name")
    c.add_argument("--out", default=".")
    c.add_argument("--dry-run", action="store_true")
    c.set_defaults(fn=cmd_create)

    p = sub.add_parser("push", help="upload a snapshot and print its ticket")
    p.add_argument("file")
    p.add_argument("dest", help="file:///dir/, ssh://user@host/dir/, rsync+ssh://user@host/dir/, s3://bucket/prefix/")
    p.add_argument("--confirm-plaintext", action="store_true", help="allow private categories over unencrypted storage")
    p.set_defaults(fn=cmd_push)

    t = sub.add_parser("ticket", help="print a ticket for a snapshot you uploaded yourself")
    t.add_argument("file")
    t.add_argument("locator")
    t.set_defaults(fn=cmd_ticket)

    for name, fn, helptext in (("plan", cmd_plan, "fetch, verify and show what would change"), ("apply", cmd_apply, "fetch, verify, back up and write approved items")):
        r = sub.add_parser(name, help=helptext)
        paths(r)
        r.add_argument("--ticket", help="ticket file, or - for stdin (default: stdin)")
        r.add_argument("--allow-presigned", action="store_true")
        if name == "apply":
            r.add_argument("--approve", action="append", help="categories, comma-separated; 'all' = every category (high-risk items still need --approve-high)")
            r.add_argument("--approve-high", action="append", help="categories whose high-risk items may be applied")
            r.add_argument("--mode", action="append", help="category=overwrite|replace (default overwrite)")
            r.add_argument("--only", action="append", help="apply only these payload paths")
            r.add_argument("--claude-md", choices=("block", "replace"), default="block")
        r.set_defaults(fn=fn)

    rb = sub.add_parser("rollback", help="restore the files changed by an apply")
    paths(rb, home=False)
    rb.add_argument("stamp", nargs="?")
    rb.set_defaults(fn=cmd_rollback)

    st = sub.add_parser("status", help="list applied snapshots")
    paths(st, home=False)
    st.set_defaults(fn=cmd_status)

    args = ap_.parse_args(argv)
    try:
        return args.fn(args)
    except SnapshotError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
