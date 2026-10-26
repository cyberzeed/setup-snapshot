"""Receiver side: turn a verified snapshot into a plan. Changes nothing on disk."""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest as mf
from .errors import SnapshotError

NEW, CHANGED, SAME = "NEW", "CHANGED", "SAME"
MERGED = {"settings.json": "settings", "hooks.json": "hooks"}  # payload files merged into settings.json


@dataclass
class PlanItem:
    rel: str  # path under payload/
    category: str
    risk: str
    target: Path
    data: bytes = field(repr=False)
    mode: int = 0o644
    status: str = NEW
    merge: bool = False
    changes: list = field(default_factory=list)  # settings key paths a merge adds or changes


@dataclass
class Plan:
    manifest: dict
    items: list
    plugin_commands: list
    mcp_commands: list

    def categories(self) -> dict:
        out: dict = {}
        for it in self.items:
            out.setdefault(it.category, []).append(it)
        return out


def expand(text: str, home: Path) -> str:
    return text.replace(mf.HOME_TOKEN, str(home))


def deep_merge(base: dict, incoming: dict) -> dict:
    """Snapshot values win on scalar conflicts; dicts merge; lists union (receiver entries first, never removed)."""
    out = dict(base)
    for k, v in incoming.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + [x for x in v if x not in out[k]]
        else:
            out[k] = v
    return out


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise SnapshotError(f"{path} is not valid JSON; fix it before applying") from None
    if not isinstance(data, dict):
        raise SnapshotError(f"{path} is not a JSON object")
    return data


def key_changes(before: dict, after: dict, prefix: str = "") -> list:
    """Key paths that differ after a deep_merge, without values (settings may hold private data)."""
    out = []
    for k in sorted(after):
        path = prefix + _printable(k)
        old, new = before.get(k), after[k]
        if k in before and old == new:
            continue
        if isinstance(new, dict) and new and (k not in before or isinstance(old, dict)):
            out += key_changes(old or {}, new, path + ".")
        elif k not in before:
            out.append(f"added    {path}")
        elif isinstance(old, list) and isinstance(new, list):
            out.append(f"extended {path} (+{len(new) - len(old)})")
        else:
            out.append(f"changed  {path}")
    return out


def _printable(key: str) -> str:
    # Keys come from the untrusted archive and end up on the terminal.
    return key.encode("unicode_escape").decode("ascii") if mf.CONTROL_RE.search(key) or not key.isprintable() else key


def merged_settings(claude_dir: Path, partials: list) -> bytes:
    current = _load_json(claude_dir / "settings.json")
    merged = current
    for data in partials:
        merged = deep_merge(merged, json.loads(data))
    return (json.dumps(merged, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def plugin_commands(plugins: list, home: Path) -> list:
    cmds = []
    seen_markets = set()
    for p in plugins:
        src = p.get("marketplace_source") or {}
        market = p.get("marketplace", "")
        if market not in seen_markets:
            seen_markets.add(market)
            kind = src.get("source")
            if kind == "github" and src.get("repo"):
                cmds.append(f"claude plugin marketplace add {shlex.quote(src['repo'])}")
            elif kind in ("git", "url") and src.get("url"):
                cmds.append(f"claude plugin marketplace add {shlex.quote(src['url'])}")
            else:
                cmds.append(f"# marketplace {market!r}: source {kind!r} must be provided by hand")
        commit = p.get("git_commit") or p.get("version") or "unknown"
        config = "".join(f" --config {shlex.quote(k + '=' + _config_str(v))}" for k, v in p.get("config", {}).items())
        cmds.append(f"claude plugin install {shlex.quote(p['id'])}{config}   # sender had {commit}; verify before enabling")
        if p.get("config_keys"):
            cmds.append(f"# set {', '.join(p['config_keys'])} for {p['id']} yourself (/plugin configure {p['id']})")
        if not p.get("enabled"):
            cmds.append(f"claude plugin disable {shlex.quote(p['id'])}   # disabled on the sender")
    return cmds


def _config_str(v) -> str:
    return ("true" if v else "false") if isinstance(v, bool) else str(v)


def mcp_commands(servers: list, home: Path) -> list:
    cmds = []
    for s in servers:
        name = shlex.quote(s["name"])
        envs = " ".join(
            [f"-e {shlex.quote(k + '=' + v)}" for k, v in s.get("env", {}).items()]
            + [f"-e {shlex.quote(k + '=')}" for k in s.get("env_keys", [])]
        )
        if s.get("type") in ("http", "sse") and s.get("url"):
            headers = " ".join(f"--header {shlex.quote(k + ': ')}" for k in s.get("header_keys", []))
            cmds.append(f"claude mcp add --scope user --transport {s['type']} {headers} {name} {shlex.quote(s['url'])}".replace("  ", " "))
        elif s.get("command"):
            argv = " ".join(shlex.quote(expand(a, home)) for a in [s["command"]] + s.get("args", []))
            cmds.append(f"claude mcp add --scope user {envs} {name} -- {argv}".replace("  ", " "))
        if s.get("env_keys") or s.get("header_keys"):
            cmds.append(f"# fill in {', '.join(s.get('env_keys', []) + s.get('header_keys', []))} for {s['name']} yourself")
    return cmds


def build(extracted: Path, manifest: dict, claude_dir: Path, home: Path) -> Plan:
    items: list = []
    partials = []
    for entry in manifest["items"]:
        rel = entry["path"][len(mf.PAYLOAD_DIR) + 1:]
        raw = (extracted / entry["path"]).read_bytes()
        try:
            data = expand(raw.decode("utf-8"), home).encode("utf-8")
        except UnicodeDecodeError:
            raise SnapshotError(f"{entry['path']}: not UTF-8 text") from None
        mode = int(entry["mode"], 8)
        if rel in MERGED:
            partials.append(data)
            items.append(PlanItem(rel, entry["category"], entry["risk"], claude_dir / "settings.json", data, 0o644, merge=True))
            continue
        target = claude_dir / rel
        status = NEW if not target.exists() else (SAME if target.read_bytes() == data else CHANGED)
        items.append(PlanItem(rel, entry["category"], entry["risk"], target, data, mode, status))
    if partials:
        exists = (claude_dir / "settings.json").exists()
        current = _load_json(claude_dir / "settings.json")
        for it in items:
            if it.merge:
                it.changes = key_changes(current, deep_merge(current, json.loads(it.data)))
                it.status = NEW if not exists else (CHANGED if it.changes else SAME)
    return Plan(manifest, items, plugin_commands(manifest.get("plugins", []), home), mcp_commands(manifest.get("mcp_servers", []), home))


def render(plan: Plan) -> str:
    m = plan.manifest
    lines = [
        f"Snapshot {m['name']}  created {m['created_at']}  from {m['source'].get('os')}  (setup-snapshot {m.get('tool_version')})",
        "",
    ]
    for cat, items in sorted(plan.categories().items()):
        risk = "high" if any(i.risk == mf.HIGH for i in items) else max((i.risk for i in items), key=mf.RISKS.index)
        counts = {s: sum(1 for i in items if i.status == s) for s in (NEW, CHANGED, SAME)}
        lines.append(f"[{cat}] risk={risk}  new={counts[NEW]} changed={counts[CHANGED]} same={counts[SAME]}")
        for i in items:
            if i.status != SAME:
                flag = "  HIGH" if i.risk == mf.HIGH else ""
                lines.append(f"    {i.status:<8} {i.rel}{flag}")
                lines += [f"        {c}" for c in i.changes]
    if plan.plugin_commands:
        lines += ["", "[plugin] risk=high  commands to run yourself after review:"] + [f"    {c}" for c in plan.plugin_commands]
    if plan.mcp_commands:
        lines += ["", "[mcp] risk=high  commands to run yourself after review:"] + [f"    {c}" for c in plan.mcp_commands]
    if m.get("warnings"):
        lines += ["", "Warnings from the sender:"] + [f"    {w}" for w in m["warnings"]]
    if m.get("overrides"):
        lines += ["", "Secret-scan overrides the sender allowed:"] + [f"    {o}" for o in m["overrides"]]
    return "\n".join(lines) + "\n"
