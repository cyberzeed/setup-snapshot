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
        cmds.append(f"claude plugin install {shlex.quote(p['id'])}   # sender had {commit}; verify before enabling")
        if not p.get("enabled"):
            cmds.append(f"claude plugin disable {shlex.quote(p['id'])}   # disabled on the sender")
    return cmds


def mcp_commands(servers: list, home: Path) -> list:
    cmds = []
    for s in servers:
        name = shlex.quote(s["name"])
        envs = " ".join(f"-e {shlex.quote(k + '=')}" for k in s.get("env_keys", []))
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
        current = (claude_dir / "settings.json").read_bytes() if (claude_dir / "settings.json").exists() else None
        preview = merged_settings(claude_dir, partials)
        for it in items:
            if it.merge:
                it.status = NEW if current is None else (SAME if json.loads(preview) == json.loads(current) else CHANGED)
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
    if plan.plugin_commands:
        lines += ["", "[plugin] risk=high  commands to run yourself after review:"] + [f"    {c}" for c in plan.plugin_commands]
    if plan.mcp_commands:
        lines += ["", "[mcp] risk=high  commands to run yourself after review:"] + [f"    {c}" for c in plan.mcp_commands]
    if m.get("warnings"):
        lines += ["", "Warnings from the sender:"] + [f"    {w}" for w in m["warnings"]]
    if m.get("overrides"):
        lines += ["", "Secret-scan overrides the sender allowed:"] + [f"    {o}" for o in m["overrides"]]
    return "\n".join(lines) + "\n"
