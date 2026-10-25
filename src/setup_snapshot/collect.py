"""Sender side: read the profile, walk allowlisted paths, scan, normalize.

Nothing outside the allowlist is read. Hard exclusions apply even if a profile
names them. Every collected text is secret-scanned; any finding aborts.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest as mf
from .errors import SnapshotError
from .scan import DEFAULT_ALLOWED_EMAIL_DOMAINS, is_secret_name, scan_text

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_NAMES = {".DS_Store"}
ALLOWED_HIDDEN = {".source"}
SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1"}

# Hard exclusions, relative to the Claude dir: never collected.
EXCLUDED_TOP = {
    ".credentials.json", "projects", "history.jsonl", "todos", "shell-snapshots", "statsig",
    "plugins", "sessions", "session-env", "file-history", "paste-cache", "backups", "cache",
    "ide", "downloads", "state", "jobs", "chrome", "daemon",
}
EXCLUDED_FILE_RE = re.compile(r"(^\.env(\..*)?$)|(\.pem$)|(^id_[a-z0-9]+(\.pub)?$)|(credentials)", re.I)

SETTINGS_KEYS_DEFAULT = ["env", "permissions", "model", "effortLevel", "theme", "outputStyle", "includeCoAuthoredBy"]
HOOK_KEYS = ("hooks", "statusLine")

DIR_CATEGORIES = {"agents": "agent", "commands": "command", "output-styles": "output-style"}
ALL_CATEGORIES = ["instructions", "skill", "agent", "command", "output-style", "settings", "hooks", "keybindings", "plugin", "mcp"]

MACOS_ONLY = re.compile(r"\b(security find-generic-password|launchctl|osascript|pbcopy|pbpaste|brew install)\b|/Users/")
LINUX_ONLY = re.compile(r"\b(systemctl|apt-get|apt install|secret-tool|xdg-open)\b|/home/")


@dataclass
class Profile:
    categories: list = field(default_factory=lambda: list(ALL_CATEGORIES))
    skills: object = "*"  # "*" or a list of names
    skip_skills: list = field(default_factory=list)  # names left out when skills is "*"
    notes_dirs: list = field(default_factory=list)  # paths relative to the Claude dir, e.g. ["notes"]
    settings_keys: list = field(default_factory=lambda: list(SETTINGS_KEYS_DEFAULT))
    allowed_email_domains: list = field(default_factory=lambda: sorted(DEFAULT_ALLOWED_EMAIL_DOMAINS))

    @classmethod
    def from_dict(cls, d: dict) -> "Profile":
        known = {"categories", "skills", "skip_skills", "notes_dirs", "settings_keys", "allowed_email_domains"}
        unknown = set(d) - known
        if unknown:
            raise SnapshotError(f"profile has unknown keys: {', '.join(sorted(unknown))}")
        p = cls(**{k: v for k, v in d.items()})
        bad = [c for c in p.categories if c not in ALL_CATEGORIES and c != "notes"]
        if bad:
            raise SnapshotError(f"profile has unknown categories: {', '.join(bad)}")
        if p.notes_dirs and "notes" not in p.categories:
            p.categories.append("notes")
        for nd in p.notes_dirs:
            if not mf.is_safe_relpath(nd) or nd.split("/")[0] in EXCLUDED_TOP:
                raise SnapshotError(f"notes dir must be a plain path inside the Claude dir: {nd!r}")
        return p


@dataclass
class Collected:
    items: list
    plugins: list
    mcp_servers: list
    warnings: list
    overrides: list


class Collector:
    def __init__(self, claude_dir: Path, claude_json: Path, home: Path, profile: Profile):
        self.claude_dir = claude_dir
        self.claude_json = claude_json
        self.home = str(home)
        self.profile = profile
        self.items: list[mf.Item] = []
        self.findings: list[str] = []
        self.overrides: list[str] = []
        self.warnings: list[str] = []

    # ---- helpers -------------------------------------------------------
    def _tokenize(self, text: str) -> str:
        return text.replace(self.home, mf.HOME_TOKEN)

    def _read_text(self, path: Path, label: str) -> str:
        if path.is_symlink():
            raise SnapshotError(f"{label}: symlinks are not collected")
        if not path.is_file():
            raise SnapshotError(f"{label}: not a regular file")
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            raise SnapshotError(f"{label}: larger than {MAX_FILE_BYTES} bytes")
        if b"\x00" in data:
            raise SnapshotError(f"{label}: binary file (NUL byte)")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise SnapshotError(f"{label}: not UTF-8 text") from None

    def _scan(self, text: str, label: str) -> None:
        f, o = scan_text(text, label, self.profile.allowed_email_domains)
        self.findings += f
        self.overrides += o
        for lineno, line in enumerate(text.splitlines(), 1):
            if MACOS_ONLY.search(line):
                self.warnings.append(f"{label}:{lineno}: macOS-specific command or path")
            elif LINUX_ONLY.search(line):
                self.warnings.append(f"{label}:{lineno}: Linux-specific command or path")

    def _add(self, rel: str, text: str, category: str, risk: str, executable: bool = False) -> None:
        self._scan(text, rel)
        self.items.append(
            mf.Item(f"{mf.PAYLOAD_DIR}/{rel}", category, risk, self._tokenize(text).encode("utf-8"), "0755" if executable else "0644")
        )

    def _walk(self, root: Path, rel_root: str) -> list[tuple[str, Path]]:
        """Regular files under root, with fail-closed checks. Returns (rel path, path)."""
        if root.is_symlink():
            raise SnapshotError(f"{rel_root}: is a symlink")
        out = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            for d in sorted(dirnames):
                label = f"{rel_root}/{(here / d).relative_to(root).as_posix()}"
                if (here / d).is_symlink():
                    raise SnapshotError(f"{label}: symlinks are not collected")
                if d.startswith("."):
                    raise SnapshotError(f"{label}: hidden directory")
            dirnames.sort()
            for fn in sorted(filenames):
                if fn in SKIP_NAMES:
                    continue
                path = here / fn
                rel = f"{rel_root}/{path.relative_to(root).as_posix()}"
                if fn.startswith(".") and fn not in ALLOWED_HIDDEN:
                    raise SnapshotError(f"{rel}: hidden file")
                if EXCLUDED_FILE_RE.search(fn):
                    raise SnapshotError(f"{rel}: looks like a secret or credential file")
                out.append((rel, path))
        return out

    # ---- categories ----------------------------------------------------
    def instructions(self) -> None:
        p = self.claude_dir / "CLAUDE.md"
        if p.exists():
            self._add("CLAUDE.md", self._read_text(p, "CLAUDE.md"), "instructions", mf.MEDIUM)

    def skills(self) -> None:
        root = self.claude_dir / "skills"
        if not root.is_dir():
            return
        wanted = self.profile.skills
        names = sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))
        if wanted != "*":
            missing = [n for n in wanted if n not in names]
            if missing:
                raise SnapshotError(f"skills not found: {', '.join(missing)}")
            names = [n for n in names if n in wanted]
        names = [n for n in names if n not in self.profile.skip_skills]
        for name in names:
            sdir = root / name
            if sdir.is_symlink():
                if wanted != "*":
                    raise SnapshotError(f"skills/{name}: is a symlink; symlinked skills are not collected")
                self.warnings.append(f"skills/{name}: symlink, skipped (installed by another tool?)")
                continue
            if not (sdir / "SKILL.md").is_file():
                continue  # not a skill (e.g. a synced folder of other tools)
            try:
                files = self._walk(sdir, f"skills/{name}")
            except SnapshotError as e:
                raise SnapshotError(f"{e} (leave the skill out with \"skip_skills\": [\"{name}\"] in the profile)") from None
            texts = [(rel, path, self._read_text(path, rel)) for rel, path in files]
            has_script = any(
                Path(rel).suffix in SCRIPT_SUFFIXES or os.access(path, os.X_OK) for rel, path, _ in texts
            ) or bool(re.search(r"(?im)^allowed-tools:.*\bBash\b", texts_skill_md(texts)))
            risk = mf.HIGH if has_script else mf.LOW
            for rel, path, text in texts:
                self._add(rel, text, "skill", risk, executable=os.access(path, os.X_OK))

    def dir_category(self, dirname: str) -> None:
        category = DIR_CATEGORIES[dirname]
        root = self.claude_dir / dirname
        if not root.is_dir():
            return
        for rel, path in self._walk(root, dirname):
            self._add(rel, self._read_text(path, rel), category, mf.CATEGORIES[category])

    def notes(self) -> None:
        for nd in self.profile.notes_dirs:
            root = self.claude_dir / nd
            if not root.is_dir():
                raise SnapshotError(f"notes dir not found: {nd}")
            for rel, path in self._walk(root, nd):
                self._add(rel, self._read_text(path, rel), "notes", mf.MEDIUM)

    def _settings(self) -> dict:
        p = self.claude_dir / "settings.json"
        if not p.exists():
            return {}
        try:
            return json.loads(self._read_text(p, "settings.json"))
        except ValueError:
            raise SnapshotError("settings.json is not valid JSON") from None

    def settings(self, s: dict) -> None:
        keep = {k: s[k] for k in self.profile.settings_keys if k in s and k not in HOOK_KEYS}
        for name in (keep.get("env") or {}):
            if is_secret_name(name):
                self.findings.append(f"settings.json: env.{name}: secret-named variable (move it out of settings.json)")
        if keep:
            self._add("settings.json", json.dumps(keep, indent=2, sort_keys=True) + "\n", "settings", mf.LOW)

    def hooks(self, s: dict) -> None:
        keep = {k: s[k] for k in HOOK_KEYS if k in s}
        if keep:
            self._add("hooks.json", json.dumps(keep, indent=2, sort_keys=True) + "\n", "hooks", mf.HIGH)

    def keybindings(self) -> None:
        p = self.claude_dir / "keybindings.json"
        if p.exists():
            self._add("keybindings.json", self._read_text(p, "keybindings.json"), "keybindings", mf.LOW)

    def plugins(self, s: dict) -> list:
        reg = self.claude_dir / "plugins" / "installed_plugins.json"
        known = self.claude_dir / "plugins" / "known_marketplaces.json"
        if not reg.exists():
            return []
        installed = json.loads(self._read_text(reg, "plugins/installed_plugins.json")).get("plugins", {})
        markets = json.loads(self._read_text(known, "plugins/known_marketplaces.json")) if known.exists() else {}
        enabled = s.get("enabledPlugins", {})
        out = []
        for pid in sorted(installed):
            entries = [e for e in installed[pid] if e.get("scope") == "user"]
            if not entries:
                continue
            name, _, market = pid.partition("@")
            src = dict((markets.get(market) or {}).get("source") or {})
            if src.get("source") in ("directory", "path", "file"):
                self.warnings.append(f"plugin {pid}: marketplace is a local path; the receiver must provide it")
            e = entries[0]
            out.append({
                "id": pid,
                "name": name,
                "marketplace": market,
                "marketplace_source": json.loads(self._tokenize(json.dumps(src))),
                "version": e.get("version"),
                "git_commit": e.get("gitCommitSha"),
                "enabled": bool(enabled.get(pid, False)),
            })
        return out

    def mcp(self) -> list:
        if not self.claude_json.exists():
            return []
        try:
            data = json.loads(self.claude_json.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise SnapshotError("~/.claude.json is not valid JSON") from None
        out = []
        for name, cfg in sorted((data.get("mcpServers") or {}).items()):
            if not isinstance(cfg, dict):
                continue
            args = [str(a) for a in cfg.get("args", [])]
            label = f"mcpServers.{name}"
            self._scan("\n".join([str(cfg.get("command", "")), str(cfg.get("url", ""))] + args), label)
            entry = {
                "name": name,
                "type": cfg.get("type", "stdio"),
                "command": self._tokenize(str(cfg.get("command", ""))) or None,
                "args": [self._tokenize(a) for a in args],
                "url": cfg.get("url"),
                "env_keys": sorted((cfg.get("env") or {}).keys()),
                "header_keys": sorted((cfg.get("headers") or {}).keys()),
            }
            out.append({k: v for k, v in entry.items() if v not in (None, [], "")})
        return out

    # ---- run -------------------------------------------------------------
    def run(self) -> Collected:
        cats = set(self.profile.categories)
        s = self._settings() if cats & {"settings", "hooks", "plugin"} else {}
        if "instructions" in cats:
            self.instructions()
        if "skill" in cats:
            self.skills()
        for dirname, cat in DIR_CATEGORIES.items():
            if cat in cats:
                self.dir_category(dirname)
        if "notes" in cats:
            self.notes()
        if "settings" in cats:
            self.settings(s)
        if "hooks" in cats:
            self.hooks(s)
        if "keybindings" in cats:
            self.keybindings()
        plugins = self.plugins(s) if "plugin" in cats else []
        mcp = self.mcp() if "mcp" in cats else []
        if self.findings:
            raise SnapshotError("secret scan failed:\n  " + "\n  ".join(self.findings))
        paths = [it.path for it in self.items]
        dupes = {p for p in paths if paths.count(p) > 1}
        if dupes:
            raise SnapshotError(f"two sources map to the same path: {', '.join(sorted(dupes))}")
        return Collected(sorted(self.items, key=lambda i: i.path), plugins, mcp, self.warnings, self.overrides)


def texts_skill_md(texts) -> str:
    for rel, _, text in texts:
        if rel.endswith("/SKILL.md") and rel.count("/") == 2:
            return text.split("\n---", 1)[0] if text.startswith("---") else ""
    return ""
