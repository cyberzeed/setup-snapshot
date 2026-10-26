"""Shared fixtures. Fake secrets are assembled at runtime so the repo holds no literal token."""
from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from setup_snapshot import create as cr  # noqa: E402
from setup_snapshot.collect import Profile  # noqa: E402

FAKE = {
    "anthropic-key": "sk-" + "ant-" + "a" * 30,
    "github-token": "gh" + "p_" + "c" * 36,
    "aws-access-key": "AK" + "IA" + "E" * 16,
    "private-key": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "secret-assignment": "api_key = " + "Z" * 24,
    "secret-keyed-value": '"MY_SERVICE_TOKEN": "' + "q" * 12 + '"',
}
NOW = dt.datetime(2026, 10, 18, 9, 0, 0, tzinfo=dt.timezone.utc)


class Machine:
    """A fake home with a ~/.claude tree."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / "home" / "alice"
        self.claude = self.home / ".claude"
        self.claude_json = self.home / ".claude.json"
        self.claude.mkdir(parents=True)

    def write(self, rel: str, text: str, mode: int = 0o644) -> Path:
        p = self.claude / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        p.chmod(mode)
        return p

    def basic(self) -> "Machine":
        self.write("CLAUDE.md", f"# rules\nnotes live in {self.home}/.claude/notes\n")
        self.write("skills/alpha/SKILL.md", "---\nname: alpha\n---\nplain skill\n")
        self.write("skills/alpha/.source", "org/alpha@abc123\n")
        self.write("skills/beta/SKILL.md", "---\nname: beta\nallowed-tools: Bash(git *)\n---\nruns things\n")
        self.write("skills/beta/run.sh", "#!/bin/sh\necho hi\n", 0o755)
        self.write("agents/reviewer.md", "---\nname: reviewer\n---\nreview\n")
        self.write("notes/tools.md", "tool notes\n")
        self.write(
            "settings.json",
            json.dumps({
                "env": {"GRAPHIFY_BACKEND": "none"},
                "permissions": {"allow": ["Bash(ls:*)"], "deny": ["Read(./.env)"]},
                "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo done"}]}]},
                "enabledPlugins": {"pordee@pordee": True},
                "theme": "dark",
            }),
        )
        self.write(
            "plugins/installed_plugins.json",
            json.dumps({"version": 2, "plugins": {"pordee@pordee": [{"scope": "user", "version": "32f6e55", "gitCommitSha": "32f6e5518ca7"}]}}),
        )
        self.write("plugins/known_marketplaces.json", json.dumps({"pordee": {"source": {"source": "github", "repo": "owner/pordee"}}}))
        self.write(".credentials.json", '{"token": "x"}')
        self.write("projects/p/session.jsonl", "{}\n")
        self.claude_json.write_text(
            json.dumps({"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp@1.2.3"], "env": {
                "DOCS_API_KEY": "real-value-here",
                "NPM_CONFIG_IGNORE_SCRIPTS": "true",
                "DESTINATION_USER_ID": "U-private-id",
                "AUTH_ENABLED": "1",
            }}}}),
            encoding="utf-8",
        )
        return self

    def collect(self, profile: Profile | None = None):
        return cr.collect(self.claude, self.claude_json, self.home, profile or Profile())

    def close(self):
        self.tmp.cleanup()
