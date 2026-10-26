import contextlib
import io
import json
import unittest
from pathlib import Path

from helpers import Machine

from setup_snapshot.cli import main
from setup_snapshot.plan import key_changes


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.sender = Machine().basic()
        self.receiver = Machine()
        self.receiver.write("CLAUDE.md", "# my own rules\n")
        self.receiver.write(
            "settings.json",
            json.dumps({"permissions": {"deny": ["Bash(rm:*)"]}, "theme": "light", "model": "keep-me"}),
        )
        self.receiver.write("skills/alpha/old.md", "stale file\n")
        self.store = self.sender.root / "store"
        self.store.mkdir()
        self.outdir = self.sender.root / "out"

    def tearDown(self):
        self.sender.close()
        self.receiver.close()

    def make_ticket(self) -> Path:
        s = self.sender
        code, out, err = run("create", "--claude-dir", str(s.claude), "--claude-json", str(s.claude_json),
                             "--home", str(s.home), "--name", "snap1", "--out", str(self.outdir))
        self.assertEqual(code, 0, err)
        code, out, err = run("push", str(self.outdir / "snap1.snap.tar.gz"), self.store.as_uri() + "/", "--confirm-plaintext")
        self.assertEqual(code, 0, err)
        ticket = self.sender.root / "ticket.txt"
        ticket.write_text(out)
        return ticket

    def recv(self, cmd, ticket, *extra):
        r = self.receiver
        return run(cmd, "--claude-dir", str(r.claude), "--home", str(r.home), "--ticket", str(ticket), *extra)

    def test_push_refuses_private_categories_over_plaintext_storage(self):
        s = self.sender
        run("create", "--claude-dir", str(s.claude), "--claude-json", str(s.claude_json), "--home", str(s.home),
            "--name", "snap2", "--out", str(self.outdir))
        code, _, err = run("push", str(self.outdir / "snap2.snap.tar.gz"), self.store.as_uri() + "/")
        self.assertEqual(code, 1)
        self.assertIn("unencrypted", err)

    def test_plan_changes_nothing(self):
        ticket = self.make_ticket()
        before = (self.receiver.claude / "settings.json").read_bytes()
        code, out, err = self.recv("plan", ticket)
        self.assertEqual(code, 0, err)
        self.assertIn("[hooks] risk=high", out)
        self.assertIn("claude plugin install pordee@pordee", out)
        self.assertIn("-e NPM_CONFIG_IGNORE_SCRIPTS=true -e AUTH_ENABLED= -e DESTINATION_USER_ID= -e DOCS_API_KEY=", out)
        self.assertIn("fill in AUTH_ENABLED, DESTINATION_USER_ID, DOCS_API_KEY for docs", out)
        self.assertIn("    CHANGED  settings.json\n        added    env.GRAPHIFY_BACKEND\n", out)
        self.assertIn("        added    permissions.allow\n", out)
        self.assertIn("        extended permissions.deny (+1)\n", out)
        self.assertIn("        changed  theme\n", out)
        self.assertNotIn("model", out)  # unchanged receiver key
        self.assertNotIn("none", out)  # values are never printed
        self.assertEqual((self.receiver.claude / "settings.json").read_bytes(), before)
        self.assertFalse((self.receiver.claude / "agents").exists())

    def test_apply_all_skips_high_risk(self):
        ticket = self.make_ticket()
        code, out, err = self.recv("apply", ticket, "--approve", "all")
        self.assertEqual(code, 0, err)
        c = self.receiver.claude
        self.assertTrue((c / "skills/alpha/SKILL.md").exists())
        self.assertFalse((c / "skills/beta").exists(), "high-risk skill applied without --approve-high")
        settings = json.loads((c / "settings.json").read_text())
        self.assertNotIn("hooks", settings, "hooks applied without --approve-high")
        self.assertEqual(settings["permissions"]["deny"], ["Bash(rm:*)", "Read(./.env)"])
        self.assertEqual(settings["model"], "keep-me")
        self.assertEqual(settings["theme"], "dark")
        claude_md = (c / "CLAUDE.md").read_text()
        self.assertTrue(claude_md.startswith("# my own rules"))
        self.assertIn("<!-- setup-snapshot:begin name=snap1", claude_md)
        self.assertIn(f"{self.receiver.home}/.claude/notes", claude_md)
        self.assertTrue((c / "skills/alpha/old.md").exists(), "overwrite mode must keep local-only files")

    def test_apply_high_needs_explicit_category(self):
        ticket = self.make_ticket()
        code, _, err = self.recv("apply", ticket, "--approve", "skill,hooks", "--approve-high", "skill,hooks")
        self.assertEqual(code, 0, err)
        c = self.receiver.claude
        self.assertTrue((c / "skills/beta/run.sh").exists())
        self.assertTrue((c / "skills/beta/run.sh").stat().st_mode & 0o100)
        self.assertIn("Stop", json.loads((c / "settings.json").read_text())["hooks"])

    def test_reapply_replaces_claude_md_block(self):
        ticket = self.make_ticket()
        self.recv("apply", ticket, "--approve", "instructions")
        self.recv("apply", ticket, "--approve", "instructions")
        self.assertEqual((self.receiver.claude / "CLAUDE.md").read_text().count("setup-snapshot:begin"), 1)

    def test_replace_mode_and_rollback_restore_bytes(self):
        c = self.receiver.claude
        before = {p: (c / p).read_bytes() for p in ("CLAUDE.md", "settings.json", "skills/alpha/old.md")}
        ticket = self.make_ticket()
        code, out, err = self.recv("apply", ticket, "--approve", "all", "--mode", "skill=replace")
        self.assertEqual(code, 0, err)
        self.assertFalse((c / "skills/alpha/old.md").exists())
        self.assertIn("removed skills/alpha/old.md", out)
        code, out, err = run("rollback", "--claude-dir", str(c))
        self.assertEqual(code, 0, err)
        for p, data in before.items():
            self.assertEqual((c / p).read_bytes(), data, p)
        self.assertFalse((c / "agents/reviewer.md").exists())
        self.assertFalse((c / "skills/alpha/SKILL.md").exists())

    def test_tampered_archive_rejected_before_unpack(self):
        ticket = self.make_ticket()
        stored = self.store / "snap1.snap.tar.gz"
        data = bytearray(stored.read_bytes())
        data[-20] ^= 0xFF
        stored.write_bytes(bytes(data))
        code, _, err = self.recv("plan", ticket)
        self.assertEqual(code, 1)
        self.assertIn("sha256 does not match", err)

    def test_nothing_approved(self):
        ticket = self.make_ticket()
        code, _, err = self.recv("apply", ticket)
        self.assertEqual(code, 1)
        self.assertIn("nothing approved", err)

    def test_status(self):
        ticket = self.make_ticket()
        self.recv("apply", ticket, "--approve", "agent")
        code, out, _ = run("status", "--claude-dir", str(self.receiver.claude))
        self.assertIn("snap1", out)



class KeyChangesTests(unittest.TestCase):
    def test_paths_without_values(self):
        before = {"a": 1, "keep": "x", "d": {"x": 1}, "l": [1], "s": "scalar"}
        after = {"a": 2, "keep": "x", "d": {"x": 1, "y": {"z": 3}}, "l": [1, 2], "s": {"now": "dict"}, "new": {}}
        self.assertEqual(key_changes(before, after), [
            "changed  a",
            "added    d.y.z",
            "extended l (+1)",
            "added    new",
            "changed  s",
        ])

    def test_control_characters_in_keys_are_escaped(self):
        out = key_changes({}, {"evil\x1b]0;pwn\x07": 1})
        self.assertEqual(out, ["added    evil\\x1b]0;pwn\\x07"])
        self.assertNotIn("\x1b", out[0])


if __name__ == "__main__":
    unittest.main()
