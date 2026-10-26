import json
import os
import unittest

from helpers import FAKE, Machine

from setup_snapshot import manifest as mf
from setup_snapshot.collect import Profile
from setup_snapshot.errors import SnapshotError
from setup_snapshot.scan import scan_text


class ScanTests(unittest.TestCase):
    def test_each_rule_detected_without_leaking_value(self):
        for rule, value in FAKE.items():
            with self.subTest(rule=rule):
                findings, _ = scan_text(f"line one\nvalue {value}\n", "f.md")
                self.assertTrue(any(f.startswith("f.md:2: ") for f in findings), findings)
                self.assertNotIn(value, "\n".join(findings))

    def test_reserved_and_allowed_email_domains(self):
        self.assertEqual(scan_text("a@example.com b@x.test", "f")[0], [])
        self.assertEqual(scan_text("someone@gmail.com", "f")[0], ["f:1: email"])

    def test_inline_allow_moves_finding_to_overrides(self):
        findings, overrides = scan_text(f"{FAKE['aws-access-key']}  # snapshot:allow aws-access-key", "f")
        self.assertEqual(findings, [])
        self.assertEqual(overrides, ["f:1: aws-access-key"])

    def test_placeholders_not_flagged(self):
        text = 'export TOKEN=<your-token>\n"API_KEY": "${API_KEY}"\npassword: ${PASSWORD}\n'
        self.assertEqual(scan_text(text, "f")[0], [])


class CollectTests(unittest.TestCase):
    def setUp(self):
        self.m = Machine().basic()

    def tearDown(self):
        self.m.close()

    def paths(self, collected):
        return {it.path: it for it in collected.items}

    def test_default_profile_collects_expected_and_excludes_private(self):
        c = self.m.collect()
        paths = self.paths(c)
        for p in ("payload/CLAUDE.md", "payload/skills/alpha/SKILL.md", "payload/skills/alpha/.source",
                  "payload/agents/reviewer.md", "payload/settings.json", "payload/hooks.json"):
            self.assertIn(p, paths)
        joined = " ".join(paths)
        for banned in (".credentials", "projects", "plugins/", "notes/"):
            self.assertNotIn(banned, joined)

    def test_home_path_tokenized(self):
        data = self.paths(self.m.collect())["payload/CLAUDE.md"].data.decode()
        self.assertIn(f"{mf.HOME_TOKEN}/.claude/notes", data)
        self.assertNotIn(str(self.m.home), data)

    def test_skill_with_script_or_bash_is_high_risk(self):
        paths = self.paths(self.m.collect())
        self.assertEqual(paths["payload/skills/alpha/SKILL.md"].risk, mf.LOW)
        self.assertEqual(paths["payload/skills/beta/SKILL.md"].risk, mf.HIGH)
        self.assertEqual(paths["payload/skills/beta/run.sh"].mode, "0755")

    def test_hooks_split_from_settings(self):
        paths = self.paths(self.m.collect())
        settings = json.loads(paths["payload/settings.json"].data)
        hooks = json.loads(paths["payload/hooks.json"].data)
        self.assertNotIn("hooks", settings)
        self.assertNotIn("enabledPlugins", settings)
        self.assertIn("Stop", hooks["hooks"])
        self.assertEqual(paths["payload/hooks.json"].risk, mf.HIGH)

    def test_plugins_and_mcp_are_metadata_without_secrets(self):
        c = self.m.collect()
        self.assertEqual(c.plugins[0]["id"], "pordee@pordee")
        self.assertEqual(c.plugins[0]["git_commit"], "32f6e5518ca7")
        self.assertEqual(c.mcp_servers[0]["env_keys"], ["AUTH_ENABLED", "DESTINATION_USER_ID", "DOCS_API_KEY"])
        self.assertNotIn("real-value-here", json.dumps(c.mcp_servers))
        self.assertNotIn("U-private-id", json.dumps(c.mcp_servers))

    def test_plugin_config_keeps_only_plain_values(self):
        p = self.m.collect().plugins[0]
        self.assertEqual(p["config"], {"ledger": False, "retries": 3})
        self.assertEqual(p["config_keys"], ["API_TOKEN", "level", "webhookUrl"])
        self.assertNotIn("private-board", json.dumps(p))
        for name, value, kept in [
            ("ledger", False, True),
            ("retries", 3, True),
            ("webhookUrl", "", True),
            ("mode", "on", True),
            ("API_TOKEN", True, False),  # secret-looking name
            ("webhookUrl", "https://x.example/hook", False),
            ("big", 10**9, False),
            ("list", ["a"], False),
        ]:
            with self.subTest(name=name, value=value):
                self.assertEqual(mf.is_plain_config_value(name, value), kept)

    def test_plugin_without_config_has_no_config_fields(self):
        s = json.loads((self.m.claude / "settings.json").read_text())
        del s["pluginConfigs"]
        self.m.write("settings.json", json.dumps(s))
        p = self.m.collect().plugins[0]
        self.assertNotIn("config", p)
        self.assertNotIn("config_keys", p)

    def test_mcp_keeps_only_plain_flag_values(self):
        c = self.m.collect()
        self.assertEqual(c.mcp_servers[0]["env"], {"NPM_CONFIG_IGNORE_SCRIPTS": "true"})
        for name, value, kept in [
            ("NPM_CONFIG_IGNORE_SCRIPTS", "true", True),
            ("DEBUG", "0", True),
            ("PORT", "8080", True),
            ("AUTH_ENABLED", "true", False),  # secret-looking name
            ("GITHUB_TOKEN", "1", False),
            ("REGION", "us-east-1", False),  # not a flag
            ("FLAG", "true; rm -rf ~", False),
            ("FLAG", True, False),  # not a string
        ]:
            with self.subTest(name=name, value=value):
                self.assertEqual(mf.is_plain_env_value(name, value), kept)

    def test_notes_opt_in(self):
        c = self.m.collect(Profile.from_dict({"notes_dirs": ["notes"]}))
        self.assertIn("payload/notes/tools.md", self.paths(c))

    def test_notes_dir_cannot_point_at_excluded(self):
        with self.assertRaises(SnapshotError):
            Profile.from_dict({"notes_dirs": ["projects"]})
        with self.assertRaises(SnapshotError):
            Profile.from_dict({"notes_dirs": ["../.ssh"]})

    def test_secret_aborts_and_names_location_only(self):
        self.m.write("skills/alpha/notes.md", "x\n" + FAKE["github-token"] + "\n")
        with self.assertRaises(SnapshotError) as ctx:
            self.m.collect()
        self.assertIn("skills/alpha/notes.md:2: github-token", str(ctx.exception))
        self.assertNotIn(FAKE["github-token"], str(ctx.exception))

    def test_secret_named_env_in_settings_aborts(self):
        self.m.write("settings.json", json.dumps({"env": {"OPENAI_API_KEY": "x"}}))
        with self.assertRaises(SnapshotError) as ctx:
            self.m.collect()
        self.assertIn("env.OPENAI_API_KEY", str(ctx.exception))

    def test_symlinked_file_rejected(self):
        os.symlink(self.m.claude / ".credentials.json", self.m.claude / "skills/alpha/creds.json")
        with self.assertRaises(SnapshotError):
            self.m.collect()

    def test_symlinked_skill_skipped_with_warning(self):
        os.symlink(self.m.claude / "skills/alpha", self.m.claude / "skills/linked")
        c = self.m.collect()
        self.assertTrue(any("skills/linked" in w for w in c.warnings))
        self.assertFalse(any("/linked/" in it.path for it in c.items))

    def test_hidden_and_env_files_rejected(self):
        self.m.write("skills/alpha/.env", "X=1\n")
        with self.assertRaises(SnapshotError):
            self.m.collect()

    def test_skip_skills(self):
        self.m.write("skills/alpha/.hidden", "x")
        c = self.m.collect(Profile.from_dict({"skip_skills": ["alpha"]}))
        self.assertFalse(any("/alpha/" in it.path for it in c.items))

    def test_binary_rejected(self):
        (self.m.claude / "skills/alpha/img.png").write_bytes(b"\x89PNG\x00")
        with self.assertRaises(SnapshotError):
            self.m.collect()

    def test_unknown_profile_key_rejected(self):
        with self.assertRaises(SnapshotError):
            Profile.from_dict({"skils": ["x"]})


if __name__ == "__main__":
    unittest.main()
