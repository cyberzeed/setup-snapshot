import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401  (sets sys.path)

from setup_snapshot import transports as tr
from setup_snapshot.errors import SnapshotError


class LocatorTests(unittest.TestCase):
    def test_remote_rejects_option_injection_and_odd_paths(self):
        for loc in (
            "ssh://-oProxyCommand=evil@host/p",
            "ssh://user@-oProxyCommand=evil/p",
            "ssh://user@host/relative/../../etc",
            "ssh://user@host/a b",
            "ssh://host/p",
            "ssh://user@host/p;rm -rf ~",
        ):
            with self.subTest(loc):
                with self.assertRaises(SnapshotError):
                    tr._split_remote(loc)

    def test_remote_ok(self):
        self.assertEqual(tr._split_remote("ssh://alice@box.local:2222/srv/snaps/x.snap.tar.gz"),
                         ("alice", "box.local", "2222", "/srv/snaps/x.snap.tar.gz"))

    def test_s3_validation(self):
        self.assertEqual(tr.S3Transport._check("s3://my-bucket/a/b.snap.tar.gz"), "s3://my-bucket/a/b.snap.tar.gz")
        for loc in ("s3://Bad_Bucket/k", "s3://bucket/", "s3://bucket/-k", "s3://bucket/k$(x)"):
            with self.subTest(loc):
                with self.assertRaises(SnapshotError):
                    tr.S3Transport._check(loc)

    def test_unknown_scheme(self):
        with self.assertRaises(SnapshotError):
            tr.get("ftp://x/y")

    def test_https_cannot_push(self):
        with self.assertRaises(SnapshotError):
            tr.get("https://x.example.com/y").push(Path("/dev/null"), "https://x.example.com/y")


class FileTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src = self.root / "s.snap.tar.gz"
        self.src.write_bytes(b"x" * 100)

    def tearDown(self):
        self.tmp.cleanup()

    def test_push_fetch_and_size_limit(self):
        store = self.root / "store"
        store.mkdir()
        loc = tr.FileTransport().push(self.src, store.as_uri() + "/")
        dl = self.root / "dl"
        dl.mkdir()
        self.assertEqual(tr.FileTransport().fetch(loc, dl, 100).read_bytes(), b"x" * 100)
        dl2 = self.root / "dl2"
        dl2.mkdir()
        with self.assertRaises(SnapshotError):
            tr.FileTransport().fetch(loc, dl2, 99)

    def test_push_to_new_dir_with_trailing_slash(self):
        loc = tr.FileTransport().push(self.src, (self.root / "new").as_uri() + "/")
        self.assertTrue(loc.endswith("/new/s.snap.tar.gz"))

    def test_push_refuses_overwrite(self):
        store = self.root / "store"
        store.mkdir()
        tr.FileTransport().push(self.src, store.as_uri() + "/")
        with self.assertRaises(SnapshotError):
            tr.FileTransport().push(self.src, store.as_uri() + "/")

    def test_fetch_refuses_symlink(self):
        link = self.root / "link.snap.tar.gz"
        link.symlink_to(self.src)
        dl = self.root / "dl"
        dl.mkdir()
        with self.assertRaises(SnapshotError):
            tr.FileTransport().fetch(link.as_uri(), dl, 1000)


if __name__ == "__main__":
    unittest.main()
