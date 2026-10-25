"""Transports move the archive; they are untrusted. Integrity comes from the ticket's sha256.

Each transport shells out to a CLI the user already has and has already
authenticated. Commands are argument lists, never shell strings. Credentials
are never read, stored or printed here.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..errors import SnapshotError

SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
SAFE_USER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/+@=-]*$")
SAFE_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
CHUNK = 1024 * 1024


def _run(cmd: list[str]) -> None:
    exe = shutil.which(cmd[0])
    if not exe:
        raise SnapshotError(f"'{cmd[0]}' is not installed")
    try:
        proc = subprocess.run([exe] + cmd[1:], capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        raise SnapshotError(f"{cmd[0]} timed out") from None
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
        raise SnapshotError(f"{cmd[0]} failed: {tail[0][:300]}")


def _check_size(path: Path, max_size: int) -> Path:
    if path.stat().st_size > max_size:
        path.unlink()
        raise SnapshotError(f"downloaded file is over the expected {max_size} bytes")
    return path


class Transport:
    scheme = ""
    can_push = True

    def push(self, local: Path, dest: str) -> str:
        raise NotImplementedError

    def fetch(self, locator: str, dest_dir: Path, max_size: int) -> Path:
        raise NotImplementedError


class FileTransport(Transport):
    """file:///abs/path — also covers cloud drives that sync a local folder."""

    scheme = "file"

    @staticmethod
    def _path(locator: str) -> Path:
        parts = urlsplit(locator)
        if parts.netloc not in ("", "localhost"):
            raise SnapshotError("file:// locator must be a local absolute path")
        p = Path(unquote(parts.path))
        if not p.is_absolute():
            raise SnapshotError("file:// locator must be absolute")
        return p

    def push(self, local: Path, dest: str) -> str:
        target = self._path(dest)
        if dest.endswith("/") or target.is_dir():
            target = target / local.name
        if target.exists():
            raise SnapshotError(f"{target} already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local, target)
        return target.as_uri()

    def fetch(self, locator: str, dest_dir: Path, max_size: int) -> Path:
        src = self._path(locator)
        if src.is_symlink() or not src.is_file():
            raise SnapshotError(f"{src}: not a regular file")
        if src.stat().st_size > max_size:
            raise SnapshotError(f"{src} is over the expected {max_size} bytes")
        out = dest_dir / "snapshot.download"
        shutil.copyfile(src, out)
        return _check_size(out, max_size)


def _split_remote(locator: str) -> tuple[str, str, str | None, str]:
    """ssh://user@host[:port]/path -> (user, host, port, path), validated against option injection."""
    parts = urlsplit(locator)
    user, host, path = parts.username, parts.hostname, unquote(parts.path)
    if not user or not SAFE_USER.match(user):
        raise SnapshotError("remote locator needs a plain user name: ssh://user@host/path")
    if not host or not SAFE_HOST.match(host) or host.startswith("-"):
        raise SnapshotError("remote locator has an invalid host")
    if not SAFE_PATH.match(path) or "/../" in path + "/" or path.endswith("/.."):
        raise SnapshotError("remote locator path must be absolute and plain")
    port = str(parts.port) if parts.port else None
    return user, host, port, path


class SshTransport(Transport):
    """ssh://user@host[:port]/abs/path via scp."""

    scheme = "ssh"

    def push(self, local: Path, dest: str) -> str:
        user, host, port, path = _split_remote(dest)
        if path.endswith("/"):
            path += local.name
        cmd = ["scp", "-q", "-o", "BatchMode=yes"] + (["-P", port] if port else []) + ["--", str(local), f"{user}@{host}:{path}"]
        _run(cmd)
        return f"ssh://{user}@{host}{':' + port if port else ''}{path}"

    def fetch(self, locator: str, dest_dir: Path, max_size: int) -> Path:
        user, host, port, path = _split_remote(locator)
        out = dest_dir / "snapshot.download"
        _run(["scp", "-q", "-o", "BatchMode=yes"] + (["-P", port] if port else []) + ["--", f"{user}@{host}:{path}", str(out)])
        return _check_size(out, max_size)


class RsyncTransport(Transport):
    """rsync+ssh://user@host[:port]/abs/path — rsync over SSH, resumable."""

    scheme = "rsync+ssh"

    @staticmethod
    def _ssh(port: str | None) -> list[str]:
        return ["-e", f"ssh -o BatchMode=yes -p {port}" if port else "ssh -o BatchMode=yes"]

    def push(self, local: Path, dest: str) -> str:
        user, host, port, path = _split_remote(dest)
        if path.endswith("/"):
            path += local.name
        _run(["rsync", "--partial", "--protect-args"] + self._ssh(port) + ["--", str(local), f"{user}@{host}:{path}"])
        return f"rsync+ssh://{user}@{host}{':' + port if port else ''}{path}"

    def fetch(self, locator: str, dest_dir: Path, max_size: int) -> Path:
        user, host, port, path = _split_remote(locator)
        out = dest_dir / "snapshot.download"
        _run(["rsync", "--partial", "--protect-args", f"--max-size={max_size}"] + self._ssh(port) + ["--", f"{user}@{host}:{path}", str(out)])
        if not out.exists():
            raise SnapshotError("rsync did not download the file (over the size limit?)")
        return _check_size(out, max_size)


class S3Transport(Transport):
    """s3://bucket/key via the aws CLI; credentials from the user's AWS profile."""

    scheme = "s3"

    @staticmethod
    def _check(locator: str) -> str:
        parts = urlsplit(locator)
        if not SAFE_BUCKET.match(parts.netloc or ""):
            raise SnapshotError("s3 locator has an invalid bucket name")
        key = parts.path.lstrip("/")
        if not key or not re.match(r"^[A-Za-z0-9!_.*'()/+=-]+$", key) or key.startswith("-"):
            raise SnapshotError("s3 locator has an invalid key")
        return f"s3://{parts.netloc}/{key}"

    def push(self, local: Path, dest: str) -> str:
        if dest.endswith("/"):
            dest += local.name
        target = self._check(dest)
        _run(["aws", "s3", "cp", "--only-show-errors", str(local), target])
        return target

    def fetch(self, locator: str, dest_dir: Path, max_size: int) -> Path:
        src = self._check(locator)
        out = dest_dir / "snapshot.download"
        _run(["aws", "s3", "cp", "--only-show-errors", src, str(out)])
        return _check_size(out, max_size)


class HttpsTransport(Transport):
    """https:// — fetch only, size enforced while streaming."""

    scheme = "https"
    can_push = False

    def push(self, local: Path, dest: str) -> str:
        raise SnapshotError("https is fetch-only; upload the file another way and use `setup-snapshot ticket`")

    def fetch(self, locator: str, dest_dir: Path, max_size: int) -> Path:
        out = dest_dir / "snapshot.download"
        req = urllib.request.Request(locator, headers={"User-Agent": "setup-snapshot"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp, out.open("wb") as f:
                if urlsplit(resp.geturl()).scheme != "https":
                    raise SnapshotError("https locator redirected to a non-https URL")
                total = 0
                for chunk in iter(lambda: resp.read(CHUNK), b""):
                    total += len(chunk)
                    if total > max_size:
                        raise SnapshotError(f"download is over the expected {max_size} bytes")
                    f.write(chunk)
        except SnapshotError:
            out.unlink(missing_ok=True)
            raise
        except OSError as e:
            out.unlink(missing_ok=True)
            raise SnapshotError(f"download failed: {type(e).__name__}") from None
        return out


TRANSPORTS = {t.scheme: t for t in (FileTransport(), SshTransport(), RsyncTransport(), S3Transport(), HttpsTransport())}


def get(locator: str) -> Transport:
    scheme = urlsplit(locator).scheme
    if scheme not in TRANSPORTS:
        raise SnapshotError(f"unknown transport {scheme!r} (known: {', '.join(sorted(TRANSPORTS))})")
    return TRANSPORTS[scheme]
