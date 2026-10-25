"""Deterministic packing and hand-written safe extraction.

Pack: entries sorted, fixed mtime, uid/gid 0, no owner names, gzip header
without name or time, so the same inputs give the same bytes.

Extract: tarfile on Python 3.9 has no `filter="data"` on every patch level, so
every member is checked here: regular files and directories only, names under
manifest.json or payload/, size/count/ratio limits, and an exact match with
the manifest (sha256 and size) for every file.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path

from . import manifest as mf
from .errors import SnapshotError

CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    max_archive_bytes: int = 50 * 1024 * 1024
    max_unpacked_bytes: int = 200 * 1024 * 1024
    max_files: int = 10_000
    max_ratio: int = 200  # unpacked / compressed


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _tarinfo(name: str, size: int, mode: int, mtime: int, is_dir: bool = False) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.size = 0 if is_dir else size
    ti.mode = mode
    ti.mtime = mtime
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    return ti


def pack(items: list[mf.Item], manifest: dict, out_path: Path, mtime: int) -> str:
    """Write a deterministic .snap.tar.gz and return its sha256. `manifest` must already list `items`."""
    files = {mf.MANIFEST_NAME: json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"}
    modes = {mf.MANIFEST_NAME: 0o644}
    for it in items:
        files[it.path] = it.data
        modes[it.path] = int(it.mode, 8)
    dirs = sorted(_parents(files))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for d in dirs:
            tar.addfile(_tarinfo(d, 0, 0o755, mtime, is_dir=True))
        for name in sorted(files):
            data = files[name]
            tar.addfile(_tarinfo(name, len(data), modes[name], mtime), io.BytesIO(data))
    tmp = out_path.with_name(out_path.name + ".part")
    with tmp.open("wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
            gz.write(raw.getvalue())
    os.replace(tmp, out_path)
    return sha256_file(out_path)


def _parents(files) -> set:
    out = set()
    for p in files:
        parts = p.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.add("/".join(parts[:i]))
    return out


def _check_name(name: str) -> None:
    if not mf.is_safe_relpath(name.rstrip("/")):
        raise SnapshotError(f"unsafe path in archive: {name!r}")
    top = name.split("/", 1)[0]
    if name.rstrip("/") != mf.MANIFEST_NAME and top != mf.PAYLOAD_DIR:
        raise SnapshotError(f"unexpected entry in archive: {name!r}")


def safe_extract(archive: Path, dest: Path, limits: Limits = Limits()) -> dict:
    """Extract into an empty `dest` and return the validated manifest. Raises on anything unexpected."""
    compressed = archive.stat().st_size
    if compressed > limits.max_archive_bytes:
        raise SnapshotError(f"archive is {compressed} bytes, over the {limits.max_archive_bytes} limit")
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise SnapshotError(f"extract target is not empty: {dest}")
    dest_root = dest.resolve()

    total = 0
    count = 0
    written: dict[str, tuple[str, int]] = {}
    try:
        tar = tarfile.open(archive, mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise SnapshotError(f"not a gzip tar archive: {type(e).__name__}") from None
    with tar:
        while True:
            try:
                member = tar.next()
            except (tarfile.TarError, OSError, EOFError) as e:
                raise SnapshotError(f"corrupt archive: {type(e).__name__}") from None
            if member is None:
                break
            count += 1
            if count > limits.max_files:
                raise SnapshotError(f"more than {limits.max_files} entries")
            name = member.name
            _check_name(name)
            if member.isdir():
                continue
            if not member.isreg():
                raise SnapshotError(f"{name}: only regular files and directories are allowed")
            if name in written:
                raise SnapshotError(f"{name}: duplicate entry")
            total += member.size
            if total > limits.max_unpacked_bytes:
                raise SnapshotError(f"unpacked size over the {limits.max_unpacked_bytes} limit")
            if total > max(compressed, 1) * limits.max_ratio:
                raise SnapshotError(f"compression ratio over {limits.max_ratio}:1")
            target = (dest_root / name).resolve()
            if dest_root not in target.parents:
                raise SnapshotError(f"{name}: escapes the extract directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                raise SnapshotError(f"{name}: unreadable entry")
            h = hashlib.sha256()
            size = 0
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                for chunk in iter(lambda: src.read(CHUNK), b""):
                    size += len(chunk)
                    if size > member.size:
                        raise SnapshotError(f"{name}: longer than its header")
                    h.update(chunk)
                    out.write(chunk)
            written[name] = (h.hexdigest(), size)

    if mf.MANIFEST_NAME not in written:
        raise SnapshotError("archive has no manifest.json")
    try:
        manifest = json.loads((dest_root / mf.MANIFEST_NAME).read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise SnapshotError("manifest.json is not valid JSON") from None
    mf.validate(manifest)

    listed = {it["path"]: it for it in manifest["items"]}
    files = {k: v for k, v in written.items() if k != mf.MANIFEST_NAME}
    extra = sorted(set(files) - set(listed))
    missing = sorted(set(listed) - set(files))
    if extra:
        raise SnapshotError(f"files not listed in manifest: {', '.join(extra[:5])}")
    if missing:
        raise SnapshotError(f"files listed but missing: {', '.join(missing[:5])}")
    for path, (digest, size) in files.items():
        if digest != listed[path]["sha256"] or size != listed[path]["size"]:
            raise SnapshotError(f"{path}: content does not match manifest")
    return manifest
