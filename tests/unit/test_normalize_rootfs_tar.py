from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest
from scripts.normalize_rootfs_tar import SOURCE_DATE_EPOCH, normalize_rootfs_tar


def _write_archive(path: Path, entries: list[tuple[str, str, bytes | str]]) -> None:
    with tarfile.open(path, "w") as archive:
        for kind, name, value in entries:
            member = tarfile.TarInfo(name)
            member.uid = 1234
            member.gid = 5678
            member.uname = "builder"
            member.gname = "builders"
            member.mtime = 1_700_000_000
            if kind == "directory":
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
            elif kind == "file":
                data = value if isinstance(value, bytes) else value.encode()
                member.size = len(data)
                member.mode = 0o755 if name.endswith("/tool") else 0o644
                archive.addfile(member, io.BytesIO(data))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = str(value)
                member.mode = 0o777
                archive.addfile(member)
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            else:
                raise AssertionError(f"unsupported test archive entry: {kind}")


def test_normalizer_produces_identical_rootfs_for_order_owner_and_timestamp_variants(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    first_entries = [
        ("directory", "etc", b""),
        ("directory", "usr/bin", b""),
        ("file", "etc/issue", b"Ubuntu 24.04"),
        ("file", ".hidden", b"keep leading dot"),
        ("file", "usr/bin/tool", b"#!/bin/sh\necho stable\n"),
        ("symlink", "usr/local-tool", "/usr/bin/tool"),
        ("file", "etc/machine-id", b"machine-one"),
        ("file", "var/log/dpkg.log", b"built at 10:00"),
    ]
    _write_archive(first, first_entries)
    _write_archive(second, list(reversed(first_entries)))

    normalized_first = tmp_path / "first.normalized.tar"
    normalized_second = tmp_path / "second.normalized.tar"
    normalize_rootfs_tar(first, normalized_first)
    normalize_rootfs_tar(second, normalized_second)

    first_digest = hashlib.sha256(normalized_first.read_bytes()).hexdigest()
    second_digest = hashlib.sha256(normalized_second.read_bytes()).hexdigest()
    assert first_digest == second_digest

    with tarfile.open(normalized_first, "r:") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == sorted(member.name for member in members)
        assert all(member.uid == 0 and member.gid == 0 for member in members)
        assert all(member.mtime == SOURCE_DATE_EPOCH for member in members)
        assert "etc/machine-id" not in archive.getnames()
        assert "var/log/dpkg.log" not in archive.getnames()
        assert ".hidden" in archive.getnames()
        assert archive.extractfile("etc/issue").read() == b"Ubuntu 24.04"
        assert archive.getmember("usr/local-tool").linkname == "/usr/bin/tool"


@pytest.mark.parametrize("name", ["../escape", "/etc/passwd", "etc/../../escape"])
def test_normalizer_rejects_unsafe_archive_paths(tmp_path: Path, name: str) -> None:
    source = tmp_path / "unsafe.tar"
    _write_archive(source, [("file", name, b"unsafe")])

    with pytest.raises(ValueError, match="unsafe rootfs archive path"):
        normalize_rootfs_tar(source, tmp_path / "normalized.tar")


@pytest.mark.parametrize("target", ["../../../escape", "/../../escape"])
def test_normalizer_rejects_escaping_symlink_targets(tmp_path: Path, target: str) -> None:
    source = tmp_path / "unsafe-link.tar"
    _write_archive(source, [("symlink", "usr/bin/escape", target)])

    with pytest.raises(ValueError, match="unsafe symlink"):
        normalize_rootfs_tar(source, tmp_path / "normalized.tar")


def test_normalizer_rejects_special_files(tmp_path: Path) -> None:
    source = tmp_path / "special.tar"
    _write_archive(source, [("fifo", "var/run/host-control", b"")])

    with pytest.raises(ValueError, match="unsupported special file"):
        normalize_rootfs_tar(source, tmp_path / "normalized.tar")
