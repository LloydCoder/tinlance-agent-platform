from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
from scripts.normalize_rootfs_tar import normalize_rootfs_tar


def _archive(path: Path, members: list[tuple[str, str, str]]) -> None:
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for kind, name, target in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                payload = target.encode()
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = target
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = target
                archive.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            elif kind == "char":
                info.type = tarfile.CHRTYPE
                info.devmajor = 1
                info.devminor = 3
                archive.addfile(info)
            else:
                raise AssertionError(kind)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        (
            [("file", "usr/bin/a", "one"), ("file", "usr/bin/a", "two")],
            "duplicate rootfs archive path",
        ),
        ([("hardlink", "usr/bin/a", "usr/bin/missing")], "missing hardlink target"),
        (
            [("hardlink", "usr/bin/a", "usr/bin/b"), ("hardlink", "usr/bin/b", "usr/bin/a")],
            "cyclic hardlink",
        ),
        ([("symlink", "usr/bin/link", "/../../etc/shadow")], "unsafe symlink"),
        ([("fifo", "var/run/agent.sock", "")], "unsupported special file"),
        ([("char", "dev/mem", "")], "unsupported special file"),
        ([("hardlink", "usr/bin/a", "../etc/passwd")], "unsafe hardlink"),
    ],
)
def test_hostile_rootfs_archive_entries_fail_closed(
    tmp_path: Path, entries: list[tuple[str, str, str]], message: str
) -> None:
    source = tmp_path / "hostile.tar"
    _archive(source, entries)
    with pytest.raises(ValueError, match=message):
        normalize_rootfs_tar(source, tmp_path / "normalized.tar")


def test_pax_path_override_cannot_escape_rootfs(tmp_path: Path) -> None:
    source = tmp_path / "pax-path.tar"
    with tarfile.open(source, "w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("safe-name")
        info.size = 1
        info.pax_headers = {"path": "../outside"}
        archive.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="unsafe rootfs archive path"):
        normalize_rootfs_tar(source, tmp_path / "normalized.tar")


def test_duplicate_paths_after_posix_normalization_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "duplicate-normalized.tar"
    _archive(source, [("file", "usr//bin/tool", "one"), ("file", "usr/bin/tool", "two")])
    with pytest.raises(ValueError, match="duplicate rootfs archive path"):
        normalize_rootfs_tar(source, tmp_path / "normalized.tar")


def test_hardlink_to_symlink_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "hardlink-symlink.tar"
    _archive(
        source,
        [
            ("symlink", "usr/bin/target", "relative"),
            ("hardlink", "usr/bin/alias", "usr/bin/target"),
        ],
    )
    with pytest.raises(ValueError, match="hardlink target is not a regular file"):
        normalize_rootfs_tar(source, tmp_path / "normalized.tar")
