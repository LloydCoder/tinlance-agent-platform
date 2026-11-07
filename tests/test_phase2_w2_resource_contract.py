from __future__ import annotations

import io
import stat
import tarfile
from pathlib import Path

import pytest
from scripts.smoke_firecracker_guest_boot import (
    _rootfs_tar_filter,
    extract_w2_rootfs_tar,
)
from scripts.smoke_firecracker_jailer import build_jailer_command


def _write_single_file_archive(
    archive_path: Path,
    *,
    name: str = "usr/bin/tool",
    mode: int = 0o755,
    pax_headers: dict[str, str] | None = None,
) -> None:
    with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.mode = mode
        member.size = 1
        member.pax_headers = pax_headers or {}
        archive.addfile(member, io.BytesIO(b"x"))


def test_w2_jailer_cgroup_limits_match_two_vcpu_two_gib_guest() -> None:
    command = build_jailer_command(
        jailer_binary="/usr/local/libexec/firecracker/1.17.0/jailer",
        firecracker_binary="/usr/local/libexec/firecracker/1.17.0/firecracker",
        jailer_id="fc-w2-421-1",
        uid=987,
        gid=987,
        chroot_base_dir="/srv/tinlance-jailer-w2",
        profile="W2",
    )

    cgroups = [
        command[index + 1] for index, value in enumerate(command[:-1]) if value == "--cgroup"
    ]
    assert cgroups == [
        "memory.max=3221225472",
        "pids.max=128",
        "cpu.max=200000 100000",
    ]


def test_w2_rootfs_extractor_rejects_libarchive_acl_metadata(tmp_path: Path) -> None:
    archive = tmp_path / "acl.tar"
    _write_single_file_archive(
        archive,
        pax_headers={"LIBARCHIVE.acl.access": "user::rwx,group::r-x,other::r-x"},
    )

    with pytest.raises(ValueError, match="extended metadata"):
        extract_w2_rootfs_tar(archive, tmp_path / "rootfs")


def test_w2_rootfs_filter_strips_setuid_and_setgid_bits(tmp_path: Path) -> None:
    member = tarfile.TarInfo("usr/bin/tool")
    member.mode = 0o6755

    filtered = _rootfs_tar_filter(member, str(tmp_path / "rootfs"))

    assert filtered.mode is not None
    assert filtered.mode & 0o6000 == 0


def test_w2_rootfs_extractor_rejects_duplicate_canonical_paths(tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.tar"
    with tarfile.open(archive, "w") as handle:
        for name, payload in (("usr/bin/tool", b"a"), ("usr//bin/tool", b"b")):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            handle.addfile(member, io.BytesIO(payload))

    with pytest.raises(ValueError, match="duplicate rootfs archive path"):
        extract_w2_rootfs_tar(archive, tmp_path / "rootfs")


def test_w2_rootfs_extractor_ignores_archive_root_directory_metadata(tmp_path: Path) -> None:
    archive = tmp_path / "root-entry.tar"
    with tarfile.open(archive, "w") as handle:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        root.mode = 0o000
        handle.addfile(root)
        member = tarfile.TarInfo("usr/bin/tool")
        member.size = 1
        handle.addfile(member, io.BytesIO(b"x"))

    destination = tmp_path / "rootfs"
    destination.mkdir()
    destination.chmod(0o755)
    extract_w2_rootfs_tar(archive, destination)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o755
    assert (destination / "usr/bin/tool").read_bytes() == b"x"
