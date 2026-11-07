from __future__ import annotations

import argparse
import copy
import hashlib
import os
import posixpath
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

SOURCE_DATE_EPOCH = 1_735_689_600

_VOLATILE_PATHS = {
    "etc/hosts",
    "etc/hostname",
    "etc/machine-id",
    "etc/resolv.conf",
    "var/lib/dbus/machine-id",
    "var/lib/systemd/random-seed",
    # ldconfig's auxiliary cache embeds build-specific state and is regenerated when needed.
    "var/cache/ldconfig/aux-cache",
    "var/log/alternatives.log",
    "var/log/dpkg.log",
}
_VOLATILE_PREFIXES = (
    "tmp/",
    "var/cache/apt/archives/",
    "var/lib/apt/lists/",
    "var/log/apt/",
    "var/tmp/",
)
_VOLATILE_PAX_HEADERS = {
    "atime",
    "ctime",
    "mtime",
    "path",
    "linkpath",
    "size",
    "uid",
    "gid",
    "uname",
    "gname",
    "hdrcharset",
    "LIBARCHIVE.creationtime",
    "SCHILY.ino",
    "SCHILY.nlink",
    "SCHILY.devmajor",
    "SCHILY.devminor",
}


def _is_volatile_path(name: str) -> bool:
    return name in _VOLATILE_PATHS or any(name.startswith(prefix) for prefix in _VOLATILE_PREFIXES)


def _normalized_member(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
    member = copy.copy(member)
    member.pax_headers = dict(member.pax_headers)
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe rootfs archive path: {member.name}")
    name = path.as_posix()
    if name in {"", "."}:
        return None
    if member.isdev() or member.isfifo():
        raise ValueError(f"unsupported special file in rootfs archive: {name}")
    if any(
        key.startswith(("SCHILY.xattr.", "SCHILY.acl.", "LIBARCHIVE.xattr.", "LIBARCHIVE.acl."))
        for key in member.pax_headers
    ):
        raise ValueError(f"unsupported extended metadata in rootfs archive: {name}")

    if member.issym():
        target = PurePosixPath(member.linkname)
        if not member.linkname or (target.is_absolute() and ".." in target.parts):
            raise ValueError(f"unsafe symlink in rootfs archive: {name}")
        if not target.is_absolute():
            resolved = posixpath.normpath(posixpath.join(path.parent.as_posix(), target.as_posix()))
            if resolved == ".." or resolved.startswith("../"):
                raise ValueError(f"unsafe symlink in rootfs archive: {name}")
    elif member.islnk():
        if _is_volatile_path(name):
            raise ValueError(f"hardlink at volatile rootfs path is unsupported: {name}")
        target = PurePosixPath(member.linkname)
        if target.is_absolute() or ".." in target.parts:
            raise ValueError(f"unsafe hardlink in rootfs archive: {name}")
        member.linkname = target.as_posix()
    elif not (member.isdir() or member.isfile()):
        raise ValueError(f"unsupported rootfs archive entry type: {name}")

    if _is_volatile_path(name):
        return None

    member.name = name
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    member.mtime = SOURCE_DATE_EPOCH
    member.pax_headers = {
        key: member.pax_headers[key]
        for key in sorted(member.pax_headers)
        if key not in _VOLATILE_PAX_HEADERS
    }
    if member.isdir() or member.issym() or member.islnk():
        member.size = 0
    return member


def _resolve_hardlink_target(
    name: str,
    entries: dict[str, tuple[tarfile.TarInfo, tarfile.TarInfo]],
    seen: set[str] | None = None,
) -> tuple[tarfile.TarInfo, tarfile.TarInfo]:
    visited = set() if seen is None else seen
    if name in visited:
        raise ValueError(f"cyclic hardlink in rootfs archive: {name}")
    visited.add(name)
    try:
        original, member = entries[name]
    except KeyError as error:
        raise ValueError(f"missing hardlink target in rootfs archive: {name}") from error
    if member.islnk():
        return _resolve_hardlink_target(member.linkname, entries, visited)
    if not member.isfile():
        raise ValueError(f"hardlink target is not a regular file: {name}")
    return original, member


def normalize_rootfs_tar(source_path: Path, output_path: Path) -> tuple[str, int]:
    """Write a stable root-owned OCI rootfs tar and return its SHA-256 and entry count.

    Hardlinks are materialized as regular files because this immutable W2 rootfs
    is read-only; inode topology is not part of the guest contract.
    """
    source = Path(source_path)
    output = Path(output_path)
    if not source.is_file():
        raise ValueError("source rootfs tar does not exist")
    if source.resolve() == output.resolve():
        raise ValueError("source and normalized rootfs paths must differ")
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(source, "r:*") as incoming:
            entries: dict[str, tuple[tarfile.TarInfo, tarfile.TarInfo]] = {}
            seen: set[str] = set()
            for original in incoming.getmembers():
                member = _normalized_member(original)
                if member is None:
                    continue
                if member.name in seen:
                    raise ValueError(f"duplicate rootfs archive path: {member.name}")
                seen.add(member.name)
                entries[member.name] = (original, member)

            normalized: list[tuple[tarfile.TarInfo, tarfile.TarInfo]] = []
            for original, member in entries.values():
                content_original = original
                if member.islnk():
                    content_original, target = _resolve_hardlink_target(member.linkname, entries)
                    merged_pax_headers = dict(target.pax_headers)
                    for key, value in member.pax_headers.items():
                        if key in merged_pax_headers and merged_pax_headers[key] != value:
                            raise ValueError(
                                f"inconsistent hardlink metadata for rootfs path: {member.name}"
                            )
                        merged_pax_headers[key] = value
                    target.pax_headers = dict(sorted(merged_pax_headers.items()))
                    member.type = tarfile.REGTYPE
                    member.linkname = ""
                    member.size = target.size
                    member.mode = target.mode
                    member.pax_headers = dict(target.pax_headers)
                normalized.append((content_original, member))

            def order(item: tuple[tarfile.TarInfo, tarfile.TarInfo]) -> tuple[int, str]:
                member = item[1]
                rank = 0 if member.isdir() else 1 if member.isfile() else 2 if member.issym() else 3
                return rank, member.name

            normalized.sort(key=order)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=output.parent,
                prefix=f".{output.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
            try:
                with tarfile.open(temporary_path, "w", format=tarfile.PAX_FORMAT) as outgoing:
                    for original, member in normalized:
                        if member.isfile():
                            content: BinaryIO | None = incoming.extractfile(original)
                            if content is None:
                                raise ValueError(
                                    f"unable to read rootfs archive entry: {member.name}"
                                )
                            with content:
                                outgoing.addfile(member, content)
                        else:
                            outgoing.addfile(member)
                with temporary_path.open("rb") as normalized_file:
                    digest = hashlib.file_digest(normalized_file, "sha256").hexdigest()
                os.replace(temporary_path, output)
            finally:
                temporary_path.unlink(missing_ok=True)
    except (tarfile.TarError, OSError) as error:
        raise ValueError(f"unable to normalize rootfs archive: {error}") from error

    return digest, len(normalized)


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize an OCI rootfs tar deterministically.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest, count = normalize_rootfs_tar(args.input, args.output)
    print(f"normalized_rootfs_sha256={digest}")
    print(f"normalized_rootfs_entries={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
