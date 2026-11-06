from __future__ import annotations

import argparse
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


def _is_volatile_path(name: str) -> bool:
    return name in _VOLATILE_PATHS or any(name.startswith(prefix) for prefix in _VOLATILE_PREFIXES)


def _normalized_member(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe rootfs archive path: {member.name}")
    name = path.as_posix()
    if name in {"", "."}:
        return None
    if _is_volatile_path(name):
        return None
    if member.isdev() or member.isfifo():
        raise ValueError(f"unsupported special file in rootfs archive: {name}")

    if member.issym():
        target = PurePosixPath(member.linkname)
        if not member.linkname or (target.is_absolute() and ".." in target.parts):
            raise ValueError(f"unsafe symlink in rootfs archive: {name}")
        if not target.is_absolute():
            resolved = posixpath.normpath(posixpath.join(path.parent.as_posix(), target.as_posix()))
            if resolved == ".." or resolved.startswith("../"):
                raise ValueError(f"unsafe symlink in rootfs archive: {name}")
    elif member.islnk():
        target = PurePosixPath(member.linkname)
        if target.is_absolute() or ".." in target.parts:
            raise ValueError(f"unsafe hardlink in rootfs archive: {name}")
        member.linkname = target.as_posix()
    elif not (member.isdir() or member.isfile()):
        raise ValueError(f"unsupported rootfs archive entry type: {name}")

    member.name = name
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    member.mtime = SOURCE_DATE_EPOCH
    member.pax_headers = {}
    if member.isdir() or member.issym() or member.islnk():
        member.size = 0
    return member


def normalize_rootfs_tar(source_path: Path, output_path: Path) -> tuple[str, int]:
    """Write a stable, root-owned OCI rootfs tar and return its SHA-256 and entry count."""
    source = Path(source_path)
    output = Path(output_path)
    if not source.is_file():
        raise ValueError("source rootfs tar does not exist")
    if source.resolve() == output.resolve():
        raise ValueError("source and normalized rootfs paths must differ")
    output.parent.mkdir(parents=True, exist_ok=True)

    normalized: list[tuple[tarfile.TarInfo, tarfile.TarInfo]] = []
    seen: set[str] = set()
    try:
        with tarfile.open(source, "r:*") as incoming:
            for original in incoming.getmembers():
                member = _normalized_member(original)
                if member is None:
                    continue
                if member.name in seen:
                    raise ValueError(f"duplicate rootfs archive path: {member.name}")
                seen.add(member.name)
                normalized.append((original, member))

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
                                raise ValueError(f"unable to read rootfs archive entry: {member.name}")
                            with content:
                                outgoing.addfile(member, content)
                        else:
                            outgoing.addfile(member)
                with temporary_path.open("rb") as normalized_file:\n                    digest = hashlib.file_digest(normalized_file, "sha256").hexdigest()
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
