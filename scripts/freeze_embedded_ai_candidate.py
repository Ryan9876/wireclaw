"""Create a deterministic archive and identity record for a staged release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("candidate_symlink_invalid")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def freeze_candidate(bundle: Path, archive: Path) -> dict:
    bundle = bundle.expanduser()
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("candidate_bundle_invalid")
    bundle = bundle.resolve(strict=True)
    archive = archive.expanduser()
    if archive.is_symlink():
        raise ValueError("candidate_archive_symlink_invalid")
    archive = archive.resolve()
    if archive == bundle or bundle in archive.parents:
        raise ValueError("candidate_archive_inside_bundle")
    if archive.exists():
        raise ValueError("candidate_archive_exists")
    metadata_path = bundle / "release-metadata.json"
    try:
        release_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ValueError("candidate_release_metadata_invalid") from None
    source_sha = release_metadata.get("source_sha")
    embedded_ai = release_metadata.get("embedded_ai")
    if (
        not isinstance(source_sha, str)
        or len(source_sha) != 40
        or any(char not in "0123456789abcdef" for char in source_sha)
        or not isinstance(embedded_ai, dict)
    ):
        raise ValueError("candidate_release_metadata_invalid")
    archive.parent.mkdir(parents=True, exist_ok=True)
    paths = [bundle, *sorted(bundle.rglob("*"), key=lambda p: p.relative_to(bundle).as_posix())]
    for path in paths:
        if path.is_symlink():
            raise ValueError("candidate_symlink_invalid")
        if not path.is_dir() and not path.is_file():
            raise ValueError("candidate_file_type_invalid")
    fd, temporary_name = tempfile.mkstemp(prefix=".wireclaw-candidate-", dir=archive.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, mode="w", format=tarfile.PAX_FORMAT) as output:
            for path in paths:
                name = "wireclaw-release" + (
                    "/" + path.relative_to(bundle).as_posix() if path != bundle else ""
                )
                info = output.gettarinfo(str(path), arcname=name)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.pax_headers = {}
                if path.is_dir():
                    info.mode = 0o755
                    output.addfile(info)
                else:
                    info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
                    with path.open("rb") as stream:
                        output.addfile(info, stream)
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)
    result = {
        "source_sha": source_sha,
        "bundle_tree_sha256": tree_sha256(bundle),
        "archive_sha256": sha256(archive),
        "archive_size_bytes": archive.stat().st_size,
        "embedded_ai": embedded_ai,
        "frozen": True,
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args(argv)
    result = freeze_candidate(args.bundle, args.archive)
    if args.metadata:
        args.metadata.parent.mkdir(parents=True, exist_ok=True)
        args.metadata.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from None
