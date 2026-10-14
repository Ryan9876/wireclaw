"""Freeze an immutable Gate 9 bundle using the accepted release packager."""

import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_bundle(release: Path, archive: Path) -> None:
    """Write a normalized tar archive of the staged release directory."""
    if not release.is_dir() or archive.exists():
        raise ValueError("invalid_release_or_existing_archive")
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as bundle:
        for path in sorted(item for item in release.rglob("*") if item.is_file()):
            relative = path.relative_to(release)
            info = bundle.gettarinfo(
                str(path), arcname=(Path("wireclaw-release") / relative).as_posix()
            )
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with path.open("rb") as stream:
                bundle.addfile(info, stream)


def candidate_metadata(release: Path, archive: Path, *, require_image: bool = False) -> dict:
    metadata_path = release / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if require_image and not metadata.get("core_image_id"):
        raise ValueError("core_image_id_missing")
    metadata["bundle_sha256"] = sha256(archive)
    metadata["bundle_bytes"] = archive.stat().st_size
    return metadata


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/gate9_freeze.py OUTPUT_DIRECTORY")
    output = Path(sys.argv[1]).expanduser().resolve()
    if output.exists():
        raise SystemExit("output directory already exists")
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    if status:
        raise SystemExit("candidate freeze requires a clean, committed source tree")

    command = [sys.executable, str(ROOT / "scripts/package_release.py"), str(output)]
    result = subprocess.run(command, cwd=ROOT, env=os.environ.copy(), check=False)
    if result.returncode:
        raise SystemExit(result.returncode)

    release = output / "wireclaw-release"
    archive = output / "gate9-candidate.tar"
    archive_bundle(release, archive)
    metadata = candidate_metadata(release, archive, require_image=True)
    metadata["candidate_archive"] = archive.name
    (release / "gate9-candidate-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(release)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(str(error)) from None
