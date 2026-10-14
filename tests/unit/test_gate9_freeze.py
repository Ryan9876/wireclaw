import hashlib
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from gate9_freeze import archive_bundle, candidate_metadata


def test_archive_bundle_contains_release_and_has_stable_member_order(tmp_path):
    release = tmp_path / "wireclaw-release"
    release.mkdir()
    (release / "release-metadata.json").write_text('{"source_sha":"abc"}\n')
    (release / "core-image.tar").write_bytes(b"image")
    archive = tmp_path / "candidate.tar"

    archive_bundle(release, archive)

    with tarfile.open(archive) as bundle:
        assert bundle.getnames() == [
            "wireclaw-release/core-image.tar",
            "wireclaw-release/release-metadata.json",
        ]
        metadata = json.load(bundle.extractfile("wireclaw-release/release-metadata.json"))
        assert metadata["source_sha"] == "abc"


def test_candidate_metadata_names_archive_and_release_hashes(tmp_path):
    release = tmp_path / "wireclaw-release"
    release.mkdir()
    (release / "release-metadata.json").write_text('{"source_sha":"abc"}\n')
    archive = tmp_path / "candidate.tar"
    archive.write_bytes(b"candidate")

    result = candidate_metadata(release, archive)

    assert result["source_sha"] == "abc"
    assert result["bundle_sha256"] == hashlib.sha256(b"candidate").hexdigest()


def test_candidate_metadata_rejects_missing_image_identity(tmp_path):
    release = tmp_path / "wireclaw-release"
    release.mkdir()
    (release / "release-metadata.json").write_text('{"source_sha":"abc"}\n')
    archive = tmp_path / "candidate.tar"
    archive.write_bytes(b"candidate")

    with pytest.raises(ValueError, match="core_image_id"):
        candidate_metadata(release, archive, require_image=True)
