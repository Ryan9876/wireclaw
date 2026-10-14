import hashlib
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from gate9_freeze import archive_bundle, candidate_metadata, finalize_release


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


def test_finalize_release_seals_metadata_without_including_archive_itself(tmp_path):
    release = tmp_path / "wireclaw-release"
    release.mkdir()
    image = release / "core-image.tar"
    image.write_bytes(b"image archive")
    bridge = release / "host-bridge/macos/wireclaw-host-bridge-darwin-arm64"
    bridge.parent.mkdir(parents=True)
    bridge.write_bytes(b"bridge")
    image_id = "sha256:image"
    (release / "core-image-id").write_text(f"{image_id}\n")
    (release / "release-metadata.json").write_text(
        json.dumps(
            {
                "source_sha": "abc",
                "core_image_id": image_id,
                "core_image_archive_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                "bridge_binary": bridge.name,
                "bridge_sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
            }
        )
        + "\n"
    )

    metadata = finalize_release(release)

    archive = tmp_path / "gate9-candidate.tar"
    assert metadata["candidate_archive"] == archive.name
    assert metadata["bundle_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    with tarfile.open(archive) as bundle:
        assert "wireclaw-release/gate9-candidate-metadata.json" not in bundle.getnames()
        assert "wireclaw-release/core-image.tar" in bundle.getnames()
    saved = json.loads((release / "gate9-candidate-metadata.json").read_text())
    assert saved == metadata
