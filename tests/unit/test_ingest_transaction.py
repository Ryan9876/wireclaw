import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from wireclaw_analyzer import AnalyzerError, Limits
from wireclaw_analyzer.storage import Store


def prepared(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"private synthetic capture")
    identity = hashlib.sha256(source.read_bytes()).hexdigest()
    store = Store(tmp_path, Limits())
    return store, source, identity


@pytest.mark.parametrize(
    "failure", ["chmod", "persist", "persist_after_write", "replace", "staging_unlink"]
)
def test_post_publication_failure_rolls_back_new_original(tmp_path, failure):
    store, source, identity = prepared(tmp_path)
    unlink = Path.unlink
    persist = store.persist
    failed_once = False

    def fail_staging_unlink(path, *args, **kwargs):
        nonlocal failed_once
        if path.parent == tmp_path / "work" and not failed_once:
            failed_once = True
            raise OSError("staging unlink failure")
        return unlink(path, *args, **kwargs)

    def fail_after_persist(*args, **kwargs):
        persist(*args, **kwargs)
        raise OSError("identity post-publication failure")

    patches = {
        "chmod": patch.object(Path, "chmod", side_effect=OSError("protection failure")),
        "persist": patch.object(store, "persist", side_effect=OSError("identity failure")),
        "persist_after_write": patch.object(store, "persist", side_effect=fail_after_persist),
        "replace": patch(
            "wireclaw_analyzer.storage.os.replace", side_effect=OSError("persist replace failure")
        ),
        "staging_unlink": patch.object(Path, "unlink", new=fail_staging_unlink),
    }
    with patches[failure], pytest.raises(AnalyzerError, match="capture_storage_failure"):
        store.ingest(source, lambda path: None)
    assert not list(tmp_path.glob("cases/*/original/capture"))
    assert not list((tmp_path / "work").iterdir())
    assert not list((tmp_path / "cases" / identity).rglob("capture-identity.json"))
    assert not list((tmp_path / "cases" / identity).rglob("tmp*"))
    assert source.read_bytes() == b"private synthetic capture"


@pytest.mark.parametrize("failure", ["persist", "staging_unlink"])
def test_duplicate_ingest_failure_preserves_existing_original(tmp_path, failure):
    store, source, identity = prepared(tmp_path)
    assert store.ingest(source, lambda path: None) == identity
    original = store.capture_path(identity)
    before = original.read_bytes(), original.stat().st_mode
    manifest = tmp_path / "cases" / identity / "normalized/capture-identity.json"
    manifest_before = manifest.read_bytes()
    unlink = Path.unlink
    failed_once = False

    def fail_staging_unlink(path, *args, **kwargs):
        nonlocal failed_once
        if path.parent == tmp_path / "work" and not failed_once:
            failed_once = True
            raise OSError("staging unlink failure")
        return unlink(path, *args, **kwargs)

    failure_patch = (
        patch.object(store, "persist", side_effect=OSError("identity failure"))
        if failure == "persist"
        else patch.object(Path, "unlink", new=fail_staging_unlink)
    )
    with failure_patch, pytest.raises(AnalyzerError, match="capture_storage_failure"):
        store.ingest(source, lambda path: None)
    assert (original.read_bytes(), original.stat().st_mode) == before
    assert manifest.read_bytes() == manifest_before
    assert store.verify(identity) == original
    assert not list((tmp_path / "work").iterdir())
    assert store.ingest(source, lambda path: None) == identity


def test_duplicate_does_not_reprotect_existing_original(tmp_path):
    store, source, identity = prepared(tmp_path)
    store.ingest(source, lambda path: None)
    with patch.object(Path, "chmod", side_effect=OSError("protection failure")):
        assert store.ingest(source, lambda path: None) == identity
    assert store.verify(identity).read_bytes() == source.read_bytes()


def test_publication_race_does_not_claim_existing_original(tmp_path):
    store, source, identity = prepared(tmp_path)
    link = os.link

    def publish_first(*args):
        link(*args)
        raise FileExistsError("another ingest published first")

    with (
        patch("wireclaw_analyzer.storage.os.link", side_effect=publish_first),
        patch.object(store, "persist", side_effect=OSError("identity failure")),
        pytest.raises(AnalyzerError, match="capture_storage_failure"),
    ):
        store.ingest(source, lambda path: None)
    assert store.verify(identity).read_bytes() == source.read_bytes()
    assert not list((tmp_path / "work").iterdir())


def test_rollback_clears_windows_readonly_protection(tmp_path):
    store, source, identity = prepared(tmp_path)
    unlink = Path.unlink
    target = tmp_path / "cases" / identity / "original/capture"

    def windows_unlink(path, *args, **kwargs):
        if path == target and path.exists() and not path.stat().st_mode & 0o222:
            raise PermissionError("read-only file")
        return unlink(path, *args, **kwargs)

    with (
        patch.object(store, "persist", side_effect=OSError("identity failure")),
        patch.object(Path, "unlink", new=windows_unlink),
        pytest.raises(AnalyzerError, match="capture_storage_failure"),
    ):
        store.ingest(source, lambda path: None)
    assert not target.exists()
    assert not list((tmp_path / "work").iterdir())


def test_cleanup_denial_is_explicit_and_still_removes_owned_original(tmp_path):
    store, source, identity = prepared(tmp_path)
    unlink = Path.unlink

    def deny_staging_unlink(path, *args, **kwargs):
        if path.parent == tmp_path / "work":
            raise OSError("filesystem denies cleanup")
        return unlink(path, *args, **kwargs)

    with (
        patch.object(Path, "unlink", new=deny_staging_unlink),
        pytest.raises(AnalyzerError, match="capture_cleanup_failure"),
    ):
        store.ingest(source, lambda path: None)
    assert not (tmp_path / "cases" / identity / "original/capture").exists()
    # Remove the intentionally inaccessible staging file once the simulated denial ends.
    for path in (tmp_path / "work").iterdir():
        path.unlink()
