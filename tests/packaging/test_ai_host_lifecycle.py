"""Trusted macOS launcher lifecycle primitives; signal tests use injected OS observations."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ai_lifecycle", ROOT / "launch/macos/ai_lifecycle.py")


@pytest.fixture
def lifecycle():
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    return module


@pytest.fixture
def identity(tmp_path):
    helper = tmp_path / "WireclawAI.app/Contents/MacOS/llama-server"
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"fixed helper")
    return {
        "pid": 4321,
        "process_start": "123:456",
        "executable": str(helper),
        "executable_sha256": __import__("hashlib").sha256(helper.read_bytes()).hexdigest(),
    }


def test_receipt_is_private_bounded_and_nonsecret(lifecycle, identity, tmp_path):
    path = tmp_path / "host/run/ai-receipt.json"
    lifecycle.write_receipt(path, identity, identity["executable"])
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(path.read_bytes()) < 1024
    assert set(json.loads(path.read_text())) == set(identity)
    assert "api-key" not in path.read_text() and "bridge" not in path.read_text()
    assert lifecycle.read_receipt(path, identity["executable"]) == identity
    assert "Library/Containers" not in str(path)


def test_receipt_missing_symlink_replaced_or_malformed_fails_closed(lifecycle, identity, tmp_path):
    path = tmp_path / "ai-receipt.json"
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.read_receipt(path, identity["executable"])
    path.symlink_to(identity["executable"])
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.read_receipt(path, identity["executable"])
    path.unlink()
    path.write_text(json.dumps(identity))
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.read_receipt(path, identity["executable"])
    path.chmod(0o600)
    path.write_bytes(b"x" * 2048)
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.read_receipt(path, identity["executable"])
    path.write_text(json.dumps(identity)[:-1] + ',"pid":9999}')
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.read_receipt(path, identity["executable"])


def test_verified_term_and_fresh_kill_reverification(lifecycle, identity, tmp_path):
    path = tmp_path / "ai-receipt.json"
    lifecycle.write_receipt(path, identity, identity["executable"])
    signals = []
    probes = iter([identity, identity, identity, None])
    lifecycle.stop_verified(
        path,
        identity["executable"],
        inspect=lambda pid: next(probes),
        signal=lambda pid, sig: signals.append((pid, sig)),
        wait=lambda _: None,
        attempts=1,
    )
    assert [sig for _, sig in signals] == ["TERM", "KILL"]


@pytest.mark.parametrize("change", ["pid", "process_start", "executable", "executable_sha256"])
def test_mismatch_never_signals(lifecycle, identity, tmp_path, change):
    path = tmp_path / "ai-receipt.json"
    lifecycle.write_receipt(path, identity, identity["executable"])
    changed = dict(identity)
    changed[change] = 9999 if change == "pid" else "changed"
    signals = []
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.stop_verified(
            path,
            identity["executable"],
            inspect=lambda _: changed,
            signal=lambda *args: signals.append(args),
            wait=lambda _: None,
        )
    assert signals == []


def test_identity_change_between_term_and_kill_blocks_kill(lifecycle, identity, tmp_path):
    path = tmp_path / "ai-receipt.json"
    lifecycle.write_receipt(path, identity, identity["executable"])
    changed = dict(identity, process_start="999:1")
    probes = iter([identity, changed, changed])
    signals = []
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.stop_verified(
            path,
            identity["executable"],
            inspect=lambda _: next(probes),
            signal=lambda pid, sig: signals.append(sig),
            wait=lambda _: None,
            attempts=1,
        )
    assert signals == ["TERM"]


def test_missing_receipt_recovery_requires_independent_fixed_helper_check(
    lifecycle, identity, tmp_path
):
    path = tmp_path / "ai-receipt.json"
    status = dict(identity, state="running")
    signals = []
    lifecycle.recover_receipt(path, status, identity["executable"], inspect=lambda _: identity)
    assert lifecycle.read_receipt(path, identity["executable"]) == identity
    path.unlink()
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.recover_receipt(
            path,
            status,
            identity["executable"],
            inspect=lambda _: dict(identity, process_start="changed"),
        )
    assert not path.exists() and signals == []


def test_stale_regular_receipt_recovers_only_with_fresh_fixed_helper_match(
    lifecycle, identity, tmp_path
):
    path = tmp_path / "ai-receipt.json"
    path.write_text("stale")
    path.chmod(0o600)
    status = dict(identity, state="running")
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.recover_receipt(
            path,
            status,
            identity["executable"],
            inspect=lambda _: dict(identity, executable_sha256="0" * 64),
        )
    assert path.read_text() == "stale"
    lifecycle.recover_receipt(path, status, identity["executable"], inspect=lambda _: identity)
    assert lifecycle.read_receipt(path, identity["executable"]) == identity


def test_receipt_swap_between_lstat_and_open_is_rejected(
    lifecycle, identity, tmp_path, monkeypatch
):
    path = tmp_path / "ai-receipt.json"
    lifecycle.write_receipt(path, identity, identity["executable"])
    replacement = tmp_path / "same-content.json"
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    original_open = os.open

    def swap_then_open(target, flags, *args, **kwargs):
        if Path(target) == path:
            os.replace(replacement, path)
        return original_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(lifecycle.os, "open", swap_then_open)
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.read_receipt(path, identity["executable"])


def test_identical_receipt_replacement_after_term_blocks_kill(lifecycle, identity, tmp_path):
    path = tmp_path / "ai-receipt.json"
    lifecycle.write_receipt(path, identity, identity["executable"])
    signals = []

    def replace_during_wait(_):
        replacement = tmp_path / "replacement.json"
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, path)

    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.stop_verified(
            path,
            identity["executable"],
            inspect=lambda _: identity,
            signal=lambda _, sig: signals.append(sig),
            wait=replace_during_wait,
            attempts=1,
        )
    assert signals == ["TERM"]
