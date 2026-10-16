from __future__ import annotations

import plistlib
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_macos_ai_app", ROOT / "scripts/build_macos_ai_app.py"
)
if SPEC is None or SPEC.loader is None:
    raise AssertionError("bundle builder module cannot be loaded")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
BUNDLE_IDENTIFIER = BUILDER.BUNDLE_IDENTIFIER
HELPER_ENTITLEMENTS = BUILDER.HELPER_ENTITLEMENTS
PARENT_ENTITLEMENTS = BUILDER.PARENT_ENTITLEMENTS
assemble_bundle = BUILDER.assemble_bundle
validate_entitlements = BUILDER.validate_entitlements


def test_assembles_deterministic_bundle_layout(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "runtime").mkdir(parents=True)
    (inputs / "resources" / "ai").mkdir(parents=True)
    for name, contents in (
        ("WireclawAI", "wrapper"),
        ("llama-server", "helper"),
        ("libggml-metal.dylib", "metal"),
    ):
        (inputs / ("runtime" if name != "WireclawAI" else "") / name).write_text(contents)
    for name in ("model.gguf", "runtime-manifest.json", "model-manifest.json"):
        (inputs / "resources" / "ai" / name).write_text(name)

    app = tmp_path / "stage" / "WireclawAI.app"
    assemble_bundle(
        app,
        wrapper=inputs / "WireclawAI",
        helper=inputs / "runtime" / "llama-server",
        runtime_dir=inputs / "runtime",
        resources_dir=inputs / "resources",
    )

    assert (app / "Contents/MacOS/WireclawAI").read_text() == "wrapper"
    assert (app / "Contents/MacOS/llama-server").read_text() == "helper"
    assert (app / "Contents/Frameworks/libggml-metal.dylib").read_text() == "metal"
    for name in ("model.gguf", "runtime-manifest.json", "model-manifest.json"):
        assert (app / "Contents/Resources/ai" / name).is_file()
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == BUNDLE_IDENTIFIER
    assert info["CFBundleExecutable"] == "WireclawAI"
    assert not (app / "Contents/Resources/ai/model.gguf").stat().st_mode & 0o222


@pytest.mark.parametrize(
    "missing",
    ("model.gguf", "runtime-manifest.json", "model-manifest.json"),
)
def test_rejects_bundle_when_required_ai_resource_is_missing(
    tmp_path: Path, missing: str
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "runtime").mkdir(parents=True)
    (inputs / "resources" / "ai").mkdir(parents=True)
    (inputs / "WireclawAI").write_text("wrapper")
    (inputs / "runtime" / "llama-server").write_text("helper")
    for name in ("model.gguf", "runtime-manifest.json", "model-manifest.json"):
        if name != missing:
            (inputs / "resources" / "ai" / name).write_text(name)

    app = tmp_path / "stage" / "WireclawAI.app"
    with pytest.raises(ValueError, match="required AI resource"):
        assemble_bundle(
            app,
            wrapper=inputs / "WireclawAI",
            helper=inputs / "runtime" / "llama-server",
            runtime_dir=inputs / "runtime",
            resources_dir=inputs / "resources",
        )
    assert not app.exists()


def test_rejects_symlinked_ai_resource_directory_before_bundle_replacement(
    tmp_path: Path,
) -> None:
    inputs = tmp_path / "inputs"
    (inputs / "runtime").mkdir(parents=True)
    (inputs / "resources").mkdir()
    (inputs / "outside-ai").mkdir()
    (inputs / "WireclawAI").write_text("wrapper")
    (inputs / "runtime" / "llama-server").write_text("helper")
    for name in ("model.gguf", "runtime-manifest.json", "model-manifest.json"):
        (inputs / "outside-ai" / name).write_text(name)
    (inputs / "resources" / "ai").symlink_to(inputs / "outside-ai", target_is_directory=True)

    app = tmp_path / "stage" / "WireclawAI.app"
    app.mkdir(parents=True)
    marker = app / "preserve-me"
    marker.write_text("existing bundle")
    with pytest.raises(ValueError, match="resource input contains a symlink"):
        assemble_bundle(
            app,
            wrapper=inputs / "WireclawAI",
            helper=inputs / "runtime" / "llama-server",
            runtime_dir=inputs / "runtime",
            resources_dir=inputs / "resources",
        )
    assert marker.read_text() == "existing bundle"


def test_entitlement_templates_are_exact() -> None:
    parent = plistlib.loads((ROOT / "ai/macos/parent.entitlements.plist").read_bytes())
    helper = plistlib.loads((ROOT / "ai/macos/helper.entitlements.plist").read_bytes())
    assert parent == PARENT_ENTITLEMENTS
    assert helper == HELPER_ENTITLEMENTS
    validate_entitlements("parent", parent)
    validate_entitlements("helper", helper)


def test_wrapper_private_key_state_uses_fixed_app_container() -> None:
    key_source = (ROOT / "ai/macos/WireclawAI/key.go").read_text()
    assert f'const bundleID = "{BUNDLE_IDENTIFIER}"' in key_source
    assert '"Library", "Containers", bundleID, "Data"' in key_source
    assert 'filepath.Join(dir, "api-key")' in key_source


@pytest.mark.parametrize(
    "role,extra",
    [
        ("parent", {"com.apple.security.network.client": True}),
        ("parent", {"com.apple.security.files.user-selected.read-only": True}),
        ("parent", {"com.apple.security.files.all": True}),
        ("parent", {"com.apple.security.application-groups": ["group.example"]}),
        ("helper", {"com.apple.security.network.client": True}),
        ("helper", {"com.apple.security.files.user-selected.read-write": True}),
        ("helper", {"com.apple.security.files.downloads.read-write": True}),
        ("helper", {"unexpected.entitlement": True}),
    ],
)
def test_rejects_extra_or_overbroad_entitlements(role: str, extra: dict) -> None:
    expected = PARENT_ENTITLEMENTS if role == "parent" else HELPER_ENTITLEMENTS
    with pytest.raises(ValueError):
        validate_entitlements(role, expected | extra)

