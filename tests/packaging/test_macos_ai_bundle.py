from __future__ import annotations

import importlib.util
import plistlib
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
sign_bundle = BUILDER.sign_bundle
verify_signed_bundle = BUILDER.verify_signed_bundle


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
def test_rejects_bundle_when_required_ai_resource_is_missing(tmp_path: Path, missing: str) -> None:
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


def test_signing_orders_nested_code_before_hardened_runtime_parent(tmp_path: Path) -> None:
    app = tmp_path / "WireclawAI.app"
    macos = app / "Contents/MacOS"
    frameworks = app / "Contents/Frameworks"
    macos.mkdir(parents=True)
    frameworks.mkdir()
    (app / "Contents/Info.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": BUNDLE_IDENTIFIER})
    )
    resource_dir = app / "Contents/Resources/ai"
    resource_dir.mkdir(parents=True)
    (resource_dir / "runtime-manifest.json").write_text(
        '{"files": [{"path": "macos-arm64/libggml-metal.dylib", "sha256": "old", "size_bytes": 1}, '
        '{"path": "macos-arm64/llama-server", "sha256": "old", "size_bytes": 1}]}',
        encoding="utf-8",
    )
    for path in (macos / "WireclawAI", macos / "llama-server", frameworks / "libggml-metal.dylib"):
        path.write_bytes(b"fixture")
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if "--sign" in argv and Path(argv[-1]).is_file():
            with Path(argv[-1]).open("ab") as stream:
                stream.write(b"signed")
            output = ""
        elif "-dv" in argv:
            output = "flags=0x10000(runtime)"
        elif "--entitlements" in argv:
            role = "helper" if argv[-1].endswith("llama-server") else "parent"
            entitlements = HELPER_ENTITLEMENTS if role == "helper" else PARENT_ENTITLEMENTS
            output = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML).decode()
        else:
            output = ""
        return type("Result", (), {"returncode": 0, "stdout": output, "stderr": ""})()

    sign_bundle(app, mode="adhoc", runner=runner)

    signed_targets = [call[-1] for call in calls if "--sign" in call]
    assert signed_targets == [
        str(frameworks / "libggml-metal.dylib"),
        str(macos / "llama-server"),
        str(macos / "WireclawAI"),
        str(app),
    ]
    for call in calls:
        if "--sign" in call:
            assert "--options" in call and call[call.index("--options") + 1] == "runtime"
    helper_call = next(call for call in calls if call[-1] == str(macos / "llama-server"))
    wrapper_call = next(call for call in calls if call[-1] == str(macos / "WireclawAI"))
    parent_call = next(call for call in calls if call[-1] == str(app))
    assert "--entitlements" in helper_call
    assert "--entitlements" in parent_call
    assert wrapper_call[wrapper_call.index("--identifier") + 1] == BUNDLE_IDENTIFIER
    manifest = __import__("json").loads((resource_dir / "runtime-manifest.json").read_text())
    import hashlib

    for record in manifest["files"]:
        relative = Path("Contents/Frameworks") / record["path"].removeprefix("macos-arm64/")
        if record["path"] == "macos-arm64/llama-server":
            relative = Path("Contents/MacOS/llama-server")
        payload = (app / relative).read_bytes()
        assert record["sha256"] == hashlib.sha256(payload).hexdigest()
    assert (macos / "llama-server").stat().st_mode & 0o777 == 0o555


def test_signing_rejects_missing_developer_id_and_invalid_signature(tmp_path: Path) -> None:
    app = tmp_path / "WireclawAI.app"
    macos = app / "Contents/MacOS"
    macos.mkdir(parents=True)
    (macos / "WireclawAI").write_bytes(b"fixture")
    with pytest.raises(ValueError, match="Developer ID identity required"):
        sign_bundle(app, mode="developer-id", runner=lambda *args, **kwargs: None)

    def failed_verify(argv, **kwargs):
        if "--verify" in argv:
            return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "invalid"})()
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signed_bundle(app, runner=failed_verify)


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


def test_native_isolation_qualification_has_repeatable_signed_probe_contract() -> None:
    runner = ROOT / "scripts/qualify_macos_embedded_ai.py"
    native_dir = ROOT / "tests/packaging/macos"
    assert runner.is_file(), "native signed sandbox qualification runner is missing"
    assert native_dir.is_dir(), "native sandbox fixtures are missing"
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            runner,
            ROOT / "ai/macos/WireclawAI/native_isolation_darwin_test.go",
            native_dir / "README.md",
        )
    )
    for marker in (
        "codesign",
        "network.client",
        "network.server",
        "inherit",
        "Docker",
        "host.docker.internal",
        "8767",
        "vmnetd",
    ):
        assert marker in source, f"native qualification omits {marker} contract"
