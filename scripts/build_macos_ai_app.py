"""Assemble the fixed WireclawAI macOS application bundle layout."""

from __future__ import annotations

import plistlib
import shutil
from pathlib import Path

BUNDLE_IDENTIFIER = "com.wireclaw.WireclawAI"
PARENT_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.network.server": True,
}
HELPER_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.inherit": True,
}
REQUIRED_AI_RESOURCES = (
    "ai/model.gguf",
    "ai/runtime-manifest.json",
    "ai/model-manifest.json",
)


def validate_entitlements(role: str, entitlements: dict) -> None:
    """Reject every capability outside the reviewed parent/helper contract."""
    expected = {"parent": PARENT_ENTITLEMENTS, "helper": HELPER_ENTITLEMENTS}.get(role)
    if expected is None:
        raise ValueError("unknown entitlement role")
    if entitlements != expected:
        raise ValueError(f"{role} entitlements do not match the approved exact set")


def _copy_file(source: Path, destination: Path, executable: bool = False) -> None:
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"required bundle input is missing or unsafe: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o555 if executable else 0o444)


def _copy_runtime_tree(runtime_dir: Path, frameworks: Path, helper: Path) -> None:
    for source in sorted(runtime_dir.rglob("*")):
        if source.is_symlink():
            raise ValueError("runtime input contains a symlink")
        if not source.is_file() or source == helper:
            continue
        relative = source.relative_to(runtime_dir)
        _copy_file(source, frameworks / relative, executable=bool(source.stat().st_mode & 0o111))


def assemble_bundle(
    app: Path,
    *,
    wrapper: Path,
    helper: Path,
    runtime_dir: Path,
    resources_dir: Path,
) -> Path:
    """Create a deterministic, unsigned staging bundle at ``app``.

    Signing is deliberately left to the packaging/release step. The runtime
    tree's helper is placed in MacOS and all other signed runtime code in
    Frameworks; model/manifests are copied read-only under Resources.
    """
    if app.name != "WireclawAI.app" or app.is_symlink():
        raise ValueError("bundle destination must be a non-symlink WireclawAI.app")
    for relative in REQUIRED_AI_RESOURCES:
        source = resources_dir / relative
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"required AI resource is missing or unsafe: {relative}")
    if app.exists():
        for existing in app.rglob("*"):
            if existing.is_dir() and not existing.is_symlink():
                existing.chmod(0o755)
            elif not existing.is_symlink():
                existing.chmod(0o644)
        app.chmod(0o755)
        shutil.rmtree(app)
    contents = app / "Contents"
    macos = contents / "MacOS"
    frameworks = contents / "Frameworks"
    resources = contents / "Resources"
    macos.mkdir(parents=True)
    frameworks.mkdir()
    resources.mkdir()

    _copy_file(wrapper, macos / "WireclawAI", executable=True)
    _copy_file(helper, macos / "llama-server", executable=True)
    _copy_runtime_tree(runtime_dir, frameworks, helper)
    for source in sorted(resources_dir.rglob("*")):
        if source.is_symlink():
            raise ValueError("resource input contains a symlink")
        if source.is_file():
            _copy_file(source, resources / source.relative_to(resources_dir))

    template = Path(__file__).resolve().parents[1] / "ai/macos/Info.plist"
    info = plistlib.loads(template.read_bytes())
    if info.get("CFBundleIdentifier") != BUNDLE_IDENTIFIER:
        raise ValueError("Info.plist bundle identifier is not approved")
    info_path = contents / "Info.plist"
    info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True))
    info_path.chmod(0o444)
    for directory in sorted((p for p in app.rglob("*") if p.is_dir()), reverse=True):
        directory.chmod(0o555)
    app.chmod(0o555)
    return app
