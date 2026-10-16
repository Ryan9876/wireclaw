"""Assemble the fixed WireclawAI macOS application bundle layout."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
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
PARENT_ENTITLEMENTS_PATH = (
    Path(__file__).resolve().parents[1] / "ai/macos/parent.entitlements.plist"
)
HELPER_ENTITLEMENTS_PATH = (
    Path(__file__).resolve().parents[1] / "ai/macos/helper.entitlements.plist"
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


def _validate_resources(resources_dir: Path) -> None:
    if resources_dir.is_symlink() or not resources_dir.is_dir():
        raise ValueError("resource input directory is missing or unsafe")
    for source in resources_dir.rglob("*"):
        if source.is_symlink():
            raise ValueError("resource input contains a symlink")
    for relative in REQUIRED_AI_RESOURCES:
        source = resources_dir / relative
        if not source.is_file():
            raise ValueError(f"required AI resource is missing or unsafe: {relative}")


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
    _validate_resources(resources_dir)
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


def _run_codesign(argv: list[str], runner=subprocess.run) -> subprocess.CompletedProcess:
    result = runner(argv, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError("codesign operation failed")
    return result


def _runtime_path(contents: Path, manifest_path: str) -> Path:
    if manifest_path == "macos-arm64/llama-server":
        return contents / "MacOS/llama-server"
    if manifest_path.startswith("macos-arm64/"):
        return contents / "Frameworks" / manifest_path.removeprefix("macos-arm64/")
    raise ValueError("runtime manifest contains an unsupported code path")


def _refresh_runtime_hashes(app: Path) -> None:
    manifest_path = app / "Contents/Resources/ai/runtime-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for record in manifest["files"]:
        path = _runtime_path(app / "Contents", record["path"])
        if not path.is_file() or path.is_symlink():
            raise ValueError("signed runtime file is missing or unsafe")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        record["sha256"] = digest
        record["size_bytes"] = path.stat().st_size
    manifest_path.chmod(0o644)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest_path.chmod(0o444)


def _prepare_signing_permissions(app: Path) -> None:
    app.chmod(0o755)
    for path in app.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o755)
    for relative in ("Contents/MacOS/WireclawAI", "Contents/MacOS/llama-server"):
        (app / relative).chmod(0o755)
    for path in (app / "Contents/Frameworks").rglob("*"):
        if (
            path.is_file()
            and not path.is_symlink()
            and (path.suffix == ".dylib" or os.access(path, os.X_OK))
        ):
            path.chmod(0o755)


def _restore_read_only_modes(app: Path) -> None:
    for path in app.rglob("*"):
        if path.is_symlink():
            raise ValueError("signed bundle unexpectedly contains a symlink")
        if path.is_dir():
            path.chmod(0o555)
        elif path.is_file():
            executable = path.stat().st_mode & 0o111
            path.chmod(0o555 if executable else 0o444)
    app.chmod(0o555)


def sign_bundle(
    app: Path,
    *,
    mode: str,
    identity: str | None = None,
    runner=subprocess.run,
) -> None:
    """Sign nested runtime code first, then parent code and bundle, with HR."""
    if mode not in {"adhoc", "developer-id"}:
        raise ValueError("unsupported signing mode")
    if mode == "developer-id" and not identity:
        raise ValueError("Developer ID identity required")
    if mode == "adhoc" and identity not in (None, "-"):
        raise ValueError("ad-hoc signing identity must be '-'")
    identity = "-" if mode == "adhoc" else identity
    contents = app / "Contents"
    helper = contents / "MacOS/llama-server"
    wrapper = contents / "MacOS/WireclawAI"
    runtime_files = sorted(
        path
        for path in (contents / "Frameworks").rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and (path.suffix == ".dylib" or os.access(path, os.X_OK))
    )
    if not wrapper.is_file() or not helper.is_file() or not (contents / "Info.plist").is_file():
        raise ValueError("application bundle is incomplete")
    _prepare_signing_permissions(app)
    signing_options = ["--options", "runtime"]
    if mode == "developer-id":
        signing_options.append("--timestamp")
    for target in runtime_files:
        _run_codesign(
            [
                "/usr/bin/codesign",
                "--force",
                *signing_options,
                "--identifier",
                target.name,
                "--sign",
                identity,
                str(target),
            ],
            runner,
        )
    _run_codesign(
        [
            "/usr/bin/codesign",
            "--force",
            *signing_options,
            "--identifier",
            "llama-server",
            "--entitlements",
            str(HELPER_ENTITLEMENTS_PATH),
            "--sign",
            identity,
            str(helper),
        ],
        runner,
    )
    _refresh_runtime_hashes(app)
    for target in (wrapper, app):
        identifier_args = ["--identifier", BUNDLE_IDENTIFIER] if target == wrapper else []
        _run_codesign(
            [
                "/usr/bin/codesign",
                "--force",
                *signing_options,
                *identifier_args,
                "--entitlements",
                str(PARENT_ENTITLEMENTS_PATH),
                "--sign",
                identity,
                str(target),
            ],
            runner,
        )
    verify_signed_bundle(app, runner=runner)
    _restore_read_only_modes(app)


def verify_signed_bundle(app: Path, *, runner=subprocess.run) -> None:
    """Strictly verify the app and exact signed parent/helper entitlements."""
    result = runner(
        ["/usr/bin/codesign", "--verify", "--strict", "--deep", "--verbose=4", str(app)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("signature verification failed")
    for target, expected in (
        (app, PARENT_ENTITLEMENTS),
        (app / "Contents/MacOS/WireclawAI", PARENT_ENTITLEMENTS),
        (app / "Contents/MacOS/llama-server", HELPER_ENTITLEMENTS),
    ):
        details = runner(
            ["/usr/bin/codesign", "-dv", "--verbose=4", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if details.returncode or not re.search(
            r"flags=.*\bruntime\b", details.stdout + details.stderr
        ):
            raise ValueError("Hardened Runtime signature missing")
        dumped = runner(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if dumped.returncode:
            raise ValueError("signed entitlements could not be inspected")
        raw = dumped.stdout or dumped.stderr
        try:
            actual = plistlib.loads(raw[raw.index("<?xml") :].encode())
        except (ValueError, TypeError):
            try:
                start = raw.index("<?xml")
                actual = plistlib.loads(raw[start:].encode())
            except (ValueError, TypeError):
                raise ValueError("signed entitlements could not be inspected") from None
        if actual != expected:
            raise ValueError("signed entitlements do not match approved exact set")
