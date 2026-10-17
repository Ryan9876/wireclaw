"""Stage a self-contained macOS release bundle and build its local core image."""

import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDED = (
    "Dockerfile",
    "compose.yaml",
    ".env.example",
    ".dockerignore",
    "docker",
    "contracts",
    "apps/web/package.json",
    "apps/web/package-lock.json",
    "apps/web/index.html",
    "apps/web/vite.config.ts",
    "apps/web/tsconfig.json",
    "apps/web/playwright.config.ts",
    "apps/web/eslint.config.js",
    "apps/web/src",
    "apps/web/scripts",
    "services/analyzer/src/wireclaw_analyzer",
    "services/api/src/wireclaw_api",
    "launch/macos",
)


def run(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(
            f"command_failed: {argv[0]} ({result.returncode})\n{result.stderr[-4000:]}"
        )
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        relative = path.relative_to(directory).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _embedded_ai_builder():
    path = ROOT / "scripts/build_embedded_ai.py"
    spec = importlib.util.spec_from_file_location("wireclaw_build_embedded_ai", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("embedded_ai_builder_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _app_builder():
    path = ROOT / "scripts/build_macos_ai_app.py"
    spec = importlib.util.spec_from_file_location("wireclaw_build_macos_ai_app", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("macos_app_builder_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_signed_ai_app(release_root: Path, *, signing_mode: str, identity: str | None) -> dict:
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise RuntimeError("signed_macos_ai_app_requires_apple_silicon")
    ai_root = release_root / "ai"
    wrapper = release_root / "build/WireclawAI"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    build_env = os.environ | {"GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "1"}
    run(
        ["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", str(wrapper), "."],
        cwd=ROOT / "ai/macos/WireclawAI",
        env=build_env,
    )
    builder = _app_builder()
    with tempfile.TemporaryDirectory(prefix="wireclaw-app-resources-") as temporary:
        resources = Path(temporary) / "Resources"
        _embedded_ai_builder().prepare_app_resources(ai_root, resources)
        app = ai_root / "WireclawAI.app"
        builder.assemble_bundle(
            app,
            wrapper=wrapper,
            helper=ai_root / "macos-arm64/llama-server",
            runtime_dir=ai_root / "macos-arm64",
            resources_dir=resources,
        )
    builder.sign_bundle(app, mode=signing_mode, identity=identity)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    model_manifest = json.loads(
        (app / "Contents/Resources/ai/model-manifest.json").read_text(encoding="utf-8")
    )
    runtime_manifest = json.loads(
        (app / "Contents/Resources/ai/runtime-manifest.json").read_text(encoding="utf-8")
    )
    helper_record = next(
        item for item in runtime_manifest["files"] if item["path"] == "macos-arm64/llama-server"
    )
    result = {
        "path": "ai/WireclawAI.app",
        "bundle_identifier": info["CFBundleIdentifier"],
        "signing_mode": signing_mode,
        "signing_identity": identity or "-",
        "hardened_runtime": signing_mode == "developer-id",
        "developer_id_validation": "NOT_RUN" if signing_mode == "adhoc" else "PASS",
        "production_qualification": "NOT_RUN",
        "notarization": "NOT_RUN",
        "stapling": "NOT_RUN",
        "production_model_present": True,
        "model_sha256": model_manifest["artifact"]["sha256"],
        "llama_server_sha256": helper_record["sha256"],
    }
    if signing_mode == "developer-id":
        profile = os.environ.get("WIRECLAW_NOTARY_PROFILE", "")
        if profile:
            archive = release_root / "WireclawAI-notarization.zip"
            run(
                ["/usr/bin/ditto", "-c", "-k", "--keepParent", str(app), str(archive)],
                cwd=release_root,
            )
            run(
                [
                    "/usr/bin/xcrun",
                    "notarytool",
                    "submit",
                    str(archive),
                    "--keychain-profile",
                    profile,
                    "--wait",
                ],
                cwd=release_root,
            )
            run(["/usr/bin/xcrun", "stapler", "staple", str(app)], cwd=release_root)
            run(["/usr/bin/xcrun", "stapler", "validate", str(app)], cwd=release_root)
            archive.unlink()
            result["notarization"] = "PASS"
            result["stapling"] = "PASS"
    result["bundle_sha256"] = tree_sha256(app)
    shutil.rmtree(wrapper.parent)
    return result


def stage_embedded_ai(source: Path, release_root: Path) -> dict:
    """Verify and copy the separately built AI release assets into a bundle."""
    source = source.expanduser()
    if source.is_symlink():
        raise ValueError("manifest_symlink_invalid")
    source = source.resolve(strict=True)
    builder = _embedded_ai_builder()
    lock = builder.load_lock(ROOT / "ai/embedded-ai.lock.json")
    validated = builder.validate_staged_ai(source, lock)
    model = validated["model"]
    runtime = validated["runtime"]
    expected_files = {
        "model-manifest.json",
        "runtime-manifest.json",
        model["artifact"]["path"],
        model["license_path"],
        runtime["entrypoint"],
        *[item["path"] for item in runtime["files"]],
        *runtime["license_paths"],
    }
    actual_files = {
        path.relative_to(source).as_posix() for path in source.rglob("*") if path.is_file()
    }
    if actual_files != expected_files:
        raise ValueError("release_ai_unmanifested_asset")
    destination = release_root / "ai"
    if destination.exists() or destination.is_symlink():
        raise ValueError("release_ai_destination_exists")
    shutil.copytree(source, destination, symlinks=True)
    validated = builder.validate_staged_ai(destination, lock)
    model = validated["model"]
    runtime = validated["runtime"]
    model_artifact = model["artifact"]
    runtime_files = [
        {"path": item["path"], "sha256": item["sha256"], "size_bytes": item["size_bytes"]}
        for item in runtime["files"]
    ]
    licenses = []
    for relative in [model["license_path"], *runtime["license_paths"]]:
        path = destination / relative
        licenses.append(
            {
                "path": f"ai/{relative}",
                "sha256": builder.sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return {
        "model": {
            "id": model["model_id"],
            "repository": model["repository"],
            "source_revision": model["revision"],
            "license": model["license"],
            "quantization": model["quantization"],
            "architecture": model["architecture"],
            "sha256": model_artifact["sha256"],
            "size_bytes": model_artifact["size_bytes"],
        },
        "runtime": {
            "repository": runtime["repository"],
            "tag": runtime["tag"],
            "revision": runtime["revision"],
            "platform": runtime["platform"],
            "architecture": runtime["architecture"],
            "files": runtime_files,
        },
        "licenses": licenses,
        "model_manifest_sha256": builder.sha256(destination / "model-manifest.json"),
        "runtime_manifest_sha256": builder.sha256(destination / "runtime-manifest.json"),
        "runtime_argv_template": [
            "ai/macos-arm64/llama-server",
            "--model",
            f"ai/{model_artifact['path']}",
            "--alias",
            runtime["policy"]["model_alias"],
            "--host",
            runtime["policy"]["listen_host"],
            "--port",
            str(runtime["policy"]["port"]),
            "--ctx-size",
            str(runtime["policy"]["context_size"]),
            "--batch-size",
            str(runtime["policy"]["batch_size"]),
            "--ubatch-size",
            str(runtime["policy"]["micro_batch_size"]),
            "--n-predict",
            str(runtime["policy"]["max_tokens"]),
            "--parallel",
            str(runtime["policy"]["parallel"]),
            "--api-key-file",
            "<ephemeral-per-launch-key-file>",
            "--no-agent",
            "--no-webui",
            "--cache-ram",
            str(runtime["policy"]["prompt_cache_ram_mib"]),
        ],
        "policy": {
            "default_provider_mode": "embedded_local",
            "port": runtime["policy"]["port"],
            "context_size": runtime["policy"]["context_size"],
            "batch_size": runtime["policy"]["batch_size"],
            "micro_batch_size": runtime["policy"]["micro_batch_size"],
            "max_tokens": runtime["policy"]["max_tokens"],
            "parallel": runtime["policy"]["parallel"],
            "prompt_cache_ram_mib": runtime["policy"]["prompt_cache_ram_mib"],
            "platform": runtime["platform"],
            "architecture": runtime["architecture"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--embedded-ai-stage", type=Path, required=True)
    parser.add_argument("--signing-mode", choices=("adhoc", "developer-id"), default="adhoc")
    args = parser.parse_args()
    status = run(["git", "status", "--porcelain"], cwd=ROOT)
    if status:
        raise SystemExit("release staging requires a clean, committed source tree")
    source_sha = run(["git", "rev-parse", "HEAD"], cwd=ROOT)
    output = args.output_directory.expanduser().resolve()
    if output.exists():
        raise SystemExit(f"output directory already exists: {output}")
    stage = output / "wireclaw-release"
    stage.mkdir(parents=True)
    for item in INCLUDED:
        source = ROOT / item
        destination = stage / item
        if source.is_dir():
            shutil.copytree(
                source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    shutil.copy2(ROOT / "wireclaw-release/README.md", stage / "README.md")
    shutil.copy2(ROOT / "wireclaw-release/.env.example", stage / ".env.example")
    metadata_embedded_ai = stage_embedded_ai(args.embedded_ai_stage, stage)
    builder = _embedded_ai_builder()
    builder.smoke_test(stage / "ai", builder.load_lock(ROOT / "ai/embedded-ai.lock.json"))
    metadata_embedded_ai["protocol_smoke"] = "PASS"
    signing_identity = (
        os.environ.get("WIRECLAW_DEVELOPER_IDENTITY")
        if args.signing_mode == "developer-id"
        else None
    )
    if args.signing_mode == "developer-id" and not signing_identity:
        raise SystemExit(
            "production signing qualification: NOT_RUN (Developer ID identity unavailable)"
        )
    metadata_app = build_signed_ai_app(
        stage, signing_mode=args.signing_mode, identity=signing_identity
    )

    architecture = run(["uname", "-m"], cwd=ROOT)
    if architecture != "arm64":
        raise SystemExit(
            f"this candidate packages only the verified macOS arm64 bridge, got {architecture}"
        )
    bridge_dir = stage / "host-bridge/macos"
    bridge_dir.mkdir(parents=True)
    bridge = bridge_dir / "wireclaw-host-bridge-darwin-arm64"
    bridge_env = os.environ | {"GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "0"}
    run(
        ["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", str(bridge), "."],
        cwd=ROOT / "services/host-bridge",
        env=bridge_env,
    )
    bridge.chmod(0o700)

    lock = json.loads((stage / "docker/analyzer-versions.lock").read_text(encoding="utf-8"))
    metadata = {
        "source_sha": source_sha,
        "platform": "macOS",
        "architecture": "arm64",
        "go_version": run(["go", "version"], cwd=ROOT / "services/host-bridge"),
        "dockerfile_sha256": sha256(stage / "Dockerfile"),
        "compose_sha256": sha256(stage / "compose.yaml"),
        "analyzer_lock_sha256": sha256(stage / "docker/analyzer-versions.lock"),
        "base_image": lock["base_image"],
        "web_builder_image": lock["web_builder_image"],
        "versions": lock,
        "bridge_binary": bridge.name,
        "bridge_sha256": sha256(bridge),
        "core_image_id": None,
        "embedded_ai": metadata_embedded_ai,
        "signed_app": metadata_app,
    }
    env = os.environ | {"WIRECLAW_DATA_ROOT": str(output / "Wireclaw Release Data")}
    run(
        ["docker", "compose", "--env-file", ".env.example", "build", "wireclaw-core"],
        cwd=stage,
        env=env,
    )
    metadata["core_image_id"] = run(
        ["docker", "image", "inspect", "wireclaw-core:gate8", "--format", "{{.Id}}"],
        cwd=stage,
    )
    (stage / "core-image-id").write_text(f"{metadata['core_image_id']}\n", encoding="utf-8")
    image_archive = stage / "core-image.tar"
    run(["docker", "save", "--output", str(image_archive), "wireclaw-core:gate8"], cwd=stage)
    metadata["core_image_archive_sha256"] = sha256(image_archive)
    metadata["docker_version"] = run(
        ["docker", "version", "--format", "{{.Server.Version}}"], cwd=stage
    )
    metadata["compose_version"] = run(["docker", "compose", "version", "--short"], cwd=stage)
    metadata["macos_version"] = run(["sw_vers", "-productVersion"], cwd=stage)
    metadata["wireshark_version"] = run(
        ["/Applications/Wireshark.app/Contents/MacOS/Wireshark", "--version"], cwd=stage
    )
    with tempfile.TemporaryDirectory(prefix="wireclaw-web-assets-") as temp_web:
        container_id = run(["docker", "create", "wireclaw-core:gate8"], cwd=stage)
        try:
            run(["docker", "cp", f"{container_id}:/opt/wireclaw/web/.", temp_web], cwd=stage)
            metadata["compiled_web_sha256"] = tree_sha256(Path(temp_web))
        finally:
            run(["docker", "rm", container_id], cwd=stage)
    (stage / "release-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(stage)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from None
