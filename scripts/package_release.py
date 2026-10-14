"""Stage a self-contained macOS release bundle and build its local core image."""

import hashlib
import json
import os
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


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/package_release.py OUTPUT_DIRECTORY")
    status = run(["git", "status", "--porcelain"], cwd=ROOT)
    if status:
        raise SystemExit("release staging requires a clean, committed source tree")
    source_sha = run(["git", "rev-parse", "HEAD"], cwd=ROOT)
    output = Path(sys.argv[1]).expanduser().resolve()
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
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from None
