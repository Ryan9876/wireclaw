"""Build and validate the pinned macOS arm64 embedded-AI release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "ai/embedded-ai.lock.json"
CONVERSION_REQUIREMENTS_LOCK = ROOT / "ai/conversion-requirements.lock.txt"
MODEL_MANIFEST = "model-manifest.json"
RUNTIME_MANIFEST = "runtime-manifest.json"
MAX_MODEL_SIZE = 3_758_096_384


def _fail(code: str) -> None:
    raise ValueError(code)


def _run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr[-2000:].strip()
        raise RuntimeError(f"command_failed:{Path(argv[0]).name}:{result.returncode}:{detail}")
    return result.stdout.strip()


def load_lock(path: Path) -> dict:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _fail("source_lock_invalid")
    expected = {
        "model": {
            "repository": "Qwen/Qwen3-4B-Instruct-2507",
            "revision": "cdbee75f17c01a7cc42f958dc650907174af0554",
            "license": "Apache-2.0",
            "quantization": "Q4_K_M",
            "gguf_architecture": "qwen3",
            "id": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
            "artifact": "models/qwen3-4b-instruct-2507-q4_k_m.gguf",
            "max_size_bytes": MAX_MODEL_SIZE,
        },
        "runtime": {
            "repository": "ggml-org/llama.cpp",
            "url": "https://github.com/ggml-org/llama.cpp.git",
            "tag": "v0.6.0",
            "tag_revision": "d81235049384534c167caea52b85a694f6103d14",
            "revision": "8345f333951c661d166b00e6f9362e553768f292",
            "required_resources": [
                "macos-arm64/llama-server",
                "macos-arm64/libggml-metal.dylib",
            ],
        },
        "policy": {
            "platform": "macos",
            "architecture": "arm64",
            "listen_host": "127.0.0.1",
            "context_size": 16384,
            "batch_size": 128,
            "micro_batch_size": 32,
            "max_tokens": 2048,
            "parallel": 1,
            "prompt_cache_ram_mib": 0,
            "port": 8767,
            "model_alias": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
            "authentication_required": True,
            "agent_tools": False,
            "web_ui": False,
            "network_downloads": False,
        },
    }
    if not isinstance(lock, dict) or lock.get("schema_version") != 1:
        _fail("source_lock_invalid")
    conversion = lock.get("conversion")
    if (
        not isinstance(conversion, dict)
        or conversion.get("huggingface_hub_version") != "0.34.4"
        or conversion.get("source_snapshot_excludes") != [".cache/**"]
    ):
        _fail("source_lock_identity_mismatch")
    for section, values in expected.items():
        if not isinstance(lock.get(section), dict) or any(
            lock[section].get(key) != value for key, value in values.items()
        ):
            _fail("source_lock_identity_mismatch")
    if (
        type(lock["policy"].get("prompt_cache_ram_mib")) is not int
        or lock["policy"].get("prompt_cache_ram_mib") != 0
        or lock["policy"] != expected["policy"]
    ):
        _fail("source_lock_identity_mismatch")
    if lock["model"].get("max_size_bytes") != MAX_MODEL_SIZE:
        _fail("source_lock_model_size_limit_invalid")
    return lock


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_record(path: Path, root: Path) -> dict:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _confined_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        _fail("manifest_path_invalid")
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or any(part in ("", ".", "..") for part in candidate.parts)
        or "\\" in relative
    ):
        _fail("manifest_path_invalid")
    root_real = root.resolve(strict=True)
    path = root
    for part in candidate.parts:
        path = path / part
        if path.is_symlink():
            _fail("manifest_symlink_invalid")
    try:
        path.resolve(strict=False).relative_to(root_real)
    except ValueError:
        _fail("manifest_path_invalid")
    return path


def _read_manifest(ai_root: Path, name: str) -> dict:
    path = _confined_file(ai_root, name)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _fail("manifest_invalid")
    if not isinstance(value, dict):
        _fail("manifest_invalid")
    return value


def _verify_file_record(ai_root: Path, record: dict, *, missing_code: str, hash_code: str):
    if not isinstance(record, dict):
        _fail("manifest_invalid")
    path = _confined_file(ai_root, record.get("path"))
    if not path.is_file():
        _fail(missing_code)
    size = path.stat().st_size
    if type(record.get("size_bytes")) is not int or record["size_bytes"] != size:
        _fail(hash_code)
    if not isinstance(record.get("sha256"), str) or sha256(path) != record["sha256"]:
        _fail(hash_code)
    return path


def validate_staged_ai(ai_root: Path, lock: dict) -> dict:
    if ai_root.is_symlink():
        _fail("manifest_symlink_invalid")
    ai_root = ai_root.resolve(strict=True)
    if any(path.is_symlink() for path in ai_root.rglob("*")):
        _fail("manifest_symlink_invalid")
    model = _read_manifest(ai_root, MODEL_MANIFEST)
    runtime = _read_manifest(ai_root, RUNTIME_MANIFEST)
    for manifest in (model, runtime):
        if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
            _fail("manifest_schema_invalid")
    expected_model = lock["model"]
    expected_runtime = lock["runtime"]
    if model.get("model_id") != expected_model["id"]:
        _fail("model_id_mismatch")
    if model.get("revision") != expected_model["revision"]:
        _fail("model_revision_mismatch")
    if (
        model.get("repository") != expected_model["repository"]
        or model.get("license") != expected_model["license"]
        or model.get("quantization") != expected_model["quantization"]
        or model.get("architecture") != expected_model["gguf_architecture"]
    ):
        _fail("model_provenance_mismatch")
    architecture_validation = model.get("architecture_validation")
    if (
        not isinstance(architecture_validation, dict)
        or architecture_validation.get("metadata_field") != "general.architecture"
        or architecture_validation.get("reader") != "gguf-py from pinned llama.cpp source"
    ):
        _fail("model_architecture_provenance_missing")
    artifact = model.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("path") != expected_model["artifact"]:
        _fail("manifest_path_invalid")
    if type(artifact.get("size_bytes")) is not int or artifact["size_bytes"] <= 0:
        _fail("model_size_invalid")
    if artifact["size_bytes"] > expected_model["max_size_bytes"]:
        _fail("model_size_limit")
    _verify_file_record(
        ai_root, artifact, missing_code="model_artifact_missing", hash_code="model_hash_mismatch"
    )
    source_files = model.get("source_files")
    if not isinstance(source_files, list) or not source_files:
        _fail("model_source_provenance_missing")
    for record in source_files:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("path"), str)
            or not record["path"]
            or PurePosixPath(record["path"]).is_absolute()
            or ".." in PurePosixPath(record["path"]).parts
            or "\\" in record["path"]
            or len(record.get("sha256", "")) != 64
            or type(record.get("size_bytes")) is not int
            or record["size_bytes"] < 0
        ):
            _fail("model_source_provenance_invalid")
    model_license = model.get("license_path")
    if not isinstance(model_license, str) or not _confined_file(ai_root, model_license).is_file():
        _fail("license_missing")

    if (
        runtime.get("repository") != expected_runtime["repository"]
        or runtime.get("tag") != expected_runtime["tag"]
        or runtime.get("tag_commit") != expected_runtime["tag_revision"]
        or runtime.get("revision") != expected_runtime["revision"]
        or runtime.get("platform") != "macos"
        or runtime.get("architecture") != "arm64"
    ):
        _fail("runtime_revision_mismatch")
    if runtime.get("build_settings", {}).get("metal") is not True:
        _fail("runtime_metal_missing")
    if runtime.get("build_settings", {}).get("server") is not True:
        _fail("runtime_server_missing")
    if not isinstance(runtime.get("build_settings", {}).get("cmake_version"), str):
        _fail("runtime_build_provenance_missing")
    if runtime.get("entrypoint") != "macos-arm64/llama-server":
        _fail("runtime_entrypoint_invalid")
    runtime_files = runtime.get("files")
    if not isinstance(runtime_files, list):
        _fail("runtime_resource_missing")
    runtime_by_path = {item.get("path"): item for item in runtime_files if isinstance(item, dict)}
    for required in expected_runtime["required_resources"]:
        if required not in runtime_by_path:
            _fail("runtime_resource_missing")
    for record in runtime_files:
        _verify_file_record(
            ai_root,
            record,
            missing_code="runtime_resource_missing",
            hash_code="runtime_hash_mismatch",
        )
    licenses = runtime.get("license_paths")
    if not isinstance(licenses, list) or not licenses:
        _fail("license_missing")
    for relative in licenses:
        license_path = _confined_file(ai_root, relative)
        if not license_path.is_file() or license_path.stat().st_size == 0:
            _fail("license_missing")
    policy = runtime.get("policy")
    if (
        not isinstance(policy, dict)
        or type(policy.get("prompt_cache_ram_mib")) is not int
        or policy.get("prompt_cache_ram_mib") != 0
        or policy != lock["policy"]
    ):
        _fail("runtime_policy_mismatch")
    return {"model": model, "runtime": runtime}


def prepare_app_resources(ai_root: Path, resources_dir: Path) -> Path:
    """Copy validated source assets to the fixed app Resources layout.

    Source manifests stay immutable. Their paths retain pinned source identity;
    the wrapper maps only those fixed paths to MacOS/Frameworks/Resources.
    Signing must update file hashes in the bundle copy after nested signing and
    before signing the enclosing app. This function does not sign any code.
    """
    validated = validate_staged_ai(ai_root, load_lock(LOCK_PATH))
    if resources_dir.exists() or resources_dir.is_symlink():
        _fail("app_resources_destination_exists")
    resources_dir.mkdir(parents=True)
    destination = resources_dir / "ai"
    destination.mkdir()
    shutil.copyfile(ai_root / validated["model"]["artifact"]["path"], destination / "model.gguf")
    licenses = {validated["model"]["license_path"], *validated["runtime"]["license_paths"]}
    for relative in sorted(licenses):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_confined_file(ai_root, relative), target)
    for name, manifest in validated.items():
        bundled = {**manifest, "bundle_identifier": "com.wireclaw.WireclawAI"}
        (destination / f"{name}-manifest.json").write_text(
            json.dumps(bundled, indent=2) + "\n", encoding="utf-8"
        )
    return resources_dir


def _repo(work: Path, lock: dict) -> Path:
    repo = work / "llama.cpp"
    if not repo.exists():
        _run(["git", "clone", lock["runtime"]["url"], str(repo)])
    if repo.is_symlink() or not repo.is_dir():
        _fail("runtime_source_path_invalid")
    if _run(["git", "remote", "get-url", "origin"], cwd=repo) != lock["runtime"]["url"]:
        _fail("runtime_source_remote_mismatch")
    status = _run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo)
    if status:
        _fail("runtime_source_cache_dirty")
    revision = lock["runtime"]["revision"]
    tag = lock["runtime"]["tag"]
    revision_available = (
        subprocess.run(
            ["git", "cat-file", "-e", f"{revision}^{{commit}}"], cwd=repo, check=False
        ).returncode
        == 0
    )
    tag_available = (
        subprocess.run(
            ["git", "rev-parse", "--verify", f"{tag}^{{}}"],
            cwd=repo,
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )
    if not revision_available or not tag_available:
        _run(["git", "fetch", "origin", "--tags", revision], cwd=repo)
    _run(["git", "checkout", "--detach", revision], cwd=repo)
    head = _run(["git", "rev-parse", "HEAD"], cwd=repo)
    if head != revision:
        _fail("runtime_revision_mismatch")
    tag_commit = _run(["git", "rev-parse", f"{tag}^{{}}"], cwd=repo)
    if tag_commit != lock["runtime"]["tag_revision"]:
        _fail("runtime_tag_revision_mismatch")
    _run(["git", "merge-base", "--is-ancestor", tag_commit, head], cwd=repo)
    return repo


def _macho_rpaths(path: Path) -> list[str]:
    output = _run(["otool", "-l", str(path)])
    rpaths = []
    in_rpath = False
    for line in output.splitlines():
        if line.strip() == "cmd LC_RPATH":
            in_rpath = True
            continue
        if in_rpath:
            match = re.match(r"\s*path (.+) \(offset [0-9]+\)$", line)
            if match:
                rpaths.append(match.group(1))
                in_rpath = False
    return rpaths


def _is_system_library_path(path: str) -> bool:
    candidate = Path(path)
    if not candidate.is_absolute():
        return False
    resolved = candidate.resolve()
    roots = (Path("/System/Library").resolve(), Path("/usr/lib").resolve())
    return any(resolved == root or root in resolved.parents for root in roots)


def _validate_macho_dependencies(runtime_root: Path, path: Path) -> None:
    files = {
        item.name for item in runtime_root.iterdir() if item.is_file() and not item.is_symlink()
    }
    lines = _run(["otool", "-L", str(path)]).splitlines()[1:]
    for line in lines:
        dependency = line.strip().split(" (compatibility version", 1)[0]
        if dependency.startswith(("@rpath/", "@loader_path/")):
            prefix, name = dependency.split("/", 1)
            if (
                not name
                or "/" in name
                or name in {".", ".."}
                or name not in files
                or prefix not in {"@rpath", "@loader_path"}
            ):
                _fail("runtime_dependency_path_invalid")
            if Path(runtime_root / name).is_symlink():
                _fail("runtime_dependency_missing")
        elif dependency.startswith("/") and not _is_system_library_path(dependency):
            _fail("runtime_external_dependency")
        elif dependency.startswith("@"):
            _fail("runtime_dependency_path_invalid")


def relocate_macos_runtime(runtime_root: Path, build_bin: Path) -> None:
    """Make every Mach-O in the release resolve dependencies from its bundle."""
    build_root = build_bin.resolve()
    binaries = sorted(path for path in runtime_root.iterdir() if path.is_file())
    if not binaries:
        _fail("runtime_build_output_missing")
    for path in binaries:
        for rpath in _macho_rpaths(path):
            if rpath.startswith("/"):
                resolved_rpath = Path(rpath).resolve()
                if resolved_rpath == build_root or build_root in resolved_rpath.parents:
                    _run(["install_name_tool", "-delete_rpath", rpath, str(path)])
                elif not _is_system_library_path(rpath):
                    _fail("runtime_external_rpath")
            elif rpath != "@loader_path":
                _fail("runtime_external_rpath")
        if "@loader_path" not in _macho_rpaths(path):
            _run(["install_name_tool", "-add_rpath", "@loader_path", str(path)])
        final_rpaths = _macho_rpaths(path)
        if "@loader_path" not in final_rpaths or any(
            rpath.startswith("/") and not _is_system_library_path(rpath) for rpath in final_rpaths
        ):
            _fail("runtime_relocation_failed")
        _validate_macho_dependencies(runtime_root, path)


def _copy_macos_dylib_aliases(build_bin: Path, runtime_root: Path) -> None:
    build_root = build_bin.resolve()
    for alias in sorted(build_bin.glob("*.dylib")):
        if not alias.is_symlink():
            continue
        target = alias.resolve(strict=True)
        if target.is_file() and target.parent == build_root:
            shutil.copy2(target, runtime_root / alias.name)


def build_runtime(lock: dict, work: Path, output: Path) -> dict:
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        _fail("macos_arm64_required")
    work.mkdir(parents=True, exist_ok=True)
    repo = _repo(work, lock)
    cmake_version = _run(["cmake", "--version"]).splitlines()[0]
    xcode_version = _run(["xcodebuild", "-version"]).replace("\n", "; ")
    build = work / "llama-build"
    _run(
        [
            "cmake",
            "-S",
            str(repo),
            "-B",
            str(build),
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_INSTALL_PREFIX=" + str(build / "install"),
            "-DGGML_METAL=ON",
            "-DLLAMA_BUILD_SERVER=ON",
            "-DLLAMA_BUILD_TOOLS=ON",
            "-DLLAMA_CURL=OFF",
            "-DLLAMA_OPENSSL=OFF",
            "-DGGML_NATIVE=OFF",
        ]
    )
    _run(
        [
            "cmake",
            "--build",
            str(build),
            "--config",
            "Release",
            "--parallel",
            "4",
            "--target",
            "llama-server",
            "llama-quantize",
        ]
    )
    binary = build / "bin/llama-server"
    quantize = build / "bin/llama-quantize"
    if not binary.is_file() or not quantize.is_file():
        _fail("runtime_build_output_missing")
    for executable in (binary, quantize):
        archs = _run(["lipo", "-archs", str(executable)]).split()
        if archs != ["arm64"]:
            _fail("runtime_architecture_mismatch")
    ai_root = output / "ai"
    runtime_root = ai_root / "macos-arm64"
    if runtime_root.is_symlink():
        _fail("runtime_output_path_invalid")
    if runtime_root.exists():
        shutil.rmtree(runtime_root)
    runtime_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, runtime_root / binary.name)
    library_sources = sorted((build / "bin").glob("*.dylib"))
    for source in library_sources:
        if (
            source.is_file()
            and not source.is_symlink()
            and source.name != "libllama-quantize-impl.dylib"
        ):
            shutil.copy2(source, runtime_root / source.name)
    metal_link = build / "bin/libggml-metal.dylib"
    if not metal_link.is_file():
        _fail("runtime_build_resource_missing")
    shutil.copy2(metal_link.resolve(strict=True), runtime_root / metal_link.name)
    _copy_macos_dylib_aliases(build / "bin", runtime_root)
    for library in runtime_root.glob("*.dylib"):
        archs = _run(["lipo", "-archs", str(library)]).split()
        if archs != ["arm64"]:
            _fail("runtime_architecture_mismatch")
    relocate_macos_runtime(runtime_root, build / "bin")
    resources = lock["runtime"]["required_resources"]
    if not all((ai_root / relative).is_file() for relative in resources):
        _fail("runtime_build_resource_missing")
    manifest = {
        "schema_version": 1,
        "repository": lock["runtime"]["repository"],
        "tag": lock["runtime"]["tag"],
        "revision": lock["runtime"]["revision"],
        "tag_commit": _run(["git", "rev-parse", f"{lock['runtime']['tag']}^{{}}"], cwd=repo),
        "platform": "macos",
        "architecture": "arm64",
        "build_settings": {
            "metal": True,
            "server": True,
            "cmake_version": cmake_version,
            "xcode_version": xcode_version,
        },
        "entrypoint": "macos-arm64/llama-server",
        "files": [
            _file_record(path, ai_root)
            for path in sorted(runtime_root.iterdir())
            if path.is_file() and not path.is_symlink()
        ],
        "license_paths": ["licenses/llama.cpp-MIT.txt"],
        "policy": lock["policy"],
    }
    licenses = ai_root / "licenses"
    licenses.mkdir(parents=True, exist_ok=True)
    upstream_license = repo / "LICENSE"
    if not upstream_license.is_file():
        _fail("license_missing")
    shutil.copy2(upstream_license, licenses / "llama.cpp-MIT.txt")
    manifest["files"] = [
        _file_record(path, ai_root)
        for path in sorted(runtime_root.iterdir())
        if path.is_file() and not path.is_symlink()
    ]
    (ai_root / RUNTIME_MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"repository": repo, "build": build, "quantizer": quantize, "manifest": manifest}


def _source_records(source: Path) -> list[dict]:
    records = []
    for path in sorted(source.rglob("*")):
        if not path.is_file() or ".cache" in path.relative_to(source).parts:
            continue
        if path.is_symlink():
            _fail("model_source_symlink_invalid")
        records.append(
            {
                "path": path.relative_to(source).as_posix(),
                "sha256": sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    if not records:
        _fail("model_source_empty")
    return records


def require_gguf_architecture(actual: str, expected: str) -> str:
    if actual != expected:
        _fail("model_architecture_mismatch")
    return actual


def read_gguf_architecture(model_path: Path, runtime_repo: Path, python: Path) -> str:
    code = (
        "import sys; from gguf import GGUFReader; "
        "reader=GGUFReader(sys.argv[1]); "
        "field=reader.fields.get('general.architecture'); "
        "print(field.contents() if field is not None else '')"
    )
    env = os.environ | {"PYTHONPATH": str(runtime_repo / "gguf-py")}
    architecture = _run([str(python), "-c", code, str(model_path)], env=env)
    if not architecture:
        _fail("model_architecture_missing")
    return architecture


def freeze_dependencies(python: Path, env: dict[str, str]) -> str:
    return _run(["uv", "pip", "freeze", "--python", str(python)], env=env)


def _dependency_versions(requirements: str) -> dict[str, str]:
    versions = {}
    for line in requirements.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9.+_-]+)(?:\s|$)", line)
        if match:
            name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
            if name in versions:
                _fail("conversion_dependency_lock_invalid")
            versions[name] = match.group(2)
    if not versions:
        _fail("conversion_dependency_lock_invalid")
    return versions


def build_model(lock: dict, work: Path, output: Path) -> dict:
    runtime = _repo(work, lock)
    model = lock["model"]
    source = work / "qwen-source"
    source.mkdir(parents=True, exist_ok=True)
    env = os.environ | {
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_ENABLE_HF_TRANSFER": "0",
        "UV_CACHE_DIR": str(work / "uv-cache"),
    }
    _run(
        [
            "uv",
            "tool",
            "run",
            "--from",
            f"huggingface_hub=={lock['conversion']['huggingface_hub_version']}",
            "hf",
            "download",
            model["repository"],
            "--revision",
            model["revision"],
            "--local-dir",
            str(source),
        ],
        env=env,
    )
    records = _source_records(source)
    convert = runtime / "convert_hf_to_gguf.py"
    convert_req = runtime / "requirements/requirements-convert_hf_to_gguf.txt"
    if (
        not convert.is_file()
        or not convert_req.is_file()
        or not CONVERSION_REQUIREMENTS_LOCK.is_file()
    ):
        _fail("model_converter_missing")
    converter_env = work / "convert-venv"
    if not converter_env.exists():
        _run(["uv", "venv", str(converter_env), "--python", "3.12"], env=env)
    python = converter_env / "bin/python"
    _run(
        [
            "uv",
            "pip",
            "install",
            "--require-hashes",
            "--python",
            str(python),
            "-r",
            str(CONVERSION_REQUIREMENTS_LOCK),
        ],
        env=env,
    )
    dependency_lock = freeze_dependencies(python, env)
    locked_versions = _dependency_versions(CONVERSION_REQUIREMENTS_LOCK.read_text(encoding="utf-8"))
    installed_versions = _dependency_versions(dependency_lock)
    if installed_versions != locked_versions:
        _fail("conversion_dependency_set_mismatch")
    intermediate = work / "qwen-f16.gguf"
    quantized = work / "qwen-q4_k_m.gguf"
    conversion_command = [
        str(python),
        str(convert),
        "--outfile",
        str(intermediate),
        "--outtype",
        "f16",
        str(source),
    ]
    _run(conversion_command, cwd=runtime, env=env)
    quantization_command = [
        str(work / "llama-build/bin/llama-quantize"),
        str(intermediate),
        str(quantized),
        "Q4_K_M",
    ]
    _run(quantization_command, cwd=runtime)
    architecture = require_gguf_architecture(
        read_gguf_architecture(quantized, runtime, python), model["gguf_architecture"]
    )
    if quantized.stat().st_size > model["max_size_bytes"]:
        _fail("model_size_limit")
    ai_root = output / "ai"
    model_path = ai_root / model["artifact"]
    model_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(quantized, model_path)
    license_path = ai_root / "licenses/Qwen-Apache-2.0.txt"
    license_path.parent.mkdir(parents=True, exist_ok=True)
    (license_path).write_text(
        "Qwen/Qwen3-4B-Instruct-2507 is licensed under Apache-2.0.\n"
        "The upstream license is available in the pinned model snapshot under LICENSE.\n",
        encoding="utf-8",
    )
    upstream_license = source / "LICENSE"
    if not upstream_license.is_file():
        _fail("license_missing")
    shutil.copy2(upstream_license, license_path)
    manifest = {
        "schema_version": 1,
        "model_id": model["id"],
        "repository": model["repository"],
        "revision": model["revision"],
        "license": model["license"],
        "quantization": model["quantization"],
        "architecture": architecture,
        "architecture_validation": {
            "metadata_field": "general.architecture",
            "reader": "gguf-py from pinned llama.cpp source",
        },
        "artifact": _file_record(model_path, ai_root),
        "source_files": records,
        "license_path": "licenses/Qwen-Apache-2.0.txt",
        "build": {
            "llama_cpp_commit": lock["runtime"]["revision"],
            "conversion_command": ["convert_hf_to_gguf.py", "--outtype", "f16"],
            "quantization_command": ["llama-quantize", "Q4_K_M"],
            "conversion_dependency_lock": dependency_lock.splitlines(),
            "conversion_dependency_lock_sha256": sha256(CONVERSION_REQUIREMENTS_LOCK),
        },
    }
    (ai_root / MODEL_MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _wait_ready(base_url: str, token: str, process: subprocess.Popen, timeout: float = 60):
    deadline = time.monotonic() + timeout
    headers = {"Authorization": f"Bearer {token}"}
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _fail("runtime_smoke_process_exit")
        request = urllib.request.Request(base_url + "/models", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.25)
    _fail("runtime_smoke_timeout")


def smoke_test(ai_root: Path, lock: dict):
    model = lock["model"]
    policy = lock["policy"]
    token = os.urandom(32).hex()
    with tempfile.TemporaryDirectory(prefix="wireclaw-ai-smoke-") as temp_dir:
        key_file = Path(temp_dir) / "api-key"
        key_file.write_text(token + "\n", encoding="utf-8")
        key_file.chmod(0o600)
        argv = [
            str(ai_root / "macos-arm64/llama-server"),
            "--model",
            str(ai_root / model["artifact"]),
            "--alias",
            policy["model_alias"],
            "--host",
            "127.0.0.1",
            "--port",
            str(policy["port"]),
            "--ctx-size",
            str(policy["context_size"]),
            "--batch-size",
            str(policy["batch_size"]),
            "--ubatch-size",
            str(policy["micro_batch_size"]),
            "--n-predict",
            str(policy["max_tokens"]),
            "--parallel",
            str(policy["parallel"]),
            "--api-key-file",
            str(key_file),
            "--no-agent",
            "--no-webui",
            "--cache-ram",
            str(policy["prompt_cache_ram_mib"]),
        ]
        env = os.environ | {"HF_HUB_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1"}
        with open(os.devnull, "wb") as sink:
            process = subprocess.Popen(argv, env=env, stdout=sink, stderr=sink, shell=False)
        try:
            base = f"http://127.0.0.1:{policy['port']}/v1"
            _wait_ready(base, token, process)
            unauthenticated = urllib.request.Request(base + "/models")
            try:
                urllib.request.urlopen(unauthenticated, timeout=2)
            except urllib.error.HTTPError as error:
                if error.code != 401:
                    _fail("runtime_smoke_authentication_missing")
            else:
                _fail("runtime_smoke_authentication_missing")
            models_request = urllib.request.Request(
                base + "/models", headers={"Authorization": f"Bearer {token}"}
            )
            with urllib.request.urlopen(models_request, timeout=5) as response:
                model_list = json.loads(response.read())
            if not any(
                item.get("id") == policy["model_alias"] for item in model_list.get("data", [])
            ):
                _fail("runtime_smoke_model_identity_mismatch")
            body = json.dumps(
                {
                    "model": policy["model_alias"],
                    "messages": [{"role": "user", "content": "Reply with the word ready."}],
                    "max_tokens": 8,
                    "temperature": 0,
                }
            ).encode()
            request = urllib.request.Request(
                base + "/chat/completions",
                data=body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read())
            if payload["choices"][0]["message"].get("content") is None:
                _fail("runtime_smoke_protocol_invalid")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    lock = load_lock(LOCK_PATH)
    work = args.work.expanduser().resolve()
    output = args.output.expanduser().resolve()
    for path in (work, output):
        if path == ROOT or ROOT in path.parents:
            _fail("generated_assets_must_be_outside_source")
    if output.exists() and any(output.iterdir()):
        _fail("output_directory_not_empty")
    output.mkdir(parents=True, exist_ok=True)
    runtime = build_runtime(lock, work, output)
    build_model(lock, work, output)
    validated = validate_staged_ai(output / "ai", lock)
    smoke_test(output / "ai", lock)
    print(
        json.dumps(
            {
                "model": validated["model"]["artifact"],
                "runtime": validated["runtime"]["revision"],
                "runtime_build": str(runtime["build"]),
                "result": "PASS",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from None
