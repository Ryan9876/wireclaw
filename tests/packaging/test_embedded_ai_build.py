import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_embedded_ai", ROOT / "scripts/build_embedded_ai.py"
)


def builder():
    if SPEC is None or SPEC.loader is None:
        raise AssertionError("builder module cannot be loaded")
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    return module


def artifact(path: Path, value: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {"path": path.name, "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}


def fixture_ai(tmp_path):
    root = tmp_path / "ai"
    model = artifact(root / "models/qwen3-4b-instruct-2507-q4_k_m.gguf", b"fixture-model")
    server = artifact(root / "macos-arm64/llama-server", b"fixture-server")
    resource = artifact(root / "macos-arm64/libggml-metal.dylib", b"fixture-resource")
    artifact(root / "licenses/Qwen-Apache-2.0.txt", b"Apache License 2.0")
    artifact(root / "licenses/llama.cpp-MIT.txt", b"MIT License")
    source_file = {"path": "config.json", "sha256": "c" * 64, "size_bytes": 100}
    model_manifest = {
        "schema_version": 1,
        "model_id": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        "repository": "Qwen/Qwen3-4B-Instruct-2507",
        "revision": "cdbee75f17c01a7cc42f958dc650907174af0554",
        "license": "Apache-2.0",
        "quantization": "Q4_K_M",
        "architecture": "qwen3",
        "architecture_validation": {
            "metadata_field": "general.architecture",
            "reader": "gguf-py from pinned llama.cpp source",
        },
        "artifact": {**model, "path": "models/qwen3-4b-instruct-2507-q4_k_m.gguf"},
        "source_files": [source_file],
        "license_path": "licenses/Qwen-Apache-2.0.txt",
        "build": {
            "llama_cpp_commit": "8345f333951c661d166b00e6f9362e553768f292",
            "conversion": ["convert_hf_to_gguf.py", "--outtype", "f16"],
            "quantization_command": ["llama-quantize", "Q4_K_M"],
        },
    }
    runtime_manifest = {
        "schema_version": 1,
        "repository": "ggml-org/llama.cpp",
        "tag": "v0.6.0",
        "revision": "8345f333951c661d166b00e6f9362e553768f292",
        "platform": "macos",
        "architecture": "arm64",
        "build_settings": {
            "metal": True,
            "server": True,
            "cmake_version": "cmake version 4.4.4",
            "xcode_version": "Xcode 27.0.1; Build version 18A123",
        },
        "entrypoint": "macos-arm64/llama-server",
        "files": [
            {**server, "path": "macos-arm64/llama-server"},
            {**resource, "path": "macos-arm64/libggml-metal.dylib"},
        ],
        "license_paths": ["licenses/llama.cpp-MIT.txt"],
        "policy": {
            "platform": "macos",
            "architecture": "arm64",
            "listen_host": "127.0.0.1",
            "port": 8767,
            "context_size": 16384,
            "batch_size": 128,
            "micro_batch_size": 32,
            "max_tokens": 2048,
            "parallel": 1,
            "model_alias": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
            "authentication_required": True,
            "agent_tools": False,
            "web_ui": False,
            "network_downloads": False,
        },
    }
    (root / "licenses").mkdir(parents=True, exist_ok=True)
    for relative, value in (
        ("model-manifest.json", model_manifest),
        ("runtime-manifest.json", runtime_manifest),
    ):
        (root / relative).write_text(json.dumps(value), encoding="utf-8")
    return root, model_manifest, runtime_manifest


def test_embedded_ai_lock_pins_exact_model_runtime_and_policy():
    lock = builder().load_lock(ROOT / "ai/embedded-ai.lock.json")
    assert lock["model"]["repository"] == "Qwen/Qwen3-4B-Instruct-2507"
    assert lock["model"]["revision"] == "cdbee75f17c01a7cc42f958dc650907174af0554"
    assert lock["model"]["quantization"] == "Q4_K_M"
    assert lock["model"]["gguf_architecture"] == "qwen3"
    assert lock["model"]["id"] == "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    assert lock["model"]["artifact"] == "models/qwen3-4b-instruct-2507-q4_k_m.gguf"
    assert lock["model"]["max_size_bytes"] == 3_758_096_384
    assert lock["runtime"]["repository"] == "ggml-org/llama.cpp"
    assert lock["runtime"]["url"] == "https://github.com/ggml-org/llama.cpp.git"
    assert lock["runtime"]["tag"] == "v0.6.0"
    assert lock["runtime"]["revision"] == "8345f333951c661d166b00e6f9362e553768f292"
    assert lock["conversion"]["huggingface_hub_version"] == "0.34.4"
    assert lock["policy"]["context_size"] == 16384
    assert lock["policy"]["batch_size"] == 128
    assert lock["policy"]["micro_batch_size"] == 32
    assert lock["policy"]["max_tokens"] == 2048
    assert lock["policy"]["parallel"] == 1
    assert lock["policy"]["port"] == 8767


def test_no_model_or_native_runtime_binary_is_tracked():
    tracked = subprocess.run(
        ["git", "ls-files", "*.gguf", "*/llama-server", "ai/staging/**", "ai/build/**"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert tracked == []


def test_staged_manifests_verify_model_runtime_and_license_artifacts(tmp_path):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, _, _ = fixture_ai(tmp_path)
    validated = module.validate_staged_ai(ai_root, lock)
    assert validated["model"]["model_id"] == lock["model"]["id"]
    assert validated["runtime"]["revision"] == lock["runtime"]["revision"]


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("revision", "model_revision_mismatch"),
        ("hash", "model_hash_mismatch"),
        ("oversized", "model_size_limit"),
        ("license", "license_missing"),
        ("runtime_resource", "runtime_resource_missing"),
        ("model_id", "model_id_mismatch"),
        ("traversal", "manifest_path_invalid"),
    ],
)
def test_staged_validation_fails_closed_for_untrusted_manifest_or_assets(
    tmp_path, mutation, expected
):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, model, runtime = fixture_ai(tmp_path)
    if mutation == "revision":
        model["revision"] = "0" * 40
    elif mutation == "hash":
        model["artifact"]["sha256"] = "0" * 64
    elif mutation == "oversized":
        model["artifact"]["size_bytes"] = lock["model"]["max_size_bytes"] + 1
    elif mutation == "license":
        (ai_root / model["license_path"]).unlink()
    elif mutation == "runtime_resource":
        (ai_root / "macos-arm64/libggml-metal.dylib").unlink()
    elif mutation == "model_id":
        model["model_id"] = "other-model"
    elif mutation == "traversal":
        model["artifact"]["path"] = "../outside.gguf"
    (ai_root / "model-manifest.json").write_text(json.dumps(model), encoding="utf-8")
    (ai_root / "runtime-manifest.json").write_text(json.dumps(runtime), encoding="utf-8")
    with pytest.raises(ValueError, match=expected):
        module.validate_staged_ai(ai_root, lock)


def test_runtime_manifest_commit_or_resource_tamper_fails_closed(tmp_path):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, _model, runtime = fixture_ai(tmp_path)
    runtime["revision"] = "0" * 40
    (ai_root / "runtime-manifest.json").write_text(json.dumps(runtime), encoding="utf-8")
    with pytest.raises(ValueError, match="runtime_revision_mismatch"):
        module.validate_staged_ai(ai_root, lock)


def test_staged_validation_rejects_symlink_substitution_outside_release_root(tmp_path):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, _model, _runtime = fixture_ai(tmp_path)
    model_path = ai_root / lock["model"]["artifact"]
    model_path.unlink()
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"fixture-model")
    model_path.symlink_to(outside)
    with pytest.raises(ValueError, match="manifest_symlink_invalid"):
        module.validate_staged_ai(ai_root, lock)


def test_source_lock_rejects_runtime_commit_drift(tmp_path):
    module = builder()
    lock = json.loads((ROOT / "ai/embedded-ai.lock.json").read_text(encoding="utf-8"))
    lock["runtime"]["revision"] = "0" * 40
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(ValueError, match="source_lock_identity_mismatch"):
        module.load_lock(path)


def test_converter_dependency_lock_uses_uv_environment_freeze(monkeypatch, tmp_path):
    module = builder()
    calls = []

    def fake_run(argv, *, cwd=None, env=None):
        calls.append((argv, env))
        return "transformers==4.0.0"

    monkeypatch.setattr(module, "_run", fake_run)
    python = tmp_path / "convert-venv/bin/python"
    env = {"UV_CACHE_DIR": str(tmp_path / "uv-cache")}
    assert module.freeze_dependencies(python, env) == "transformers==4.0.0"
    assert calls == [(["uv", "pip", "freeze", "--python", str(python)], env)]


def test_gguf_architecture_must_match_the_pinned_qwen_architecture():
    module = builder()
    assert module.require_gguf_architecture("qwen3", "qwen3") == "qwen3"
    with pytest.raises(ValueError, match="model_architecture_mismatch"):
        module.require_gguf_architecture("llama", "qwen3")
