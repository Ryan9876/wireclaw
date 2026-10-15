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
    return {
        "path": path.name,
        "sha256": hashlib.sha256(value).hexdigest(),
        "size_bytes": len(value),
    }


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
        "tag_commit": "d81235049384534c167caea52b85a694f6103d14",
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
            "prompt_cache_ram_mib": 0,
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
    assert lock["policy"]["prompt_cache_ram_mib"] == 0
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
    assert validated["runtime"]["policy"]["prompt_cache_ram_mib"] == 0


def test_runtime_smoke_argv_pins_prompt_cache_policy(monkeypatch, tmp_path):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, _, _ = fixture_ai(tmp_path)
    observed = {}

    class Process:
        def terminate(self):
            observed["terminated"] = True

        def wait(self, timeout=None):
            return 0

    def popen(argv, **_kwargs):
        observed["argv"] = argv
        return Process()

    class Response:
        status = 200

        def __init__(self, value):
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(self.value).encode()

    def urlopen(request, **_kwargs):
        if request.full_url.endswith("/models") and not request.headers.get("Authorization"):
            raise module.urllib.error.HTTPError(request.full_url, 401, "unauthorized", {}, None)
        if request.full_url.endswith("/models"):
            return Response({"data": [{"id": lock["policy"]["model_alias"]}]})
        return Response({"choices": [{"message": {"content": "ready"}}]})

    monkeypatch.setattr(module.subprocess, "Popen", popen)
    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(module, "_wait_ready", lambda *_args: None)
    module.smoke_test(ai_root, lock)
    argv = observed["argv"]
    assert argv[-2:] == ["--cache-ram", "0"]
    assert observed["terminated"] is True


def test_runtime_smoke_fails_closed_when_required_prompt_cache_flag_is_rejected(
    monkeypatch, tmp_path
):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, _, _ = fixture_ai(tmp_path)

    class ExitedProcess:
        def poll(self):
            return 64

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 64

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: ExitedProcess())
    with pytest.raises(ValueError, match="runtime_smoke_process_exit"):
        module.smoke_test(ai_root, lock)


def test_runtime_policy_rejects_unspecified_runtime_flags(tmp_path):
    module = builder()
    source_lock = json.loads((ROOT / "ai/embedded-ai.lock.json").read_text(encoding="utf-8"))
    source_lock["policy"]["extra_runtime_flag"] = "--unsafe-value"
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(source_lock), encoding="utf-8")
    with pytest.raises(ValueError, match="source_lock_identity_mismatch"):
        module.load_lock(path)


def test_runtime_cache_policy_rejects_boolean_zero(tmp_path):
    module = builder()
    source_lock = json.loads((ROOT / "ai/embedded-ai.lock.json").read_text(encoding="utf-8"))
    source_lock["policy"]["prompt_cache_ram_mib"] = False
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(source_lock), encoding="utf-8")
    with pytest.raises(ValueError, match="source_lock_identity_mismatch"):
        module.load_lock(path)


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


def test_runtime_manifest_requires_exact_prompt_cache_policy(tmp_path):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, _model, runtime = fixture_ai(tmp_path)
    runtime["policy"]["prompt_cache_ram_mib"] = 8192
    (ai_root / "runtime-manifest.json").write_text(json.dumps(runtime), encoding="utf-8")
    with pytest.raises(ValueError, match="runtime_policy_mismatch"):
        module.validate_staged_ai(ai_root, lock)


def test_runtime_manifest_rejects_boolean_prompt_cache_zero(tmp_path):
    module = builder()
    lock = module.load_lock(ROOT / "ai/embedded-ai.lock.json")
    ai_root, _model, runtime = fixture_ai(tmp_path)
    runtime["policy"]["prompt_cache_ram_mib"] = False
    (ai_root / "runtime-manifest.json").write_text(json.dumps(runtime), encoding="utf-8")
    with pytest.raises(ValueError, match="runtime_policy_mismatch"):
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


def test_runtime_checkout_reuses_verified_pinned_cache_without_network(monkeypatch, tmp_path):
    module = builder()
    work = tmp_path / "work"
    repo = work / "llama.cpp"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "wireclaw@example.invalid"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "Wireclaw Test"], cwd=repo, check=True)
    (repo / "source.txt").write_text("pinned source", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "pinned source"], cwd=repo, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["git", "tag", "v0.6.0", revision], cwd=repo, check=True)
    source = tmp_path / "upstream.git"
    subprocess.run(
        ["git", "clone", "--bare", str(repo), str(source)], check=True, capture_output=True
    )
    subprocess.run(["git", "remote", "add", "origin", str(source)], cwd=repo, check=True)
    lock = {
        "runtime": {
            "url": str(source),
            "revision": revision,
            "tag": "v0.6.0",
            "tag_revision": revision,
        }
    }
    real_run = module._run
    commands = []

    def offline_run(argv, *, cwd=None, env=None):
        commands.append(argv)
        if argv[:2] == ["git", "fetch"]:
            raise AssertionError("pinned cached checkout should not fetch")
        return real_run(argv, cwd=cwd, env=env)

    monkeypatch.setattr(module, "_run", offline_run)
    assert module._repo(work, lock) == repo
    assert not any(argv[:2] == ["git", "fetch"] for argv in commands)
    assert (
        subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
        ).stdout.strip()
        == revision
    )


def test_runtime_checkout_clones_clean_source_before_pinning_revision(tmp_path):
    module = builder()
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source_repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "wireclaw@example.invalid"],
        cwd=source_repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Wireclaw Test"], cwd=source_repo, check=True)
    (source_repo / "source.txt").write_text("pinned source", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=source_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "pinned source"], cwd=source_repo, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source_repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "tag", "v0.6.0", revision], cwd=source_repo, check=True)
    bare_source = tmp_path / "upstream.git"
    subprocess.run(
        ["git", "clone", "--bare", str(source_repo), str(bare_source)],
        check=True,
        capture_output=True,
    )
    work = tmp_path / "work"
    lock = {
        "runtime": {
            "url": str(bare_source),
            "revision": revision,
            "tag": "v0.6.0",
            "tag_revision": revision,
        }
    }

    repo = module._repo(work, lock)

    assert (repo / "source.txt").read_text(encoding="utf-8") == "pinned source"
    assert (
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )


def test_runtime_checkout_rejects_dirty_cached_source(monkeypatch, tmp_path):
    module = builder()
    work = tmp_path / "work"
    repo = work / "llama.cpp"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "wireclaw@example.invalid"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "Wireclaw Test"], cwd=repo, check=True)
    (repo / "source.txt").write_text("pinned source", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "pinned source"], cwd=repo, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["git", "tag", "v0.6.0", revision], cwd=repo, check=True)
    source = tmp_path / "upstream.git"
    subprocess.run(
        ["git", "clone", "--bare", str(repo), str(source)], check=True, capture_output=True
    )
    subprocess.run(["git", "remote", "add", "origin", str(source)], cwd=repo, check=True)
    (repo / "source.txt").write_text("modified source", encoding="utf-8")
    lock = {
        "runtime": {
            "url": str(source),
            "revision": revision,
            "tag": "v0.6.0",
            "tag_revision": revision,
        }
    }

    with pytest.raises(ValueError, match="runtime_source_cache_dirty"):
        module._repo(work, lock)


def test_runtime_checkout_rejects_tag_that_does_not_match_locked_tag_commit(tmp_path):
    module = builder()
    work = tmp_path / "work"
    repo = work / "llama.cpp"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "wireclaw@example.invalid"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "Wireclaw Test"], cwd=repo, check=True)
    (repo / "source.txt").write_text("tag source", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "tag source"], cwd=repo, check=True)
    tag_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["git", "tag", "v0.6.0", tag_revision], cwd=repo, check=True)
    (repo / "source.txt").write_text("later pinned source", encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "pinned source"], cwd=repo, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    source = tmp_path / "upstream.git"
    subprocess.run(
        ["git", "clone", "--bare", str(repo), str(source)], check=True, capture_output=True
    )
    subprocess.run(["git", "remote", "add", "origin", str(source)], cwd=repo, check=True)
    lock = {
        "runtime": {
            "url": str(source),
            "revision": revision,
            "tag": "v0.6.0",
            "tag_revision": revision,
        }
    }

    with pytest.raises(ValueError, match="runtime_tag_revision_mismatch"):
        module._repo(work, lock)


@pytest.mark.parametrize(
    "dependency",
    ["@rpath/../../../outside/libggml-metal.dylib", "@loader_path/../../outside.dylib"],
)
def test_runtime_relocation_rejects_dependency_path_escape(monkeypatch, tmp_path, dependency):
    module = builder()
    runtime = tmp_path / "ai/macos-arm64"
    runtime.mkdir(parents=True)
    (runtime / "llama-server").write_bytes(b"server")
    (runtime / "libggml-metal.dylib").write_bytes(b"bundled file with colliding basename")

    def fake_run(argv, *, cwd=None, env=None):
        if argv[0] == "otool" and argv[1] == "-l":
            return "Load command 1\n cmd LC_RPATH\n path @loader_path (offset 12)\n"
        if argv[0] == "otool" and argv[1] == "-L":
            return f"{argv[2]}:\n\t{dependency} (compatibility version 1.0.0)\n"
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    with pytest.raises(ValueError, match="runtime_dependency_path_invalid"):
        module.relocate_macos_runtime(runtime, tmp_path / "llama-build/bin")


def test_runtime_relocation_rejects_traversal_rpath(monkeypatch, tmp_path):
    module = builder()
    runtime = tmp_path / "ai/macos-arm64"
    runtime.mkdir(parents=True)
    (runtime / "llama-server").write_bytes(b"server")

    def fake_run(argv, *, cwd=None, env=None):
        if argv[0] == "otool" and argv[1] == "-l":
            return (
                "Load command 1\n cmd LC_RPATH\n path @loader_path/../../../outside (offset 12)\n"
            )
        if argv[0] == "otool" and argv[1] == "-L":
            return f"{argv[2]}:\\n"
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    with pytest.raises(ValueError, match="runtime_external_rpath"):
        module.relocate_macos_runtime(runtime, tmp_path / "llama-build/bin")


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


def test_runtime_relocation_removes_build_tree_rpaths_and_uses_packaged_libraries(
    monkeypatch, tmp_path
):
    module = builder()
    runtime = tmp_path / "ai/macos-arm64"
    runtime.mkdir(parents=True)
    (runtime / "llama-server").write_bytes(b"server")
    (runtime / "libllama.0.dylib").write_bytes(b"library")
    build_bin = str(tmp_path / "llama-build/bin")
    commands = []
    removed = set()
    added = set()

    def fake_run(argv, *, cwd=None, env=None):
        commands.append(argv)
        if argv[0] == "otool" and argv[1] == "-l":
            path = argv[2]
            if path in added:
                return "Load command 1\n cmd LC_RPATH\n path @loader_path (offset 12)\n"
            if path in removed:
                return ""
            return (
                "Load command 1\n          cmd LC_RPATH\n      cmdsize 48\n"
                f"         path {build_bin} (offset 12)\n"
            )
        if argv[0] == "install_name_tool" and argv[1] == "-delete_rpath":
            removed.add(argv[3])
        if argv[0] == "install_name_tool" and argv[1] == "-add_rpath":
            added.add(argv[3])
        if argv[0] == "otool" and argv[1] == "-L":
            return (
                f"{argv[2]}:\n"
                "\t@rpath/libllama.0.dylib (compatibility version 0.0.0, current version 0.0.0)\n"
                "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1359.0.0)\n"
            )
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    module.relocate_macos_runtime(runtime, Path(build_bin))
    assert [
        "install_name_tool",
        "-delete_rpath",
        build_bin,
        str(runtime / "llama-server"),
    ] in commands
    assert [
        "install_name_tool",
        "-add_rpath",
        "@loader_path",
        str(runtime / "llama-server"),
    ] in commands


def test_runtime_relocation_accepts_system_framework_dependency(monkeypatch, tmp_path):
    module = builder()
    runtime = tmp_path / "ai/macos-arm64"
    runtime.mkdir(parents=True)
    (runtime / "llama-server").write_bytes(b"server")

    def fake_run(argv, *, cwd=None, env=None):
        if argv[0] == "otool" and argv[1] == "-l":
            return "Load command 1\n cmd LC_RPATH\n path @loader_path (offset 12)\n"
        if argv[0] == "otool" and argv[1] == "-L":
            return (
                f"{argv[2]}:\\n"
                "\\t/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation "
                "(compatibility version 300.0.0)\\n"
            )
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    module.relocate_macos_runtime(runtime, tmp_path / "llama-build/bin")


def test_runtime_relocation_rejects_unbundled_absolute_dependencies(monkeypatch, tmp_path):
    module = builder()
    runtime = tmp_path / "ai/macos-arm64"
    runtime.mkdir(parents=True)
    (runtime / "llama-server").write_bytes(b"server")

    def fake_run(argv, *, cwd=None, env=None):
        if argv[0] == "otool" and argv[1] == "-l":
            return "Load command 1\n cmd LC_RPATH\n path @loader_path (offset 12)\n"
        if argv[0] == "otool" and argv[1] == "-L":
            return f"{argv[2]}:\n\t/private/tmp/llama-build/libfoo.dylib (compatibility version 1.0.0)\n"
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    with pytest.raises(ValueError, match="runtime_external_dependency"):
        module.relocate_macos_runtime(runtime, tmp_path / "llama-build/bin")


def test_runtime_relocation_rejects_system_prefixed_dependency_that_escapes(monkeypatch, tmp_path):
    module = builder()
    runtime = tmp_path / "ai/macos-arm64"
    runtime.mkdir(parents=True)
    (runtime / "llama-server").write_bytes(b"server")

    def fake_run(argv, *, cwd=None, env=None):
        if argv[0] == "otool" and argv[1] == "-l":
            return "Load command 1\n cmd LC_RPATH\n path @loader_path (offset 12)\n"
        if argv[0] == "otool" and argv[1] == "-L":
            return (
                f"{argv[2]}:\n"
                "\t/System/Library/../../private/tmp/libevil.dylib "
                "(compatibility version 1.0.0)\n"
            )
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    with pytest.raises(ValueError, match="runtime_external_dependency"):
        module.relocate_macos_runtime(runtime, tmp_path / "llama-build/bin")


def test_runtime_relocation_rejects_system_prefixed_rpath_that_escapes(monkeypatch, tmp_path):
    module = builder()
    runtime = tmp_path / "ai/macos-arm64"
    runtime.mkdir(parents=True)
    (runtime / "llama-server").write_bytes(b"server")

    def fake_run(argv, *, cwd=None, env=None):
        if argv[0] == "otool" and argv[1] == "-l":
            return (
                "Load command 1\n cmd LC_RPATH\n path @loader_path (offset 12)\n"
                "Load command 2\n cmd LC_RPATH\n "
                "path /System/Library/../../private/tmp (offset 12)\n"
            )
        if argv[0] == "otool" and argv[1] == "-L":
            return f"{argv[2]}:\n"
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    with pytest.raises(ValueError, match="runtime_external_rpath"):
        module.relocate_macos_runtime(runtime, tmp_path / "llama-build/bin")


def test_runtime_aliases_are_copied_as_regular_packaged_libraries(tmp_path):
    module = builder()
    build_bin = tmp_path / "llama-build/bin"
    runtime = tmp_path / "ai/macos-arm64"
    build_bin.mkdir(parents=True)
    runtime.mkdir(parents=True)
    actual = build_bin / "libllama.0.6.0.dylib"
    actual.write_bytes(b"versioned-library")
    (build_bin / "libllama.0.dylib").symlink_to(actual.name)

    module._copy_macos_dylib_aliases(build_bin, runtime)

    alias = runtime / "libllama.0.dylib"
    assert alias.is_file()
    assert not alias.is_symlink()
    assert alias.read_bytes() == actual.read_bytes()
