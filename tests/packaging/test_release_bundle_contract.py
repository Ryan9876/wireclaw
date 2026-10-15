import hashlib
import importlib.util
import json
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGER = (ROOT / "scripts/package_release.py").read_text(encoding="utf-8")
CONTAINER_VALIDATOR = (ROOT / "scripts/validate_container_release.py").read_text(encoding="utf-8")


def module_at(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_ai(tmp_path):
    ai = tmp_path / "source-ai"
    (ai / "models").mkdir(parents=True)
    (ai / "macos-arm64").mkdir()
    (ai / "licenses").mkdir()
    model = b"fixture-model"
    server = b"fixture-server"
    metal = b"fixture-metal"
    (ai / "models/qwen3-4b-instruct-2507-q4_k_m.gguf").write_bytes(model)
    (ai / "macos-arm64/llama-server").write_bytes(server)
    (ai / "macos-arm64/libggml-metal.dylib").write_bytes(metal)
    (ai / "licenses/Qwen-Apache-2.0.txt").write_text("Apache-2.0", encoding="utf-8")
    (ai / "licenses/llama.cpp-MIT.txt").write_text("MIT", encoding="utf-8")

    def record(path, data):
        return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}

    (ai / "model-manifest.json").write_text(
        json.dumps(
            {
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
                "artifact": record("models/qwen3-4b-instruct-2507-q4_k_m.gguf", model),
                "source_files": [record("config.json", b"fixture-source")],
                "license_path": "licenses/Qwen-Apache-2.0.txt",
                "build": {
                    "llama_cpp_commit": "8345f333951c661d166b00e6f9362e553768f292",
                    "conversion": ["convert_hf_to_gguf.py", "--outtype", "f16"],
                    "quantization": ["llama-quantize", "Q4_K_M"],
                },
            }
        ),
        encoding="utf-8",
    )
    (ai / "runtime-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository": "ggml-org/llama.cpp",
                "tag": "v0.6.0",
                "revision": "8345f333951c661d166b00e6f9362e553768f292",
                "platform": "macos",
                "architecture": "arm64",
                "build_settings": {"metal": True, "server": True, "cmake_version": "cmake 4"},
                "entrypoint": "macos-arm64/llama-server",
                "files": [
                    record("macos-arm64/llama-server", server),
                    record("macos-arm64/libggml-metal.dylib", metal),
                ],
                "license_paths": ["licenses/llama.cpp-MIT.txt"],
                "policy": {
                    "platform": "macos",
                    "architecture": "arm64",
                    "listen_host": "127.0.0.1",
                    "port": 8767,
                    "context_size": 16384,
                    "max_tokens": 2048,
                    "parallel": 1,
                    "model_alias": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
                    "authentication_required": True,
                    "agent_tools": False,
                    "web_ui": False,
                    "network_downloads": False,
                },
            }
        ),
        encoding="utf-8",
    )
    return ai


def test_package_stages_verified_ai_assets_and_release_identities(tmp_path):
    source = fixture_ai(tmp_path)
    release = tmp_path / "wireclaw-release"
    release.mkdir()
    metadata = module_at(ROOT / "scripts/package_release.py", "package_release").stage_embedded_ai(
        source, release
    )
    assert (
        release / "ai/models/qwen3-4b-instruct-2507-q4_k_m.gguf"
    ).read_bytes() == b"fixture-model"
    assert (release / "ai/macos-arm64/llama-server").read_bytes() == b"fixture-server"
    assert (release / "ai/licenses/Qwen-Apache-2.0.txt").is_file()
    assert metadata["model"]["source_revision"] == "cdbee75f17c01a7cc42f958dc650907174af0554"
    assert metadata["model"]["quantization"] == "Q4_K_M"
    assert metadata["model"]["size_bytes"] == len(b"fixture-model")
    assert metadata["model"]["sha256"] == hashlib.sha256(b"fixture-model").hexdigest()
    assert metadata["runtime"]["revision"] == "8345f333951c661d166b00e6f9362e553768f292"
    assert metadata["runtime"]["files"]
    assert len(metadata["licenses"]) == 2
    assert all(len(item["sha256"]) == 64 for item in metadata["licenses"])
    assert len(metadata["model_manifest_sha256"]) == 64
    assert len(metadata["runtime_manifest_sha256"]) == 64
    assert metadata["policy"] == {
        "default_provider_mode": "embedded_local",
        "port": 8767,
        "context_size": 16384,
        "max_tokens": 2048,
        "parallel": 1,
        "platform": "macos",
        "architecture": "arm64",
    }


@pytest.mark.parametrize("failure", ["tampered", "missing", "unmanifested"])
def test_package_refuses_unverified_or_incomplete_ai_stage(tmp_path, failure):
    source = fixture_ai(tmp_path)
    if failure == "tampered":
        (source / "models/qwen3-4b-instruct-2507-q4_k_m.gguf").write_bytes(b"tampered")
    elif failure == "missing":
        (source / "macos-arm64/libggml-metal.dylib").unlink()
    else:
        (source / "macos-arm64/extra-tool").write_bytes(b"not-in-manifest")
    release = tmp_path / "wireclaw-release"
    release.mkdir()
    with pytest.raises((ValueError, OSError)):
        module_at(ROOT / "scripts/package_release.py", "package_release").stage_embedded_ai(
            source, release
        )


def test_candidate_archive_is_deterministic_for_identical_release_tree(tmp_path):
    release = tmp_path / "wireclaw-release"
    (release / "ai/models").mkdir(parents=True)
    (release / "README.md").write_text("candidate", encoding="utf-8")
    (release / "ai/models/model.gguf").write_bytes(b"fixture-model")
    (release / "release-metadata.json").write_text(
        json.dumps({"source_sha": "a" * 40, "embedded_ai": {"model": {"id": "fixture"}}}),
        encoding="utf-8",
    )
    freezer = module_at(ROOT / "scripts/freeze_embedded_ai_candidate.py", "freeze_candidate")
    first = freezer.freeze_candidate(release, tmp_path / "candidate-one.tar")
    second = freezer.freeze_candidate(release, tmp_path / "candidate-two.tar")
    assert first["archive_sha256"] == second["archive_sha256"]
    assert (tmp_path / "candidate-one.tar").read_bytes() == (
        tmp_path / "candidate-two.tar"
    ).read_bytes()
    assert first["source_sha"] == "a" * 40
    assert first["embedded_ai"]["model"]["id"] == "fixture"
    with tarfile.open(tmp_path / "candidate-one.tar") as archive:
        assert archive.getnames() == [
            "wireclaw-release",
            "wireclaw-release/README.md",
            "wireclaw-release/ai",
            "wireclaw-release/ai/models",
            "wireclaw-release/ai/models/model.gguf",
            "wireclaw-release/release-metadata.json",
        ]


def test_packaged_launcher_does_not_fetch_or_build_ai_at_startup():
    launchers = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "launch/macos").glob("*.sh")
    )
    assert "huggingface" not in launchers.lower()
    assert "hf download" not in launchers
    assert "github.com/ggml-org/llama.cpp" not in launchers
    assert "curl https://" not in launchers
    assert "wget https://" not in launchers
    assert "git clone" not in launchers


def test_release_stager_includes_the_production_build_context_and_native_launchers():
    for required in (
        '"Dockerfile"',
        '"compose.yaml"',
        '".env.example"',
        '".dockerignore"',
        '"docker"',
        '"contracts"',
        '"services/analyzer/src/wireclaw_analyzer"',
        '"services/api/src/wireclaw_api"',
        '"launch/macos"',
        '"core-image.tar"',
        '"core-image-id"',
        '"ai"',
        '"--embedded-ai-stage"',
    ):
        assert required in PACKAGER
    assert '"host-bridge/macos"' in PACKAGER
    assert '"README.md"' in PACKAGER


def test_release_readme_documents_staged_bundle_and_platform_scope():
    readme = " ".join((ROOT / "wireclaw-release/README.md").read_text(encoding="utf-8").split())
    assert "macOS arm64" in readme
    assert "host-bridge/macos" in readme
    assert "launch/macos/start.sh" in readme
    assert "core-image.tar" in readme
    assert "core-image-id" in readme
    assert (
        "Windows and Linux embedded-AI implementation and qualification are outside this stage"
        in readme
    )
    assert "no model or runtime download" in readme
    assert "Qwen3-4B-Instruct-2507 Q4_K_M" in readme


def test_container_acceptance_reuses_frozen_image_for_mounted_tls_privacy_test():
    assert 'command.extend(["-d", "--no-build"])' in CONTAINER_VALIDATOR
    assert 'compose(env, "up", files=host_route_files)' in CONTAINER_VALIDATOR
    assert "privacy_files = (*host_route_files, override)" in CONTAINER_VALIDATOR
    assert 'compose(env, "up", files=privacy_files)' in CONTAINER_VALIDATOR
    assert '"wireclaw-core:gate8"' in CONTAINER_VALIDATOR
    assert '"candidate_certifi_bundle_unavailable"' in CONTAINER_VALIDATOR
    assert '"candidate_default_ca_bundle_unavailable"' in CONTAINER_VALIDATOR
    assert "target: {json.dumps(candidate_bundle_path)}\\n" in CONTAINER_VALIDATOR
    assert '"        read_only: true\\n"' in CONTAINER_VALIDATOR
    assert '"docker",\n                    "build"' not in CONTAINER_VALIDATOR
    assert 'builder.smoke_test(stage / "ai"' in PACKAGER


def test_linux_ci_host_gateway_alias_is_opt_in_and_test_only():
    assert 'os.environ.get("WIRECLAW_TEST_HOST_GATEWAY") != "1"' in CONTAINER_VALIDATOR
    assert "host.docker.internal:host-gateway" in CONTAINER_VALIDATOR
