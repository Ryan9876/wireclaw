import ast
import errno
import hashlib
import importlib.util
import json
import plistlib
import tarfile
import urllib.error
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

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
                "tag_commit": "d81235049384534c167caea52b85a694f6103d14",
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
    assert metadata["runtime_argv_template"][-2:] == ["--cache-ram", "0"]
    assert metadata["runtime_argv_template"][-4:-2] == ["--no-agent", "--no-webui"]
    assert metadata["policy"] == {
        "default_provider_mode": "embedded_local",
        "port": 8767,
        "context_size": 16384,
        "batch_size": 128,
        "micro_batch_size": 32,
        "max_tokens": 2048,
        "parallel": 1,
        "prompt_cache_ram_mib": 0,
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
    app = release / "ai/WireclawAI.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": "com.wireclaw.WireclawAI"})
    )
    (app / "Contents/MacOS/WireclawAI").write_bytes(b"wrapper")
    (app / "Contents/MacOS/llama-server").write_bytes(b"helper")
    (release / "README.md").write_text("candidate", encoding="utf-8")
    (release / "ai/models/model.gguf").write_bytes(b"fixture-model")
    (release / "release-metadata.json").write_text(
        json.dumps(
            {
                "source_sha": "a" * 40,
                "embedded_ai": {"model": {"id": "fixture"}},
                "signed_app": {
                    "path": "ai/WireclawAI.app",
                    "bundle_identifier": "com.wireclaw.WireclawAI",
                    "signing_mode": "adhoc",
                    "signing_identity": "-",
                    "hardened_runtime": False,
                    "developer_id_validation": "NOT_RUN",
                    "production_qualification": "NOT_RUN",
                    "notarization": "NOT_RUN",
                    "stapling": "NOT_RUN",
                    "model_sha256": "b" * 64,
                    "llama_server_sha256": "c" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    freezer = module_at(ROOT / "scripts/freeze_embedded_ai_candidate.py", "freeze_candidate")

    def codesign_runner(argv, **_kwargs):
        target = Path(argv[-1])
        if "--verify" in argv:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "-dv" in argv:
            identifier = (
                "llama-server" if target.name == "llama-server" else "com.wireclaw.WireclawAI"
            )
            details = f"Identifier={identifier}\nSignature=adhoc\nTeamIdentifier=not set\nflags=0x0"
            return SimpleNamespace(returncode=0, stdout="", stderr=details)
        entitlements = (
            {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": True}
            if target.name == "llama-server"
            else {
                "com.apple.security.app-sandbox": True,
                "com.apple.security.network.server": True,
            }
        )
        return SimpleNamespace(
            returncode=0, stdout=plistlib.dumps(entitlements).decode(), stderr=""
        )

    first = freezer.freeze_candidate(
        release, tmp_path / "candidate-one.tar", codesign_runner=codesign_runner
    )
    second = freezer.freeze_candidate(
        release, tmp_path / "candidate-two.tar", codesign_runner=codesign_runner
    )
    assert first["archive_sha256"] == second["archive_sha256"]
    assert (tmp_path / "candidate-one.tar").read_bytes() == (
        tmp_path / "candidate-two.tar"
    ).read_bytes()
    assert first["source_sha"] == "a" * 40
    assert first["embedded_ai"]["model"]["id"] == "fixture"
    assert first["signed_app"]["bundle_identifier"] == "com.wireclaw.WireclawAI"
    with tarfile.open(tmp_path / "candidate-one.tar") as archive:
        assert archive.getnames() == [
            "wireclaw-release",
            "wireclaw-release/README.md",
            "wireclaw-release/ai",
            "wireclaw-release/ai/WireclawAI.app",
            "wireclaw-release/ai/WireclawAI.app/Contents",
            "wireclaw-release/ai/WireclawAI.app/Contents/Info.plist",
            "wireclaw-release/ai/WireclawAI.app/Contents/MacOS",
            "wireclaw-release/ai/WireclawAI.app/Contents/MacOS/WireclawAI",
            "wireclaw-release/ai/WireclawAI.app/Contents/MacOS/llama-server",
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


def test_release_stager_copies_the_approved_logo_into_web_build_context(tmp_path):
    packager = module_at(ROOT / "scripts/package_release.py", "package_release")
    release = tmp_path / "wireclaw-release"
    packager.stage_source_tree(release)
    source_logo = ROOT / "apps/web/public/brand/wireclaw-logo.jpeg"
    staged_logo = release / "apps/web/public/brand/wireclaw-logo.jpeg"
    assert staged_logo.read_bytes() == source_logo.read_bytes()


def test_release_stager_copies_embedded_timeout_default_into_bundle():
    env_template = (ROOT / "wireclaw-release/.env.example").read_text(encoding="utf-8")
    assert "WIRECLAW_PROVIDER_TIMEOUT_SECONDS=120" in env_template
    assert (
        'shutil.copy2(ROOT / "wireclaw-release/.env.example", stage / ".env.example")' in PACKAGER
    )


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


def test_release_signing_pipeline_distinguishes_adhoc_from_production_acceptance():
    workflow = (ROOT / ".github/workflows/gate6-validation.yml").read_text(encoding="utf-8")
    app_builder = (ROOT / "scripts/build_macos_ai_app.py").read_text(encoding="utf-8")
    assert 'choices=("adhoc", "developer-id")' in PACKAGER
    assert "build_signed_ai_app" in PACKAGER and "sign_bundle(app" in PACKAGER
    assert "WIRECLAW_DEVELOPER_IDENTITY" in PACKAGER
    assert "WIRECLAW_NOTARY_PROFILE" in PACKAGER
    assert "notarytool" in PACKAGER and "stapler" in PACKAGER
    assert (
        'signing_options = ["--options", "runtime"] if mode == "developer-id" else []'
        in app_builder
    )
    assert 'has_runtime != (mode == "developer-id")' in app_builder
    assert "nested Developer ID Team IDs do not match" in app_builder
    assert '"hardened_runtime": signing_mode == "developer-id"' in PACKAGER
    assert '"developer_id_validation": "NOT_RUN" if signing_mode == "adhoc" else "PASS"' in PACKAGER
    assert '"production_qualification": "NOT_RUN"' in PACKAGER
    assert 'result["production_qualification"] = "PASS"' not in PACKAGER
    assert '"stapling": "NOT_RUN"' in PACKAGER
    assert (
        "production signing qualification: NOT_RUN (Developer ID identity unavailable)" in PACKAGER
    )
    assert "Developer ID and notarization release qualification: NOT_RUN" in workflow
    assert "--signing-mode developer-id" not in workflow


def test_exact_branch_runs_wireclawai_go_tests_and_vet_in_macos_ci():
    workflow = (ROOT / ".github/workflows/gate6-validation.yml").read_text(encoding="utf-8")
    assert "post-v1-embedded-ai-impl" in workflow
    job = workflow.split("  macos-ai-sandbox-qualification:", 1)[1].split("\n  docker-release:", 1)[
        0
    ]
    assert "working-directory: ai/macos/WireclawAI" in job
    assert "go test ./..." in job
    assert "go vet ./..." in job
    assert "run: |\n          echo 'Developer ID and notarization release qualification:" in job


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
    assert '"docker",\\n                    "build"' not in CONTAINER_VALIDATOR
    assert 'builder.smoke_test(stage / "ai"' in PACKAGER


def test_native_qualification_rejects_unsigned_or_incorrect_app_metadata(tmp_path):
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_qualifier")
    app = tmp_path / "WireclawAI.app"
    info = app / "Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(
        __import__("plistlib").dumps({"CFBundleIdentifier": "com.wireclaw.WireclawAI"})
    )
    wrapper = app / "Contents/MacOS/WireclawAI"
    helper = app / "Contents/MacOS/llama-server"
    wrapper.parent.mkdir(parents=True)
    (app / "Contents/Frameworks").mkdir()
    wrapper.write_bytes(b"fixture wrapper")
    helper.write_bytes(b"fixture helper")

    parent_entitlements = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.server": True,
    }
    helper_entitlements = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.inherit": True,
    }

    def signed_codesign(argv, **_kwargs):
        from types import SimpleNamespace

        path = Path(argv[-1])
        if "--verify" in argv:
            return SimpleNamespace(returncode=0, stdout=b"", stderr="")
        if "-dv" in argv:
            identifier = "com.wireclaw.WireclawAI" if path == wrapper else "llama-server"
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr=f"Identifier={identifier}\nSignature=adhoc\nTeamIdentifier=not set",
            )
        entitlements = parent_entitlements if path == wrapper else helper_entitlements
        return SimpleNamespace(
            returncode=0, stdout=__import__("plistlib").dumps(entitlements), stderr=b""
        )

    qualifier.verify_signed_app_bundle(app, codesign=signed_codesign)

    def hardened_codesign(argv, **_kwargs):
        from types import SimpleNamespace

        if "-dv" in argv:
            identifier = "com.wireclaw.WireclawAI" if Path(argv[-1]) == wrapper else "llama-server"
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr=f"Identifier={identifier}\nflags=0x10000(runtime)",
            )
        return signed_codesign(argv, **_kwargs)

    with pytest.raises(ValueError, match="development_signature_enables_hardened_runtime"):
        qualifier.verify_signed_app_bundle(app, codesign=hardened_codesign)

    def non_adhoc_codesign(argv, **_kwargs):
        from types import SimpleNamespace

        if "-dv" in argv:
            identifier = "com.wireclaw.WireclawAI" if Path(argv[-1]) == wrapper else "llama-server"
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr=f"Identifier={identifier}\nAuthority=Apple Development: Dev (TEAM)",
            )
        return signed_codesign(argv, **_kwargs)

    with pytest.raises(ValueError, match="development_signature_not_adhoc"):
        qualifier.verify_signed_app_bundle(app, codesign=non_adhoc_codesign)

    def unsigned_codesign(argv, **_kwargs):
        from types import SimpleNamespace

        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"code object is not signed")

    with pytest.raises(ValueError, match="signature"):
        qualifier.verify_signed_app_bundle(app, codesign=unsigned_codesign)

    info.write_bytes(__import__("plistlib").dumps({"CFBundleIdentifier": "com.example.wrong"}))
    with pytest.raises(ValueError, match="bundle"):
        qualifier.verify_signed_app_bundle(app, codesign=signed_codesign)

    info.write_bytes(__import__("plistlib").dumps(["not", "a", "dictionary"]))
    with pytest.raises(ValueError, match="metadata"):
        qualifier.verify_signed_app_bundle(app, codesign=signed_codesign)

    info.write_bytes(
        __import__("plistlib").dumps({"CFBundleIdentifier": "com.wireclaw.WireclawAI"})
    )

    def overbroad_codesign(argv, **_kwargs):
        from types import SimpleNamespace

        if "--verify" in argv:
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        if "-dv" in argv:
            identifier = "com.wireclaw.WireclawAI" if Path(argv[-1]) == wrapper else "llama-server"
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr=f"Identifier={identifier}\nSignature=adhoc\nTeamIdentifier=not set",
            )
        entitlements = dict(parent_entitlements)
        entitlements["com.apple.security.network.client"] = True
        return SimpleNamespace(
            returncode=0, stdout=__import__("plistlib").dumps(entitlements), stderr=b""
        )

    with pytest.raises(ValueError, match="entitlements"):
        qualifier.verify_signed_app_bundle(app, codesign=overbroad_codesign)


def test_native_qualification_normalizes_malformed_runtime_manifest_shapes(tmp_path):
    import json

    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_runtime_shape_checks")
    app = tmp_path / "WireclawAI.app"
    resources = app / "Contents/Resources/ai"
    resources.mkdir(parents=True)
    (resources / "model-manifest.json").write_text(
        json.dumps(
            {
                "bundle_identifier": "com.wireclaw.WireclawAI",
                "model_id": qualifier.MODEL_ID,
                "repository": "Qwen/Qwen3-4B-Instruct-2507",
                "revision": "cdbee75f17c01a7cc42f958dc650907174af0554",
                "quantization": "Q4_K_M",
                "architecture": "qwen3",
                "artifact": {
                    "size_bytes": 1,
                    "sha256": __import__("hashlib").sha256(b"x").hexdigest(),
                },
            }
        )
    )
    (resources / "model.gguf").write_bytes(b"x")
    manifest = {
        "bundle_identifier": "com.wireclaw.WireclawAI",
        "build_settings": {"metal": True},
        "policy": {
            "model_alias": qualifier.MODEL_ID,
            "listen_host": "127.0.0.1",
            "port": 8767,
            "context_size": 16384,
            "max_tokens": 2048,
            "parallel": 1,
            "prompt_cache_ram_mib": 0,
        },
        "files": [
            {"path": "macos-arm64/llama-server"},
            {"path": "macos-arm64/libggml-metal.dylib"},
        ],
    }
    runtime_path = resources / "runtime-manifest.json"
    manifest["build_settings"] = []
    runtime_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="runtime_manifest"):
        qualifier.verify_packaged_model_identity(app)

    manifest["build_settings"] = {"metal": True}
    manifest["files"] = [{"path": []}]
    runtime_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="runtime_manifest"):
        qualifier.verify_packaged_model_identity(app)


def test_native_qualification_fixture_contracts_reject_bad_provider_integration(monkeypatch):
    from urllib.request import Request

    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_qualifier_checks")
    model = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    qualifier.validate_auth_rejection(401)
    with pytest.raises(ValueError, match="authentication"):
        qualifier.validate_auth_rejection(200)
    qualifier.validate_model_response(200, {"data": [{"id": model}]})
    sentinel = "f" * 64
    with pytest.raises(ValueError, match="identity") as mismatch:
        qualifier.validate_model_response(200, {"data": [{"id": sentinel}]})
    assert sentinel not in str(mismatch.value)
    with pytest.raises(ValueError, match="request"):
        qualifier.validate_model_response(401, {"data": [{"id": model}]})
    chat_ok = {
        "model": model,
        "choices": [{"message": {"content": "WIRECLAW_TASK10_INFERENCE_OK"}}],
        "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
    }
    qualifier.validate_chat_response(200, chat_ok)
    with pytest.raises(ValueError, match="chat"):
        qualifier.validate_chat_response(200, {"choices": []})
    for invalid_chat in (
        {**chat_ok, "model": "wrong-model"},
        {**chat_ok, "choices": [{"message": {"content": "unrelated output"}}]},
        {**chat_ok, "usage": {"prompt_tokens": 1}},
    ):
        with pytest.raises(ValueError, match="chat"):
            qualifier.validate_chat_response(200, invalid_chat)
    qualifier.validate_core_response_body(b'{"data": []}')
    with pytest.raises(ValueError, match="response"):
        qualifier.validate_core_response_body(b"x" * (qualifier.MAX_CORE_RESPONSE_BYTES + 1))
    assert "response.read(MAX_CORE_RESPONSE_BYTES + 1)" in qualifier.CORE_INTEGRATION_PROBE
    compile(qualifier.CORE_INTEGRATION_PROBE, "<task10-core-probe>", "exec")

    proxy_handler, redirect_handler = qualifier.direct_request_handlers()
    assert proxy_handler.proxies == {}
    assert isinstance(redirect_handler, qualifier.NoRedirectHandler)
    request = Request("http://127.0.0.1:8767/v1/models")
    assert (
        redirect_handler.redirect_request(request, None, 302, "Found", {}, "http://elsewhere/")
        is None
    )
    with pytest.raises(ValueError, match="endpoint"):
        qualifier.validate_provider_endpoint("http://127.0.0.1:8767/v1")
    qualifier.validate_provider_endpoint("http://host.docker.internal:8767/v1")

    qualifier.validate_numeric_listener(["127.0.0.1:8767"])
    with pytest.raises(ValueError, match="listener"):
        qualifier.validate_numeric_listener(["127.0.0.1:8767", "0.0.0.0:8767"])
    with pytest.raises(ValueError, match="listener"):
        qualifier.validate_numeric_listener(["*:8767"])
    qualifier.validate_metal_log("ggml_metal_init: found device: Apple M3 GPU")
    with pytest.raises(ValueError, match="metal"):
        qualifier.validate_metal_log("ggml_metal_init: no usable device found")
    qualifier.validate_core_reachability(0)
    with pytest.raises(ValueError, match="reachability"):
        qualifier.validate_core_reachability(1)
    observed = {}

    def fake_run(_argv, **kwargs):
        observed.update(kwargs)
        from types import SimpleNamespace

        return SimpleNamespace(returncode=1, stdout=sentinel * 1000, stderr=sentinel * 1000)

    monkeypatch.setenv("WIRECLAW_PROVIDER_API_KEY", sentinel)
    monkeypatch.setattr(qualifier.subprocess, "run", fake_run)
    result = qualifier._run_hidden(["fixed-command"])
    assert result.stdout == "" and result.stderr == ""
    assert observed["stdout"] == qualifier.subprocess.DEVNULL
    assert observed["stderr"] == qualifier.subprocess.DEVNULL

    marker = "CORE_AUTH_MODELS_CHAT_WRONG_ENDPOINT=PASS"
    captured = qualifier._run_hidden(
        [
            qualifier.sys.executable,
            "-c",
            "import sys; print('" + marker + "'); print('" + sentinel + "', file=sys.stderr)",
        ],
        capture_stdout=True,
        max_output_bytes=128,
    )
    assert captured.returncode == 0
    assert captured.stdout.strip() == marker
    assert captured.stderr == ""
    assert sentinel not in captured.stdout
    oversized = qualifier._run_hidden(
        [qualifier.sys.executable, "-c", "print('x' * 10000)"],
        capture_stdout=True,
        max_output_bytes=128,
    )
    assert oversized.stdout_truncated is True
    assert len(oversized.stdout.encode()) == 128
    assert "WIRECLAW_PROVIDER_API_KEY" not in observed["env"]
    assert sentinel not in result.stdout and sentinel not in result.stderr


def test_task10_reports_missing_release_model_as_not_run_and_core_probe_is_secret_free(tmp_path):
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_qualifier_preflight")
    assert qualifier.task10_release_prerequisite(tmp_path, environ={}) == "release_app_missing"
    app = tmp_path / "ai/WireclawAI.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Frameworks").mkdir()
    (app / "Contents/Resources/ai").mkdir(parents=True)
    (app / "Contents/MacOS/llama-server").write_bytes(b"fixture")
    (app / "Contents/Frameworks/libggml-metal.dylib").write_bytes(b"fixture")
    assert qualifier.task10_release_prerequisite(tmp_path, environ={}) == "release_model_missing"
    sentinel = "a" * 64
    assert sentinel not in qualifier.CORE_INTEGRATION_PROBE
    assert "WIRECLAW_PROVIDER_API_KEY" in qualifier.CORE_INTEGRATION_PROBE
    assert "host.docker.internal:8768" in qualifier.CORE_INTEGRATION_PROBE


def test_task10_integration_requires_two_completed_cycles_without_shared_state_deletion(tmp_path):
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "task10_cycle_count")
    calls = []

    def completed_cycle(_root):
        calls.append("completed")
        return None

    assert qualifier._run_task10_cycles(tmp_path, cycle_runner=completed_cycle) is None
    assert calls == ["completed", "completed"]

    calls.clear()

    def failed_cycle(_root):
        calls.append("failed")
        return "ai_launcher_start_failed"

    assert (
        qualifier._run_task10_cycles(tmp_path, cycle_runner=failed_cycle)
        == "ai_launcher_start_failed"
    )
    assert calls == ["failed"]


def test_linux_ci_host_gateway_alias_is_opt_in_and_test_only():
    assert 'os.environ.get("WIRECLAW_TEST_HOST_GATEWAY") != "1"' in CONTAINER_VALIDATOR
    assert "host.docker.internal:host-gateway" in CONTAINER_VALIDATOR


def test_core_probe_failure_diagnostics_are_bounded_and_allowlisted():
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_core_failure_codes")
    assert qualifier.normalize_core_probe_failure("chat_request_failed\n") == "chat_request_failed"
    assert (
        qualifier.normalize_core_probe_failure("core_name_resolution_failed\n")
        == "core_name_resolution_failed"
    )
    assert qualifier.normalize_core_probe_failure("Bearer secret-value") is None
    assert qualifier.normalize_core_probe_failure("wrong_endpoint_served_model\n" * 500) is None


def test_core_probe_accepts_expected_closed_wrong_endpoint():
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_wrong_endpoint_probe")
    tree = ast.parse(qualifier.CORE_INTEGRATION_PROBE)
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "request_expected_closed_endpoint"
    )
    namespace = {}
    exec(
        compile(ast.Module(body=[helper], type_ignores=[]), "<wrong-endpoint-helper>", "exec"),
        namespace,
    )

    for error_code in ("core_host_unreachable", "core_connection_refused"):

        def unavailable(_url, token=None, code=error_code):
            raise SystemExit(code)

        namespace["request"] = unavailable
        assert namespace["request_expected_closed_endpoint"]("fixed-url", "fixed-token") == (0, b"")

    def permission_denied(_url, token=None):
        raise SystemExit("core_network_permission_denied")

    namespace["request"] = permission_denied
    with pytest.raises(SystemExit, match="core_network_permission_denied"):
        namespace["request_expected_closed_endpoint"]("fixed-url", "fixed-token")

    def timeout(_url, token=None):
        raise SystemExit("core_connection_timeout")

    namespace["request"] = timeout
    with pytest.raises(SystemExit, match="core_connection_timeout"):
        namespace["request_expected_closed_endpoint"]("fixed-url", "fixed-token")


def test_task10_metal_sample_requires_compute_and_synchronize_frames():
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_metal_sample_contract")
    active_sample = "ggml_metal_graph_compute (in libggml-metal.0.dylib)\nggml_metal_synchronize (in libggml-metal.0.dylib)"
    qualifier.validate_metal_runtime_evidence("", active_sample)
    with pytest.raises(ValueError, match="metal"):
        qualifier.validate_metal_runtime_evidence("", "libggml-metal.0.dylib loaded")


def test_core_probe_keeps_required_endpoints_strict_and_rejects_wrong_model(monkeypatch, capsys):
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_core_probe_simulation")
    key = "a" * 64
    model_body = json.dumps({"data": [{"id": qualifier.MODEL_ID}]}).encode()
    chat_body = json.dumps(
        {
            "model": qualifier.MODEL_ID,
            "choices": [{"message": {"content": qualifier.TASK10_CHAT_EXPECTED}}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
        }
    ).encode()

    class Response:
        def __init__(self, status, body):
            self.status = status
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return self.body

    def run_probe(mode):
        class FakeOpener:
            def open(self, request, timeout):
                parsed = urllib.parse.urlsplit(request.full_url)
                if parsed.port == 8768:
                    if mode == "wrong_endpoint_serves_model":
                        return Response(200, model_body)
                    error = ConnectionRefusedError(111, "connection refused")
                    if mode == "wrong_endpoint_unreachable":
                        error = OSError(errno.EHOSTUNREACH, "host unreachable")
                    raise urllib.error.URLError(error)
                if mode == "required_endpoint_unreachable":
                    raise urllib.error.URLError(OSError(errno.EHOSTUNREACH, "host unreachable"))
                if request.get_header("Authorization") != f"Bearer {key}":
                    raise urllib.error.HTTPError(request.full_url, 401, "unauthorized", {}, None)
                if parsed.path.endswith("/models"):
                    return Response(200, model_body)
                return Response(200, chat_body)

        monkeypatch.setenv("WIRECLAW_PROVIDER_API_KEY", key)
        monkeypatch.setattr(qualifier.urllib.request, "build_opener", lambda *_args: FakeOpener())
        exec(compile(qualifier.CORE_INTEGRATION_PROBE, "<core-probe>", "exec"), {})

    run_probe("wrong_endpoint_unreachable")
    assert capsys.readouterr().out.strip() == "CORE_AUTH_MODELS_CHAT_WRONG_ENDPOINT=PASS"
    with pytest.raises(SystemExit, match="core_host_unreachable"):
        run_probe("required_endpoint_unreachable")
    with pytest.raises(SystemExit, match="wrong_endpoint_served_model"):
        run_probe("wrong_endpoint_serves_model")


def test_metal_sample_reader_enforces_size_limit_and_removes_file(tmp_path):
    qualifier = module_at(ROOT / "scripts/qualify_macos_embedded_ai.py", "ai_metal_sample_cleanup")

    class FinishedProcess:
        def wait(self, timeout):
            return 0

        def poll(self):
            return 0

    sample_path = tmp_path / "sample.txt"
    sample_path.write_text("ggml_metal_graph_compute", encoding="utf-8")
    assert (
        qualifier._finish_metal_sample((FinishedProcess(), sample_path))
        == "ggml_metal_graph_compute"
    )
    assert not sample_path.exists()
    sample_path.write_bytes(b"x" * (qualifier.MAX_METAL_SAMPLE_BYTES + 1))
    assert qualifier._finish_metal_sample((FinishedProcess(), sample_path)) == ""
    assert not sample_path.exists()
