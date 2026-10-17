"""Conversion dependencies are fixed inputs, not an after-the-fact inventory."""

import hashlib
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_builder():
    path = ROOT / "scripts/build_embedded_ai.py"
    spec = importlib.util.spec_from_file_location("wireclaw_embedded_builder", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_model_build_installs_the_committed_pinned_conversion_lock(monkeypatch, tmp_path):
    builder = load_builder()
    runtime = tmp_path / "llama.cpp"
    (runtime / "requirements").mkdir(parents=True)
    (runtime / "requirements/requirements-convert_hf_to_gguf.txt").write_text(
        "transformers>=4\n", encoding="utf-8"
    )
    (runtime / "convert_hf_to_gguf.py").touch()
    (tmp_path / "qwen-source").mkdir()
    (tmp_path / "qwen-source/LICENSE").write_text("Apache-2.0", encoding="utf-8")
    commands = []
    lock_file = tmp_path / "conversion-requirements.lock.txt"
    lock_file.write_text("transformers==4.57.6\n", encoding="utf-8")
    monkeypatch.setattr(builder, "_repo", lambda _work, _lock: runtime)
    monkeypatch.setattr(builder, "CONVERSION_REQUIREMENTS_LOCK", lock_file)
    monkeypatch.setattr(builder, "freeze_dependencies", lambda *_args: "transformers==4.57.6")

    def run(argv, **_kwargs):
        commands.append(argv)
        if argv[-1] == "Q4_K_M":
            Path(argv[-2]).write_bytes(b"gguf")
        return ""

    monkeypatch.setattr(builder, "_run", run)
    monkeypatch.setattr(builder, "_source_records", lambda _source: [])
    monkeypatch.setattr(builder, "read_gguf_architecture", lambda *_args: "qwen3")
    monkeypatch.setattr(builder, "require_gguf_architecture", lambda actual, _expected: actual)
    monkeypatch.setattr(
        builder,
        "_file_record",
        lambda *_args: {"path": "fixture", "sha256": "0" * 64, "size_bytes": 1},
    )

    class Model:
        def __getitem__(self, key):
            return {
                "repository": "Qwen/Qwen3-4B-Instruct-2507",
                "revision": "cdbee75f17c01a7cc42f958dc650907174af0554",
                "gguf_architecture": "qwen3",
                "max_size_bytes": 10,
                "license": "Apache-2.0",
                "id": "wireclaw-model",
                "quantization": "Q4_K_M",
                "artifact": "models/model.gguf",
            }[key]

    lock = {
        "model": Model(),
        "conversion": {"huggingface_hub_version": "0.34.4"},
        "runtime": {"revision": "8345f333951c661d166b00e6f9362e553768f292"},
    }
    manifest = builder.build_model(lock, tmp_path, tmp_path / "output")
    install = next(command for command in commands if command[:3] == ["uv", "pip", "install"])
    assert "--require-hashes" in install
    assert "-r" in install
    assert install[install.index("-r") + 1] == str(lock_file)
    assert str(runtime / "requirements/requirements-convert_hf_to_gguf.txt") not in install
    assert (
        manifest["build"]["conversion_dependency_lock_sha256"]
        == hashlib.sha256(lock_file.read_bytes()).hexdigest()
    )


def test_committed_conversion_lock_contains_only_exact_version_pins():
    lock = ROOT / "ai/conversion-requirements.lock.txt"
    lines = [line.strip() for line in lock.read_text(encoding="utf-8").splitlines()]
    pins = [line for line in lines if re.match(r"^[A-Za-z0-9_.-]+==", line)]
    assert pins
    assert all(re.match(r"^[A-Za-z0-9_.-]+==[A-Za-z0-9.+_-]+", pin) for pin in pins)
    assert any("--hash=sha256:" in line for line in lines)
