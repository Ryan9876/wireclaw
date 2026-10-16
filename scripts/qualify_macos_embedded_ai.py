#!/usr/bin/env python3
"""Run the opt-in signed native App Sandbox boundary probe on Apple Silicon."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import plistlib
import re
import selectors
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]

PARENT_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.network.server": True,
}
HELPER_ENTITLEMENTS = {
    "com.apple.security.app-sandbox": True,
    "com.apple.security.inherit": True,
}

MODEL_ID = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
PROVIDER_ENDPOINT = "http://host.docker.internal:8767/v1"
MAX_CORE_RESPONSE_BYTES = 65_536
TASK10_CHAT_PROMPT = "Reply exactly with WIRECLAW_TASK10_INFERENCE_OK."
TASK10_CHAT_EXPECTED = "WIRECLAW_TASK10_INFERENCE_OK"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def direct_request_handlers():
    """Return handlers that bypass proxies and reject HTTP redirects."""
    return urllib.request.ProxyHandler({}), NoRedirectHandler()


def direct_no_redirect_opener():
    return urllib.request.build_opener(*direct_request_handlers())


def validate_auth_rejection(status: int) -> None:
    if status != 401:
        raise ValueError("ai_authentication_missing")


def validate_model_response(status: int, payload: dict, expected_model: str = MODEL_ID) -> None:
    if status != 200:
        raise ValueError("ai_model_request_failed")
    records = payload.get("data") if isinstance(payload, dict) else None
    identities = (
        [item.get("id") for item in records if isinstance(item, dict)]
        if isinstance(records, list)
        else []
    )
    if identities != [expected_model]:
        raise ValueError("ai_model_identity_mismatch")


def validate_chat_response(
    status: int,
    payload: dict,
    expected_model: str = MODEL_ID,
    expected_content: str = TASK10_CHAT_EXPECTED,
) -> None:
    if status != 200:
        raise ValueError("ai_chat_request_failed")
    if not isinstance(payload, dict) or payload.get("model") != expected_model:
        raise ValueError("ai_chat_response_invalid")
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("ai_chat_response_invalid")
    message = choices[0].get("message")
    if (
        not isinstance(message, dict)
        or not isinstance(message.get("content"), str)
        or message["content"] != expected_content
    ):
        raise ValueError("ai_chat_response_invalid")
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        raise ValueError("ai_chat_response_invalid")
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    total_tokens = usage.get("total_tokens")
    if (
        any(type(value) is not int or value <= 0 for value in (prompt_tokens, completion_tokens))
        or type(total_tokens) is not int
        or total_tokens != prompt_tokens + completion_tokens
    ):
        raise ValueError("ai_chat_response_invalid")


def validate_core_response_body(raw: bytes) -> bytes:
    if len(raw) > MAX_CORE_RESPONSE_BYTES:
        raise ValueError("ai_core_response_too_large")
    return raw


def validate_numeric_listener(addresses: list[str]) -> None:
    if addresses != ["127.0.0.1:8767"]:
        raise ValueError("ai_listener_identity_mismatch")


def validate_metal_log(log_text: str) -> None:
    normalized = log_text.lower()
    if "ggml_metal_init: found device:" not in normalized:
        raise ValueError("ai_metal_device_unverified")


def validate_core_reachability(returncode: int) -> None:
    if returncode != 0:
        raise ValueError("ai_core_reachability_failed")


def validate_provider_endpoint(endpoint: str) -> None:
    if endpoint != PROVIDER_ENDPOINT:
        raise ValueError("ai_provider_endpoint_invalid")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_packaged_model_identity(app: Path) -> None:
    """Check release-sized model metadata and bytes before starting services."""
    resources = app / "Contents/Resources/ai"
    try:
        model = json.loads((resources / "model-manifest.json").read_text(encoding="utf-8"))
        runtime = json.loads((resources / "runtime-manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise ValueError("ai_model_manifest_invalid") from None
    expected = {
        "bundle_identifier": "com.wireclaw.WireclawAI",
        "model_id": MODEL_ID,
        "repository": "Qwen/Qwen3-4B-Instruct-2507",
        "revision": "cdbee75f17c01a7cc42f958dc650907174af0554",
        "quantization": "Q4_K_M",
        "architecture": "qwen3",
    }
    if not isinstance(model, dict) or any(
        model.get(field) != value for field, value in expected.items()
    ):
        raise ValueError("ai_model_identity_mismatch")
    artifact = model.get("artifact")
    model_file = resources / "model.gguf"
    if (
        model_file.is_symlink()
        or not model_file.is_file()
        or not isinstance(artifact, dict)
        or type(artifact.get("size_bytes")) is not int
        or not 0 < artifact["size_bytes"] <= 3_758_096_384
        or model_file.stat().st_size != artifact["size_bytes"]
        or not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", "")))
        or _sha256_file(model_file) != artifact["sha256"]
    ):
        raise ValueError("ai_model_artifact_invalid")
    if not isinstance(runtime, dict):
        raise ValueError("ai_runtime_manifest_invalid")
    build_settings = runtime.get("build_settings")
    policy = runtime.get("policy")
    runtime_files = runtime.get("files")
    if (
        not isinstance(build_settings, dict)
        or not isinstance(policy, dict)
        or not isinstance(runtime_files, list)
        or any(
            not isinstance(item, dict) or not isinstance(item.get("path"), str)
            for item in runtime_files
        )
    ):
        raise ValueError("ai_runtime_manifest_invalid")
    if (
        runtime.get("bundle_identifier") != "com.wireclaw.WireclawAI"
        or build_settings.get("metal") is not True
        or policy.get("model_alias") != MODEL_ID
        or policy.get("listen_host") != "127.0.0.1"
        or policy.get("port") != 8767
        or policy.get("context_size") != 16384
        or policy.get("max_tokens") != 2048
        or policy.get("parallel") != 1
        or policy.get("prompt_cache_ram_mib") != 0
    ):
        raise ValueError("ai_runtime_policy_invalid")
    if not {item["path"] for item in runtime_files} >= {
        "macos-arm64/llama-server",
        "macos-arm64/libggml-metal.dylib",
    }:
        raise ValueError("ai_metal_runtime_missing")
    metal_library = app / "Contents/Frameworks/libggml-metal.dylib"
    if metal_library.is_symlink() or not metal_library.is_file():
        raise ValueError("ai_metal_runtime_missing")


def task10_release_prerequisite(root: Path, *, environ=None) -> str | None:
    """Return a bounded NOT_RUN reason before touching a host installation."""
    env = os.environ if environ is None else environ
    root = Path(root)
    if not root.is_dir():
        return "release_bundle_missing"
    app = root / "ai/WireclawAI.app"
    if not app.is_dir():
        return "release_app_missing"
    if not (app / "Contents/Resources/ai/model.gguf").is_file():
        return "release_model_missing"
    if (
        not (app / "Contents/MacOS/llama-server").is_file()
        or not (app / "Contents/Frameworks/libggml-metal.dylib").is_file()
    ):
        return "release_runtime_missing"
    required = (
        root / ".env",
        root / "compose.yaml",
        root / "core-image.tar",
        root / "core-image-id",
        root / "launch/macos/start.sh",
        root / "launch/macos/stop.sh",
    )
    if any(not path.exists() for path in required):
        return "release_assets_missing"
    if env.get("WIRECLAW_PROVIDER_API_KEY"):
        return "host_key_environment_present"
    try:
        settings = {}
        for line in (root / ".env").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                settings[key] = value
    except (OSError, UnicodeError):
        return "release_configuration_unreadable"
    if settings.get("WIRECLAW_PROVIDER_MODE") != "embedded_local":
        return "embedded_provider_not_configured"
    if settings.get("WIRECLAW_PROVIDER_API_KEY", ""):
        return "persistent_provider_key_present"
    support = Path.home() / "Library/Application Support/Wireclaw"
    run_dir = support / "run"
    if run_dir.is_symlink():
        return "existing_wireclaw_lifecycle_state"
    if any(
        (run_dir / name).exists() or (run_dir / name).is_symlink()
        for name in ("ai-host-receipt.json", "ai-status", "bridge.pid")
    ):
        return "existing_wireclaw_lifecycle_state"
    private = (
        Path.home()
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    if private.is_symlink() or (private.exists() and any(private.iterdir())):
        return "existing_ai_private_state"
    if not (support / "bin/wireclaw-host-bridge").is_file():
        return "host_bridge_missing"
    if not Path("/Applications/Wireshark.app/Contents/MacOS/Wireshark").is_file() and not env.get(
        "WIRECLAW_WIRESHARK_PATH"
    ):
        return "wireshark_missing"
    if env.get("WIRECLAW_WIRESHARK_PATH") and not Path(env["WIRECLAW_WIRESHARK_PATH"]).is_file():
        return "wireshark_missing"
    return None


CORE_INTEGRATION_PROBE = textwrap.dedent(
    r"""
    import json, os, urllib.error, urllib.request
    BASE = "http://host.docker.internal:8767/v1"
    MODEL = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        type("NoRedirect", (urllib.request.HTTPRedirectHandler,),
             {"redirect_request": lambda *args: None})())
    key = os.environ.get("WIRECLAW_PROVIDER_API_KEY", "")
    if not key or len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise SystemExit("invalid_core_provider_state")
    MAX_CORE_RESPONSE_BYTES = 65536
    def request(url, token=None, body=None):
        headers = {"Authorization": "Bearer " + token} if token is not None else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with opener.open(req, timeout=120) as response:
                raw = response.read(MAX_CORE_RESPONSE_BYTES + 1)
                if len(raw) > MAX_CORE_RESPONSE_BYTES:
                    raise SystemExit("core_response_too_large")
                return response.status, raw
        except urllib.error.HTTPError as error:
            return error.code, b""
    for path, body in (("/models", None), ("/chat/completions", json.dumps({
        "model": MODEL, "messages": [{"role": "user", "content": "Reply exactly with WIRECLAW_TASK10_INFERENCE_OK."}],
        "max_tokens": 16, "temperature": 0}).encode())):
        status, _ = request(BASE + path, body=body)
        if status != 401:
            raise SystemExit("unauthenticated_request_accepted")
        wrong = "0" * 64 if key != "0" * 64 else "1" * 64
        status, _ = request(BASE + path, token=wrong, body=body)
        if status != 401:
            raise SystemExit("wrong_key_accepted")
    status, raw = request(BASE + "/models", token=key)
    try:
        models = json.loads(raw)
    except (ValueError, UnicodeError):
        raise SystemExit("model_response_invalid")
    ids = [item.get("id") for item in models.get("data", []) if isinstance(item, dict)]
    if status != 200 or ids != [MODEL]:
        raise SystemExit("model_identity_mismatch")
    body = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "Reply exactly with WIRECLAW_TASK10_INFERENCE_OK."}],
        "max_tokens": 16, "temperature": 0}).encode()
    status, raw = request(BASE + "/chat/completions", token=key, body=body)
    try:
        chat = json.loads(raw)
        content = chat["choices"][0]["message"]["content"]
        usage = chat["usage"]
    except (ValueError, UnicodeError, KeyError, IndexError, TypeError):
        raise SystemExit("chat_response_invalid")
    if (status != 200 or chat.get("model") != MODEL or content != "WIRECLAW_TASK10_INFERENCE_OK"
            or not isinstance(usage, dict)
            or type(usage.get("prompt_tokens")) is not int or usage["prompt_tokens"] <= 0
            or type(usage.get("completion_tokens")) is not int or usage["completion_tokens"] <= 0
            or type(usage.get("total_tokens")) is not int
            or usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]):
        raise SystemExit("chat_request_failed")
    wrong_status, wrong_body = request("http://host.docker.internal:8768/v1/models", token=key)
    try:
        wrong_ids = [item.get("id") for item in json.loads(wrong_body).get("data", []) if isinstance(item, dict)]
    except (ValueError, UnicodeError, AttributeError):
        wrong_ids = []
    if wrong_status == 200 and MODEL in wrong_ids:
        raise SystemExit("wrong_endpoint_served_model")
    print("CORE_AUTH_MODELS_CHAT_WRONG_ENDPOINT=PASS")
    """
).strip()


def _load_lifecycle_module():
    path = ROOT / "launch/macos/ai_lifecycle.py"
    spec = importlib.util.spec_from_file_location("wireclaw_ai_lifecycle_qualification", path)
    if spec is None or spec.loader is None:
        raise ValueError("ai_lifecycle_primitives_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _compose(root: Path, *args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(root / ".env"),
        "-f",
        str(root / "compose.yaml"),
        *args,
    ]


def _run_hidden(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 180,
    capture_stdout: bool = False,
    max_output_bytes: int = 4096,
):
    env = {key: value for key, value in os.environ.items() if key != "WIRECLAW_PROVIDER_API_KEY"}
    try:
        if not capture_stdout:
            result = subprocess.run(
                argv,
                cwd=cwd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout,
                env=env,
            )
            return SimpleNamespace(
                returncode=result.returncode, stdout="", stderr="", stdout_truncated=False
            )

        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        assert process.stdout is not None
        captured = bytearray()
        truncated = False
        deadline = time.monotonic() + timeout
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key_event, _ in selector.select(remaining):
                    block = os.read(key_event.fd, 4096)
                    if not block:
                        selector.unregister(key_event.fileobj)
                        continue
                    room = max_output_bytes + 1 - len(captured)
                    if room > 0:
                        captured.extend(block[:room])
                    if len(block) > room or len(captured) > max_output_bytes:
                        truncated = True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            returncode = process.wait(timeout=remaining)
        except (subprocess.TimeoutExpired, OSError):
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
        finally:
            selector.close()
            process.stdout.close()
        return SimpleNamespace(
            returncode=returncode,
            stdout=bytes(captured[:max_output_bytes]).decode("utf-8", errors="replace"),
            stderr="",
            stdout_truncated=truncated,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _readiness_and_listener(root: Path) -> int:
    support = Path.home() / "Library/Application Support/Wireclaw"
    run_dir = support / "run"
    receipt_path = run_dir / "ai-host-receipt.json"
    status_path = run_dir / "ai-status"
    helper = root / "ai/WireclawAI.app/Contents/MacOS/llama-server"
    try:
        if status_path.read_text(encoding="utf-8").strip() != "ready":
            raise ValueError("ai_helper_not_ready")
        lifecycle = _load_lifecycle_module()
        identity = lifecycle.read_receipt(receipt_path, str(helper))
        if not lifecycle._verified(identity, str(helper), lifecycle.inspect_process):
            raise ValueError("ai_helper_identity_unverified")
    except (OSError, ValueError):
        raise ValueError("ai_helper_identity_unverified") from None
    listener = _run_hidden(
        [
            "/usr/sbin/lsof",
            "-nP",
            "-a",
            "-p",
            str(identity["pid"]),
            "-iTCP:8767",
            "-sTCP:LISTEN",
            "-Fn",
        ],
        capture_stdout=True,
    )
    if listener is None or listener.returncode or listener.stdout_truncated:
        raise ValueError("ai_listener_unavailable")
    addresses = [line[1:] for line in listener.stdout.splitlines() if line.startswith("n")]
    validate_numeric_listener(addresses)
    return identity["pid"]


def _verify_metal_runtime_log() -> None:
    state = (
        Path.home()
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
        / "runtime.log"
    )
    try:
        info = state.stat()
        if info.st_size > 1_048_576:
            raise ValueError("ai_runtime_log_invalid")
        contents = state.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raise ValueError("ai_runtime_log_unavailable") from None
    validate_metal_log(contents)


def _run_core_integration(root: Path) -> None:
    validate_provider_endpoint(PROVIDER_ENDPOINT)
    result = _run_hidden(
        _compose(root, "exec", "-T", "wireclaw-core", "python", "-c", CORE_INTEGRATION_PROBE),
        cwd=root,
        timeout=180,
        capture_stdout=True,
    )
    if (
        result is None
        or result.returncode
        or result.stdout_truncated
        or result.stdout.strip() != "CORE_AUTH_MODELS_CHAT_WRONG_ENDPOINT=PASS"
    ):
        raise ValueError("ai_core_integration_failed")


def _stop_and_verify(root: Path, helper_pid: int | None) -> None:
    stop_script = root / "launch/macos/stop.sh"
    result = _run_hidden([str(stop_script)], cwd=root, timeout=180)
    if result is None or result.returncode:
        raise ValueError("ai_cleanup_failed")
    support = Path.home() / "Library/Application Support/Wireclaw"
    run_dir = support / "run"
    private = (
        Path.home()
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    if any(
        (run_dir / name).exists() or (run_dir / name).is_symlink()
        for name in ("ai-host-receipt.json", "ai-status", "bridge.pid")
    ):
        raise ValueError("ai_host_state_cleanup_failed")
    if any(
        (private / name).exists() or (private / name).is_symlink()
        for name in ("api-key", "process.json")
    ):
        raise ValueError("ai_private_state_cleanup_failed")
    if helper_pid is not None and _load_lifecycle_module().inspect_process(helper_pid) is not None:
        raise ValueError("ai_helper_exit_unconfirmed")
    remaining = _run_hidden(
        _compose(root, "ps", "-aq", "wireclaw-core"), cwd=root, capture_stdout=True
    )
    if (
        remaining is None
        or remaining.returncode
        or remaining.stdout_truncated
        or remaining.stdout.strip()
    ):
        raise ValueError("ai_core_container_cleanup_failed")


def run_task10_integration(root: Path) -> int:
    """Run the real packaged app/Core path, or report a precise NOT_RUN reason."""
    root = Path(root).resolve()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("Task 10 packaged inference/Core integration: NOT_RUN (macOS arm64 required)")
        return 0
    missing = task10_release_prerequisite(root)
    if missing:
        print(f"Task 10 packaged inference/Core integration: NOT_RUN ({missing})")
        return 0
    app = root / "ai/WireclawAI.app"
    try:
        verify_signed_app_bundle(app)
        verify_packaged_model_identity(app)
    except ValueError as error:
        print(f"Task 10 packaged inference/Core integration: FAIL ({error})", file=sys.stderr)
        return 1

    for argv in (["docker", "info"], ["docker", "compose", "version"]):
        check = _run_hidden(list(argv), cwd=root, timeout=30)
        if check is None or check.returncode:
            print(
                "Task 10 packaged inference/Core integration: NOT_RUN (Docker Engine unavailable)"
            )
            return 0
    active = _run_hidden(
        _compose(root, "ps", "-q", "wireclaw-core"),
        cwd=root,
        timeout=30,
        capture_stdout=True,
    )
    if active is None or active.returncode or active.stdout_truncated:
        print("Task 10 packaged inference/Core integration: NOT_RUN (Compose state unavailable)")
        return 0
    if active.stdout.strip():
        print("Task 10 packaged inference/Core integration: NOT_RUN (Core is already running)")
        return 0

    start_attempted = False
    failure = None
    helper_pid = None
    try:
        start_attempted = True
        started = _run_hidden([str(root / "launch/macos/start.sh")], cwd=root, timeout=600)
        if started is None or started.returncode:
            raise ValueError("ai_launcher_start_failed")
        helper_pid = _readiness_and_listener(root)
        _run_core_integration(root)
        _verify_metal_runtime_log()
    except ValueError as error:
        failure = str(error)
    except (OSError, subprocess.SubprocessError):
        failure = "ai_integration_command_failed"
    finally:
        if start_attempted:
            try:
                _stop_and_verify(root, helper_pid)
            except ValueError as error:
                failure = str(error)
    if failure:
        print(f"Task 10 packaged inference/Core integration: FAIL ({failure})", file=sys.stderr)
        return 1
    print("Task 10 packaged inference/Core integration: PASS")
    print("DEVELOPMENT_SIGNING=PASS (ad-hoc App Sandbox; Hardened Runtime disabled)")
    print("PRODUCTION_HARDENED_RUNTIME_VALIDATION=NOT_RUN")
    print("DEVELOPER_ID_VALIDATION=NOT_RUN")
    print("NOTARIZATION=NOT_RUN")
    print("STAPLING=NOT_RUN")
    return 0


def verify_signed_app_bundle(app: Path, *, codesign=subprocess.run) -> None:
    """Validate fixed bundle metadata and signatures without running the app."""
    app = Path(app)
    if app.is_symlink() or not app.is_dir():
        raise ValueError("ai_bundle_missing")
    info_path = app / "Contents/Info.plist"
    wrapper = app / "Contents/MacOS/WireclawAI"
    helper = app / "Contents/MacOS/llama-server"
    if any(path.is_symlink() for path in app.rglob("*")):
        raise ValueError("ai_bundle_layout_invalid")
    if any(path.is_symlink() or not path.is_file() for path in (info_path, wrapper, helper)):
        raise ValueError("ai_bundle_layout_invalid")
    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException):
        raise ValueError("ai_bundle_metadata_invalid") from None
    if not isinstance(info, dict):
        raise ValueError("ai_bundle_metadata_invalid")
    if info.get("CFBundleIdentifier") != "com.wireclaw.WireclawAI":
        raise ValueError("ai_bundle_identity_invalid")

    frameworks = app / "Contents/Frameworks"
    if frameworks.is_symlink() or not frameworks.is_dir():
        raise ValueError("ai_bundle_layout_invalid")
    nested_code = sorted(
        path
        for path in frameworks.rglob("*")
        if path.is_file() and (path.suffix == ".dylib" or os.access(path, os.X_OK))
    )
    if any(path.is_symlink() or not path.is_file() for path in nested_code):
        raise ValueError("ai_bundle_layout_invalid")
    signed_code = (app, wrapper, helper, *nested_code)
    for path in signed_code:
        verified = codesign(
            [
                "/usr/bin/codesign",
                "--verify",
                "--deep",
                "--strict",
                "--verbose=4",
                str(path),
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        if verified.returncode:
            raise ValueError("ai_bundle_signature_invalid")
        details = codesign(
            ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)],
            capture_output=True,
            check=False,
            text=True,
        )
        if details.returncode:
            raise ValueError("ai_bundle_signature_invalid")
        signature_details = details.stdout + details.stderr
        if re.search(r"flags=.*\bruntime\b", signature_details):
            raise ValueError("ai_bundle_development_signature_enables_hardened_runtime")
        if not re.search(r"^Signature=adhoc$", signature_details, flags=re.MULTILINE):
            raise ValueError("ai_bundle_development_signature_not_adhoc")

    for path, expected, identifier in (
        (wrapper, PARENT_ENTITLEMENTS, "com.wireclaw.WireclawAI"),
        (helper, HELPER_ENTITLEMENTS, "llama-server"),
    ):
        details = codesign(
            ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)],
            capture_output=True,
            check=False,
            text=True,
        )
        if details.returncode or f"Identifier={identifier}" not in details.stderr:
            raise ValueError("ai_bundle_code_identity_invalid")
        dumped = codesign(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(path)],
            capture_output=True,
            check=False,
            text=False,
        )
        if dumped.returncode:
            raise ValueError("ai_bundle_entitlements_invalid")
        try:
            actual = plistlib.loads(dumped.stdout)
        except (ValueError, plistlib.InvalidFileException):
            raise ValueError("ai_bundle_entitlements_invalid") from None
        if actual != expected:
            raise ValueError("ai_bundle_entitlements_invalid")
    for path in nested_code:
        details = codesign(
            ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)],
            capture_output=True,
            check=False,
            text=True,
        )
        if details.returncode or f"Identifier={path.name}" not in details.stderr:
            raise ValueError("ai_bundle_code_identity_invalid")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--task10-release-root",
        type=Path,
        help="run the opt-in packaged app/Core inference qualification",
    )
    args = parser.parse_args()
    if args.task10_release_root is not None:
        return run_task10_integration(args.task10_release_root)
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("Task 9 native qualification requires macOS arm64", file=sys.stderr)
        return 2
    env = os.environ.copy()
    env["WIRECLAW_NATIVE_TASK9"] = "1"
    result = subprocess.run(
        ["go", "test", "-run", "^TestNativeTask9Isolation$", "-count=1", "-v"],
        cwd=ROOT / "ai/macos/WireclawAI",
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = result.stdout
    if result.returncode:
        # The probe output is fixed and secret-free. Bound diagnostics even on failure.
        print(output[-4096:], end="" if output.endswith("\n") else "\n")
        return result.returncode
    # Preserve explicit DENIED/NOT_RUN evidence while keeping output bounded.
    print(output[-4096:], end="" if output.endswith("\n") else "\n")
    print("Task 9 signed App Sandbox isolation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
