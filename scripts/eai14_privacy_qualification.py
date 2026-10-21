#!/usr/bin/env python3
"""Run the bounded, synthetic-only EAI.14-16 privacy check on a private copy."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import importlib.util
import json
import os
import re
import secrets
import selectors
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
MODEL_ID = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
PROVIDER_URL = "http://host.docker.internal:8767/v1"
MAX_BODY_BYTES = 1_048_576
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SCAN_FILES = 2048
MAX_DATABASE_ROWS = 100_000
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_SYNTHETIC_PCAP_BYTES = 1 * 1024 * 1024
REQUIRED_SURFACES = (
    "model_context",
    "api_responses",
    "case_database",
    "runtime_logs",
    "core_logs",
    "browser_status",
    "reports",
)
BROWSER_PROBE_METHOD = "bounded_http_ui_probe"
BROWSER_PROBE_RETAINS_ARTIFACTS = False
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_identity_sha256",
        "model_sha256",
        "llama_server_sha256",
        "provider_mode",
        "scenario_id",
        "reviewed_surfaces",
        "sentinel_absent_from_all_surfaces",
    }
)
FINAL_ACTION = {
    "action": "finalize",
    "hypotheses": [],
    "remaining_hypotheses": [],
}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _qualification_module():
    path = ROOT / "scripts/native_embedded_ai_qualification.py"
    spec = importlib.util.spec_from_file_location("native_embedded_ai_qualification", path)
    if spec is None or spec.loader is None:
        raise ValueError("qualification_identity_tool_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivacyProviderFixture:
    """OpenAI-compatible recorder; request secrets and bodies remain memory-only."""

    def __init__(self, synthetic_token: str, sentinels: list[str], *, max_requests: int = 1):
        if (
            not isinstance(synthetic_token, str)
            or len(synthetic_token) < 32
            or not re.fullmatch(r"[A-Za-z0-9_-]+", synthetic_token)
            or not sentinels
            or any(not isinstance(value, str) or not value for value in sentinels)
            or type(max_requests) is not int
            or not 1 <= max_requests <= 4
        ):
            raise ValueError("privacy_fixture_configuration_invalid")
        self._token = synthetic_token
        self._sentinels = tuple(value.encode("utf-8") for value in sentinels)
        self._max_requests = max_requests
        self._expected_case_id: str | None = None
        self._active_case_id: str | None = None
        self._request_count = 0
        self._body_bytes = 0
        self._body_sha256: str | None = None
        self._body_sentinel_absent = False
        self._header_sentinel_absent = False
        self._auth_valid = False
        self._correlated = False
        self._overflow = False
        self._diagnostics = bytearray()
        self._state_lock = threading.Lock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, address: tuple[str, int] = ("127.0.0.1", 0)) -> tuple[str, int]:
        if self._server is not None:
            raise ValueError("privacy_fixture_already_started")
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def log_message(self, _format, *_args):
                return

            def _reply(self, status: int, value: dict) -> None:
                encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(encoded)
                self.close_connection = True

            def _auth_ok(self) -> bool:
                provided = self.headers.get("Authorization", "")
                expected = f"Bearer {fixture._token}"
                return hmac.compare_digest(provided, expected)

            def do_GET(self):
                if self.path != "/v1/models":
                    self._reply(404, {"error": {"message": "not_found"}})
                    return
                if not self._auth_ok():
                    self._reply(401, {"error": {"message": "authentication_required"}})
                    return
                fixture._diagnostics.extend(b"models_request\n")
                self._reply(200, {"data": [{"id": MODEL_ID, "object": "model"}]})

            def do_POST(self):
                if self.path != "/v1/chat/completions":
                    self._reply(404, {"error": {"message": "not_found"}})
                    return
                raw_length = self.headers.get("Content-Length", "")
                if not raw_length.isdecimal() or int(raw_length) > MAX_BODY_BYTES:
                    self._reply(413, {"error": {"message": "request_limit"}})
                    return
                body = self.rfile.read(int(raw_length))
                if len(body) != int(raw_length):
                    self._reply(400, {"error": {"message": "invalid_request"}})
                    return
                fixture._request_count += 1
                fixture._diagnostics.extend(b"chat_completion_request\n")
                fixture._body_bytes = len(body)
                fixture._body_sha256 = hashlib.sha256(body).hexdigest()
                fixture._body_sentinel_absent = all(
                    value not in body for value in fixture._sentinels
                )
                non_auth_headers = b"\n".join(
                    name.encode("utf-8", "replace") + b":" + value.encode("utf-8", "replace")
                    for name, value in self.headers.items()
                    if name.casefold() != "authorization"
                )
                fixture._header_sentinel_absent = all(
                    value not in non_auth_headers for value in fixture._sentinels
                )
                fixture._auth_valid = self._auth_ok()
                fixture._correlated = fixture._request_matches_expected_case(body)
                if fixture._request_count > fixture._max_requests:
                    fixture._overflow = True
                    self._reply(429, {"error": {"message": "request_limit"}})
                    return
                if not fixture._auth_valid:
                    self._reply(401, {"error": {"message": "authentication_required"}})
                    return
                response_body = {
                    "id": "chatcmpl-qualification",
                    "object": "chat.completion",
                    "created": 0,
                    "model": MODEL_ID,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": json.dumps(FINAL_ACTION)},
                            "finish_reason": "stop",
                        }
                    ],
                }
                self._reply(200, response_body)

        try:
            self._server = http.server.ThreadingHTTPServer(address, Handler)
            self._server.daemon_threads = True
            self._server.timeout = 1
        except OSError:
            raise ValueError("privacy_fixture_bind_failed") from None
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._server.server_address[0], self._server.server_address[1]

    def expect_case(self, case_id: str) -> None:
        if not isinstance(case_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", case_id):
            raise ValueError("privacy_case_identity_invalid")
        self._expected_case_id = case_id

    def begin_case_investigation(self, case_id: str) -> None:
        if case_id != self._expected_case_id:
            raise ValueError("privacy_case_identity_invalid")
        with self._state_lock:
            if self._active_case_id is not None or self._request_count:
                raise ValueError("privacy_case_investigation_scope_invalid")
            self._active_case_id = case_id

    def end_case_investigation(self, case_id: str) -> None:
        with self._state_lock:
            if self._active_case_id != case_id:
                raise ValueError("privacy_case_investigation_scope_invalid")
            self._active_case_id = None

    def _request_matches_expected_case(self, raw: bytes) -> bool:
        with self._state_lock:
            scoped_case_id = self._active_case_id
        if self._expected_case_id is None or scoped_case_id != self._expected_case_id:
            return False
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or payload.get("model") != MODEL_ID:
                return False
            messages = payload.get("messages")
            if not isinstance(messages, list):
                return False
            user_message = next(
                item for item in messages if isinstance(item, dict) and item.get("role") == "user"
            )
            content = user_message.get("content")
            if not isinstance(content, str):
                return False
            context = json.loads(content)
            if not isinstance(context, dict):
                return False
            context_case_id = context.get("case_id")
            return context_case_id is None or context_case_id == self._expected_case_id
        except (ValueError, TypeError, KeyError, StopIteration):
            return False

    def result(self) -> dict:
        """Return only bounded, non-secret metadata; never retain body/header values."""
        return {
            "request_observed": self._request_count > 0,
            "request_count": self._request_count,
            "request_body_bytes": self._body_bytes,
            "request_body_sha256": self._body_sha256,
            "model_context_sentinel_absent": self._body_sentinel_absent,
            "non_authorization_header_sentinel_absent": self._header_sentinel_absent,
            "synthetic_authorization_valid": self._auth_valid,
            "request_correlated": self._correlated,
            "request_limit_exceeded": self._overflow,
        }

    def runtime_log_bytes(self) -> bytes:
        """Return event labels only; request headers and body are never logged."""
        return bytes(self._diagnostics)

    def require_pass(self) -> None:
        result = self.result()
        if not result["request_observed"]:
            raise ValueError("privacy_provider_request_missing")
        if result["request_limit_exceeded"] or result["request_count"] != 1:
            raise ValueError("privacy_provider_request_count_invalid")
        if not result["synthetic_authorization_valid"]:
            raise ValueError("privacy_provider_auth_invalid")
        if not result["request_correlated"] or self._active_case_id is not None:
            raise ValueError("privacy_provider_request_uncorrelated")
        if (
            not result["model_context_sentinel_absent"]
            or not result["non_authorization_header_sentinel_absent"]
        ):
            raise ValueError("privacy_sentinel_present")

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                raise ValueError("privacy_fixture_shutdown_timeout")
            self._thread = None
        self._token = ""


def _read_bounded(
    value: bytes | bytearray | Path | bool, *, maximum: int = MAX_SCAN_BYTES
) -> bytes:
    if isinstance(value, bool):
        return b"\x01" if value else b"\x00"
    if isinstance(value, Path):
        if value.is_symlink() or not value.is_file() or value.stat().st_size > maximum:
            raise ValueError("privacy_surface_uninspectable")
        return value.read_bytes()
    if isinstance(value, (bytes, bytearray)) and len(value) <= maximum:
        return bytes(value)
    raise ValueError("privacy_surface_uninspectable")


def verify_surfaces(
    surfaces: dict[str, bytes | bytearray | Path | bool], sentinels: list[str]
) -> dict:
    if not isinstance(surfaces, dict):
        raise ValueError("privacy_surface_set_invalid")
    if set(REQUIRED_SURFACES) - set(surfaces):
        raise ValueError("privacy_surface_missing")
    if set(surfaces) - set(REQUIRED_SURFACES):
        raise ValueError("privacy_surface_set_invalid")
    if not sentinels or any(not isinstance(value, str) or not value for value in sentinels):
        raise ValueError("privacy_sentinel_set_invalid")
    results = {}
    encoded = tuple(value.encode("utf-8") for value in sentinels)
    for name in REQUIRED_SURFACES:
        raw = _read_bounded(surfaces[name])
        if name == "model_context" and surfaces[name] is not True:
            raise ValueError("privacy_sentinel_present")
        if name != "model_context" and any(value in raw for value in encoded):
            raise ValueError("privacy_sentinel_present")
        results[name] = True
    return results


def build_receipt(identity: dict, scenario_id: str, checks: dict[str, bool]) -> dict:
    if not re.fullmatch(r"wireclaw-privacy-[0-9a-f]{16}", scenario_id or ""):
        raise ValueError("privacy_scenario_invalid")
    if set(checks) != set(REQUIRED_SURFACES) or any(value is not True for value in checks.values()):
        raise ValueError("privacy_checks_incomplete")
    try:
        candidate_sha = identity["candidate_identity_sha256"]
        model_sha = identity["signed_app"]["model_sha256"]
        helper_sha = identity["signed_app"]["llama_server_sha256"]
    except (KeyError, TypeError):
        raise ValueError("candidate_identity_mismatch") from None
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (candidate_sha, model_sha, helper_sha)
    ):
        raise ValueError("candidate_identity_mismatch")
    return {
        "schema_version": 1,
        "candidate_identity_sha256": candidate_sha,
        "model_sha256": model_sha,
        "llama_server_sha256": helper_sha,
        "provider_mode": "embedded_local",
        "scenario_id": scenario_id,
        "reviewed_surfaces": list(REQUIRED_SURFACES),
        "sentinel_absent_from_all_surfaces": True,
    }


def validate_receipt(receipt: dict, identity: dict) -> None:
    if (
        not isinstance(receipt, dict)
        or set(receipt) != RECEIPT_FIELDS
        or type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 1
        or receipt.get("candidate_identity_sha256") != identity.get("candidate_identity_sha256")
        or receipt.get("model_sha256") != identity.get("signed_app", {}).get("model_sha256")
        or receipt.get("llama_server_sha256")
        != identity.get("signed_app", {}).get("llama_server_sha256")
    ):
        raise ValueError("candidate_identity_mismatch")
    if (
        receipt.get("provider_mode") != "embedded_local"
        or not re.fullmatch(r"wireclaw-privacy-[0-9a-f]{16}", str(receipt.get("scenario_id", "")))
        or receipt.get("reviewed_surfaces") != list(REQUIRED_SURFACES)
        or receipt.get("sentinel_absent_from_all_surfaces") is not True
    ):
        raise ValueError("privacy_receipt_invalid")


def cleanup_qualification(
    *,
    project_name: str,
    compose_file: Path,
    private_root: Path,
    evidence_output: Path,
    runner=subprocess.run,
) -> None:
    root = Path(private_root)
    output = Path(evidence_output).resolve(strict=False)
    if (
        not re.fullmatch(r"wireclaw-privacy-[0-9a-f]{16}", project_name)
        or root.is_symlink()
        or not root.name.startswith("wireclaw-privacy-")
        or not root.exists()
        or not root.is_dir()
        or output == root.resolve()
        or root.resolve() in output.parents
    ):
        raise ValueError("privacy_cleanup_scope_invalid")
    compose_file = Path(compose_file)
    if root.resolve() not in compose_file.resolve(strict=False).parents:
        raise ValueError("privacy_cleanup_scope_invalid")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("WIRECLAW_", "COMPOSE_"))
        and not re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key, re.IGNORECASE)
    }
    environment["COMPOSE_PROJECT_NAME"] = project_name
    if compose_file.is_file() and not compose_file.is_symlink():
        result = runner(
            [
                "docker",
                "compose",
                "--project-name",
                project_name,
                "--env-file",
                str(compose_file.parent / ".env"),
                "-f",
                str(compose_file),
                "down",
                "--remove-orphans",
                "--volumes",
            ],
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise ValueError("privacy_compose_cleanup_failed")
    result = runner(
        ["/bin/rm", "-rf", str(root)],
        capture_output=True,
        timeout=30,
        check=False,
        env=environment,
    )
    if result.returncode or root.exists():
        raise ValueError("privacy_workspace_cleanup_failed")


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    body=None,
    content_type=None,
    timeout: float = 20,
):
    headers = {"Host": base_url.removeprefix("http://")}
    data = body
    if isinstance(body, dict):
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if content_type:
        headers["Content-Type"] = content_type
    request = Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}), NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            content = response.read(8 * 1024 * 1024 + 1)
            if len(content) > 8 * 1024 * 1024:
                raise ValueError("privacy_api_response_too_large")
            return response.status, content
    except HTTPError as error:
        body = error.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024:
            raise ValueError("privacy_api_response_too_large") from None
        return error.code, body
    except (URLError, OSError, TimeoutError):
        raise ValueError("privacy_api_request_failed") from None


def _run(argv: list[str], *, env: dict, timeout: int, maximum: int = MAX_LOG_BYTES):
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            argv,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout = bytearray()
        stderr = bytearray()
        assert process.stdout is not None and process.stderr is not None
        streams = {process.stdout: stdout, process.stderr: stderr}
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=2)
                raise ValueError("privacy_command_timeout")
            for key, _ in selector.select(remaining):
                captured = streams[key.fileobj]
                room = maximum + 1 - len(stdout) - len(stderr)
                chunk = os.read(key.fd, min(65_536, max(room, 1)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                captured.extend(chunk)
                if len(stdout) + len(stderr) > maximum:
                    process.kill()
                    process.wait(timeout=2)
                    raise ValueError("privacy_command_output_limit")
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except ValueError:
        raise
    except (OSError, subprocess.SubprocessError):
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        raise ValueError("privacy_command_failed") from None
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
    if return_code:
        raise ValueError("privacy_command_failed")
    return bytes(stdout), bytes(stderr)


def _sentinel_capture(sentinels: dict[str, str]) -> bytes:
    fixture_root = ROOT / "tests/fixtures"
    sys.path.insert(0, str(fixture_root))
    try:
        from generate_gate2 import CLIENT, SERVER, tcp, timed_pcap
    except ImportError:
        raise ValueError("privacy_capture_fixture_unavailable") from None
    request = (
        f"GET /{sentinels['raw']} HTTP/1.1\r\n"
        "Host: synthetic.invalid\r\n"
        f"Cookie: session={sentinels['cookie']}\r\n"
        f"Authorization: Bearer {sentinels['bearer']}\r\n"
        f"X-Token: {sentinels['token']}\r\n"
        "Connection: close\r\n\r\n"
        f"{sentinels['payload']}"
    ).encode("ascii")
    response = (
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
        f"Set-Cookie: session={sentinels['cookie']}\r\n"
        "Connection: close\r\n\r\nok"
    ).encode("ascii")
    return timed_pcap(
        [
            (0, tcp(seq=100, ack=0, flags=2)),
            (10_000, tcp(SERVER, CLIENT, seq=200, ack=101, flags=18)),
            (20_000, tcp(seq=101, ack=201)),
            (30_000, tcp(seq=101, ack=201, flags=24, payload=request)),
            (
                40_000,
                tcp(SERVER, CLIENT, seq=201, ack=101 + len(request), flags=24, payload=response),
            ),
        ]
    )


def _scan_database(database: Path, sentinels: list[str]) -> bytes:
    paths = [database, Path(str(database) + "-wal"), Path(str(database) + "-shm")]
    inspected = bytearray()
    total_bytes = 0
    for path in paths:
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
                raise ValueError("privacy_surface_uninspectable")
            content = path.read_bytes()
            total_bytes += len(content)
            if total_bytes > MAX_SCAN_BYTES:
                raise ValueError("privacy_surface_uninspectable")
            if any(value.encode() in content for value in sentinels):
                raise ValueError("privacy_sentinel_present")
            inspected.extend(b"\x00")
    if not database.is_file():
        raise ValueError("privacy_surface_uninspectable")
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2)
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            total_rows = 0
            for (table,) in tables:
                escaped = str(table).replace('"', '""')
                cursor = connection.execute(f'SELECT * FROM "{escaped}"')
                for row in cursor:
                    total_rows += 1
                    if total_rows > MAX_DATABASE_ROWS:
                        raise ValueError("privacy_surface_uninspectable")
                    for cell in row:
                        if isinstance(cell, str):
                            raw = cell.encode("utf-8", "replace")
                        elif isinstance(cell, bytes):
                            raw = cell
                        else:
                            continue
                        total_bytes += len(raw)
                        if total_bytes > 2 * MAX_SCAN_BYTES:
                            raise ValueError("privacy_surface_uninspectable")
                        if any(value.encode() in raw for value in sentinels):
                            raise ValueError("privacy_sentinel_present")
        finally:
            connection.close()
    except sqlite3.Error:
        raise ValueError("privacy_surface_uninspectable") from None
    return bytes(inspected)


def _scan_tree(root: Path, *, patterns: tuple[str, ...], sentinels: list[str]) -> bytes:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("privacy_surface_uninspectable")
    output = bytearray()
    total_bytes = 0
    total_files = 0
    for pattern in patterns:
        for path in root.rglob(pattern):
            total_files += 1
            if total_files > MAX_SCAN_FILES:
                raise ValueError("privacy_surface_uninspectable")
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
                raise ValueError("privacy_surface_uninspectable")
            content = path.read_bytes()
            total_bytes += len(content)
            if total_bytes > MAX_SCAN_BYTES:
                raise ValueError("privacy_surface_uninspectable")
            if any(value.encode() in content for value in sentinels):
                raise ValueError("privacy_sentinel_present")
            output.extend(b"\x00")
    return bytes(output)


def _candidate_context(bundle: Path, archive: Path, metadata_path: Path):
    qualification = _qualification_module()
    if metadata_path.is_symlink() or metadata_path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("candidate_metadata_invalid")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("candidate_metadata_invalid") from None
    identity = qualification.candidate_identity(bundle, archive, frozen_metadata=metadata)
    qualification.verify_candidate_unchanged(bundle, archive, identity, frozen_metadata=metadata)
    return qualification, identity, metadata


def _reject_persisted_provider_key(bundle: Path) -> None:
    for config_file in (bundle / ".env", bundle / ".env.example"):
        if config_file.is_symlink() or not config_file.is_file():
            raise ValueError("candidate_configuration_invalid")
        try:
            lines = config_file.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            raise ValueError("candidate_configuration_invalid") from None
        for line in lines:
            key, separator, value = line.partition("=")
            if (
                separator
                and key.strip() == "WIRECLAW_PROVIDER_API_KEY"
                and value.strip().strip("\"'")
            ):
                raise ValueError("candidate_persistent_provider_key_present")


def _perform(args) -> dict:
    bundle_input = Path(args.candidate_bundle)
    archive_input = Path(args.candidate_archive)
    metadata_input = Path(args.candidate_metadata)
    if bundle_input.is_symlink() or archive_input.is_symlink() or metadata_input.is_symlink():
        raise ValueError("candidate_artifact_invalid")
    bundle = bundle_input.resolve(strict=True)
    archive = archive_input.resolve(strict=True)
    metadata_path = metadata_input.resolve(strict=True)
    output_input = Path(args.receipt_output)
    if output_input.exists() or output_input.is_symlink():
        raise ValueError("privacy_output_invalid")
    output = output_input.resolve(strict=False)
    if output.exists() or output.is_symlink() or bundle in output.parents or archive == output:
        raise ValueError("privacy_output_invalid")
    qualification, identity, metadata = _candidate_context(bundle, archive, metadata_path)
    _reject_persisted_provider_key(bundle)
    scenario_id = "wireclaw-privacy-" + secrets.token_hex(8)
    project_name = scenario_id
    private_root = Path(tempfile.mkdtemp(prefix="wireclaw-privacy-"))
    private_copy = private_root / "candidate"
    data_root = private_root / "isolated-data"
    compose_file = private_copy / "compose.yaml"
    fixture = None
    token = ""
    try:
        private_root.chmod(0o700)
        data_root.mkdir(mode=0o700)
        sentinel_prefixes = {
            "raw": "RAW_CAPTURE_SENTINEL",
            "payload": "PAYLOAD_SENTINEL",
            "cookie": "COOKIE_SENTINEL",
            "bearer": "BEARER_SENTINEL",
            "token": "TOKEN_SENTINEL",
        }
        sentinels = {
            kind: f"{prefix}_{secrets.token_hex(8)}" for kind, prefix in sentinel_prefixes.items()
        }
        token = "TEST_ONLY_" + secrets.token_hex(32)
        private_values = [*sentinels.values(), token]
        fixture = PrivacyProviderFixture(token, private_values)
        if bundle.is_symlink() or not (bundle / "compose.yaml").is_file():
            raise ValueError("candidate_compose_missing")
        if output == private_root or private_root in output.parents:
            raise ValueError("privacy_output_invalid")
        shutil.copytree(bundle, private_copy, symlinks=True)
        private_identity = qualification.candidate_identity(
            private_copy, archive, frozen_metadata=metadata
        )
        if private_identity != identity:
            raise ValueError("candidate_identity_mismatch")
        port = int(os.environ.get("WIRECLAW_AI_PORT", "8767"))
        if port != 8767:
            raise ValueError("privacy_provider_port_invalid")
        fixture_host, fixture_port = fixture.start(("127.0.0.1", port))
        if fixture_host != "127.0.0.1" or fixture_port != 8767:
            raise ValueError("privacy_fixture_bind_failed")
        # Load only the already-packaged image and verify the exact metadata ID.
        image_id = metadata.get("core_image_id")
        image_archive = private_copy / "core-image.tar"
        image_id_file = private_copy / "core-image-id"
        if not image_archive.is_file() or image_id_file.is_symlink() or not image_id_file.is_file():
            raise ValueError("candidate_core_image_missing")
        expected_image_id = image_id_file.read_text(encoding="utf-8").strip()
        if image_id and image_id != expected_image_id:
            raise ValueError("candidate_core_image_identity_mismatch")
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("WIRECLAW_", "COMPOSE_"))
            and not re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key, re.IGNORECASE)
        }
        environment["COMPOSE_PROJECT_NAME"] = project_name
        environment["WIRECLAW_PROVIDER_MODE"] = "embedded_local"
        environment["WIRECLAW_PROVIDER_BASE_URL"] = PROVIDER_URL
        environment["WIRECLAW_PROVIDER_MODEL"] = MODEL_ID
        environment["WIRECLAW_PROVIDER_API_KEY"] = token
        environment["WIRECLAW_DATA_ROOT"] = str(data_root)
        app_port = _free_port()
        bridge_port = _free_port()
        while bridge_port == app_port:
            bridge_port = _free_port()
        environment["WIRECLAW_PORT"] = str(app_port)
        environment["WIRECLAW_BRIDGE_PORT"] = str(bridge_port)
        environment["WIRECLAW_UID"] = str(os.getuid())
        environment["WIRECLAW_GID"] = str(os.getgid())
        compose_argv = [
            "docker",
            "compose",
            "--project-name",
            project_name,
            "--env-file",
            str(private_copy / ".env"),
            "-f",
            str(compose_file),
        ]
        # Use the package's normal image-loading behavior, without building.
        current_image, _ = _run(
            ["docker", "image", "inspect", "wireclaw-core:gate8", "--format", "{{.Id}}"],
            env=environment,
            timeout=15,
            maximum=4096,
        )
        if current_image.decode("utf-8", "replace").strip() != expected_image_id:
            _run(["docker", "load", "--input", str(image_archive)], env=environment, timeout=900)
            current_image, _ = _run(
                ["docker", "image", "inspect", "wireclaw-core:gate8", "--format", "{{.Id}}"],
                env=environment,
                timeout=15,
                maximum=4096,
            )
            if current_image.decode("utf-8", "replace").strip() != expected_image_id:
                raise ValueError("candidate_core_image_identity_mismatch")
        _run(
            [*compose_argv, "up", "-d", "--no-build", "--pull", "never"],
            env=environment,
            timeout=180,
        )
        base_url = f"http://127.0.0.1:{environment['WIRECLAW_PORT']}"
        api_responses = []
        ui_responses = []
        health = None
        readiness_deadline = time.monotonic() + 120
        while time.monotonic() < readiness_deadline:
            try:
                status, response = _request(
                    base_url,
                    "/api/health",
                    timeout=min(2, max(0.1, readiness_deadline - time.monotonic())),
                )
                if status == 200:
                    api_responses.append(response)
                    health = json.loads(response)
                    break
            except (ValueError, json.JSONDecodeError):
                time.sleep(min(1, max(0.0, readiness_deadline - time.monotonic())))
        if not isinstance(health, dict) or health.get("provider_mode") != "embedded_local":
            raise ValueError("privacy_core_health_failed")
        status, capabilities = _request(base_url, "/api/config/capabilities")
        if status != 200:
            raise ValueError("privacy_core_capabilities_failed")
        api_responses.append(capabilities)
        ui_status, ui_document = _request(base_url, "/")
        if ui_status != 200:
            raise ValueError("privacy_browser_status_unavailable")
        ui_responses.append(ui_document)
        case_symptom = "Analyze response timing in this synthetic privacy qualification capture."
        status, created = _request(
            base_url, "/api/cases", method="POST", body={"symptom": case_symptom}
        )
        if status != 201:
            raise ValueError("privacy_case_create_failed")
        api_responses.append(created)
        case_record = json.loads(created)
        case_id = case_record.get("id")
        if not isinstance(case_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", case_id):
            raise ValueError("privacy_case_identity_invalid")
        fixture.expect_case(case_id)
        capture_path = private_root / "synthetic-privacy.pcap"
        capture_bytes = _sentinel_capture(sentinels)
        if not capture_bytes or len(capture_bytes) > MAX_SYNTHETIC_PCAP_BYTES:
            raise ValueError("privacy_capture_fixture_invalid")
        capture_path.write_bytes(capture_bytes)
        capture_path.chmod(0o600)
        capture = capture_path.read_bytes()
        if not all(value.encode() in capture for value in sentinels.values()):
            raise ValueError("privacy_capture_sentinel_generation_failed")
        status, captured = _request(
            base_url,
            f"/api/cases/{case_id}/capture",
            method="POST",
            body=capture,
            content_type="application/octet-stream",
        )
        if status != 200:
            raise ValueError("privacy_capture_upload_failed")
        api_responses.append(captured)
        fixture.begin_case_investigation(case_id)
        try:
            status, investigated = _request(
                base_url,
                f"/api/cases/{case_id}/investigate",
                method="POST",
                timeout=120,
            )
        finally:
            fixture.end_case_investigation(case_id)
        if status != 200:
            raise ValueError("privacy_investigation_failed")
        api_responses.append(investigated)
        investigation = json.loads(investigated)
        if (
            investigation.get("state") != "COMPLETE"
            or investigation.get("provider_mode") != "embedded_local"
        ):
            raise ValueError("privacy_investigation_incomplete")
        fixture.require_pass()
        status, final_case = _request(base_url, f"/api/cases/{case_id}")
        if status != 200:
            raise ValueError("privacy_case_read_failed")
        api_responses.append(final_case)
        status, report = _request(base_url, f"/api/cases/{case_id}/report")
        if status != 200:
            raise ValueError("privacy_report_unavailable")
        api_responses.append(report)
        report_value = json.loads(report)
        if report_value.get("status") not in {"complete", "COMPLETE"}:
            raise ValueError("privacy_report_incomplete")
        stdout_logs, stderr_logs = _run(
            [*compose_argv, "logs", "--no-color", "--tail=all", "wireclaw-core"],
            env={
                key: value
                for key, value in environment.items()
                if key != "WIRECLAW_PROVIDER_API_KEY"
            },
            timeout=30,
        )
        core_log_bytes = stdout_logs + stderr_logs
        response_bytes = b"\n".join(api_responses)
        if len(response_bytes) > MAX_SCAN_BYTES:
            raise ValueError("privacy_surface_uninspectable")
        browser_bytes = b"\n".join([*ui_responses, api_responses[0], capabilities])
        database_bytes = _scan_database(data_root / "cases.sqlite3", private_values)
        runtime_bytes = _scan_tree(
            data_root,
            patterns=("*.log", "runtime.log"),
            sentinels=private_values,
        )
        fixture_runtime_logs = fixture.runtime_log_bytes()
        report_files = _scan_tree(
            data_root,
            patterns=("*.json",),
            sentinels=private_values,
        )
        surfaces = {
            "model_context": (
                fixture.result()["model_context_sentinel_absent"]
                and fixture.result()["non_authorization_header_sentinel_absent"]
            ),
            "api_responses": response_bytes,
            "case_database": database_bytes,
            "runtime_logs": runtime_bytes + fixture_runtime_logs,
            "core_logs": core_log_bytes,
            "browser_status": browser_bytes,
            "reports": report + report_files,
        }
        checks = verify_surfaces(surfaces, private_values)
        if fixture.result()["request_count"] != 1 or not fixture.result()["request_correlated"]:
            raise ValueError("privacy_provider_request_uncorrelated")
        qualification.verify_candidate_unchanged(
            bundle, archive, identity, frozen_metadata=metadata
        )
        receipt = build_receipt(identity, scenario_id, checks)
        validate_receipt(receipt, identity)
        return receipt
    finally:
        try:
            if fixture is not None:
                fixture.close()
        finally:
            if private_root.exists():
                cleanup_qualification(
                    project_name=project_name,
                    compose_file=compose_file,
                    private_root=private_root,
                    evidence_output=output,
                )
        token = ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-bundle", type=Path, required=True)
    parser.add_argument("--candidate-archive", type=Path, required=True)
    parser.add_argument("--candidate-metadata", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = _perform(args)
        output = Path(args.receipt_output)
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write("\n")
        output.chmod(0o600)
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        code = str(error) or "privacy_qualification_failed"
        if not re.fullmatch(r"[a-z0-9_]{1,80}", code):
            code = "privacy_qualification_failed"
        print(code, file=sys.stderr)
        return 1
    print("PASS eai14-16 privacy receipt written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
