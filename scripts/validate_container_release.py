"""Exercise the release image end-to-end with fixture traffic and a fake host provider."""

import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/fixtures"))
from generate_gate2 import generate  # noqa: E402


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(base: str, path: str, *, method="GET", body=None, content_type=None, headers=None):
    request_headers = dict(headers or {})
    data = body
    if isinstance(body, dict):
        data = json.dumps(body).encode()
        request_headers["content-type"] = "application/json"
    if content_type:
        request_headers["content-type"] = content_type
    req = Request(f"{base}{path}", data=data, headers=request_headers, method=method)
    try:
        with urlopen(req, timeout=15) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()
    except URLError as error:
        raise RuntimeError(f"request_failed {method} {path}: {error}") from None
    except Exception as error:
        raise RuntimeError(f"request_failed {method} {path}: {type(error).__name__}") from None


class FakeProvider(BaseHTTPRequestHandler):
    requests_seen: ClassVar[list[tuple[dict, str | None]]] = []

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        self.requests_seen.append((json.loads(body), self.headers.get("Authorization")))
        action = {"action": "finalize", "hypotheses": [], "remaining_hypotheses": []}
        result = {"choices": [{"message": {"content": json.dumps(action)}}]}
        encoded = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


def compose(env: dict[str, str], action: str, *, files=()):
    command = [
        "docker",
        "compose",
        "--env-file",
        ".env.example",
        "-f",
        "compose.yaml",
    ]
    for file in files:
        command.extend(["-f", str(file)])
    command.append(action)
    if action == "up":
        command.extend(["-d", "--no-build"])
    else:
        command.append("--remove-orphans")
    result = subprocess.run(command, cwd=ROOT, env=os.environ | env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"compose_{action}_failed ({result.returncode})")


def wait_health(base: str):
    for _ in range(60):
        try:
            status, body = request(base, "/api/health")
        except RuntimeError:
            time.sleep(1)
            continue
        if status == 200:
            health = json.loads(body)
            if health["provider_mode"] in {
                "none",
                "openai_compatible_local",
                "openai_compatible_cloud",
            }:
                return health
        time.sleep(1)
    raise RuntimeError("core_health_timeout")


def main() -> int:
    app_port = free_port()
    bridge_port = free_port()
    while bridge_port == app_port:
        bridge_port = free_port()
    with tempfile.TemporaryDirectory(prefix="Wireclaw Gate8 Release ") as temp:
        root = Path(temp) / "Case Data Ω"
        root.mkdir()
        fixtures = generate(Path(temp) / "fixtures")
        original_bytes = fixtures["http_server_wait"]
        original_sha = hashlib.sha256(original_bytes).hexdigest()
        env = {
            "WIRECLAW_PORT": str(app_port),
            "WIRECLAW_BRIDGE_PORT": str(bridge_port),
            "WIRECLAW_DATA_ROOT": str(root),
            "WIRECLAW_UID": str(os.getuid()),
            "WIRECLAW_GID": str(os.getgid()),
            "WIRECLAW_PROVIDER_MODE": "none",
            "WIRECLAW_PROVIDER_BASE_URL": "",
            "WIRECLAW_PROVIDER_MODEL": "",
            "WIRECLAW_PROVIDER_API_KEY": "",
        }
        base = f"http://127.0.0.1:{app_port}"
        compose(env, "up")
        try:
            health = wait_health(base)
            assert health["provider_mode"] == "none"
            status, capability_bytes = request(base, "/api/config/capabilities")
            capabilities = json.loads(capability_bytes)
            assert status == 200
            assert capabilities["bridge"]["origin"] == f"http://127.0.0.1:{bridge_port}"
            status, page = request(base, "/")
            assert status == 200 and b"/assets/index-" in page
            assert request(base, "/api/health", headers={"Host": "evil.invalid"})[0] == 403
            assert request(base, "/api/health", headers={"Origin": "http://evil.invalid"})[0] == 403

            status, created = request(
                base, "/api/cases", method="POST", body={"symptom": "slow HTTP response"}
            )
            assert status == 201
            case_id = json.loads(created)["id"]
            status, ingested = request(
                base,
                f"/api/cases/{case_id}/capture",
                method="POST",
                body=original_bytes,
                content_type="application/octet-stream",
            )
            assert status == 200
            case = json.loads(ingested)
            assert case["capture_sha"] == original_sha
            assert case["provider_mode"] == "none"
            status, _investigated = request(
                base, f"/api/cases/{case_id}/investigate", method="POST"
            )
            assert status == 200
            status, report_bytes = request(base, f"/api/cases/{case_id}/report")
            assert status == 200
            report = json.loads(report_bytes)
            assert report["reasoning"]["mode"] == "rules_only"
            finding = next(
                item for item in report["findings"] if item.get("wireshark", {}).get("applicable")
            )
            assert finding["wireshark"]["display_filter"]
            assert finding["wireshark"]["full_capture"]
            assert finding["wireshark"]["evidence_capture"]
            status, evidence_bytes = request(
                base,
                f"/api/cases/{case_id}/artifacts/evidence-capture",
                method="POST",
                body={"finding_id": finding["id"]},
            )
            assert status == 200
            evidence = json.loads(evidence_bytes)
            assert evidence["provenance"]["parent_sha256"] == original_sha
            original_path = (
                root
                / "cases"
                / case_id
                / "analyzer"
                / "cases"
                / original_sha
                / "original"
                / "capture"
            )
            assert hashlib.sha256(original_path.read_bytes()).hexdigest() == original_sha

            compose(env, "down")
            compose(env, "up")
            health = wait_health(base)
            assert health["provider_mode"] == "none"
            status, saved_case = request(base, f"/api/cases/{case_id}")
            assert status == 200 and json.loads(saved_case)["capture_sha"] == original_sha
            status, saved_report = request(base, f"/api/cases/{case_id}/report")
            assert status == 200 and json.loads(saved_report)["reasoning"]["mode"] == "rules_only"
            status, artifact = request(
                base, f"/api/cases/{case_id}/artifacts/{evidence['artifact_id']}"
            )
            assert status == 200 and json.loads(artifact)["parent_sha"] == original_sha
            assert hashlib.sha256(original_path.read_bytes()).hexdigest() == original_sha

            FakeProvider.requests_seen = []
            provider = ThreadingHTTPServer(("0.0.0.0", bridge_port), FakeProvider)
            thread = threading.Thread(target=provider.serve_forever, daemon=True)
            thread.start()
            env.update(
                {
                    "WIRECLAW_PROVIDER_MODE": "openai_compatible_local",
                    "WIRECLAW_PROVIDER_BASE_URL": f"http://host.docker.internal:{bridge_port}/v1",
                    "WIRECLAW_PROVIDER_MODEL": "wireclaw-fake",
                    "WIRECLAW_PROVIDER_API_KEY": "CREDENTIAL_SENTINEL",
                }
            )
            compose(env, "down")
            compose(env, "up")
            try:
                health = wait_health(base)
                assert health["provider_mode"] == "openai_compatible_local"
                status, _ = request(base, f"/api/cases/{case_id}/investigate", method="POST")
                assert status == 200
                assert FakeProvider.requests_seen
                provider_body, authorization = FakeProvider.requests_seen[0]
                serialized = json.dumps(provider_body)
                assert "CREDENTIAL_SENTINEL" not in serialized
                assert str(root) not in serialized
                assert "RAW_CAPTURE" not in serialized
                assert authorization == "Bearer CREDENTIAL_SENTINEL"
            finally:
                provider.shutdown()
                provider.server_close()
                thread.join(timeout=2)

            # A temporary child image trusts only the test CA so the cloud HTTPS
            # adapter is exercised without weakening certificate checks in release.
            tls_dir = Path(temp) / "privacy tls"
            generated = subprocess.run(
                ["go", "run", str(ROOT / "tests/packaging/generate_test_ca.go"), str(tls_dir)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            if generated.returncode:
                raise RuntimeError("test_ca_generation_failed")
            (tls_dir / "Dockerfile").write_text(
                "FROM wireclaw-core:gate8\n"
                "USER 0\n"
                "COPY test-ca.pem /tmp/wireclaw-test-ca.pem\n"
                'RUN /opt/venv/bin/python -c "from pathlib import Path; import certifi; '
                "p=Path(certifi.where()); p.write_bytes(p.read_bytes()+Path('/tmp/wireclaw-test-ca.pem').read_bytes())\" "
                "&& rm -f /tmp/wireclaw-test-ca.pem\n"
                "USER 10001:10001\n",
                encoding="utf-8",
            )
            override = Path(temp) / "compose.privacy-test.yaml"
            override.write_text(
                "services:\n"
                "  wireclaw-core:\n"
                "    image: wireclaw-core:gate8-privacy-test\n"
                f"    build:\n      context: {json.dumps(str(tls_dir))}\n      dockerfile: Dockerfile\n",
                encoding="utf-8",
            )
            https_server = ThreadingHTTPServer(("0.0.0.0", bridge_port), FakeProvider)
            https_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            https_context.load_cert_chain(
                certfile=tls_dir / "server-cert.pem", keyfile=tls_dir / "server-key.pem"
            )
            https_server.socket = https_context.wrap_socket(https_server.socket, server_side=True)
            https_thread = threading.Thread(target=https_server.serve_forever, daemon=True)
            https_thread.start()
            env.update(
                {
                    "WIRECLAW_PROVIDER_MODE": "openai_compatible_cloud",
                    "WIRECLAW_PROVIDER_BASE_URL": f"https://host.docker.internal:{bridge_port}/v1",
                    "WIRECLAW_PROVIDER_MODEL": "wireclaw-fake-cloud",
                    "WIRECLAW_PROVIDER_API_KEY": "CLOUD_CREDENTIAL_SENTINEL",
                }
            )
            FakeProvider.requests_seen = []
            compose(env, "down", files=(override,))
            compose(env, "up", files=(override,))
            try:
                health = wait_health(base)
                assert health["provider_mode"] == "openai_compatible_cloud"
                status, _ = request(base, f"/api/cases/{case_id}/investigate", method="POST")
                assert status == 200
                assert FakeProvider.requests_seen
                provider_body, authorization = FakeProvider.requests_seen[0]
                serialized = json.dumps(provider_body)
                assert "CLOUD_CREDENTIAL_SENTINEL" not in serialized
                assert "BRIDGE_TOKEN_SENTINEL" not in serialized
                assert str(root) not in serialized
                assert "RAW_CAPTURE" not in serialized
                assert original_bytes.hex() not in serialized
                assert authorization == "Bearer CLOUD_CREDENTIAL_SENTINEL"
                logs = subprocess.run(
                    [
                        "docker",
                        "compose",
                        "--env-file",
                        ".env.example",
                        "-f",
                        "compose.yaml",
                        "-f",
                        str(override),
                        "logs",
                        "--no-color",
                        "wireclaw-core",
                    ],
                    cwd=ROOT,
                    env=os.environ | env,
                    capture_output=True,
                    text=True,
                )
                assert "CLOUD_CREDENTIAL_SENTINEL" not in logs.stdout + logs.stderr
            finally:
                https_server.shutdown()
                https_server.server_close()
                https_thread.join(timeout=2)
            print(
                "PASS: health/web, Host/Origin policy, rules-only investigation, evidence, "
                "restart persistence, immutable original, host.docker.internal provider route, "
                "and cloud privacy through the image"
            )
        finally:
            compose(env, "down")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, RuntimeError, URLError) as error:
        raise SystemExit(str(error) or "container_release_check_failed") from None
