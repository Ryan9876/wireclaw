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
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/fixtures"))
from generate import generate as generate_baseline  # noqa: E402
from generate_gate2 import CLIENT, SERVER, dns_packet, generate, tcp, timed_pcap  # noqa: E402


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
    requests_seen: ClassVar[list[tuple[dict, dict[str, str]]]] = []

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        headers = {name.lower(): value for name, value in self.headers.items()}
        self.requests_seen.append((json.loads(body), headers))
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


def investigate_capture(base: str, symptom: str, capture: bytes):
    status, created = request(base, "/api/cases", method="POST", body={"symptom": symptom})
    assert status == 201
    case_id = json.loads(created)["id"]
    status, ingested = request(
        base,
        f"/api/cases/{case_id}/capture",
        method="POST",
        body=capture,
        content_type="application/octet-stream",
    )
    assert status == 200
    case = json.loads(ingested)
    assert request(base, f"/api/cases/{case_id}/investigate", method="POST")[0] == 200
    status, report = request(base, f"/api/cases/{case_id}/report")
    assert status == 200
    status, evidence = request(base, f"/api/cases/{case_id}/evidence?limit=100")
    assert status == 200
    return case, json.loads(report), json.loads(evidence)["evidence"]


def evidence_values(evidence: list[dict], category: str) -> list[dict]:
    return [item["value"] for item in evidence if item.get("category") == category]


def validate_malformed_uploads(base: str, root: Path, baseline: dict) -> list[dict]:
    results = []
    for name in ("malformed", "damaged_record", "unsupported"):
        status, created = request(base, "/api/cases", method="POST", body={"symptom": name})
        assert status == 201
        case_id = json.loads(created)["id"]
        status, _ = request(
            base,
            f"/api/cases/{case_id}/capture",
            method="POST",
            body=baseline[name],
            content_type="application/octet-stream",
        )
        assert status == 422
        status, case_bytes = request(base, f"/api/cases/{case_id}")
        assert status == 200
        case = json.loads(case_bytes)
        assert case["state"] == "FAILED" and not case["artifacts"]
        assert not list((root / "cases" / case_id).rglob("capture"))
        status, _ = request(
            base,
            f"/api/cases/{case_id}/capture",
            method="POST",
            body=baseline["healthy"],
            content_type="application/octet-stream",
        )
        assert status == 200
        assert (
            request(
                base,
                f"/api/cases/{case_id}/capture",
                method="POST",
                body=baseline["healthy"],
                content_type="application/octet-stream",
            )[0]
            == 409
        )
        results.append(
            {
                "task": "G9.12",
                "scenario": name,
                "result": "PASS",
                "case_id": case_id,
                "malformed_upload_rejected": True,
                "partial_artifacts_absent": True,
                "healthy_retry_succeeded_once": True,
            }
        )
    return results


def oversized_capture_probe(base: str) -> None:
    port = int(base.rsplit(":", 1)[1])
    request_bytes = (
        "POST /api/cases/00000000000000000000000000000000/capture HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {64 * 1024 * 1024 + 1}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(request_bytes)
        response = client.recv(2048)
    assert response.startswith(b"HTTP/1.1 413")
    assert b"request_size_limit" in response


def validate_diagnostic_corpus(base: str, baseline: dict, gate2: dict) -> list[dict]:
    results = []

    def record(task: str, scenario: str, case: dict, report: dict):
        extractions = []
        for finding in report["findings"]:
            actions = finding.get("wireshark", {})
            if not actions.get("applicable"):
                continue
            assert actions.get("display_filter") and finding["evidence_ids"]
            assert all(
                actions.get(key)
                for key in (
                    "full_capture",
                    "evidence_capture",
                    "copy_filter",
                    "show_packet_evidence",
                )
            )
            status, encoded = request(
                base,
                f"/api/cases/{case['id']}/artifacts/evidence-capture",
                method="POST",
                body={"finding_id": finding["id"]},
            )
            assert status == 200
            extracted = json.loads(encoded)
            provenance = extracted["provenance"]
            assert provenance["parent_sha256"] == case["capture_sha"]
            assert provenance["finding_id"] == finding["id"]
            assert provenance["evidence_ids"] == finding["evidence_ids"]
            assert provenance["display_filter"] == actions["display_filter"]
            assert extracted["bytes"] <= 16 * 1024 * 1024
            extractions.append(
                {
                    "finding_id": finding["id"],
                    "artifact_id": extracted["artifact_id"],
                    "sha256": extracted["sha256"],
                    "display_filter": provenance["display_filter"],
                    "extraction_mode": provenance["extraction_mode"],
                    "bytes": extracted["bytes"],
                }
            )
        results.append(
            {
                "task": task,
                "scenario": scenario,
                "result": "PASS",
                "case_id": case["id"],
                "capture_sha256": case["capture_sha"],
                "quality": report["capture_quality"]["state"],
                "conclusion": report["conclusion"]["type"],
                "finding_categories": sorted(item["category"] for item in report["findings"]),
                "evidence_extractions": extractions,
            }
        )

    # G9.1: healthy traffic and a clean TCP stream must not invent a fault.
    healthy, healthy_report, healthy_evidence = investigate_capture(
        base, "healthy connection, no reported fault", baseline["healthy"]
    )
    metadata = evidence_values(healthy_evidence, "get_capture_metadata")[0]
    assert (metadata["packet_count"], metadata["wire_bytes"], metadata["duration_seconds"]) == (
        7,
        469,
        0.6,
    )
    assert healthy_report["capture_quality"]["state"] == "good"
    healthy_faults = {
        "dns.failure",
        "tcp.retransmission",
        "tcp.receive_window",
        "tcp.reset",
        "tls.handshake",
        "server.application_wait",
        "network.pmtud",
    }
    assert not healthy_faults.intersection(item["category"] for item in healthy_report["findings"])
    record("G9.1", "healthy", healthy, healthy_report)

    clean, clean_report, clean_evidence = investigate_capture(
        base, "healthy clean TCP exchange", gate2["clean_tcp"]
    )
    establishment = evidence_values(clean_evidence, "analyze_tcp_establishment")[0]
    rtt = evidence_values(clean_evidence, "analyze_rtt")[0]
    throughput = evidence_values(clean_evidence, "analyze_throughput")[0]["directions"]
    mss = evidence_values(clean_evidence, "analyze_mss")[0]["records"]
    assert establishment["establishment_seconds"] == 0.02
    assert rtt["sample_count"] == 4 and rtt["median_seconds"] == 0.01
    assert [
        (item["tcp_payload_bytes"], item["unique_acknowledged_payload_bytes"])
        for item in throughput
    ] == [
        (20, 20),
        (30, 30),
    ]
    assert [item["mss_bytes"] for item in mss] == [1460, 1460]
    assert clean_report["conclusion"]["type"] == "insufficient_evidence"
    assert not clean_report["findings"]
    record("G9.1", "clean_tcp", clean, clean_report)

    dns, dns_report, dns_evidence = investigate_capture(
        base, "DNS lookup is slow", gate2["dns_delay"]
    )
    dns_value = evidence_values(dns_evidence, "analyze_dns")[0]
    transaction = dns_value["transactions"][0]
    assert (transaction["query_frame"], transaction["response_frame"]) == (1, 2)
    assert transaction["elapsed_seconds"] == 1.5
    dns_finding = next(item for item in dns_report["findings"] if item["category"] == "dns.timing")
    assert dns_finding["evidence_ids"] and dns_finding["wireshark"]["display_filter"] == (
        "(frame.number >= 1 && frame.number <= 2)"
    )
    assert "does not by itself prove" in " ".join(dns_finding["alternate_explanations"])
    status, extracted = request(
        base,
        f"/api/cases/{dns['id']}/artifacts/evidence-capture",
        method="POST",
        body={"finding_id": dns_finding["id"]},
    )
    assert status == 200
    extraction = json.loads(extracted)
    assert extraction["provenance"]["parent_sha256"] == dns["capture_sha"]
    assert extraction["provenance"]["evidence_ids"] == dns_finding["evidence_ids"]
    assert extraction["provenance"]["display_filter"] == dns_finding["wireshark"]["display_filter"]
    assert extraction["provenance"]["extraction_mode"] == "dns_transaction_set"
    assert extraction["bytes"] <= 16 * 1024 * 1024
    record("G9.2", "dns_delay", dns, dns_report)

    dns_with_unrelated = timed_pcap(
        [
            (0, dns_packet(ident=42, name="slow.invalid")),
            (10_000, dns_packet(ident=43, name="unrelated.invalid", sport=53001)),
            (
                20_000,
                dns_packet(
                    ident=43,
                    name="unrelated.invalid",
                    sport=53001,
                    response=True,
                ),
            ),
            (1_500_000, dns_packet(ident=42, name="slow.invalid", response=True)),
        ]
    )
    mixed_dns, mixed_report, mixed_evidence = investigate_capture(
        base, "slow DNS lookup", dns_with_unrelated
    )
    mixed_value = evidence_values(mixed_evidence, "analyze_dns")[0]
    matched = [item for item in mixed_value["transactions"] if item["state"] == "matched"]
    slow = next(item for item in matched if item["elapsed_seconds"] == 1.5)
    quick = next(item for item in matched if item["elapsed_seconds"] == 0.01)
    assert slow["frame_refs"] == [1, 4]
    assert quick["frame_refs"] == [2, 3]
    mixed_finding = next(
        item for item in mixed_report["findings"] if item["category"] == "dns.timing"
    )
    assert mixed_finding["wireshark"]["display_filter"] == (
        "frame.number == 1 || frame.number == 4"
    )
    record("G9.2", "dns_delay_with_unrelated_dns", mixed_dns, mixed_report)

    loss, loss_report, loss_evidence = investigate_capture(
        base, "TCP transfer is slow", gate2["loss_tcp"]
    )
    health = evidence_values(loss_evidence, "analyze_tcp_health")[0]
    directions = evidence_values(loss_evidence, "analyze_throughput")[0]["directions"]
    assert health["retransmission_union_frames"] == [5, 11, 13]
    assert health["indicators"]["fast_retransmission"]["frame_refs"] == [11]
    assert health["indicators"]["spurious_retransmission"]["frame_refs"] == [13]
    assert health["indicators"]["duplicate_ack"]["frame_refs"] == [8, 9, 10]
    assert sum(item["tcp_payload_bytes"] for item in directions) == 100
    assert sum(item["unique_observed_payload_bytes"] for item in directions) == 40
    assert sum(item["unique_acknowledged_payload_bytes"] or 0 for item in directions) == 40
    assert all(
        item["unique_acknowledged_payload_bytes"] is not None or item["tcp_payload_bytes"] == 0
        for item in directions
    )
    retransmission = next(
        item for item in loss_report["findings"] if item["category"] == "tcp.retransmission"
    )
    assert retransmission["evidence_ids"] and "local_network" in retransmission["fault_domains"]
    assert "localize" in " ".join(retransmission["alternate_explanations"])
    record("G9.3", "loss_tcp", loss, loss_report)

    high_rtt, high_report, high_evidence = investigate_capture(
        base, "TCP transaction is slow", gate2["high_rtt"]
    )
    setup = evidence_values(high_evidence, "analyze_tcp_establishment")[0]
    rtt = evidence_values(high_evidence, "analyze_rtt")[0]
    assert setup["establishment_seconds"] == 0.4
    assert rtt["median_seconds"] == 0.2
    assert any(item["category"] == "tcp.rtt" for item in high_report["findings"])
    record("G9.4", "high_rtt", high_rtt, high_report)

    window_case, window_report, window_evidence = investigate_capture(
        base, "TCP transfer is stalled", gate2["window_tcp"]
    )
    window = evidence_values(window_evidence, "analyze_window_behavior")[0]
    server_direction = next(
        item
        for item in window["directions"]
        if item["advertiser"] == {"address": SERVER, "port": 443}
    )
    interval = server_direction["zero_window_intervals"][0]
    assert window["indicators"]["window_full"] == [5]
    assert window["indicators"]["zero_window"] == [6, 8]
    assert window["indicators"]["zero_window_probe"] == [7]
    assert (interval["start_frame"], interval["reopen_frame"], interval["observed_seconds"]) == (
        6,
        9,
        1.0,
    )
    assert any(item["category"] == "tcp.receive_window" for item in window_report["findings"])
    record("G9.5", "window_tcp", window_case, window_report)

    reset, reset_report, reset_evidence = investigate_capture(
        base, "connection reset unexpectedly", gate2["reset_tcp"]
    )
    reset_value = evidence_values(reset_evidence, "analyze_tcp_resets")[0]
    assert reset_value["count"] == 1
    assert reset_value["resets"][0]["frame"] == 6
    assert reset_value["resets"][0]["seconds_since_established"] == 0.08
    reset_finding = next(
        item for item in reset_report["findings"] if item["category"] == "tcp.reset"
    )
    assert reset_finding["evidence_ids"]
    assert any("does not establish" in item for item in reset_finding["alternate_explanations"])
    reconnect, reconnect_report, reconnect_evidence = investigate_capture(
        base, "connection resets and reconnects", gate2["reset_reconnect"]
    )
    lifecycle = evidence_values(reconnect_evidence, "analyze_tcp_resets")
    assert len(lifecycle) == 2
    assert lifecycle[0]["resets"][0]["frame"] == 6
    assert lifecycle[0]["observed_reconnect_attempts"] == []
    assert lifecycle[1]["observed_reconnect_attempts"] == [
        {
            "prior_reset_frame": 6,
            "prior_tcp_stream": 0,
            "seconds_since_reset": 0.1,
            "syn_frame": 7,
        }
    ]
    assert lifecycle[1]["resets"][0]["frame"] == 10
    assert all("continuity" in " ".join(item["limitations"]) for item in lifecycle)
    record("G9.6", "reset_tcp", reset, reset_report)
    record("G9.6", "reset_reconnect", reconnect, reconnect_report)

    tls_case, tls_report, tls_evidence = investigate_capture(
        base, "TLS handshake takes too long", gate2["tls_delay"]
    )
    tls = evidence_values(tls_evidence, "analyze_tls_handshakes")[0]
    attempt = tls["attempts"][0]
    assert (attempt["client_hello_frame"], attempt["server_hello_frame"]) == (4, 6)
    assert attempt["tcp_established_to_client_hello_seconds"] == 0.08
    assert attempt["client_hello_to_server_hello_seconds"] == 1.0
    assert 0x0304 in [
        version for item in tls["supported_version_fields"] for version in item["versions"]
    ]
    tls_finding = next(
        item for item in tls_report["findings"] if item["category"] == "tls.handshake"
    )
    assert "Encrypted session usability/completion" in " ".join(
        tls_finding["alternate_explanations"]
    )
    record("G9.7", "tls_delay", tls_case, tls_report)

    http_case, http_report, http_evidence = investigate_capture(
        base, "plaintext HTTP request is slow", gate2["http_server_wait"]
    )
    http_value = evidence_values(http_evidence, "analyze_http_timing")[0]
    http_transaction = http_value["transactions"][0]
    assert http_transaction["tcp_stream"] == 0
    assert http_transaction["request_frame_range"] == {"start": 4, "end": 4}
    assert http_transaction["first_response_frame"] == 5
    assert http_transaction["frame_refs"] == [4, 5]
    assert abs(http_transaction["request_to_first_response_seconds"] - 2.1) <= 0.01
    assert http_transaction["response_transfer_seconds"] == 0
    http_finding = next(
        item for item in http_report["findings"] if item["category"] == "server.application_wait"
    )
    assert http_finding["confidence"] == "medium"
    assert http_finding["evidence_ids"] and "downstream dependency" in " ".join(
        http_finding["alternate_explanations"]
    )
    assert any(
        item["name"] == "server_application_wait"
        and item["measurement_class"] == "derived"
        and abs(item["duration_ms"] - 2100) <= 10
        for item in http_report["time_attribution"]["segments"]
    )
    record("G9.8", "http_server_wait", http_case, http_report)

    opaque_case, opaque_report, _ = investigate_capture(
        base, "opaque TCP transaction is slow", gate2["server_wait"]
    )
    assert opaque_report["conclusion"]["type"] == "insufficient_evidence"
    assert not any(
        item["category"] == "server.application_wait" for item in opaque_report["findings"]
    )
    assert not any(
        item["name"] == "server_application_wait"
        for item in opaque_report["time_attribution"]["segments"]
    )
    assert opaque_report["remaining_hypotheses"] and opaque_report["recommended_next_evidence"]
    record("G9.8", "opaque_server_wait", opaque_case, opaque_report)

    pmtu_case, pmtu_report, pmtu_evidence = investigate_capture(
        base, "large transfer may have a path MTU issue", gate2["pmtud_signals"]
    )
    pmtu = evidence_values(pmtu_evidence, "analyze_pmtud_signals")[0]
    assert [(item["frame"], item["mtu_bytes"]) for item in pmtu["records"]] == [
        (2, 1200),
        (3, 1280),
    ]
    pmtu_finding = next(
        item for item in pmtu_report["findings"] if item["category"] == "network.pmtud"
    )
    assert "does not by itself prove an MTU black hole" in " ".join(
        pmtu_finding["alternate_explanations"]
    )
    record("G9.9", "pmtud_signals", pmtu_case, pmtu_report)

    for name in ("one_sided", "midstream", "incomplete_handshake", "truncated"):
        capture = baseline[name]
        quality_case, quality_report, quality_evidence = investigate_capture(
            base, "connection is slow", capture
        )
        quality = evidence_values(quality_evidence, "assess_capture_quality")[0]
        assert quality["state"] in {"limited", "insufficient"}
        assert quality["limitations"]
        if name == "incomplete_handshake":
            # This conclusion supports only the observed incomplete handshake;
            # the report must keep all candidate fault domains open.
            assert quality_report["conclusion"]["type"] == "supported_finding"
            finding = next(
                item
                for item in quality_report["findings"]
                if item["category"] == "tcp.establishment_failure"
            )
            assert set(finding["fault_domains"]) == {
                "local_network",
                "network_path",
                "server_application",
            }
            assert "capture incompleteness" in " ".join(finding["alternate_explanations"])
            assert finding["recommended_validation"]
        else:
            assert quality_report["conclusion"]["type"] == "insufficient_evidence", (
                f"quality_uncertainty_mismatch:{name}:{quality_report['conclusion']['type']}"
            )
            assert quality_report["remaining_hypotheses"]
            assert quality_report["recommended_next_evidence"]
        assert not any(
            item["category"] in {"tcp.retransmission", "tcp.receive_window", "tls.handshake"}
            for item in quality_report["findings"]
        )
        record("G9.10", name, quality_case, quality_report)
        if name == "incomplete_handshake":
            results[-1]["interpretation"] = (
                "The supported item is the observed handshake state only; the report leaves "
                "client, path, and server/application causes open and requests opposite-side capture."
            )

    return results


def ci_host_route_override(directory: Path) -> tuple[Path, ...]:
    if os.environ.get("WIRECLAW_TEST_HOST_GATEWAY") != "1":
        return ()
    override = directory / "compose.test-host-route.yaml"
    override.write_text(
        "services:\n"
        "  wireclaw-core:\n"
        "    extra_hosts:\n"
        "      - host.docker.internal:host-gateway\n",
        encoding="utf-8",
    )
    return (override,)


def main() -> int:
    expected_image_id = os.environ.get("WIRECLAW_EXPECTED_IMAGE_ID")
    image_ref = os.environ.get("WIRECLAW_IMAGE", "wireclaw-core:gate8")
    image_result = subprocess.run(
        ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if image_result.returncode:
        raise RuntimeError("candidate_image_inspection_failed")
    starting_image_id = image_result.stdout.strip()
    if expected_image_id and starting_image_id != expected_image_id:
        raise RuntimeError("candidate_image_id_mismatch_before_acceptance")

    app_port = free_port()
    bridge_port = free_port()
    while bridge_port == app_port:
        bridge_port = free_port()
    with tempfile.TemporaryDirectory(prefix="Wireclaw Gate8 Release ") as temp:
        root = Path(temp) / "Case Data Ω"
        root.mkdir()
        host_route_files = ci_host_route_override(Path(temp))
        fixtures = generate(Path(temp) / "fixtures")
        original_bytes = fixtures["http_server_wait"]
        original_sha = hashlib.sha256(original_bytes).hexdigest()
        private_request = (
            b"GET / HTTP/1.1\r\nHost: example.invalid\r\n"
            b"Cookie: session=G9_COOKIE_SENTINEL\r\n"
            b"Authorization: Bearer G9_AUTH_SENTINEL\r\n"
            b"Connection: close\r\n\r\n"
        )
        private_response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Set-Cookie: session=G9_SET_COOKIE_SENTINEL\r\n"
            b"Connection: close\r\n\r\nok"
        )
        privacy_capture = timed_pcap(
            [
                (0, tcp(seq=100, ack=0, flags=2)),
                (10_000, tcp(SERVER, CLIENT, seq=200, ack=101, flags=18)),
                (20_000, tcp(seq=101, ack=201)),
                (30_000, tcp(seq=101, ack=201, flags=24, payload=private_request)),
                (
                    40_000,
                    tcp(
                        SERVER,
                        CLIENT,
                        seq=201,
                        ack=101 + len(private_request),
                        flags=24,
                        payload=private_response,
                    ),
                ),
            ]
        )
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
        compose(env, "up", files=host_route_files)
        try:
            health = wait_health(base)
            assert health["provider_mode"] == "none"
            baseline_fixtures = generate_baseline(Path(temp) / "baseline fixtures")
            corpus_results = validate_diagnostic_corpus(base, baseline_fixtures, fixtures)
            oversized_capture_probe(base)
            status, oversized_json = request(
                base,
                "/api/cases",
                method="POST",
                body={"symptom": "x" * (16_384 + 1)},
            )
            assert status == 413 and b"request_size_limit" in oversized_json
            corpus_results.append(
                {
                    "task": "G9.11",
                    "scenario": "capture and JSON request limits",
                    "result": "PASS",
                    "configured_capture_limit_bytes": 64 * 1024 * 1024,
                    "oversized_upload_rejected_before_body": True,
                    "oversized_json_rejected": True,
                }
            )
            corpus_results.extend(validate_malformed_uploads(base, root, baseline_fixtures))
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
            http_wait = next(
                item for item in report["findings"] if item["category"] == "server.application_wait"
            )
            assert http_wait["epistemic_class"] == "inferred"
            assert http_wait["confidence"] == "medium"
            assert len(http_wait["evidence_ids"]) == 1
            request_frame = http_wait["affected_scope"]["request_frame"]
            response_frame = http_wait["affected_scope"]["response_frame"]
            assert (request_frame, response_frame) == (4, 5)
            status, http_evidence_bytes = request(
                base,
                f"/api/cases/{case_id}/evidence/{http_wait['evidence_ids'][0]}",
            )
            assert status == 200
            http_evidence = json.loads(http_evidence_bytes)
            transaction = http_evidence["value"]["transactions"][0]
            assert transaction["tcp_stream"] == 0
            assert transaction["client"] == {"address": "192.0.2.1", "port": 50000}
            assert transaction["server"] == {"address": "192.0.2.2", "port": 443}
            assert transaction["request_frame_range"] == {"start": 4, "end": 4}
            assert transaction["first_response_frame"] == 5
            assert transaction["frame_refs"] == [4, 5]
            assert abs(transaction["request_to_first_response_seconds"] - 2.1) <= 0.01
            assert transaction["response_transfer_seconds"] == 0
            assert transaction["display_filter"] == (
                "tcp.stream == 0 && (frame.number == 4 || frame.number == 5)"
            )
            assert "visible server/application boundary" in " ".join(
                http_wait["alternate_explanations"]
            )
            assert "downstream dependency" in " ".join(http_wait["alternate_explanations"])
            assert http_wait["wireshark"]["display_filter"]
            assert all(
                http_wait["wireshark"][key]
                for key in (
                    "full_capture",
                    "evidence_capture",
                    "copy_filter",
                    "show_packet_evidence",
                )
            )
            segments = report["time_attribution"]["segments"]
            server_wait_segment = next(
                item for item in segments if item["name"] == "server_application_wait"
            )
            assert abs(server_wait_segment["duration_ms"] - 2100) <= 10
            assert server_wait_segment["measurement_class"] == "derived"
            assert server_wait_segment["evidence_ids"] == http_wait["evidence_ids"]
            status, report_bytes = request(base, f"/api/cases/{case_id}/report")
            assert status == 200
            report = json.loads(report_bytes)
            assert report["reasoning"]["mode"] == "rules_only"
            finding = http_wait
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

            # Opaque TCP silence is a negative control: the gap alone cannot
            # create an HTTP or server/application semantic measurement.
            status, created = request(
                base,
                "/api/cases",
                method="POST",
                body={"symptom": "the opaque TCP transaction is slow"},
            )
            assert status == 201
            opaque_case_id = json.loads(created)["id"]
            status, _ = request(
                base,
                f"/api/cases/{opaque_case_id}/capture",
                method="POST",
                body=fixtures["server_wait"],
                content_type="application/octet-stream",
            )
            assert status == 200
            assert (
                request(base, f"/api/cases/{opaque_case_id}/investigate", method="POST")[0] == 200
            )
            status, opaque_report_bytes = request(base, f"/api/cases/{opaque_case_id}/report")
            assert status == 200
            opaque_report = json.loads(opaque_report_bytes)
            assert opaque_report["conclusion"]["type"] == "insufficient_evidence"
            assert not any(
                item["category"] == "server.application_wait" for item in opaque_report["findings"]
            )
            assert not any(
                item["name"] == "server_application_wait"
                for item in opaque_report["time_attribution"]["segments"]
            )
            assert opaque_report["remaining_hypotheses"]
            assert opaque_report["recommended_next_evidence"]

            compose(env, "down", files=host_route_files)
            compose(env, "up", files=host_route_files)
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
            compose(env, "down", files=host_route_files)
            compose(env, "up", files=host_route_files)
            try:
                health = wait_health(base)
                assert health["provider_mode"] == "openai_compatible_local"
                status, _ = request(base, f"/api/cases/{case_id}/investigate", method="POST")
                assert status == 200
                assert FakeProvider.requests_seen
                provider_body, provider_headers = FakeProvider.requests_seen[0]
                serialized = json.dumps(provider_body)
                assert "CREDENTIAL_SENTINEL" not in serialized
                assert str(root) not in serialized
                assert "RAW_CAPTURE" not in serialized
                assert provider_headers.get("authorization") == "Bearer CREDENTIAL_SENTINEL"
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
            privacy_image = subprocess.run(
                [
                    "docker",
                    "build",
                    "--tag",
                    "wireclaw-core:gate8-privacy-test",
                    "--file",
                    str(tls_dir / "Dockerfile"),
                    str(tls_dir),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            if privacy_image.returncode:
                raise RuntimeError("privacy_test_image_build_failed")
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
            privacy_files = (*host_route_files, override)
            compose(env, "down", files=privacy_files)
            compose(env, "up", files=privacy_files)
            try:
                health = wait_health(base)
                assert health["provider_mode"] == "openai_compatible_cloud"
                status, privacy_case = request(
                    base,
                    "/api/cases",
                    method="POST",
                    body={
                        "symptom": (
                            "slow HTTP response\n"
                            "Cookie: session=G9_SYMPTOM_COOKIE_SENTINEL\n"
                            "Authorization: Bearer G9_SYMPTOM_AUTH_SENTINEL\n"
                            "token=G9_SYMPTOM_TOKEN_SENTINEL\n"
                            "password=G9_SYMPTOM_PASSWORD_SENTINEL\n"
                            "bridge token=G9_SYMPTOM_BRIDGE_SENTINEL\n"
                            "capture path=/private/tmp/G9_CAPTURE_PATH_SENTINEL"
                        )
                    },
                )
                assert status == 201
                privacy_case_id = json.loads(privacy_case)["id"]
                status, _ = request(
                    base,
                    f"/api/cases/{privacy_case_id}/capture",
                    method="POST",
                    body=privacy_capture,
                    content_type="application/octet-stream",
                )
                assert status == 200
                status, _ = request(
                    base, f"/api/cases/{privacy_case_id}/investigate", method="POST"
                )
                assert status == 200
                assert FakeProvider.requests_seen
                provider_body, provider_headers = FakeProvider.requests_seen[0]
                serialized = json.dumps(provider_body)
                forbidden = (
                    "G9_COOKIE_SENTINEL",
                    "G9_AUTH_SENTINEL",
                    "G9_SET_COOKIE_SENTINEL",
                    "G9_SYMPTOM_COOKIE_SENTINEL",
                    "G9_SYMPTOM_AUTH_SENTINEL",
                    "G9_SYMPTOM_TOKEN_SENTINEL",
                    "G9_SYMPTOM_PASSWORD_SENTINEL",
                    "G9_SYMPTOM_BRIDGE_SENTINEL",
                    "G9_CAPTURE_PATH_SENTINEL",
                )
                assert all(sentinel not in serialized for sentinel in forbidden)
                assert "CLOUD_CREDENTIAL_SENTINEL" not in serialized
                assert str(root) not in serialized
                assert "RAW_CAPTURE" not in serialized
                assert original_bytes.hex() not in serialized
                assert privacy_capture.hex() not in serialized
                assert all(
                    sentinel.encode() not in json.dumps(provider_headers).encode()
                    for sentinel in forbidden
                )
                assert all(
                    "CLOUD_CREDENTIAL_SENTINEL" not in value
                    for name, value in provider_headers.items()
                    if name != "authorization"
                )
                assert provider_headers.get("authorization") == "Bearer CLOUD_CREDENTIAL_SENTINEL"
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
                combined_logs = logs.stdout + logs.stderr
                assert "CLOUD_CREDENTIAL_SENTINEL" not in combined_logs
                assert all(sentinel not in combined_logs for sentinel in forbidden)
                corpus_results.append(
                    {
                        "task": "G9.13",
                        "scenario": "fake HTTPS cloud provider seeded-sentinel inspection",
                        "result": "PASS",
                        "request_count": len(FakeProvider.requests_seen),
                        "authorization_header_only": True,
                        "forbidden_body_header_log_values_absent": True,
                        "raw_capture_and_payload_absent": True,
                    }
                )
            finally:
                https_server.shutdown()
                https_server.server_close()
                https_thread.join(timeout=2)
            print(
                "PASS: automated G9.1-G9.13 corpus, health/web, Host/Origin policy, "
                "rules-only investigation, evidence, "
                "restart persistence, immutable original, host.docker.internal provider route, "
                "and cloud privacy through the image"
            )
        finally:
            compose(env, "down", files=host_route_files)
    final_image = subprocess.run(
        ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if final_image.returncode or final_image.stdout.strip() != starting_image_id:
        raise RuntimeError("candidate_image_identity_changed_during_acceptance")
    if expected_image_id and final_image.stdout.strip() != expected_image_id:
        raise RuntimeError("candidate_image_id_mismatch_after_acceptance")
    artifact_root = Path(os.environ.get("WIRECLAW_GATE9_ARTIFACT_DIR", ROOT / "artifacts/gate9"))
    artifact_root.mkdir(parents=True, exist_ok=True)
    (artifact_root / "corpus.json").write_text(
        json.dumps(
            {
                "candidate_image_id": final_image.stdout.strip(),
                "results": corpus_results,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        detail = str(error)
        raise SystemExit(
            f"acceptance_assertion_failed:{Path(frame.filename).name}:{frame.lineno}"
            + (f":{detail}" if detail else "")
        ) from None
    except (OSError, RuntimeError, URLError) as error:
        raise SystemExit(str(error) or "container_release_check_failed") from None
