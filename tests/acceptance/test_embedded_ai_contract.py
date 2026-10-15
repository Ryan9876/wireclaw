"""Adversarial privacy and trust-boundary acceptance for embedded reasoning."""

import json
import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
from fastapi.testclient import TestClient
from wireclaw_api import create_app
from wireclaw_api.config import Policy, ProviderMode
from wireclaw_api.providers.openai_compatible import OpenAICompatibleProvider
from wireclaw_api.reasoning import loop, persistence
from wireclaw_api.reasoning.context import SYSTEM_INSTRUCTION


class StepDatabase:
    def __init__(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute(
            "CREATE TABLE reasoning_steps (case_id TEXT,step_id TEXT,sequence INTEGER,at TEXT,metadata TEXT,UNIQUE(case_id,sequence))"
        )

    @contextmanager
    def connect(self):
        with self.connection:
            yield self.connection


class EmbeddedService:
    def __init__(self, api_token):
        self.policy = SimpleNamespace(
            provider_mode=ProviderMode.EMBEDDED,
            provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
            provider_base_url="http://host.docker.internal:8767/v1",
            provider_timeout_seconds=5,
            provider_api_key=api_token,
            max_provider_request_bytes=131072,
            max_provider_response_bytes=65536,
            max_reasoning_steps=8,
            max_reasoning_evidence_items=200,
            max_identical_capability_request_count=1,
            max_display_filter_chars=2048,
        )
        self.db = StepDatabase()
        self.original_capture = b"RAW_CAPTURE_SENTINEL_71ac"
        self.case = {
            "id": "case-boundary-01",
            "symptom": (
                "Cookie: COOKIE_SENTINEL_72bd Authorization: Bearer "
                "BEARER_SENTINEL_83ce; inspect /Users/private/capture.pcap"
            ),
            "original_id": "c" * 32,
            "capture_sha": "d" * 64,
        }
        self.evidence = [
            {
                "id": "ev_" + "a" * 64 + "_analyze_http_timing_stream0",
                "category": "analyze_http_timing",
                "epistemic_class": "derived",
                "source": {"capability": "analyze_http_timing", "tool": "tshark", "version": "4.2"},
                "scope": {
                    "tcp_stream": 0,
                    "absolute_path": "/Users/private/original.pcapng",
                },
                "value": {
                    "state": "ok",
                    "limitations": ["Cookie: COOKIE_SENTINEL_72bd", "token=TOKEN_SENTINEL_94df"],
                    "transactions": [
                        {
                            "request_to_first_response_seconds": 2.1,
                            "request_text": "PAYLOAD_SENTINEL_a5e0",
                        }
                    ],
                    "raw_payload": "PAYLOAD_SENTINEL_a5e0",
                    "absolute_path": "/Users/private/original.pcapng",
                    "bridge_token": "BRIDGE_TOKEN_SENTINEL_b6f1",
                    "analyzer_stdout": "ANALYZER_STDOUT_SENTINEL_c702",
                },
                "summary": "Derived timing; Set-Cookie: COOKIE_SENTINEL_72bd",
                "limitations": ["Bearer BEARER_SENTINEL_83ce"],
                "frame_refs": [1, 2],
            }
        ]
        self.report = {
            "capture_quality": {"state": "good", "evidence_ids": [], "limitations": []},
            "findings": [],
            "remaining_hypotheses": [],
        }
        self.calls = 0

    def get(self, case_id):
        return self.case

    def evidence_records(self, case_id):
        return self.evidence

    def run_reasoning_capability(self, case_id, request):
        self.calls += 1
        return {"evidence": []}


def test_exact_embedded_provider_request_and_persisted_audit_exclude_private_sentinels(
    monkeypatch, caplog
):
    ai_token = "AI_TOKEN_SENTINEL_d813"
    service = EmbeddedService(ai_token)
    captured = []
    original_client = httpx.AsyncClient

    def handler(request):
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {"action": "finalize", "hypotheses": [], "remaining_hypotheses": []}
                            )
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    monkeypatch.setattr(
        loop,
        "make_provider",
        lambda policy: OpenAICompatibleProvider(
            mode=policy.provider_mode,
            base_url=policy.provider_base_url,
            model=policy.provider_model,
            timeout_seconds=policy.provider_timeout_seconds,
            api_key=policy.provider_api_key,
        ),
    )

    result, _, _ = loop.run_loop(service, service.case["id"], service.report)
    assert result["mode"] == "model_assisted"
    assert len(captured) == 1
    request = captured[0]
    body = json.loads(request.content)
    assert set(body) == {"model", "messages", "temperature"}
    assert body["model"] == "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    assert body["temperature"] == 0
    assert body["messages"][0] == {"role": "system", "content": SYSTEM_INSTRUCTION}
    assert set(request.headers) == {
        "host",
        "accept",
        "accept-encoding",
        "connection",
        "user-agent",
        "content-type",
        "content-length",
        "authorization",
    }
    assert request.headers["authorization"] == f"Bearer {ai_token}"
    non_auth_headers = {
        key: value for key, value in request.headers.items() if key != "authorization"
    }
    sentinels = (
        "RAW_CAPTURE_SENTINEL_71ac",
        "PAYLOAD_SENTINEL_a5e0",
        "/Users/private/",
        "COOKIE_SENTINEL_72bd",
        "BEARER_SENTINEL_83ce",
        "TOKEN_SENTINEL_94df",
        "BRIDGE_TOKEN_SENTINEL_b6f1",
        "ANALYZER_STDOUT_SENTINEL_c702",
        ai_token,
    )
    serialized_request = request.content.decode()
    for sentinel in sentinels:
        assert sentinel not in serialized_request
        assert sentinel not in json.dumps(non_auth_headers)
    context_json = json.loads(body["messages"][1]["content"])
    assert context_json["evidence"][0]["value"]["transactions"] == [
        {"request_to_first_response_seconds": 2.1}
    ]
    audit = json.dumps(persistence.steps(service, service.case["id"]), sort_keys=True)
    case_and_capture = json.dumps(
        {"case": service.case, "raw_capture": service.original_capture.decode()}, sort_keys=True
    )
    for sentinel in sentinels:
        assert sentinel not in audit
    assert ai_token not in case_and_capture
    assert ai_token not in caplog.text
    assert not service.calls


def test_injected_arbitrary_command_and_capability_fields_never_execute(monkeypatch):
    service = EmbeddedService("x" * 32)
    provider = SimpleNamespace(
        propose=lambda request: SimpleNamespace(
            failure_code=None,
            content=json.dumps(
                {
                    "action": "request_capability",
                    "capability": "analyze_rtt",
                    "parameters": {"tcp_stream": 0, "command": "touch /tmp/injected"},
                }
            ),
        )
    )
    monkeypatch.setattr(loop, "make_provider", lambda _policy: provider)
    result, ranking, next_evidence = loop.run_loop(service, service.case["id"], service.report)
    assert result["mode"] == "model_fallback"
    assert result["failure_code"] == "provider_invalid_response"
    assert ranking == []
    assert next_evidence == []
    assert service.calls == 0


def test_api_responses_and_case_database_exclude_provider_credentials(tmp_path, monkeypatch):
    api_token = "API_RESPONSE_SENTINEL_9012" + "x" * 32
    base_url = "http://host.docker.internal:8767/v1"
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "unavailable:docker-connectivity")
    app = create_app(
        tmp_path / "api",
        Policy(
            provider_mode=ProviderMode.EMBEDDED,
            provider_base_url=base_url,
            provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
            provider_api_key=api_token,
        ),
    )
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        health = client.get("/api/health")
        capabilities = client.get("/api/config/capabilities")
        created = client.post("/api/cases", json={"symptom": "request latency"})
    assert health.status_code == 200 and health.json()["status"] == "ok"
    assert capabilities.status_code == 200
    for response in (health, capabilities, created):
        encoded = response.text
        assert api_token not in encoded
        assert base_url not in encoded
        assert "Authorization" not in encoded
    assert health.json()["ai"]["embedded_availability"] == "unavailable"
    database_files = list((tmp_path / "api").rglob("*.sqlite3"))
    assert database_files
    for path in database_files:
        assert api_token.encode() not in path.read_bytes()
