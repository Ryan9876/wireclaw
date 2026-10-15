"""Gate 7 orchestration, persistence, and safe fallback without a real model."""

import json

import wireclaw_api.app as api_module
from fastapi.testclient import TestClient
from wireclaw_api import create_app
from wireclaw_api.config import Policy, ProviderMode
from wireclaw_api.gate4_service import Service as Gate4Service
from wireclaw_api.gate6_service import Service as Gate6Service
from wireclaw_api.gate7_service import Service
from wireclaw_api.models import CapabilityRequest, State
from wireclaw_api.providers.models import ProviderResult
from wireclaw_api.reasoning import loop, persistence


def prepared_service(tmp_path, policy):
    service = Service(tmp_path, policy)
    case = service.create("A slow HTTP transaction")
    case_id = case["id"]
    capture_sha = "a" * 64
    artifact_id = "b" * 32
    with service.db.connect() as conn:
        conn.execute(
            "UPDATE cases SET capture_sha=?,original_id=? WHERE id=?",
            (capture_sha, artifact_id, case_id),
        )
    run_id, _ = service.start(case_id, "seed", {})
    evidence = [
        {
            "schema_version": "1.0",
            "id": f"ev_{capture_sha}_assess_capture_quality",
            "category": "assess_capture_quality",
            "epistemic_class": "derived",
            "source": {"capability": "assess_capture_quality", "tool": "tshark", "version": "test"},
            "scope": {"capture": True},
            "value": {"capture_sha256": capture_sha, "state": "good", "limitations": []},
            "summary": "capture quality",
            "limitations": [],
        },
        {
            "schema_version": "1.0",
            "id": f"ev_{capture_sha}_list_conversations",
            "category": "list_conversations",
            "epistemic_class": "derived",
            "source": {"capability": "list_conversations", "tool": "tshark", "version": "test"},
            "scope": {"capture": True},
            "value": {"capture_sha256": capture_sha, "conversations": []},
            "summary": "conversation inventory",
            "limitations": [],
        },
    ]
    service.save(
        case_id,
        run_id,
        {
            "schema_version": "1.0",
            "capture_sha256": capture_sha,
            "analyzer_version": "test",
            "tool_versions": {},
            "configuration": {},
            "evidence": evidence,
        },
    )
    for state in (
        State.INGESTING,
        State.VALIDATING_CAPTURE,
        State.BASELINE_ANALYSIS,
        State.INVESTIGATING,
    ):
        service.transition(case_id, state)
    return service, case_id


class ScriptedCycleProvider:
    def __init__(self, actions):
        self.actions = iter(actions)
        self.requests = []

    def propose(self, request):
        self.requests.append(request)
        return ProviderResult(content=json.dumps(next(self.actions)))


def capability_action(name="analyze_dns"):
    return {"action": "request_capability", "capability": name, "parameters": {}}


def finalize_action():
    return {"action": "finalize", "hypotheses": [], "remaining_hypotheses": []}


def install_cycle_runner(monkeypatch, providers, capability_calls):
    provider_iter = iter(providers)
    monkeypatch.setattr(loop, "make_provider", lambda _policy: next(provider_iter))

    def run_capability(_case_id, request):
        capability_calls.append(request.capability)
        return {"evidence": []}

    def investigate(self, case_id):
        if self.get(case_id)["state"] in (State.COMPLETE, State.FAILED):
            self.transition(case_id, State.BASELINE_ANALYSIS)
            self.transition(case_id, State.INVESTIGATING)
        return self._assemble_report(case_id)

    monkeypatch.setattr(Gate4Service, "investigate", investigate)
    return run_capability


def test_first_model_assisted_investigation_persists_reconstructable_step_audit(
    tmp_path, monkeypatch
):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
        provider_api_key="API_KEY_SENTINEL",
        max_reasoning_steps=2,
    )
    service, case_id = prepared_service(tmp_path, policy)
    final_with_response_sentinel = {
        **finalize_action(),
        "hypotheses": [
            {
                "category": "unsupported.category",
                "evidence_ids": [],
                "fault_domains": [],
                "summary": "RAW_RESPONSE_SENTINEL",
            }
        ],
    }
    provider = ScriptedCycleProvider([capability_action(), final_with_response_sentinel])
    calls = []
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], calls)
    with service.db.connect() as conn:
        conn.execute(
            "UPDATE cases SET symptom=? WHERE id=?",
            ("RAW_PROMPT_SENTINEL /private/case.pcap", case_id),
        )
    try:
        service.investigate(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)
        assert report["reasoning"]["mode"] == "model_assisted"
        assert report["reasoning"]["steps"] == 2
        assert len(records) == 2
        first = records[0]
        assert first["case_id"] == case_id
        assert first["step_id"]
        assert first["sequence"] == 1
        assert first["at"]
        assert first["provider_mode"] == ProviderMode.LOCAL.value
        assert first["model"] == "cycle-model"
        assert first["endpoint_class"] == "local"
        assert len(first["context_digest"]) == 64
        assert first["action_type"] == "request_capability"
        assert first["capability"] == "analyze_dns"
        assert first["parameters"] == {}
        assert first["request_fingerprint"]
        assert first["resulting_evidence_ids"] == []
        assert first["status"] == "complete"
        assert first["failure_code"] is None
        assert isinstance(first["duration_ms"], int)
        assert first["reasoning_session_id"] == records[1]["reasoning_session_id"]
        serialized_history = json.dumps(records)
        for sentinel in (
            "API_KEY_SENTINEL",
            "RAW_PROMPT_SENTINEL",
            "/private/case.pcap",
            "Authorization",
            "RAW_RESPONSE_SENTINEL",
        ):
            assert sentinel not in serialized_history
    finally:
        service.close()


def test_reinvestigation_uses_fresh_cycle_and_preserves_previous_audit(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
        max_reasoning_steps=2,
    )
    service, case_id = prepared_service(tmp_path, policy)
    repeated_capability = capability_action()
    first_provider = ScriptedCycleProvider([repeated_capability, finalize_action()])
    second_provider = ScriptedCycleProvider([repeated_capability, finalize_action()])
    calls = []
    service.run_reasoning_capability = install_cycle_runner(
        monkeypatch, [first_provider, second_provider], calls
    )
    try:
        service.investigate(case_id)
        first_records = persistence.steps(service, case_id)
        first_session = first_records[0]["reasoning_session_id"]
        assert len(first_records) == 2

        service.investigate(case_id)
        all_records = persistence.steps(service, case_id)
        second_records = [
            row for row in all_records if row["reasoning_session_id"] != first_session
        ]
        assert len(all_records) == 4
        assert len(second_records) == 2
        assert calls == ["analyze_dns", "analyze_dns"]
        assert first_records[0]["request_fingerprint"] == second_records[0]["request_fingerprint"]
        assert first_session != second_records[0]["reasoning_session_id"]
        assert service.report(case_id)["reasoning"]["steps"] == 2
        assert service.report(case_id)["reasoning"]["mode"] == "model_assisted"
    finally:
        service.close()


def test_step_limit_is_applied_independently_to_each_reasoning_cycle(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
        max_reasoning_steps=2,
    )
    service, case_id = prepared_service(tmp_path, policy)
    first_provider = ScriptedCycleProvider([capability_action(), finalize_action()])
    second_provider = ScriptedCycleProvider(
        [capability_action(), capability_action("analyze_tls_handshakes")]
    )
    calls = []
    service.run_reasoning_capability = install_cycle_runner(
        monkeypatch, [first_provider, second_provider], calls
    )
    try:
        service.investigate(case_id)
        service.investigate(case_id)
        records = persistence.steps(service, case_id)
        sessions = {record["reasoning_session_id"] for record in records}
        assert len(sessions) == 2
        assert [
            sum(row["reasoning_session_id"] == session for row in records) for session in sessions
        ] == [2, 2]
        assert calls == ["analyze_dns", "analyze_dns", "analyze_tls_handshakes"]
        assert service.report(case_id)["reasoning"]["mode"] == "model_fallback"
        assert service.report(case_id)["reasoning"]["steps"] == 2
        assert service.report(case_id)["reasoning"]["failure_code"] == "reasoning_step_limit"
    finally:
        service.close()


def test_completed_case_capability_rebuild_preserves_reasoning_history(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
    )
    service, case_id = prepared_service(tmp_path, policy)
    providers = [
        ScriptedCycleProvider([finalize_action()]),
        ScriptedCycleProvider([finalize_action()]),
    ]
    calls = []
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, providers, calls)
    external_capability_calls = []

    def complete_capability(self, case, request):
        external_capability_calls.append(request.capability)
        self.transition(case, State.BASELINE_ANALYSIS)
        self.transition(case, State.INVESTIGATING)
        self._assemble_report(case)
        return {"ok": True}

    monkeypatch.setattr(Gate6Service, "capability", complete_capability)
    try:
        service.investigate(case_id)
        prior = persistence.steps(service, case_id)
        assert len(prior) == 1
        service.capability(
            case_id,
            CapabilityRequest(artifact_id="b" * 32, capability="analyze_dns"),
        )
        history = persistence.steps(service, case_id)
        assert len(history) == 2
        assert history[0]["reasoning_session_id"] != history[1]["reasoning_session_id"]
        assert service.report(case_id)["reasoning"]["steps"] == 1
        assert external_capability_calls == ["analyze_dns"]
        assert len(calls) == 0
    finally:
        service.close()


def test_case_deletion_cascades_all_reasoning_cycles(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
    )
    service, case_id = prepared_service(tmp_path, policy)
    providers = [
        ScriptedCycleProvider([finalize_action()]),
        ScriptedCycleProvider([finalize_action()]),
    ]
    calls = []
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, providers, calls)
    try:
        # Two report cycles exercise the same cascade regardless of case state.
        service._assemble_report(case_id)
        service.transition(case_id, State.BASELINE_ANALYSIS)
        service.transition(case_id, State.INVESTIGATING)
        service._assemble_report(case_id)
        assert len(persistence.steps(service, case_id)) == 2
        service.delete(case_id)
        with service.db.connect() as conn:
            assert (
                conn.execute(
                    "SELECT count(*) FROM reasoning_steps WHERE case_id=?", (case_id,)
                ).fetchone()[0]
                == 0
            )
    finally:
        service.close()


def test_rules_only_report_exposes_mode_and_keeps_database_reasoning_table(tmp_path):
    service, case_id = prepared_service(tmp_path, Policy())
    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        assert report["reasoning"] == {
            "mode": "rules_only",
            "status": "complete",
            "steps": 0,
            "provider_mode": "none",
            "model": None,
            "embedded_availability": "not_applicable",
            "embedded_failure_code": None,
        }
        with service.db.connect() as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
            assert conn.execute("SELECT count(*) FROM reasoning_steps").fetchone()[0] == 0
    finally:
        service.close()


def test_embedded_health_and_capabilities_expose_safe_ready_status(tmp_path, monkeypatch):
    token = "API_KEY_SENTINEL_" + "x" * 40
    path_sentinel = "/private/model/path/SECRET.gguf"
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key=token,
    )
    app = create_app(tmp_path / "api", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        health = client.get("/api/health").json()
        capabilities = client.get("/api/config/capabilities").json()
    for value in (health, capabilities):
        encoded = json.dumps(value)
        assert token not in encoded
        assert path_sentinel not in encoded
        assert "Authorization" not in encoded
        assert value["ai"] == {
            "effective_provider_mode": "embedded_local",
            "embedded_availability": "ready",
            "model": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
            "failure_code": None,
        }


def test_launcher_unavailable_status_does_not_change_core_health(tmp_path, monkeypatch):
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "unavailable:docker-connectivity")
    app = create_app(tmp_path / "api", Policy())
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        health_response = client.get("/api/health")
        health = health_response.json()
    assert health_response.status_code == 200
    assert health["status"] == "ok"
    assert health["ai"] == {
        "effective_provider_mode": "none",
        "embedded_availability": "unavailable",
        "model": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        "failure_code": "docker-connectivity",
    }


def test_embedded_reasoning_audit_records_model_and_launcher_fallback_without_secrets(
    tmp_path, monkeypatch
):
    token = "API_KEY_SENTINEL_" + "x" * 40
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key=token,
        max_reasoning_steps=1,
    )
    service, case_id = prepared_service(tmp_path / "embedded", policy)
    provider = ScriptedCycleProvider([finalize_action()])
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])
    service._assemble_report(case_id)
    assisted = service.report(case_id)
    assert assisted["reasoning"]["provider_mode"] == "embedded_local"
    assert assisted["reasoning"]["model"] == "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    assert assisted["reasoning"]["embedded_availability"] == "ready"
    assert token not in json.dumps(assisted)

    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "unavailable:docker-connectivity")
    rules_service, rules_case = prepared_service(tmp_path / "rules", Policy())
    rules_service._assemble_report(rules_case)
    fallback = rules_service.report(rules_case)
    assert fallback["reasoning"]["mode"] == "rules_only"
    assert fallback["reasoning"]["embedded_availability"] == "unavailable"
    assert fallback["reasoning"]["embedded_failure_code"] == "docker-connectivity"


def test_embedded_provider_failure_degrades_health_and_case_ai_status(tmp_path, monkeypatch):
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key="ephemeral-test-token-" + "x" * 40,
        max_reasoning_steps=1,
    )
    service, case_id = prepared_service(tmp_path / "embedded-crash", policy)

    class FailedProvider:
        def propose(self, _request):
            return ProviderResult(failure_code="provider_unavailable")

    monkeypatch.setattr(loop, "make_provider", lambda _policy: FailedProvider())
    service._assemble_report(case_id)

    expected = {
        "effective_provider_mode": "none",
        "embedded_availability": "unavailable",
        "model": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        "failure_code": "runtime-unhealthy",
    }
    assert service.ai_status() == expected
    assert service.get(case_id)["ai_status"] == expected
    assert service.report(case_id)["reasoning"]["embedded_availability"] == "unavailable"
    monkeypatch.setattr(api_module, "Service", lambda *_args: service)
    app = create_app(tmp_path / "embedded-crash-api", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        assert client.get("/api/health").json()["ai"] == expected
        assert client.get("/api/config/capabilities").json()["ai"] == expected


def test_provider_timeout_persists_bounded_audit_and_keeps_report_usable(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.CLOUD,
        provider_base_url="https://provider.example/v1",
        provider_model="fake-model",
        provider_api_key="API_KEY_SENTINEL",
    )
    service, case_id = prepared_service(tmp_path, policy)

    class TimeoutProvider:
        def propose(self, request):
            return ProviderResult(failure_code="provider_timeout")

    monkeypatch.setattr(loop, "make_provider", lambda _policy: TimeoutProvider())
    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        assert report["reasoning"]["mode"] == "model_fallback"
        assert report["reasoning"]["failure_code"] == "provider_timeout"
        assert any("provider_timeout" in item for item in report["limitations"])
        with service.db.connect() as conn:
            metadata = conn.execute(
                "SELECT metadata FROM reasoning_steps WHERE case_id=?", (case_id,)
            ).fetchone()[0]
            runs = json.dumps(
                [
                    dict(row)
                    for row in conn.execute("SELECT * FROM runs WHERE case_id=?", (case_id,))
                ]
            )
        assert "API_KEY_SENTINEL" not in metadata
        assert "API_KEY_SENTINEL" not in runs
        assert "API_KEY_SENTINEL" not in json.dumps(report)
        assert service.evidence_records(case_id)
    finally:
        service.close()
