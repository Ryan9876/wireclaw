"""Gate 7 orchestration, persistence, and safe fallback without a real model."""

import gc
import hashlib
import json
import warnings
from threading import get_ident

import httpx
import wireclaw_api.app as api_module
import wireclaw_api.gate7_service as gate7_module
from fastapi.testclient import TestClient
from wireclaw_analyzer import AnalyzerError
from wireclaw_api import create_app
from wireclaw_api.config import Policy, ProviderMode
from wireclaw_api.gate4_service import Service as Gate4Service
from wireclaw_api.gate6_service import Service as Gate6Service
from wireclaw_api.gate7_service import Service
from wireclaw_api.models import CapabilityRequest, State
from wireclaw_api.providers import openai_compatible
from wireclaw_api.providers.models import ProviderResult
from wireclaw_api.reasoning import loop, persistence
from wireclaw_api.service import Service as Gate3Service


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


def test_async_capture_executes_embedded_status_probe_off_the_event_loop(tmp_path, monkeypatch):
    model_id = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    token = "ASYNC_CAPTURE_STATUS_TOKEN_SENTINEL_" + "x" * 32
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model=model_id,
        provider_api_key=token,
    )
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")

    requests = []
    probe_threads = []
    real_client = httpx.AsyncClient

    async def healthy_model_server(request):
        requests.append(request)
        return httpx.Response(200, json={"data": [{"id": model_id}]})

    transport = httpx.MockTransport(healthy_model_server)

    def client_factory(*args, **kwargs):
        return real_client(*args, transport=transport, **kwargs)

    real_probe = openai_compatible.embedded_runtime_available

    def observed_probe(current_policy):
        probe_threads.append(get_ident())
        return real_probe(current_policy)

    monkeypatch.setattr(openai_compatible.httpx, "AsyncClient", client_factory)
    monkeypatch.setattr(gate7_module, "embedded_runtime_available", observed_probe)

    app = create_app(tmp_path / "async-capture", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        service = client.app.state.service

        def complete_fake_ingest(case_id, run_id, path):
            capture_sha = hashlib.sha256(path.read_bytes()).hexdigest()
            service.transition(case_id, State.VALIDATING_CAPTURE)
            with service.db.connect() as conn:
                conn.execute(
                    "UPDATE cases SET capture_sha=?,original_id=? WHERE id=?",
                    (capture_sha, "c" * 32, case_id),
                )
                conn.execute("UPDATE runs SET status='complete' WHERE id=?", (run_id,))
            service.transition(case_id, State.BASELINE_ANALYSIS)
            return service.get(case_id)

        service.ingest = complete_fake_ingest
        created = client.post("/api/cases", json={"symptom": "A slow connection"})
        assert created.status_code == 201
        requests.clear()
        probe_threads.clear()

        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always", RuntimeWarning)
            uploaded = client.post(
                f"/api/cases/{created.json()['id']}/capture",
                content=b"synthetic capture bytes",
                headers={"content-type": "application/octet-stream"},
            )
            gc.collect()

    unawaited_warnings = [
        str(item.message) for item in caught_warnings if "was never awaited" in str(item.message)
    ]
    assert len(requests) == 2, (
        "expected embedded model probes in begin_ingest and threaded ingest; "
        f"observed {len(requests)} requests and warnings {unawaited_warnings}"
    )
    assert not unawaited_warnings
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["state"] == State.BASELINE_ANALYSIS
    assert len(probe_threads) == 2
    assert all(request.headers["authorization"] == f"Bearer {token}" for request in requests)


def test_async_capture_cleanup_executes_embedded_status_probe_off_the_event_loop(
    tmp_path, monkeypatch
):
    model_id = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model=model_id,
        provider_api_key="ASYNC_CAPTURE_CLEANUP_TOKEN_SENTINEL_" + "x" * 32,
    )
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")

    requests = []
    real_client = httpx.AsyncClient

    async def healthy_model_server(request):
        requests.append(request)
        return httpx.Response(200, json={"data": [{"id": model_id}]})

    transport = httpx.MockTransport(healthy_model_server)
    monkeypatch.setattr(
        openai_compatible.httpx,
        "AsyncClient",
        lambda *args, **kwargs: real_client(*args, transport=transport, **kwargs),
    )
    monkeypatch.setattr(
        gate7_module, "embedded_runtime_available", openai_compatible.embedded_runtime_available
    )

    app = create_app(tmp_path / "async-capture-cleanup", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        service = client.app.state.service

        def fail_ingest(_case_id, _run_id, _path):
            raise AnalyzerError("synthetic_ingest_failure")

        service.ingest = fail_ingest
        created = client.post("/api/cases", json={"symptom": "A slow connection"})
        assert created.status_code == 201
        case_id = created.json()["id"]
        requests.clear()

        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always", RuntimeWarning)
            uploaded = client.post(
                f"/api/cases/{case_id}/capture",
                content=b"synthetic capture bytes",
                headers={"content-type": "application/octet-stream"},
            )
            gc.collect()
        with service.db.connect() as conn:
            failed_state = conn.execute(
                "SELECT state FROM cases WHERE id=?", (case_id,)
            ).fetchone()["state"]

    unawaited_warnings = [
        str(item.message) for item in caught_warnings if "was never awaited" in str(item.message)
    ]
    assert len(requests) == 2, (
        "expected embedded model probes in begin_ingest and cleanup_ingest; "
        f"observed {len(requests)} requests and warnings {unawaited_warnings}"
    )
    assert not unawaited_warnings
    assert uploaded.status_code == 422
    assert failed_state == State.FAILED


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


def test_finalize_recommendations_cannot_outgrow_deterministic_hypotheses(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    evidence = service.evidence_records(case_id)
    deterministic = service.build_investigation_result(
        case_id=case_id,
        symptom=service.get(case_id)["symptom"],
        evidence=evidence,
        analyzer_versions=service.analyzer_versions(case_id),
        max_display_filter_chars=policy.max_display_filter_chars,
    )
    prose_sentinel = "ATTACKER_NEXT_EVIDENCE_SENTINEL: assert an unrelated breach"
    action = {
        "action": "finalize",
        "hypotheses": [],
        "remaining_hypotheses": [
            {
                "category": "server.application_wait",
                "evidence_ids": [],
                "fault_domains": ["server_application"],
                "next_evidence": [prose_sentinel, "browser_har"],
            }
        ],
    }
    provider = ScriptedCycleProvider([action])
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)

        assert report["remaining_hypotheses"] == deterministic["remaining_hypotheses"]
        assert prose_sentinel not in json.dumps(report)
        assert prose_sentinel not in json.dumps(records)
        assert (
            "Capture a browser HAR for the same user-visible transaction."
            not in report["recommended_next_evidence"]
        )
        assert records[-1]["next_evidence_codes"] == []

        monkeypatch.setattr(api_module, "Service", lambda *_args: service)
        app = create_app(tmp_path / "recommendation-api", policy)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            api_report = client.get(f"/api/cases/{case_id}/report")
            assert api_report.status_code == 200
            assert prose_sentinel not in api_report.text
            assert "Capture a browser HAR for the same user-visible transaction." not in (
                api_report.text
            )
    finally:
        service.close()


def test_model_omission_cannot_remove_deterministic_finding(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    deterministic_finding = {
        "id": "finding_deterministic_rtt",
        "title": "Measured RTT",
        "category": "tcp.rtt",
        "confidence": "medium",
        "statement": "The deterministic baseline measured elevated RTT.",
        "epistemic_class": "inferred",
        "fault_domains": ["network_path"],
        "affected_scope": {},
        "evidence_ids": [service.evidence_records(case_id)[0]["id"]],
        "alternate_explanations": [],
        "limitations": [],
        "recommended_validation": [],
        "wireshark": {
            "applicable": False,
            "full_capture": False,
            "evidence_capture": False,
            "copy_filter": False,
            "show_packet_evidence": False,
            "display_filter": None,
        },
    }

    def build_with_deterministic_finding(**kwargs):
        report = build_investigation_result(**kwargs)
        report["findings"] = [deterministic_finding]
        return report

    from wireclaw_api import gate4_service, gate7_service
    from wireclaw_api.investigation import build_investigation_result

    monkeypatch.setattr(
        gate7_service, "build_investigation_result", build_with_deterministic_finding
    )
    monkeypatch.setattr(
        gate4_service, "build_investigation_result", build_with_deterministic_finding
    )
    provider = ScriptedCycleProvider([finalize_action()])
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)

        assert report["reasoning"]["mode"] == "model_assisted"
        assert report["reasoning"]["accepted_categories"] == []
        assert report["findings"] == [deterministic_finding]
    finally:
        service.close()


def test_remaining_recommendation_rejects_evidence_from_another_finding(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    evidence = service.evidence_records(case_id)
    unrelated_evidence_id = evidence[0]["id"]
    related_evidence_id = evidence[1]["id"]
    assert evidence[0]["epistemic_class"] in {"observed", "derived"}
    assert evidence[1]["epistemic_class"] in {"observed", "derived"}

    def report_with_unrelated_finding_evidence(**kwargs):
        report = build_investigation_result(**kwargs)
        report["findings"] = [
            {
                "id": "finding_review_other",
                "title": "Unrelated deterministic finding",
                "category": "tcp.rtt",
                "confidence": "medium",
                "statement": "This finding owns the cited evidence.",
                "epistemic_class": "inferred",
                "fault_domains": ["server_application"],
                "affected_scope": {},
                "evidence_ids": [unrelated_evidence_id],
                "alternate_explanations": [],
                "limitations": [],
                "recommended_validation": [],
                "wireshark": {
                    "applicable": False,
                    "full_capture": False,
                    "evidence_capture": False,
                    "copy_filter": False,
                    "show_packet_evidence": False,
                    "display_filter": None,
                },
            }
        ]
        report["remaining_hypotheses"] = [
            {
                "statement": "A deterministic server wait remains unresolved.",
                "fault_domains": ["server_application"],
                "evidence_ids": [related_evidence_id],
                "next_evidence": [],
            }
        ]
        return report

    from wireclaw_api import gate7_service
    from wireclaw_api.investigation import build_investigation_result

    monkeypatch.setattr(
        gate7_service, "build_investigation_result", report_with_unrelated_finding_evidence
    )
    prose_sentinel = "MODEL_RECOMMENDATION_PROSE_SENTINEL"
    provider = ScriptedCycleProvider(
        [
            {
                "action": "finalize",
                "hypotheses": [],
                "remaining_hypotheses": [
                    {
                        "category": "server.application_wait",
                        "evidence_ids": [unrelated_evidence_id],
                        "fault_domains": ["server_application"],
                        "next_evidence": ["server_side_capture", prose_sentinel],
                    }
                ],
            }
        ]
    )
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)
        deterministic = report_with_unrelated_finding_evidence(
            case_id=case_id,
            symptom=service.get(case_id)["symptom"],
            evidence=evidence,
            analyzer_versions=service.analyzer_versions(case_id),
            max_display_filter_chars=policy.max_display_filter_chars,
        )
        assert unrelated_evidence_id in evidence[0]["id"]
        assert unrelated_evidence_id in deterministic["findings"][0]["evidence_ids"]
        assert unrelated_evidence_id not in deterministic["remaining_hypotheses"][0]["evidence_ids"]
        assert report["reasoning"]["mode"] == "model_assisted"
        assert records[-1]["next_evidence_codes"] == []
        assert prose_sentinel not in json.dumps(report)
        assert (
            "Collect a synchronized server-side capture for the same transaction."
            not in (report["recommended_next_evidence"])
        )
    finally:
        service.close()


def test_valid_hypothesis_summary_sentinel_is_not_persisted_or_exposed(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    evidence = service.evidence_records(case_id)
    evidence_id = evidence[0]["id"]
    sentinel = "MODEL_SUMMARY_SENTINEL: claim a fabricated packet fact"

    def report_with_supported_test_finding(**kwargs):
        report = build_investigation_result(**kwargs)
        report["findings"] = [
            {
                "id": "finding_review_test",
                "title": "Review test finding",
                "category": "tcp.rtt",
                "confidence": "medium",
                "statement": "The test evidence supports a bounded finding.",
                "epistemic_class": "inferred",
                "fault_domains": ["network_path"],
                "affected_scope": {},
                "evidence_ids": [evidence_id],
                "alternate_explanations": [],
                "limitations": [],
                "recommended_validation": [],
                "wireshark": {
                    "applicable": False,
                    "full_capture": False,
                    "evidence_capture": False,
                    "copy_filter": False,
                    "show_packet_evidence": False,
                    "display_filter": None,
                },
            }
        ]
        return report

    from wireclaw_api import gate4_service, gate7_service
    from wireclaw_api.investigation import build_investigation_result

    monkeypatch.setattr(
        gate7_service, "build_investigation_result", report_with_supported_test_finding
    )
    monkeypatch.setattr(
        gate4_service, "build_investigation_result", report_with_supported_test_finding
    )
    provider = ScriptedCycleProvider(
        [
            {
                "action": "finalize",
                "hypotheses": [
                    {
                        "category": "tcp.rtt",
                        "evidence_ids": [evidence_id],
                        "fault_domains": ["network_path"],
                        "summary": sentinel,
                    }
                ],
                "remaining_hypotheses": [],
            }
        ]
    )
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)
        _, report_path = service.artifact(case_id, service._report_row(case_id)["id"])

        assert report["reasoning"]["accepted_categories"] == ["tcp.rtt"]
        assert sentinel not in json.dumps(records)
        assert sentinel not in json.dumps(service.get(case_id))
        assert sentinel not in json.dumps(report)
        assert sentinel.encode() not in report_path.read_bytes()

        monkeypatch.setattr(api_module, "Service", lambda *_args: service)
        app = create_app(tmp_path / "review-api", policy)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            api_report = client.get(f"/api/cases/{case_id}/report")
            assert api_report.status_code == 200
            assert sentinel not in api_report.text
            api_case = client.get(f"/api/cases/{case_id}")
            assert api_case.status_code == 200
            assert sentinel not in api_case.text
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
    from wireclaw_api import gate7_service

    monkeypatch.setattr(gate7_service, "embedded_runtime_available", lambda _policy: True)
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


def test_embedded_health_tracks_runtime_loss_and_recovery_without_investigation(
    tmp_path, monkeypatch
):
    token = "RUNTIME_STATUS_TOKEN_SENTINEL_" + "x" * 40
    model_id = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    reachability = {"ready": True, "calls": 0}

    def runtime_probe(_policy):
        reachability["calls"] += 1
        return reachability["ready"]

    from wireclaw_api import gate7_service

    monkeypatch.setattr(gate7_service, "embedded_runtime_available", runtime_probe, raising=False)
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model=model_id,
        provider_api_key=token,
    )
    app = create_app(tmp_path / "runtime-status", policy)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        ready_health = client.get("/api/health").json()
        ready_capabilities = client.get("/api/config/capabilities").json()
        assert ready_health["ai"]["embedded_availability"] == "ready"
        assert ready_capabilities["ai"]["embedded_availability"] == "ready"

        # Model-server process loss is injected after startup readiness. No case
        # investigation or provider completion is performed before these checks.
        reachability["ready"] = False
        unavailable_health_response = client.get("/api/health")
        unavailable_health = unavailable_health_response.json()
        unavailable_capabilities_response = client.get("/api/config/capabilities")
        unavailable_capabilities = unavailable_capabilities_response.json()

        assert unavailable_health_response.status_code == 200
        assert unavailable_health["status"] == "ok"
        assert unavailable_health["ai"]["embedded_availability"] == "unavailable"
        assert unavailable_health["ai"]["effective_provider_mode"] == "none"
        assert unavailable_capabilities["ai"] == unavailable_health["ai"]
        assert token not in unavailable_health_response.text
        assert token not in unavailable_capabilities_response.text
        assert "host.docker.internal" not in unavailable_health_response.text
        assert reachability["calls"] == 4

        created = client.post("/api/cases", json={"symptom": "A slow transaction"})
        assert created.status_code == 201
        case_status = client.get(f"/api/cases/{created.json()['id']}")
        assert case_status.status_code == 200
        assert case_status.json()["ai_status"] == unavailable_health["ai"]
        assert token not in case_status.text

        reachability["ready"] = True
        recovered_health = client.get("/api/health").json()
        assert recovered_health["ai"]["embedded_availability"] == "ready"


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
    from wireclaw_api import gate7_service

    monkeypatch.setattr(gate7_service, "embedded_runtime_available", lambda _policy: True)
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


def test_embedded_runtime_failure_state_is_initialized_before_recovery(tmp_path, monkeypatch):
    original_recover = Gate3Service.recover

    def recover_during_parent_init(self):
        assert self._embedded_runtime_failure_code is None
        return original_recover(self)

    monkeypatch.setattr(Gate3Service, "recover", recover_during_parent_init)
    service = Service(tmp_path, Policy())
    service.close()


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
