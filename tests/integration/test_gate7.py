"""Gate 7 orchestration, persistence, and safe fallback without a real model."""

import json

from wireclaw_api.config import Policy, ProviderMode
from wireclaw_api.gate7_service import Service
from wireclaw_api.models import State
from wireclaw_api.providers.models import ProviderResult
from wireclaw_api.reasoning import loop


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
        }
        with service.db.connect() as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
            assert conn.execute("SELECT count(*) FROM reasoning_steps").fetchone()[0] == 0
    finally:
        service.close()


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
