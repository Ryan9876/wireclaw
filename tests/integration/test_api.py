"""Gate 3 real-tool API, lifecycle, persistence and failure/security regressions."""

import hashlib
import json
import logging
import shutil
import sqlite3
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from generate import generate
from generate_gate2 import generate as generate_diagnostics
from wireclaw_analyzer import Analyzer, AnalyzerError, Limits
from wireclaw_analyzer.runner import Operation
from wireclaw_api import Policy, create_app
from wireclaw_api.models import State

pytestmark = pytest.mark.skipif(
    not shutil.which("tshark") or not shutil.which("capinfos"),
    reason="requires real TShark and capinfos",
)


@pytest.fixture
def environment(tmp_path):
    captures = generate(tmp_path / "fixtures")
    captures.update(generate_diagnostics(tmp_path / "diagnostics"))
    return tmp_path / "data", captures


def client_for(root, policy=None):
    return TestClient(
        create_app(root, policy), base_url="http://127.0.0.1:8765", raise_server_exceptions=False
    )


def case(client, symptom="application is slow"):
    response = client.post("/api/cases", json={"symptom": symptom})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def upload(client, case_id, data):
    return client.post(
        f"/api/cases/{case_id}/capture",
        content=data,
        headers={"content-type": "application/octet-stream"},
    )


def prepared(client, captures, name="clean_tcp"):
    case_id = case(client)
    assert upload(client, case_id, captures[name]).status_code == 200
    response = client.post(f"/api/cases/{case_id}/investigate")
    assert response.status_code == 200, response.text
    return case_id, response.json()


def request_for(record, capability="analyze_rtt", stream=0):
    return {"artifact_id": record["original_id"], "capability": capability, "tcp_stream": stream}


def test_case_lifecycle_restart_cached_determinism_schema_and_deletion(environment):
    root, captures = environment
    hostile = "$(touch /tmp/injected); --help ' OR 1=1; SECRET.symptom"
    with client_for(root) as client:
        case_id = case(client, hostile)
        intake = upload(client, case_id, captures["clean_tcp"])
        assert intake.status_code == 200
        assert intake.json()["capture_sha"] == hashlib.sha256(captures["clean_tcp"]).hexdigest()
        record = client.post(f"/api/cases/{case_id}/investigate").json()
        assert record["state"] == State.INVESTIGATING
        assert record["symptom"] == hostile
        assert [r["state"] for r in record["history"]] == [
            "NEW",
            "INGESTING",
            "VALIDATING_CAPTURE",
            "BASELINE_ANALYSIS",
            "INVESTIGATING",
        ]
        assert record["quality"] == "good"
        evidence = client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]
        assert len(evidence) == 16
        for item in evidence:
            client.app.state.service.analyzer(case_id).validator.validate(item)
        response = client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record))
        assert response.status_code == 200
        first = response.json()
        assert first["evidence"][0]["value"]["median_seconds"] == 0.01
        assert (
            client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record)).json()
            == first
        )
        original_row, original = client.app.state.service.artifact(case_id, record["original_id"])
        assert original.read_bytes() == captures["clean_tcp"]
        assert not original.stat().st_mode & 0o222
        assert (
            "relative_path"
            not in client.get(f"/api/cases/{case_id}/artifacts/{original_row['id']}").json()
        )
        assert (
            client.get(f"/api/cases/{case_id}/evidence/{evidence[0]['id']}").json() == evidence[0]
        )
        assert all(r["versions"] for r in record["runs"])
    with client_for(root) as client:
        assert client.get(f"/api/cases/{case_id}").json()["symptom"] == hostile
        with patch.object(
            Analyzer, "run_diagnostic", side_effect=AssertionError("must not execute")
        ):
            assert (
                client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record)).json()
                == first
            )
        assert client.get(f"/api/cases/{case_id}/evidence").json()["evidence"] == evidence
        assert client.delete(f"/api/cases/{case_id}").json() == {
            "deleted": True,
            "original_deleted": True,
            "registered_artifacts_deleted": True,
            "cleanup_pending": False,
        }
        assert client.get(f"/api/cases/{case_id}").status_code == 404
        assert client.delete(f"/api/cases/{case_id}").status_code == 404
        assert not (root / "cases" / case_id).exists()


@pytest.mark.parametrize("name", ["malformed", "damaged_record", "unsupported"])
def test_invalid_upload_cleanup_and_retry(environment, name):
    root, captures = environment
    with client_for(root) as client:
        case_id = case(client)
        assert upload(client, case_id, captures[name]).status_code == 422
        record = client.get(f"/api/cases/{case_id}").json()
        assert record["state"] == "FAILED"
        assert not record["artifacts"]
        assert not list((root / "cases" / case_id).rglob("capture"))
        assert upload(client, case_id, captures["healthy"]).status_code == 200
        assert upload(client, case_id, captures["healthy"]).status_code == 409


@pytest.mark.parametrize(
    "code",
    [
        "tool_timeout",
        "tool_output_limit",
        "tool_unavailable",
        "invalid_tool_output",
        "diagnostic_evidence_limit",
    ],
)
def test_optional_failure_preserves_prior_evidence_and_logs(environment, code, caplog):
    root, captures = environment
    with client_for(root) as client:
        case_id, record = prepared(client, captures)
        before = client.get(f"/api/cases/{case_id}/evidence").json()
        caplog.set_level(logging.INFO, logger="wireclaw.api")
        with patch.object(Analyzer, "run_diagnostic", side_effect=AnalyzerError(code)):
            response = client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record))
        assert response.status_code == 422
        assert response.json()["error"]["code"] == code
        assert client.get(f"/api/cases/{case_id}/evidence").json() == before
        after = client.get(f"/api/cases/{case_id}").json()
        assert after["state"] == "INVESTIGATING"
        assert after["runs"][-1]["status"] == "failed"
        logs = [json.loads(r.message) for r in caplog.records if r.name == "wireclaw.api"]
        assert logs[-1]["error_code"] == code
        assert set(logs[-1]) == {
            "case_id",
            "component",
            "capability",
            "duration_ms",
            "status",
            "error_code",
        }


def test_diagnostic_failure_retains_completed_baseline_and_recovery(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id = case(client)
        assert upload(client, case_id, captures["clean_tcp"]).status_code == 200
        with patch.object(Analyzer, "diagnose", side_effect=AnalyzerError("tool_timeout")):
            assert client.post(f"/api/cases/{case_id}/investigate").status_code == 422
        assert client.get(f"/api/cases/{case_id}").json()["state"] == "FAILED"
        assert len(client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]) == 5
    with client_for(root) as client:
        assert client.post(f"/api/cases/{case_id}/investigate").json()["state"] == "INVESTIGATING"
        assert len(client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]) == 16


def test_real_unknown_stream_failure_and_cross_case_isolation(environment):
    root, captures = environment
    with client_for(root) as client:
        first, record = prepared(client, captures)
        second, record2 = prepared(client, captures)
        original = client.app.state.service.artifact(second, record2["original_id"])[1]
        assert record["capture_sha"] == record2["capture_sha"]
        assert (
            client.post(f"/api/cases/{second}/capabilities", json=request_for(record)).status_code
            == 404
        )
        assert (
            client.get(f"/api/cases/{second}/artifacts/{record['original_id']}").status_code == 404
        )
        response = client.post(
            f"/api/cases/{first}/capabilities", json=request_for(record, stream=999)
        )
        assert response.status_code == 422
        assert client.delete(f"/api/cases/{first}").status_code == 200
        assert original.read_bytes() == captures["clean_tcp"]
        assert client.get(f"/api/cases/{second}").json()["state"] == "INVESTIGATING"


@pytest.mark.parametrize(
    "injection",
    [
        {"capability": "tshark"},
        {"capability": "analyze_rtt; rm -rf /"},
        {"filter": "tcp.stream == 0"},
        {"flags": ["-V"]},
        {"path": "../../capture"},
        {"command": "whoami"},
        {"tcp_stream": True},
        {"tcp_stream": -1},
        {"tcp_stream": "0"},
        {"artifact_id": "../capture"},
    ],
)
def test_strict_capability_contract_rejects_injection(environment, injection):
    root, captures = environment
    with client_for(root) as client:
        case_id, record = prepared(client, captures)
        with patch.object(
            Analyzer, "run_diagnostic", side_effect=AssertionError("must not execute")
        ):
            response = client.post(
                f"/api/cases/{case_id}/capabilities", json={**request_for(record), **injection}
            )
        assert response.status_code == 422
        assert response.json() == {"error": {"code": "invalid_request"}}


def test_resource_limits_busy_and_bounded_repetition(environment):
    root, captures = environment
    policy = Policy(max_cases=1, max_runs=4, max_json_bytes=4096, max_result_items=2)
    with client_for(root, policy) as client:
        case_id, record = prepared(client, captures)
        assert client.post("/api/cases", json={"symptom": "second"}).status_code == 429
        assert client.post("/api/cases", content=b"x" * 4097).status_code == 413
        assert client.get(f"/api/cases/{case_id}/evidence?limit=3").status_code == 413
        assert len(client.get(f"/api/cases/{case_id}/evidence?limit=2").json()["evidence"]) == 2
        with client.app.state.service.admission():
            assert client.post(f"/api/cases/{case_id}/investigate").status_code == 429
        for _ in range(3):
            assert (
                client.post(
                    f"/api/cases/{case_id}/capabilities", json=request_for(record)
                ).status_code
                == 200
            )
        assert len(client.get(f"/api/cases/{case_id}").json()["runs"]) == 4
        assert (
            client.post(
                f"/api/cases/{case_id}/capabilities", json=request_for(record, "analyze_tcp_health")
            ).status_code
            == 429
        )


def test_evidence_budget_failure_preserves_original(environment):
    root, captures = environment
    with client_for(root, Policy(max_evidence_items=5)) as client:
        case_id = case(client)
        assert upload(client, case_id, captures["clean_tcp"]).status_code == 200
        response = client.post(f"/api/cases/{case_id}/investigate")
        assert response.status_code == 413
        record = client.get(f"/api/cases/{case_id}").json()
        assert record["state"] == "FAILED"
        assert record["evidence_count"] == 5
        assert (
            client.app.state.service.artifact(case_id, record["original_id"])[1].read_bytes()
            == captures["clean_tcp"]
        )


def test_oversized_streamed_upload_and_declared_size(environment):
    root, _ = environment
    with client_for(root, Policy(analyzer=Limits(max_capture_bytes=16))) as client:
        case_id = case(client)
        assert upload(client, case_id, b"x" * 17).status_code == 413
        response = client.post(
            f"/api/cases/{case_id}/capture",
            content=iter([b"x" * 8, b"y" * 9]),
            headers={"content-type": "application/octet-stream"},
        )
        assert response.status_code == 413
        record = client.get(f"/api/cases/{case_id}").json()
        assert record["state"] == "FAILED"
        assert not record["artifacts"]
        assert not (root / "cases" / case_id / "analyzer").exists()


def test_symlink_escape_original_tampering_and_confined_deletion(environment, tmp_path):
    root, captures = environment
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "protected"
    protected.write_text("preserve")
    with client_for(root) as client:
        case_id, record = prepared(client, captures)
        original = client.app.state.service.artifact(case_id, record["original_id"])[1]
        original.chmod(0o600)
        original.write_bytes(b"tampered")
        assert (
            client.post(f"/api/cases/{case_id}/investigate").json()["error"]["code"]
            == "artifact_integrity_failure"
        )
        link = root / "cases" / case_id / "escape"
        link.symlink_to(outside, target_is_directory=True)
        assert client.delete(f"/api/cases/{case_id}").status_code == 422
        assert protected.read_text() == "preserve"
        link.unlink()
        assert client.delete(f"/api/cases/{case_id}").status_code == 200


def test_partial_deletion_journal_restart_recovery(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id, _ = prepared(client, captures)
        with patch.object(
            client.app.state.service, "remove_tree", side_effect=PermissionError("private")
        ):
            result = client.delete(f"/api/cases/{case_id}").json()
        assert result["cleanup_pending"] is True
        assert result["original_deleted"] is False
        assert client.get(f"/api/cases/{case_id}").status_code == 404
        assert (root / "trash" / case_id).exists()
        assert client.post("/api/cases", json={"symptom": "new"}).status_code == 503
    with client_for(root) as client:
        assert not (root / "trash" / case_id).exists()
        assert client.post("/api/cases", json={"symptom": "new"}).status_code == 201


def test_interrupted_intake_recovery_removes_unregistered_original(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id = case(client)
        svc = client.app.state.service
        _run_id, path = svc.begin_ingest(case_id)
        path.write_bytes(captures["clean_tcp"])
        svc.transition(case_id, State.VALIDATING_CAPTURE)
        analyzer = svc.analyzer(case_id)
        analyzer.ingest_capture(path.relative_to(analyzer.store.root))
    with client_for(root) as client:
        record = client.get(f"/api/cases/{case_id}").json()
        assert record["state"] == "FAILED"
        assert record["last_error"] == "service_interrupted"
        assert record["runs"][0]["error"] == "service_interrupted"
        assert not list((root / "cases" / case_id).rglob("capture"))
        assert upload(client, case_id, captures["clean_tcp"]).status_code == 200


def test_sqlite_and_snapshot_persistence_failure_preserve_evidence(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id, record = prepared(client, captures)
        before = client.get(f"/api/cases/{case_id}/evidence").json()
        with patch.object(
            client.app.state.service,
            "save",
            side_effect=sqlite3.OperationalError("SECRET db exception"),
        ):
            response = client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record))
        assert response.status_code == 503
        assert "SECRET" not in response.text
        assert client.get(f"/api/cases/{case_id}/evidence").json() == before
        with patch.object(
            client.app.state.service.db, "connect", side_effect=sqlite3.OperationalError("SECRET")
        ):
            response = client.get(f"/api/cases/{case_id}")
        assert response.status_code == 503
        assert "SECRET" not in response.text


def test_snapshot_transaction_rollback_and_delete_rename_recovery(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id, record = prepared(client, captures)
        svc = client.app.state.service
        before = client.get(f"/api/cases/{case_id}/evidence").json()
        paths = set((root / "cases" / case_id / "normalized").iterdir())
        with patch.object(
            svc, "register", side_effect=sqlite3.OperationalError("storage rejected")
        ):
            response = client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record))
        assert response.status_code == 503
        assert client.get(f"/api/cases/{case_id}/evidence").json() == before
        assert set((root / "cases" / case_id / "normalized").iterdir()) == paths
        trash = root / "trash" / case_id
        trash.parent.mkdir()
        (root / "cases" / case_id).rename(trash)
    with client_for(root) as client:
        assert not trash.exists()
        assert client.get(f"/api/cases/{case_id}/evidence").json() == before
        assert client.delete(f"/api/cases/{case_id}").status_code == 200


def test_tool_version_change_invalidates_success_cache(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id, record = prepared(client, captures)
        assert (
            client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record)).status_code
            == 200
        )
        real_versions = client.app.state.service.analyzer(case_id).versions
        changed = {
            **real_versions,
            "zeek": {"available": False, "version": None, "error": {"code": "changed"}},
        }
        with (
            patch("wireclaw_analyzer.runner.Runner.versions", return_value=changed),
            patch.object(Analyzer, "run_diagnostic", side_effect=AnalyzerError("tool_timeout")),
        ):
            response = client.post(f"/api/cases/{case_id}/capabilities", json=request_for(record))
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "tool_timeout"


def test_real_timeout_and_failed_run_budget_bound_history(environment):
    root, captures = environment
    with client_for(root, Policy(analyzer=Limits(timeout_seconds=0.000001))) as client:
        case_id = case(client)
        response = upload(client, case_id, captures["clean_tcp"])
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "tool_timeout"
    with client_for(root / "budget", Policy(max_runs=3)) as client:
        case_id = case(client)
        assert upload(client, case_id, captures["clean_tcp"]).status_code == 200
        with patch.object(Analyzer, "diagnose", side_effect=AnalyzerError("tool_timeout")):
            assert client.post(f"/api/cases/{case_id}/investigate").status_code == 422
        before = client.get(f"/api/cases/{case_id}").json()
        for _ in range(4):
            assert client.post(f"/api/cases/{case_id}/investigate").status_code == 429
        assert client.get(f"/api/cases/{case_id}").json()["history"] == before["history"]


def test_all_baseline_capability_routes_use_existing_schema(environment):
    from wireclaw_api.models import BASELINE

    root, captures = environment
    with client_for(root) as client:
        case_id, record = prepared(client, captures)
        for capability in BASELINE:
            response = client.post(
                f"/api/cases/{case_id}/capabilities", json=request_for(record, capability, None)
            )
            assert response.status_code == 200
            evidence = response.json()["evidence"]
            assert len(evidence) == 1
            assert evidence[0]["source"]["capability"] == capability
            client.app.state.service.validator.validate(evidence[0])


def test_sensitive_text_excluded_from_logs_errors_and_packet_operations(environment, caplog):
    root, captures = environment
    caplog.set_level(logging.INFO, logger="wireclaw.api")
    with client_for(root) as client:
        case_id = case(client, "SECRET.symptom; $(whoami)")
        assert upload(client, case_id, captures["dns_sequences"]).status_code == 200
        assert client.post(f"/api/cases/{case_id}/investigate").status_code == 200
        record = client.get(f"/api/cases/{case_id}").json()
        with patch.object(
            Analyzer, "run_diagnostic", side_effect=ValueError("SECRET.payload bearer credential")
        ):
            response = client.post(
                f"/api/cases/{case_id}/capabilities", json=request_for(record, "analyze_dns", None)
            )
        assert response.status_code == 422
        assert "SECRET" not in response.text
    logs = "\n".join(r.message for r in caplog.records if r.name == "wireclaw.api")
    assert "SECRET" not in logs
    assert "example.invalid" not in logs
    assert "bearer" not in logs


def test_missing_packet_tool_and_real_runner_output_bound(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id = case(client)
        with patch("wireclaw_analyzer.runner.shutil.which", return_value=None):
            response = upload(client, case_id, captures["clean_tcp"])
        assert response.json()["error"]["code"] == "tool_unavailable"
        assert client.get(f"/api/cases/{case_id}").json()["state"] == "FAILED"
    with client_for(root / "output", Policy(analyzer=Limits(max_output_bytes=32))) as client:
        case_id = case(client)
        assert upload(client, case_id, captures["clean_tcp"]).status_code == 422


def test_api_capability_result_matches_direct_analyzer(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id, record = prepared(client, captures, "loss_tcp")
        svc = client.app.state.service
        direct = svc.analyzer(case_id).diagnose(record["capture_sha"])
        observed = client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]
        for item in direct["evidence"]:
            assert item in observed
        # Captures containing packet text never construct caller-controlled operations.
        runner = svc.analyzer(case_id).runner
        with pytest.raises(AnalyzerError):
            runner.run("whoami")
        assert isinstance(Operation.PACKETS, Operation)
