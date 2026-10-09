"""Gate 4 report persistence, integrity boundary and failure-isolation regressions."""

import hashlib
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from generate_gate2 import generate
from jsonschema import Draft202012Validator
from wireclaw_analyzer import Analyzer, AnalyzerError
from wireclaw_api import create_app

pytestmark = pytest.mark.skipif(
    not shutil.which("tshark") or not shutil.which("capinfos"),
    reason="requires real TShark and capinfos",
)
ROOT = Path(__file__).resolve().parents[2]


def _client(root):
    return TestClient(
        create_app(root), base_url="http://127.0.0.1:8765", raise_server_exceptions=False
    )


def _prepare(client, capture, symptom="application is slow"):
    created = client.post("/api/cases", json={"symptom": symptom})
    assert created.status_code == 201, created.text
    case_id = created.json()["id"]
    uploaded = client.post(
        f"/api/cases/{case_id}/capture",
        content=capture,
        headers={"content-type": "application/octet-stream"},
    )
    assert uploaded.status_code == 200, uploaded.text
    return case_id, uploaded.json()


def test_report_persists_validates_and_is_stable_across_restart_and_rerun(tmp_path):
    captures = generate(tmp_path / "fixtures")
    root = tmp_path / "data"
    schema = json.loads((ROOT / "contracts/investigation-result.schema.json").read_text())
    validator = Draft202012Validator(schema)

    with _client(root) as client:
        case_id, uploaded = _prepare(client, captures["high_rtt"])
        assert client.get(f"/api/cases/{case_id}/report").status_code == 409
        completed = client.post(f"/api/cases/{case_id}/investigate")
        assert completed.status_code == 200, completed.text
        record = completed.json()
        assert record["state"] == "COMPLETE"
        assert record["history"][-2]["state"] == "ASSEMBLING_REPORT"
        assert record["history"][-1]["state"] == "COMPLETE"

        response = client.get(f"/api/cases/{case_id}/report")
        assert response.status_code == 200, response.text
        report = response.json()
        validator.validate(report)
        findings = client.get(f"/api/cases/{case_id}/findings")
        assert findings.status_code == 200
        assert findings.json()["findings"] == report["findings"]

        report_artifacts = [item for item in record["artifacts"] if item["kind"] == "report"]
        assert len(report_artifacts) == 1
        artifact = report_artifacts[0]
        row, path = client.app.state.service.artifact(case_id, artifact["id"])
        assert row["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert not path.stat().st_mode & 0o222
        report_artifact_id = artifact["id"]

    with _client(root) as client:
        restarted = client.get(f"/api/cases/{case_id}")
        assert restarted.status_code == 200
        assert restarted.json()["state"] == "COMPLETE"
        assert client.get(f"/api/cases/{case_id}/report").json() == report

        rerun = client.post(f"/api/cases/{case_id}/investigate")
        assert rerun.status_code == 200, rerun.text
        assert rerun.json()["state"] == "COMPLETE"
        rerun_report = client.get(f"/api/cases/{case_id}/report").json()
        assert rerun_report == report
        report_artifacts = [item for item in rerun.json()["artifacts"] if item["kind"] == "report"]
        assert len(report_artifacts) == 1
        assert report_artifacts[0]["id"] == report_artifact_id

        request = {
            "artifact_id": uploaded["original_id"],
            "capability": "analyze_rtt",
            "tcp_stream": 0,
        }
        with patch.object(Analyzer, "run_diagnostic", side_effect=AnalyzerError("tool_timeout")):
            failed = client.post(f"/api/cases/{case_id}/capabilities", json=request)
        assert failed.status_code == 422
        assert client.get(f"/api/cases/{case_id}").json()["state"] == "COMPLETE"
        assert client.get(f"/api/cases/{case_id}/report").json() == report


def test_report_assembly_failure_preserves_deterministic_evidence_and_original(tmp_path):
    captures = generate(tmp_path / "fixtures")
    root = tmp_path / "data"

    with _client(root) as client:
        case_id, uploaded = _prepare(client, captures["clean_tcp"])
        service = client.app.state.service
        _, original = service.artifact(case_id, uploaded["original_id"])
        original_bytes = original.read_bytes()
        with patch(
            "wireclaw_api.gate4_service.build_investigation_result",
            side_effect=RuntimeError("synthetic-report-failure"),
        ):
            failed = client.post(f"/api/cases/{case_id}/investigate")
        assert failed.status_code == 500
        assert failed.json() == {"error": {"code": "report_assembly_failed"}}
        record = client.get(f"/api/cases/{case_id}").json()
        assert record["state"] == "FAILED"
        assert record["evidence_count"] > 0
        assert record["last_error"] == "report_assembly_failed"
        assert client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]
        assert client.get(f"/api/cases/{case_id}/report").status_code == 409
        assert original.read_bytes() == original_bytes
        assert hashlib.sha256(original_bytes).hexdigest() == record["capture_sha"]
