"""Gate 4 report persistence, integrity boundary and failure-isolation regressions."""

import hashlib
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from generate_gate2 import generate, handshake, timed_pcap
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
        tool_versions = client.app.state.service.analyzer(case_id).versions
        assert report["analyzer_versions"]["analyzer"] == "0.2.0"
        assert report["analyzer_versions"]["tshark"] == tool_versions["tshark"]["version"]
        assert report["analyzer_versions"]["capinfos"] == tool_versions["capinfos"]["version"]
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


def test_successful_post_complete_capability_rebuilds_report_from_current_evidence(tmp_path):
    captures = generate(tmp_path / "fixtures")
    root = tmp_path / "data"

    with _client(root) as client:
        case_id, uploaded = _prepare(client, captures["high_rtt"])
        completed = client.post(f"/api/cases/{case_id}/investigate")
        assert completed.status_code == 200, completed.text
        before = client.get(f"/api/cases/{case_id}/report").json()
        assert before["conclusion"]["type"] == "supported_finding"
        assert any(item["category"] == "tcp.rtt" for item in before["findings"])

        original_run = Analyzer.run_diagnostic

        def changed_rtt(analyzer, request):
            result = original_run(analyzer, request)
            for item in result["evidence"]:
                if item["category"] == "analyze_rtt":
                    item["value"]["median_seconds"] = 0.01
                    item["value"]["p95_seconds"] = 0.01
            return result

        request = {
            "artifact_id": uploaded["original_id"],
            "capability": "analyze_rtt",
            "tcp_stream": 0,
        }
        with patch.object(Analyzer, "run_diagnostic", new=changed_rtt):
            refreshed = client.post(f"/api/cases/{case_id}/capabilities", json=request)
        assert refreshed.status_code == 200, refreshed.text
        record = client.get(f"/api/cases/{case_id}").json()
        assert record["state"] == "COMPLETE"
        assert record["history"][-1]["state"] == "COMPLETE"
        assert record["history"][-2]["state"] == "ASSEMBLING_REPORT"
        after = client.get(f"/api/cases/{case_id}/report").json()
        assert after != before
        assert after["conclusion"]["type"] == "insufficient_evidence"
        current_rtt = client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]
        current_rtt = next(item for item in current_rtt if item["category"] == "analyze_rtt")
        assert current_rtt["value"]["median_seconds"] == 0.01


def test_vantage_relabel_recomputes_cross_vantage_report_without_reextracting_packets(tmp_path):
    generate(tmp_path / "fixtures")
    delayed_handshake = timed_pcap(handshake(step=3_200_000))
    with _client(tmp_path / "data") as client:
        created = client.post("/api/cases", json={"symptom": "slow connection"})
        case_id = created.json()["id"]
        capture_rows = []
        for name, vantage in (("client.pcap", "client"), ("server.pcap", "unknown")):
            capture = client.post(
                f"/api/cases/{case_id}/captures",
                json={"capture_name": name, "vantage_type": vantage},
            ).json()
            uploaded = client.put(
                f"/api/cases/{case_id}/captures/{capture['id']}/data",
                content=delayed_handshake,
                headers={"content-type": "application/octet-stream"},
            )
            assert uploaded.status_code == 200, uploaded.text
            client.app.state.service.execute_capture_analysis(case_id, capture["id"])
            capture_rows.append(capture)
        completed = client.post(f"/api/cases/{case_id}/investigate")
        assert completed.status_code == 200, completed.text
        before = client.get(f"/api/cases/{case_id}/report").json()
        second_id = capture_rows[1]["id"]
        assert before["cross_vantage"]["correlations"]
        assert not any(
            finding["category"] == "tcp.server_response_delay" for finding in before["findings"]
        )
        assert (
            before["cross_vantage"]["correlations"][0]["capture_vantages"][second_id] == "unknown"
        )
        run_count = len(client.get(f"/api/cases/{case_id}").json()["runs"])

        with patch.object(
            Analyzer,
            "tcp_correlation_observations",
            side_effect=AssertionError("packet_reextraction"),
        ):
            updated = client.patch(
                f"/api/cases/{case_id}/captures/{second_id}",
                json={"vantage_type": "server"},
            )
        assert updated.status_code == 200, updated.text
        after = client.get(f"/api/cases/{case_id}/report").json()
        assert after["cross_vantage"]["correlations"][0]["capture_vantages"][second_id] == "server"
        localized = next(
            finding
            for finding in after["findings"]
            if finding["category"] == "tcp.server_response_delay"
        )
        assert localized["confidence"] == "high"
        assert "3.2 seconds" in localized["statement"]
        assert len(client.get(f"/api/cases/{case_id}").json()["runs"]) == run_count

        with patch.object(
            Analyzer,
            "tcp_correlation_observations",
            side_effect=AssertionError("packet_reextraction"),
        ):
            removed = client.delete(f"/api/cases/{case_id}/captures/{second_id}")
        assert removed.status_code == 200, removed.text
        remaining = client.get(f"/api/cases/{case_id}").json()
        assert remaining["id"] == case_id
        assert [capture["id"] for capture in remaining["captures"]] == [capture_rows[0]["id"]]
        assert (
            client.get(f"/api/cases/{case_id}/report").json()["cross_vantage"]["correlations"] == []
        )


def test_investigate_analyzes_new_secondary_capture_and_rebuilds_localized_report(tmp_path):
    delayed_handshake = timed_pcap(handshake(step=3_200_000))
    with _client(tmp_path / "data") as client:
        created = client.post("/api/cases", json={"symptom": "slow connection"})
        case_id = created.json()["id"]
        first = client.post(
            f"/api/cases/{case_id}/capture",
            content=delayed_handshake,
            headers={"content-type": "application/octet-stream"},
        )
        assert first.status_code == 200, first.text
        first_capture = first.json()["captures"][0]
        assert (
            client.patch(
                f"/api/cases/{case_id}/captures/{first_capture['id']}",
                json={"vantage_type": "client"},
            ).status_code
            == 200
        )
        assert client.post(f"/api/cases/{case_id}/investigate").json()["state"] == "COMPLETE"

        second = client.post(
            f"/api/cases/{case_id}/captures",
            json={"capture_name": "server.pcap", "vantage_type": "server"},
        ).json()
        uploaded = client.put(
            f"/api/cases/{case_id}/captures/{second['id']}/data",
            content=delayed_handshake,
            headers={"content-type": "application/octet-stream"},
        )
        assert uploaded.status_code == 200, uploaded.text
        assert uploaded.json()["status"] == "analyzing"
        primary_run_ids = {run["id"] for run in client.get(f"/api/cases/{case_id}").json()["runs"]}

        completed = client.post(f"/api/cases/{case_id}/investigate")
        assert completed.status_code == 200, completed.text
        captures = completed.json()["captures"]
        assert [capture["status"] for capture in captures] == ["analyzed", "analyzed"]
        runs_after = completed.json()["runs"]
        assert primary_run_ids.issubset({run["id"] for run in runs_after})
        with client.app.state.service.db.connect() as conn:
            secondary_runs = conn.execute(
                "SELECT capability FROM runs WHERE case_id=? AND capture_id=?",
                (case_id, second["id"]),
            ).fetchall()
        assert {run["capability"] for run in secondary_runs} >= {"baseline", "diagnostics"}
        assert len(runs_after) == len(primary_run_ids) + 2
        report = client.get(f"/api/cases/{case_id}/report").json()
        assert report["cross_vantage"]["support"] == "stronger"
        correlations = report["cross_vantage"]["correlations"]
        assert correlations
        for correlation in correlations:
            for capture_id in correlation["capture_ids"]:
                frame_descriptor = correlation["matched_frames"][0][capture_id]
                provenance_ids = correlation["capture_evidence_ids"][capture_id]
                assert provenance_ids
                assert any(
                    frame_descriptor["frame"]
                    in client.app.state.service.evidence(case_id, evidence_id=evidence_id)[
                        "frame_refs"
                    ]
                    for evidence_id in provenance_ids
                )
        finding = next(
            item for item in report["findings"] if item["category"] == "tcp.server_response_delay"
        )
        grant = client.post(
            f"/api/cases/{case_id}/bridge-grants",
            json={
                "artifact_id": uploaded.json()["original_artifact_id"],
                "finding_id": finding["id"],
            },
        )
        assert grant.status_code == 200, grant.text
        grant_data = client.app.state.service.files.path(
            __import__("pathlib").Path("bridge") / "requests" / f"{grant.json()['request_id']}.json"
        )
        grant_manifest = __import__("json").loads(grant_data.read_text())
        assert grant_manifest["artifact_id"] == uploaded.json()["original_artifact_id"]
        assert grant_manifest["display_filter"] == "(frame.number >= 1 && frame.number <= 2)"
        evidence_capture = client.post(
            f"/api/cases/{case_id}/artifacts/evidence-capture",
            json={"finding_id": finding["id"], "capture_id": second["id"]},
        )
        assert evidence_capture.status_code == 200, evidence_capture.text
        assert evidence_capture.json()["provenance"]["capture_id"] == second["id"]
        evidence_grant = client.post(
            f"/api/cases/{case_id}/bridge-grants",
            json={
                "artifact_id": evidence_capture.json()["artifact_id"],
                "finding_id": finding["id"],
            },
        )
        assert evidence_grant.status_code == 200, evidence_grant.text
