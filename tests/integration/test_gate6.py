"""Gate 6 real-tool evidence extraction and bridge-boundary regressions."""

import hashlib
import json
import shutil

import pytest
from fastapi.testclient import TestClient
from generate_gate2 import generate as generate_diagnostics
from wireclaw_analyzer.runner import Operation, Runner
from wireclaw_api import Policy, create_app

pytestmark = pytest.mark.skipif(
    not shutil.which("tshark") or not shutil.which("capinfos"),
    reason="requires real TShark and capinfos",
)


@pytest.fixture
def environment(tmp_path):
    captures = generate_diagnostics(tmp_path / "fixtures")
    return tmp_path / "data", captures


def client_for(root, policy=None):
    return TestClient(
        create_app(root, policy), base_url="http://127.0.0.1:8765", raise_server_exceptions=False
    )


def prepared(client, captures, name="loss_tcp"):
    created = client.post("/api/cases", json={"symptom": "transfer is slow and retransmitting"})
    assert created.status_code == 201, created.text
    case_id = created.json()["id"]
    uploaded = client.post(
        f"/api/cases/{case_id}/capture",
        content=captures[name],
        headers={"content-type": "application/octet-stream"},
    )
    assert uploaded.status_code == 200, uploaded.text
    investigated = client.post(f"/api/cases/{case_id}/investigate")
    assert investigated.status_code == 200, investigated.text
    record = investigated.json()
    report = client.get(f"/api/cases/{case_id}/report").json()
    finding = next(item for item in report["findings"] if item["wireshark"]["applicable"])
    return case_id, record, finding


def test_evidence_capture_is_bounded_registered_parseable_and_preserves_original(environment):
    root, captures = environment
    with client_for(root) as client:
        case_id, record, finding = prepared(client, captures)
        service = client.app.state.service
        original_row, original_path = service.artifact(case_id, record["original_id"])
        before = original_path.read_bytes()
        before_hash = hashlib.sha256(before).hexdigest()

        response = client.post(
            f"/api/cases/{case_id}/artifacts/evidence-capture",
            json={"finding_id": finding["id"]},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["provenance"]["parent_sha256"] == before_hash == original_row["sha256"]
        assert body["provenance"]["finding_id"] == finding["id"]
        assert body["provenance"]["evidence_ids"] == finding["evidence_ids"]
        assert body["provenance"]["display_filter"] == finding["wireshark"]["display_filter"]
        assert body["bytes"] <= service.policy.max_evidence_capture_bytes

        derived_row, derived_path = service.artifact(case_id, body["artifact_id"])
        assert derived_row["kind"] == "evidence_capture"
        assert derived_row["parent_sha"] == before_hash
        assert hashlib.sha256(derived_path.read_bytes()).hexdigest() == body["sha256"]
        assert Runner(service.files.store).run(Operation.METADATA, derived_path)
        assert original_path.read_bytes() == before
        assert hashlib.sha256(original_path.read_bytes()).hexdigest() == before_hash

        provenance_rows = [
            item
            for item in service.get(case_id)["artifacts"]
            if item["kind"] == "evidence_provenance"
        ]
        assert len(provenance_rows) == 1
        _, provenance_path = service.artifact(case_id, provenance_rows[0]["id"])
        provenance = json.loads(provenance_path.read_text())
        assert provenance["artifact_id"] == body["artifact_id"]
        assert provenance["parent_sha256"] == before_hash


def test_gate6_api_accepts_no_path_filter_or_executable_input_and_isolates_cases(environment):
    root, captures = environment
    with client_for(root) as client:
        first_id, first, finding = prepared(client, captures)
        second_id, second, second_finding = prepared(client, captures)

        for payload in (
            {"finding_id": finding["id"], "display_filter": "frame"},
            {"finding_id": finding["id"], "path": "/tmp/capture"},
            {"finding_id": finding["id"], "executable": "/bin/sh"},
        ):
            response = client.post(
                f"/api/cases/{first_id}/artifacts/evidence-capture", json=payload
            )
            assert response.status_code == 422
            assert response.json() == {"error": {"code": "invalid_request"}}

        for payload in (
            {
                "artifact_id": first["original_id"],
                "finding_id": finding["id"],
                "display_filter": "tcp",
            },
            {
                "artifact_id": first["original_id"],
                "finding_id": finding["id"],
                "path": "../capture",
            },
            {
                "artifact_id": first["original_id"],
                "finding_id": finding["id"],
                "args": ["--help"],
            },
        ):
            response = client.post(f"/api/cases/{first_id}/bridge-grants", json=payload)
            assert response.status_code == 422
            assert response.json() == {"error": {"code": "invalid_request"}}

        cross_case = client.post(
            f"/api/cases/{second_id}/bridge-grants",
            json={"artifact_id": first["original_id"], "finding_id": second_finding["id"]},
        )
        assert cross_case.status_code == 404
        assert cross_case.json() == {"error": {"code": "artifact_not_found"}}
        assert second["original_id"] != first["original_id"]


def test_bridge_grant_contains_only_hash_of_short_lived_token_and_deletion_revokes(environment):
    root, captures = environment
    policy = Policy(bridge_grant_ttl_seconds=5)
    with client_for(root, policy) as client:
        case_id, record, finding = prepared(client, captures)
        response = client.post(
            f"/api/cases/{case_id}/bridge-grants",
            json={"artifact_id": record["original_id"], "finding_id": finding["id"]},
        )
        assert response.status_code == 200, response.text
        grant = response.json()
        assert grant["bridge_origin"] == "http://127.0.0.1:8766"
        assert 32 <= len(grant["token"]) <= 128
        manifest = root / "bridge" / "requests" / f"{grant['request_id']}.json"
        stored = json.loads(manifest.read_text())
        assert "token" not in stored
        assert stored["token_sha256"] == hashlib.sha256(grant["token"].encode()).hexdigest()
        assert stored["case_id"] == case_id
        assert stored["artifact_id"] == record["original_id"]
        assert stored["relative_path"].startswith(f"cases/{case_id}/")
        assert stored["expires_unix"] == grant["expires_unix"]

        deleted = client.delete(f"/api/cases/{case_id}")
        assert deleted.status_code == 200
        assert deleted.json()["cleanup_pending"] is False
        assert not manifest.exists()


def test_evidence_capture_limits_fail_without_corrupting_case(environment):
    root, captures = environment
    policy = Policy(max_evidence_capture_bytes=1)
    with client_for(root, policy) as client:
        case_id, record, finding = prepared(client, captures)
        original = client.app.state.service.artifact(case_id, record["original_id"])[1]
        before = original.read_bytes()
        response = client.post(
            f"/api/cases/{case_id}/artifacts/evidence-capture",
            json={"finding_id": finding["id"]},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_capture_size_limit"
        after = client.get(f"/api/cases/{case_id}").json()
        assert after["state"] == "COMPLETE"
        assert not [item for item in after["artifacts"] if item["kind"] == "evidence_capture"]
        assert original.read_bytes() == before
