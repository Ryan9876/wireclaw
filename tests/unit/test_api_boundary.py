"""Gate 3 state, policy and local HTTP security contracts without packet tools."""

from dataclasses import replace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from wireclaw_analyzer import AnalyzerError
from wireclaw_api import Policy, create_app
from wireclaw_api.models import TRANSITIONS, State
from wireclaw_api.storage import ApiError, Files


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.1", "localhost", "attacker.invalid"])
def test_non_loopback_or_unresolved_bind_rejected(host):
    with pytest.raises(ValueError):
        Policy(host=host)


@pytest.mark.parametrize(
    "key,value",
    [
        ("max_runs", 0),
        ("max_cases", True),
        ("max_json_bytes", 1.5),
        ("upload_timeout_seconds", float("inf")),
        ("port", 0),
    ],
)
def test_invalid_resource_policy(key, value):
    with pytest.raises(ValueError):
        replace(Policy(), **{key: value})


def test_default_loopback_and_no_future_gate_routes(tmp_path):
    policy = Policy()
    assert policy.host == "127.0.0.1"
    assert Policy(host="::1").host == "::1"
    app = create_app(tmp_path)
    paths = app.openapi()["paths"]
    assert "/api/cases/{case_id}/capabilities" in paths
    assert not any("findings" in path or "evidence-capture" in path for path in paths)
    schema = app.openapi()["components"]["schemas"]["CapabilityRequest"]
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"artifact_id", "capability", "tcp_stream"}
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[2]
    snapshot = json.loads((root / "contracts/api.openapi.json").read_text())
    assert app.openapi() == snapshot
    for definition in snapshot["components"]["schemas"].values():
        Draft202012Validator.check_schema(definition)


@pytest.mark.parametrize("source", list(State))
@pytest.mark.parametrize("target", list(State))
def test_authoritative_state_transition_matrix(tmp_path, source, target):
    app = create_app(tmp_path)
    with TestClient(app, base_url="http://127.0.0.1:8765"):
        service = app.state.service
        case_id = service.create("test")["id"]
        with service.db.connect() as conn:
            conn.execute("UPDATE cases SET state=? WHERE id=?", (source, case_id))
        if target in TRANSITIONS[source]:
            service.transition(case_id, target)
            assert service.get(case_id)["state"] == target
        else:
            with pytest.raises(ApiError, match="invalid_state_transition"):
                service.transition(case_id, target)
            assert service.get(case_id)["state"] == source


def test_host_origin_no_body_echo_and_sql_parameterization(tmp_path):
    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1:8765") as client:
        assert client.get("/api/health", headers={"host": "attacker.invalid"}).status_code == 403
        assert (
            client.post(
                "/api/cases",
                json={"symptom": "test"},
                headers={"origin": "https://attacker.invalid"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/cases", json={"symptom": "test"}, headers={"origin": "http://127.0.0.1:8765"}
            ).status_code
            == 201
        )
        response = client.post("/api/cases", json={"symptom": {"SECRET": "private"}})
        assert response.status_code == 422
        assert "SECRET" not in response.text
        response = client.post("/api/cases", json={"symptom": "'; DROP TABLE cases; --"})
        case_id = response.json()["id"]
        assert client.get(f"/api/cases/{case_id}").json()["symptom"] == "'; DROP TABLE cases; --"
        assert client.get("/api/cases/..%5C..%5Coutside").status_code == 422


def test_path_confinement_and_symlink_root(tmp_path):
    files = Files(tmp_path / "root")
    for path in ("../outside", "/tmp/outside", "..\\outside"):
        with pytest.raises((ApiError, AnalyzerError)):
            files.path(path)
    link = tmp_path / "link"
    link.symlink_to(files.root, target_is_directory=True)
    with pytest.raises(ApiError, match="symlink_rejected"):
        Files(link)


def test_one_process_owns_data_root_and_schema_version(tmp_path):
    from wireclaw_api.service import Service

    service = Service(tmp_path, Policy())
    try:
        with pytest.raises(ApiError, match="data_root_in_use"):
            Service(tmp_path, Policy())
        with service.db.connect() as conn:
            conn.execute("PRAGMA user_version=99")
    finally:
        service.close()
    with pytest.raises(ApiError, match="unsupported_schema_version"):
        Service(tmp_path, Policy())


def test_streamed_json_limit_precedes_parser(tmp_path):
    with TestClient(
        create_app(tmp_path, Policy(max_json_bytes=8)), base_url="http://127.0.0.1:8765"
    ) as client:
        response = client.post("/api/cases", content=iter([b"12345", b"67890"]))
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "request_size_limit"


def test_launcher_never_selects_wildcard_bind(tmp_path):
    from wireclaw_api.cli import main

    with (
        patch("sys.argv", ["wireclaw-api", "--data-root", str(tmp_path)]),
        patch("wireclaw_api.cli.uvicorn.run") as run,
    ):
        main()
    assert run.call_args.kwargs["host"] == "127.0.0.1"
    assert run.call_args.kwargs["workers"] == 1
    assert run.call_args.kwargs["access_log"] is False
