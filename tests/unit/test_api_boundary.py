"""Gate 3-6 state, policy and local HTTP security contracts without packet tools."""

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
        ("bridge_port", 0),
    ],
)
def test_invalid_resource_policy(key, value):
    with pytest.raises(ValueError):
        replace(Policy(), **{key: value})


def test_default_loopback_and_gate6_routes(tmp_path):
    policy = Policy()
    assert policy.host == "127.0.0.1"
    assert Policy(host="::1").host == "::1"
    app = create_app(tmp_path)
    paths = app.openapi()["paths"]
    assert "/api/cases/{case_id}/capabilities" in paths
    assert "/api/cases/{case_id}/findings" in paths
    assert "/api/cases/{case_id}/report" in paths
    assert "/api/cases/{case_id}/artifacts/evidence-capture" in paths
    assert "/api/cases/{case_id}/bridge-grants" in paths

    schemas = app.openapi()["components"]["schemas"]
    capability = schemas["CapabilityRequest"]
    assert capability["additionalProperties"] is False
    assert set(capability["properties"]) == {"artifact_id", "capability", "tcp_stream"}
    extraction = schemas["EvidenceCaptureRequest"]
    assert extraction["additionalProperties"] is False
    assert set(extraction["properties"]) == {"capture_id", "finding_id"}
    bridge = schemas["BridgeGrantRequest"]
    assert bridge["additionalProperties"] is False
    assert set(bridge["properties"]) == {"artifact_id", "finding_id"}
    assert not any(
        key in extraction["properties"] or key in bridge["properties"]
        for key in ("path", "display_filter", "executable", "args", "command")
    )

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


@pytest.mark.parametrize("method,path", [("get", "/api/cases"), ("patch", "/api/cases/{case_id}")])
def test_case_metadata_openapi_documents_code_only_errors(tmp_path, method, path):
    from jsonschema import Draft202012Validator

    responses = create_app(tmp_path).openapi()["paths"][path][method]["responses"]
    expected = {
        "400": {"invalid_content_length"},
        "403": {"host_rejected", "origin_rejected"},
        "408": {"request_timeout"},
        "413": {"request_size_limit"},
        "422": {"invalid_request"},
        "500": {"operation_failed"},
        "503": {"persistence_failure"},
    }
    if method == "patch":
        expected.update(
            {
                "404": {"case_not_found"},
                "422": {"invalid_request", "invalid_id"},
                "429": {"service_busy"},
            }
        )
    assert set(responses) == {"200", "default", *expected}
    for status, codes in expected.items():
        schema = responses[status]["content"]["application/json"]["schema"]
        assert schema["additionalProperties"] is False
        assert schema["required"] == ["error"]
        error_schema = schema["properties"]["error"]
        assert error_schema["additionalProperties"] is False
        assert error_schema["required"] == ["code"]
        assert set(error_schema["properties"]["code"]["enum"]) == codes
        validator = Draft202012Validator(schema)
        for code in codes:
            validator.validate({"error": {"code": code}})
        assert not validator.is_valid({"detail": "PRIVATE_REQUEST"})
        assert not validator.is_valid(
            {"error": {"code": next(iter(codes)), "message": "PRIVATE_REQUEST"}}
        )
        assert not validator.is_valid({"error": {"code": "undocumented"}})
    shared_schema = responses["default"]["content"]["application/json"]["schema"]
    Draft202012Validator(shared_schema).validate({"error": {"code": "operation_failed"}})
    assert "HTTPValidationError" not in str(responses)


def test_case_metadata_validation_errors_match_documented_envelope(tmp_path):
    from jsonschema import Draft202012Validator

    with TestClient(create_app(tmp_path), base_url="http://127.0.0.1:8765") as client:
        paths = client.app.openapi()["paths"]
        requests = [
            (
                "get",
                "/api/cases",
                {"params": {"limit": "PRIVATE_REQUEST"}},
                "/api/cases",
                "invalid_request",
            ),
            (
                "patch",
                f"/api/cases/{'f' * 32}",
                {"json": {"display_name": ""}},
                "/api/cases/{case_id}",
                "invalid_request",
            ),
            (
                "patch",
                "/api/cases/not-an-id",
                {"json": {"display_name": "Capture"}},
                "/api/cases/{case_id}",
                "invalid_id",
            ),
        ]
        for method, url, kwargs, path, code in requests:
            response = client.request(method, url, **kwargs)
            assert response.status_code == 422
            assert response.json() == {"error": {"code": code}}
            schema = paths[path][method]["responses"]["422"]["content"]["application/json"][
                "schema"
            ]
            assert "$ref" not in schema
            Draft202012Validator(schema).validate(response.json())
