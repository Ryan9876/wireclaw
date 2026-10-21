import hashlib
import importlib.util
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/eai14_privacy_qualification.py"
QUALIFICATION = ROOT / "scripts/native_embedded_ai_qualification.py"
SURFACES = [
    "model_context",
    "api_responses",
    "case_database",
    "runtime_logs",
    "core_logs",
    "browser_status",
    "reports",
]


def helper_module():
    spec = importlib.util.spec_from_file_location("eai14_privacy_qualification", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_provider_fixture_fails_when_sentinel_is_in_actual_request(capsys):
    helper = helper_module()
    token = "TEST_ONLY_PROVIDER_TOKEN_abcdef0123456789"
    marker = "PAYLOAD_SENTINEL_7d3a"
    fixture = helper.PrivacyProviderFixture(token, [marker])
    fixture.expect_case("case-test-1")
    host, port = fixture.start()
    try:
        payload = {
            "model": helper.MODEL_ID,
            "messages": [
                {"role": "system", "content": "bounded test system instruction"},
                {
                    "role": "user",
                    "content": json.dumps({"case_id": "case-test-1", "evidence": marker}),
                },
            ],
        }
        request = urllib.request.Request(
            f"http://{host}:{port}/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3):
            pass
        with pytest.raises(ValueError, match="privacy_sentinel_present"):
            fixture.require_pass()
        emitted = json.dumps(fixture.result()) + capsys.readouterr().out
        assert token not in emitted
        assert marker not in emitted
    finally:
        fixture.close()


def test_provider_fixture_passes_when_sentinel_is_absent_and_correlates_case():
    helper = helper_module()
    token = "TEST_ONLY_PROVIDER_TOKEN_abcdef0123456789"
    marker = "RAW_CAPTURE_SENTINEL_83e1"
    fixture = helper.PrivacyProviderFixture(token, [marker])
    fixture.expect_case("case-test-2")
    host, port = fixture.start()
    try:
        context = json.dumps({"case_id": "case-test-2", "evidence": "bounded normalized evidence"})
        body = json.dumps(
            {
                "model": helper.MODEL_ID,
                "messages": [
                    {"role": "system", "content": "system"},
                    {"role": "user", "content": context},
                ],
            }
        ).encode()
        request = urllib.request.Request(
            f"http://{host}:{port}/v1/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            assert response.status == 200
            assert json.loads(response.read())["choices"][0]["message"]["content"]
        fixture.require_pass()
        result = fixture.result()
        assert result["model_context_sentinel_absent"] is True
        assert result["request_correlated"] is True
        assert result["request_count"] == 1
        assert result["request_body_bytes"] == len(body)
        assert result["request_body_sha256"] == hashlib.sha256(body).hexdigest()
    finally:
        fixture.close()


def test_provider_fixture_result_never_contains_authorization_or_request_body(capsys):
    helper = helper_module()
    token = "TEST_ONLY_PROVIDER_TOKEN_abcdef0123456789"
    marker = "COOKIE_SENTINEL_31bc"
    fixture = helper.PrivacyProviderFixture(token, [marker])
    host, port = fixture.start()
    try:
        body = json.dumps(
            {"model": helper.MODEL_ID, "messages": [{"role": "user", "content": "synthetic"}]}
        ).encode()
        request = urllib.request.Request(
            f"http://{host}:{port}/v1/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {token}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3):
            pass
        emitted = json.dumps(fixture.result()) + capsys.readouterr().out
        fixture_logs = fixture.runtime_log_bytes().decode()
        assert token not in emitted
        assert body.decode() not in emitted
        assert marker not in emitted
        assert token not in fixture_logs
        assert body.decode() not in fixture_logs
        assert marker not in fixture_logs
    finally:
        fixture.close()


def test_missing_provider_request_fails_closed():
    helper = helper_module()
    fixture = helper.PrivacyProviderFixture(
        "TEST_ONLY_PROVIDER_TOKEN_abcdef0123456789", ["TOKEN_SENTINEL_04aa"]
    )
    with pytest.raises(ValueError, match="privacy_provider_request_missing"):
        fixture.require_pass()
    fixture.close()


def test_missing_required_surface_fails_closed():
    helper = helper_module()
    surfaces = {name: b"bounded synthetic bytes" for name in SURFACES}
    del surfaces["core_logs"]
    with pytest.raises(ValueError, match="privacy_surface_missing"):
        helper.verify_surfaces(surfaces, ["RAW_CAPTURE_SENTINEL_aa01"])


@pytest.mark.parametrize("surface", SURFACES)
def test_sentinel_in_any_required_surface_fails_closed(surface):
    helper = helper_module()
    surfaces = {name: b"no marker" for name in SURFACES}
    surfaces[surface] = b"PAYLOAD_SENTINEL_662a"
    with pytest.raises(ValueError, match="privacy_sentinel_present"):
        helper.verify_surfaces(surfaces, ["PAYLOAD_SENTINEL_662a"])


def test_exact_seven_surfaces_are_required():
    helper = helper_module()
    assert tuple(SURFACES) == helper.REQUIRED_SURFACES
    surfaces = {name: b"clean" for name in (*SURFACES, "extra_surface")}
    with pytest.raises(ValueError, match="privacy_surface_set_invalid"):
        helper.verify_surfaces(surfaces, ["RAW_CAPTURE_SENTINEL_917f"])


def test_receipt_preserves_existing_schema_and_candidate_model_runtime_binding():
    helper = helper_module()
    identity = {
        "candidate_identity_sha256": "a" * 64,
        "signed_app": {"model_sha256": "b" * 64, "llama_server_sha256": "c" * 64},
    }
    receipt = helper.build_receipt(
        identity,
        "wireclaw-privacy-0123456789abcdef",
        {surface: True for surface in SURFACES},
    )
    assert set(receipt) == {
        "schema_version",
        "candidate_identity_sha256",
        "model_sha256",
        "llama_server_sha256",
        "provider_mode",
        "scenario_id",
        "reviewed_surfaces",
        "sentinel_absent_from_all_surfaces",
    }
    assert receipt["schema_version"] == 1
    assert receipt["candidate_identity_sha256"] == "a" * 64
    assert receipt["model_sha256"] == "b" * 64
    assert receipt["llama_server_sha256"] == "c" * 64
    assert receipt["provider_mode"] == "embedded_local"
    assert receipt["reviewed_surfaces"] == SURFACES
    assert receipt["sentinel_absent_from_all_surfaces"] is True
    helper.validate_receipt(receipt, identity)


def test_receipt_rejects_wrong_candidate_model_or_helper_binding():
    helper = helper_module()
    identity = {
        "candidate_identity_sha256": "a" * 64,
        "signed_app": {"model_sha256": "b" * 64, "llama_server_sha256": "c" * 64},
    }
    receipt = helper.build_receipt(
        identity,
        "wireclaw-privacy-0123456789abcdef",
        {surface: True for surface in SURFACES},
    )
    for key in ("candidate_identity_sha256", "model_sha256", "llama_server_sha256"):
        changed = dict(receipt, **{key: "f" * 64})
        with pytest.raises(ValueError, match="candidate_identity_mismatch"):
            helper.validate_receipt(changed, identity)


def test_receipt_scenario_id_has_exact_pattern():
    helper = helper_module()
    identity = {
        "candidate_identity_sha256": "a" * 64,
        "signed_app": {"model_sha256": "b" * 64, "llama_server_sha256": "c" * 64},
    }
    for scenario in ("wireclaw-privacy-0123456789abcdeG", "wireclaw-privacy-short"):
        with pytest.raises(ValueError, match="privacy_scenario_invalid"):
            helper.build_receipt(identity, scenario, {surface: True for surface in SURFACES})


def test_operator_procedure_contains_executable_privacy_invocation():
    result = subprocess.run(
        [
            sys.executable,
            str(QUALIFICATION),
            "--candidate-bundle",
            "bundle",
            "--candidate-archive",
            "archive",
            "--candidate-metadata",
            "metadata",
            "--evidence-dir",
            "evidence",
            "--output",
            "output",
            "--print-operator-procedure",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "scripts/eai14_privacy_qualification.py" in result.stdout
    assert "--candidate-bundle <frozen-candidate-root>" in result.stdout
    assert "--receipt-output <operator-evidence/eai14-16.json>" in result.stdout
    assert "unique Compose project" in result.stdout
    assert "isolated data root" in result.stdout


def test_browser_status_probe_does_not_retain_browser_artifacts():
    helper = helper_module()
    assert helper.BROWSER_PROBE_RETAINS_ARTIFACTS is False
    assert helper.BROWSER_PROBE_METHOD == "bounded_http_ui_probe"


def test_cleanup_is_bounded_and_removes_only_private_qualification_tree(tmp_path):
    helper = helper_module()
    workspace = tmp_path / "wireclaw-privacy-qualification-run"
    private_copy = workspace / "private-candidate"
    private_copy.mkdir(parents=True)
    (private_copy / "compose.yaml").write_text("services: {}\n")
    (private_copy / ".env").write_text("\n")
    (private_copy / ".env.example").write_text("\n")
    (private_copy / "marker").write_text("synthetic")
    evidence = tmp_path / "operator-evidence"
    evidence.mkdir()
    receipt = evidence / "eai14-16.json"
    receipt.write_text("keep")
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "/bin/rm":
            import shutil

            shutil.rmtree(argv[-1])
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    helper.cleanup_qualification(
        project_name="wireclaw-privacy-0123456789abcdef",
        compose_file=private_copy / "compose.yaml",
        private_root=workspace,
        evidence_output=receipt,
        runner=runner,
    )
    assert calls and all(call[1]["timeout"] <= 30 for call in calls)
    assert not workspace.exists()
    assert receipt.read_text() == "keep"
