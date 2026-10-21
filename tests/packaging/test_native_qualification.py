import hashlib
import importlib.util
import json
import plistlib
import struct
import subprocess
import sys
import tarfile
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/native_embedded_ai_qualification.py"
SPEC = ROOT / "specs/post-v1/embedded-local-ai.md"


def qualification_module():
    spec = importlib.util.spec_from_file_location("native_embedded_ai_qualification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def module_at(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def png_1x1():
    def chunk(kind, payload):
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff"))
        + chunk(b"IEND", b"")
    )


def operator_case_report(case_id, identity):
    return {
        "schema_version": 1,
        "case_id": case_id,
        "scenario_id": case_id,
        "conclusion_type": "supported_finding",
        "source_report_sha256": "b" * 64,
        "candidate_identity_sha256": identity["candidate_identity_sha256"],
        "model_sha256": identity["signed_app"]["model_sha256"],
        "llama_server_sha256": identity["signed_app"]["llama_server_sha256"],
        "provider_mode": "embedded_local",
        "original_capture_sha256_before": "a" * 64,
        "original_capture_sha256_after": "a" * 64,
        "evidence_ids": ["ev-1"],
        "findings": [{"finding_id": "finding-1", "evidence_ids": ["ev-1"]}],
    }


def completed_case_report(case_id, conclusion_type="supported_finding", *, empty=False):
    return {
        "schema_version": "1.0",
        "case_id": case_id,
        "status": "complete",
        "symptom": "Slow response",
        "capture_quality": {
            "state": "limited",
            "evidence_ids": ["ev-quality"],
            "limitations": ["Incomplete transaction visibility"],
        },
        "conclusion": {
            "type": conclusion_type,
            "statement": "Inspect available timing",
            "confidence": "low",
            "fault_domains": ["unknown"],
            "evidence_ids": ["ev-1"],
        },
        "findings": []
        if empty
        else [
            {
                "id": "finding-1",
                "title": "Timing",
                "category": "timing",
                "confidence": "low",
                "statement": "Observed timing requires validation",
                "evidence_ids": ["ev-1"],
                "alternate_explanations": [],
                "limitations": [],
                "recommended_validation": ["Collect server capture"],
                "wireshark": {
                    "applicable": True,
                    "full_capture": True,
                    "evidence_capture": True,
                    "copy_filter": True,
                    "show_packet_evidence": True,
                    "display_filter": "tcp",
                },
            }
        ],
        "remaining_hypotheses": [
            {
                "statement": "Server delay remains possible",
                "fault_domains": ["server_application"],
                "evidence_ids": ["ev-1"],
                "next_evidence": ["Collect server capture"],
            }
        ],
        "recommended_next_evidence": ["Collect server capture"],
        "limitations": ["Incomplete transaction visibility"],
        "analyzer_versions": {},
        "reasoning": {
            "mode": "model_assisted",
            "status": "complete",
            "steps": 1,
            "provider_mode": "embedded_local",
            "model": "packaged-model",
        },
    }


def validate_eai14_08_artifact(tmp_path, qualification, payload, identity):
    operator_root = tmp_path / "operator"
    evidence_root = tmp_path / "evidence"
    operator_root.mkdir(exist_ok=True)
    evidence_root.mkdir(exist_ok=True)
    source = operator_root / f"{payload['scenario_id']}.json"
    source.write_text(json.dumps(payload))
    return qualification._operator_artifact(
        operator_root,
        evidence_root,
        "eai14-08",
        {
            "path": source.name,
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "media_type": "application/json",
        },
        identity,
    )


def test_eai14_08_accepts_server_wait_insufficient_evidence_with_zero_findings(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    payload = operator_case_report("server_wait", identity)
    payload.update(conclusion_type="insufficient_evidence", findings=[])
    assert validate_eai14_08_artifact(tmp_path, qualification, payload, identity)


def test_eai14_08_rejects_server_wait_zero_findings_with_other_conclusion(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    payload = operator_case_report("server_wait", identity)
    payload["findings"] = []
    with pytest.raises(ValueError, match="operator_evidence_invalid"):
        validate_eai14_08_artifact(tmp_path, qualification, payload, identity)


@pytest.mark.parametrize("case_id", ["high_rtt", "midstream"])
@pytest.mark.parametrize("conclusion", ["supported_finding", "insufficient_evidence"])
def test_eai14_08_rejects_zero_findings_for_other_cases(tmp_path, case_id, conclusion):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    payload = operator_case_report(case_id, identity)
    payload.update(conclusion_type=conclusion, findings=[])
    with pytest.raises(ValueError, match="operator_evidence_invalid"):
        validate_eai14_08_artifact(tmp_path, qualification, payload, identity)


@pytest.mark.parametrize("case_id", ["high_rtt", "server_wait", "midstream"])
def test_eai14_08_requires_conclusion_type_for_all_case_artifacts(tmp_path, case_id):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    payload = operator_case_report(case_id, identity)
    del payload["conclusion_type"]
    with pytest.raises(ValueError, match="operator_evidence_invalid"):
        validate_eai14_08_artifact(tmp_path, qualification, payload, identity)


def test_eai14_08_projection_cli_derives_conclusion_from_actual_report(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    archive.unlink()
    freezer = module_at(ROOT / "scripts/freeze_embedded_ai_candidate.py", "projection_freezer")
    metadata = freezer.freeze_candidate(bundle, archive, codesign_runner=ad_hoc_codesign_runner)
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(json.dumps(metadata))
    generated_case_id = "case_7f3a9c2e1b4d"
    source = completed_case_report(generated_case_id, "insufficient_evidence", empty=True)
    source_path = tmp_path / "actual-report.json"
    source_path.write_text(json.dumps(source, indent=2))
    output = tmp_path / "server_wait.json"
    args = [
        sys.executable,
        str(SCRIPT),
        "--project-eai14-08-report",
        str(source_path),
        "--candidate-bundle",
        str(bundle),
        "--candidate-archive",
        str(archive),
        "--candidate-metadata",
        str(metadata_path),
        "--capture-sha256-before",
        "a" * 64,
        "--capture-sha256-after",
        "a" * 64,
        "--scenario-id",
        "server_wait",
        "--output",
        str(output),
    ]
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    projected = json.loads(output.read_text())
    assert output.name == "server_wait.json"
    assert projected["case_id"] == generated_case_id
    assert projected["scenario_id"] == "server_wait"
    assert projected["conclusion_type"] == source["conclusion"]["type"]
    assert projected["findings"] == []
    assert projected["evidence_ids"] == ["ev-1", "ev-quality"]
    assert (
        projected["source_report_sha256"]
        == hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    identity = qualification.candidate_identity(bundle, archive, frozen_metadata=metadata)
    assert projected["candidate_identity_sha256"] == identity["candidate_identity_sha256"]
    assert projected["model_sha256"] == identity["signed_app"]["model_sha256"]
    assert projected["llama_server_sha256"] == identity["signed_app"]["llama_server_sha256"]
    assert projected["original_capture_sha256_before"] == projected["original_capture_sha256_after"]
    assert validate_eai14_08_artifact(tmp_path, qualification, projected, identity)
    rejected = subprocess.run(
        [*args, "--conclusion-type", "supported_finding"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode == 2


def test_eai14_08_operator_procedure_prints_scenario_projection_invocation():
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-bundle",
            "candidate",
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
    assert "--scenario-id high_rtt|server_wait|midstream" in result.stdout
    assert "--output <scenario_id>.json" in result.stdout
    assert "Never hand-author projection JSON" in result.stdout


def test_eai14_08_projection_preserves_generated_case_id_and_binds_scenario(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    generated_case_id = "case_7f3a9c2e1b4d"
    source = completed_case_report(generated_case_id)

    projected = qualification.project_eai14_08_case_report(
        source, identity, "a" * 64, "a" * 64, scenario_id="high_rtt"
    )

    assert projected["case_id"] == generated_case_id
    assert projected["scenario_id"] == "high_rtt"
    assert (
        projected["source_report_sha256"]
        == hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
    )
    assert validate_eai14_08_artifact(tmp_path, qualification, projected, identity)


@pytest.mark.parametrize("case_id", ["high_rtt", "server_wait", "midstream"])
def test_eai14_08_projection_retains_source_findings_and_case_evidence(tmp_path, case_id):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    report = completed_case_report(case_id)
    projected = qualification.project_eai14_08_case_report(
        report, identity, "a" * 64, "a" * 64, scenario_id=case_id
    )
    assert projected["case_id"] == case_id
    assert projected["scenario_id"] == case_id
    assert projected["conclusion_type"] == "supported_finding"
    assert projected["findings"] == [{"finding_id": "finding-1", "evidence_ids": ["ev-1"]}]
    assert projected["evidence_ids"] == ["ev-1", "ev-quality"]
    assert validate_eai14_08_artifact(tmp_path, qualification, projected, identity)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_report_sha256", None),
        ("source_report_sha256", "invalid"),
        ("candidate_identity_sha256", "f" * 64),
        ("model_sha256", "f" * 64),
        ("llama_server_sha256", "f" * 64),
        ("original_capture_sha256_after", "f" * 64),
        ("scenario_id", "unrecognized"),
        ("provider_mode", "none"),
        ("findings", [{"finding_id": "finding-1", "evidence_ids": ["foreign-case-evidence"]}]),
    ],
)
def test_eai14_08_rejects_invalid_projection_binding(tmp_path, field, value):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    payload = operator_case_report("high_rtt", identity)
    if value is None:
        del payload[field]
    else:
        payload[field] = value
    with pytest.raises(ValueError, match="operator_evidence_invalid"):
        validate_eai14_08_artifact(tmp_path, qualification, payload, identity)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(status="partial"),
        lambda r: r["reasoning"].update(provider_mode="none"),
        lambda r: r["conclusion"].update(type="invented"),
        lambda r: r["findings"][0].update(evidence_ids=[]),
        lambda r: r["findings"][0].update(affected_scope={"evidence_ids": [{}]}),
    ],
)
def test_eai14_08_projection_rejects_invalid_source_report(tmp_path, mutation):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    report = completed_case_report("high_rtt")
    mutation(report)
    with pytest.raises(ValueError, match="operator_source_report_invalid"):
        qualification.project_eai14_08_case_report(
            report, identity, "a" * 64, "a" * 64, scenario_id="high_rtt"
        )


def operator_native_report(check_id, identity):
    common = {
        "schema_version": 1,
        "candidate_identity_sha256": identity["candidate_identity_sha256"],
        "model_sha256": identity["signed_app"]["model_sha256"],
        "llama_server_sha256": identity["signed_app"]["llama_server_sha256"],
        "provider_mode": "embedded_local",
    }
    records = {
        "eai14-10": {
            **common,
            "scenario_id": "wireclaw-eai14-10-0123456789abcdef",
            "managed_helper_stopped_via_verified_host_primitive": True,
            "rules_only_analysis_completed": True,
            "safe_restart_succeeded": True,
            "case_data_preserved": True,
        },
        "eai14-14": {
            **common,
            "scenario_id": "wireclaw-eai14-14-0123456789abcdef",
            "port_conflict_fallback_completed": True,
            "model_hash_tamper_fallback_completed": True,
            "original_candidate_unchanged": True,
            "loopback_only": True,
            "case_data_preserved": True,
        },
        "eai14-16": {
            **common,
            "scenario_id": "wireclaw-privacy-0123456789abcdef",
            "reviewed_surfaces": [
                "model_context",
                "api_responses",
                "case_database",
                "runtime_logs",
                "core_logs",
                "browser_status",
                "reports",
            ],
            "sentinel_absent_from_all_surfaces": True,
        },
    }
    return records[check_id]


def candidate_fixture(tmp_path):
    bundle = tmp_path / "candidate" / "wireclaw-release"
    app = bundle / "ai/WireclawAI.app"
    (app / "Contents/Resources/ai").mkdir(parents=True)
    (app / "Contents/MacOS").mkdir()
    (app / "Contents/Info.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": "com.wireclaw.WireclawAI"})
    )
    (app / "Contents/MacOS/WireclawAI").write_bytes(b"wrapper")
    (app / "Contents/MacOS/llama-server").write_bytes(b"helper")
    (app / "Contents/MacOS/llama-server").chmod(0o755)
    (app / "Contents/Resources/ai/model.gguf").write_bytes(b"model")
    model_sha256 = hashlib.sha256(b"model").hexdigest()
    helper_sha256 = hashlib.sha256(b"helper").hexdigest()
    (app / "Contents/Resources/ai/model-manifest.json").write_text(
        json.dumps({"artifact": {"sha256": model_sha256}}), encoding="utf-8"
    )
    runtime_files = [
        {
            "path": "macos-arm64/llama-server",
            "sha256": helper_sha256,
            "size_bytes": len(b"helper"),
        }
    ]
    (app / "Contents/Resources/ai/runtime-manifest.json").write_text(
        json.dumps(
            {
                "revision": "runtime-rev",
                "files": runtime_files,
                "policy": {"network_downloads": False},
            }
        ),
        encoding="utf-8",
    )
    (bundle / "release-metadata.json").write_text(
        json.dumps(
            {
                "source_sha": "a" * 40,
                "embedded_ai": {
                    "model": {"sha256": model_sha256},
                    "runtime": {"revision": "runtime-rev", "files": runtime_files},
                },
                "signed_app": {
                    "path": "ai/WireclawAI.app",
                    "bundle_identifier": "com.wireclaw.WireclawAI",
                    "signing_mode": "adhoc",
                    "signing_identity": "-",
                    "hardened_runtime": False,
                    "developer_id_validation": "NOT_RUN",
                    "production_qualification": "NOT_RUN",
                    "notarization": "NOT_RUN",
                    "stapling": "NOT_RUN",
                    "model_sha256": model_sha256,
                    "llama_server_sha256": helper_sha256,
                },
            }
        ),
        encoding="utf-8",
    )
    (bundle / "compose.yaml").write_text(
        "services:\n  wireclaw-core:\n    image: wireclaw-core:gate8\n",
        encoding="utf-8",
    )
    (bundle / ".env.example").write_text(
        "WIRECLAW_PORT=8765\n"
        "WIRECLAW_BRIDGE_PORT=8766\n"
        "WIRECLAW_AI_PORT=8767\n"
        'WIRECLAW_DATA_ROOT="${HOME}/Library/Application Support/Wireclaw/data"\n'
        "WIRECLAW_PROVIDER_MODE=embedded_local\n"
        "WIRECLAW_PROVIDER_BASE_URL=\n"
        "WIRECLAW_PROVIDER_MODEL=\n",
        encoding="utf-8",
    )
    archive = tmp_path / "candidate.tar"
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as stream:
        stream.add(bundle, arcname=".")
    return bundle, archive


def ad_hoc_codesign_runner(argv, **_kwargs):
    target = Path(argv[-1])
    if "--verify" in argv:
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    if "-dv" in argv:
        identifier = "llama-server" if target.name == "llama-server" else "com.wireclaw.WireclawAI"
        details = f"Identifier={identifier}\nSignature=adhoc\nTeamIdentifier=not set\nflags=0x0"
        return SimpleNamespace(returncode=0, stdout="", stderr=details)
    parent = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.server": True,
    }
    helper = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.inherit": True,
    }
    entitlements = helper if target.name == "llama-server" else parent
    return SimpleNamespace(
        returncode=0,
        stdout=plistlib.dumps(entitlements).decode(),
        stderr="",
    )


def test_runner_declares_exact_spec_16_checks_and_required_sandbox_suite():
    qualification = qualification_module()
    spec = SPEC.read_text(encoding="utf-8")
    assert len(qualification.EAI14_CHECKS) == 16
    assert len({check[0] for check in qualification.EAI14_CHECKS}) == 16
    eai14_spec = spec.split("## 22. Native macOS end-to-end acceptance", 1)[1].split("## 23.", 1)[0]
    assert [title for _, title in qualification.EAI14_CHECKS] == [
        line.split(". ", 1)[1].rstrip(";.")
        for line in eai14_spec.splitlines()
        if line.startswith(tuple(f"{number}. " for number in range(1, 17)))
    ]
    assert qualification.SANDBOX_CHECKS
    assert qualification.SANDBOX_CHECKS == (
        "exact_parent_helper_entitlements",
        "docker_engine_control_sockets_denied",
        "wireclaw_state_and_host_bridge_state_denied",
        "core_api_and_host_bridge_network_denied",
        "packaged_assets_and_bounded_private_writes",
        "secret_handoff_and_cleanup_boundary",
        "host_receipt_and_verified_signal_lifecycle",
        "fixed_loopback_listener_and_core_reachability",
        "vmnetd_informational_only",
    )


def test_evidence_rejects_missing_duplicate_and_mixed_candidate_checks(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    results = qualification.empty_results(identity)
    qualification.validate_results(results, identity)

    results["eai14"].pop()
    with pytest.raises(ValueError, match="eai14_coverage_invalid"):
        qualification.validate_results(results, identity)

    results = qualification.empty_results(identity)
    results["eai14"][1] = dict(results["eai14"][0])
    with pytest.raises(ValueError, match="eai14_coverage_invalid"):
        qualification.validate_results(results, identity)

    results = qualification.empty_results(identity)
    results["eai14"][0]["candidate_identity_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="candidate_identity_mismatch"):
        qualification.validate_results(results, identity)

    results = qualification.empty_results(identity)
    results["sandbox"].append(dict(results["sandbox"][0]))
    with pytest.raises(ValueError, match="sandbox_coverage_invalid"):
        qualification.validate_results(results, identity)

    results = qualification.empty_results(identity)
    results["sandbox"].pop()
    with pytest.raises(ValueError, match="sandbox_coverage_invalid"):
        qualification.validate_results(results, identity)


def test_pass_evidence_is_required_and_hash_checked(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    results = qualification.empty_results(identity)
    results["eai14"][2]["status"] = "PASS"
    results["eai14"][2]["not_run_reason"] = None
    with pytest.raises(ValueError, match="qualification_evidence_missing"):
        qualification.validate_results(results, identity)

    evidence_root = tmp_path / "evidence-input"
    evidence_root.mkdir(mode=0o700)
    evidence = evidence_root / "eai14-01.txt"
    evidence.write_bytes(b"verified native evidence")
    results["eai14"][2]["evidence"] = [
        {"path": evidence.name, "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}
    ]
    qualification.validate_results(results, identity, evidence_root)
    evidence.write_bytes(b"altered evidence")
    with pytest.raises(ValueError, match="qualification_evidence_identity_mismatch"):
        qualification.validate_results(results, identity, evidence_root)


def test_validation_rejects_operator_production_signing_claim_for_adhoc_candidate(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    results = qualification.empty_results(identity)
    results["signing_status"]["developer_id"] = "PASS"
    with pytest.raises(ValueError, match="qualification_signing_status_mismatch"):
        qualification.validate_results(results, identity)


def test_candidate_identity_requires_real_bundle_and_archive_hashes(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    first = qualification.candidate_identity(bundle, archive)
    assert len(first["bundle_tree_sha256"]) == 64
    assert len(first["archive_sha256"]) == 64
    assert first["source_sha"] == "a" * 40
    (bundle / "ai/WireclawAI.app/Contents/MacOS/WireclawAI").write_bytes(b"changed")
    with pytest.raises(ValueError, match="candidate_bundle_identity_mismatch"):
        qualification.verify_candidate_unchanged(bundle, archive, first)
    (bundle / "ai/WireclawAI.app/Contents/MacOS/WireclawAI").write_bytes(b"wrapper")
    archive.write_bytes(b"changed archive")
    with pytest.raises(ValueError, match="candidate_archive_identity_mismatch"):
        qualification.verify_candidate_unchanged(bundle, archive, first)


def test_archive_must_contain_the_exact_bundle_tree(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    archive.write_bytes(b"different archive with independent hash")
    with pytest.raises(ValueError, match="candidate_archive_content_mismatch"):
        qualification.candidate_identity(bundle, archive)
    with pytest.raises(ValueError, match="candidate_archive_identity_mismatch"):
        qualification.verify_candidate_unchanged(bundle, archive, identity)


def test_archive_member_size_is_checked_before_streaming(tmp_path, monkeypatch):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    real_open = tarfile.open

    class ArchiveProxy:
        def __init__(self, archive_file):
            self.archive_file = archive_file

        def __enter__(self):
            self.inner = real_open(*self.archive_file[0], **self.archive_file[1])
            self.inner.__enter__()
            return self

        def __exit__(self, *args):
            return self.inner.__exit__(*args)

        def getmembers(self):
            members = self.inner.getmembers()
            member = next(item for item in members if item.name.endswith("model.gguf"))
            member.size += 1
            return members

        def extractfile(self, member):
            return self.inner.extractfile(member)

    def fake_open(*args, **kwargs):
        return ArchiveProxy((args, kwargs))

    monkeypatch.setattr(qualification.tarfile, "open", fake_open)
    with pytest.raises(ValueError, match="candidate_archive_content_mismatch"):
        qualification.verify_archive_matches_bundle(bundle, archive)


def test_archive_member_hashing_uses_bounded_chunks():
    qualification = qualification_module()

    class TrackingStream:
        def __init__(self):
            self.data = b"abcdefgh"
            self.sizes = []

        def read(self, size):
            self.sizes.append(size)
            chunk, self.data = self.data[:size], self.data[size:]
            return chunk

    stream = TrackingStream()
    digest = qualification._stream_sha256(stream, chunk_size=3)
    assert digest == hashlib.sha256(b"abcdefgh").hexdigest()
    assert stream.sizes == [3, 3, 3, 3]


def test_bundle_identity_and_archive_require_behavior_relevant_file_modes(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    before = qualification.candidate_identity(bundle, archive)
    helper = bundle / "ai/WireclawAI.app/Contents/MacOS/llama-server"
    helper.chmod(0o644)
    assert qualification.tree_sha256(bundle) != before["bundle_tree_sha256"]
    with pytest.raises(ValueError, match="candidate_archive_content_mismatch"):
        qualification.verify_archive_matches_bundle(bundle, archive)
    archive.unlink()
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as stream:
        stream.add(bundle, arcname=".")
    after = qualification.candidate_identity(bundle, archive)
    assert after["candidate_identity_sha256"] != before["candidate_identity_sha256"]


def test_runner_executes_fixed_handlers_and_leaves_unsupported_checks_not_run(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    signature_checks = []
    monkeypatch.setattr(
        qualification,
        "verify_frozen_signatures",
        lambda _bundle, _identity: signature_checks.append("verified"),
    )
    evidence_root = tmp_path / "handler-evidence"
    results = qualification.run_supported_checks(bundle, identity, evidence_root)
    assert signature_checks == ["verified"]
    assert results["eai14"][2]["status"] == "PASS"
    assert results["sandbox"][0]["status"] == "PASS"
    for index, row in enumerate(results["eai14"]):
        if index != 2:
            assert row["status"] == "NOT_RUN"
            if row["id"] in qualification.UNAVAILABLE_CHECKS:
                assert row["not_run_reason"] in {
                    qualification.UNAVAILABLE_CHECKS[row["id"]],
                    *qualification.NATIVE_NOT_RUN_REASONS,
                }
            else:
                assert row["not_run_reason"] in qualification.NATIVE_NOT_RUN_REASONS
    for index, row in enumerate(results["sandbox"]):
        if index != 0:
            assert row["status"] == "NOT_RUN"
            assert row["not_run_reason"] in qualification.NATIVE_NOT_RUN_REASONS
    for row in (results["eai14"][2], results["sandbox"][0]):
        item = row["evidence"][0]
        evidence_path = evidence_root / item["path"]
        assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == item["sha256"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        assert evidence["candidate_identity_sha256"] == identity["candidate_identity_sha256"]
    qualification.validate_results(results, identity, evidence_root)


def test_fixed_handler_plan_covers_available_native_and_source_checks():
    qualification = qualification_module()
    expected_gaps = {
        "eai14-07": "native_ui_automation_unavailable",
        "eai14-08": "representative_case_runner_unavailable",
        "eai14-09": "wireshark_ui_automation_unavailable",
    }
    assert qualification.UNAVAILABLE_CHECKS == {}
    assert set(qualification.OPERATOR_CHECKS) == set(expected_gaps) | {
        "eai14-10",
        "eai14-14",
        "eai14-16",
    }
    assert set(qualification.FIXED_HANDLERS) == (
        {check_id for check_id, _title in qualification.EAI14_CHECKS}
        | set(qualification.SANDBOX_CHECKS)
    ) - set(qualification.UNAVAILABLE_CHECKS)


def test_source_checkout_change_during_collection_invalidates_candidate_evidence(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    monkeypatch.setattr(
        qualification,
        "_candidate_source_checkout",
        lambda _identity: "candidate_source_checkout_dirty",
    )
    with pytest.raises(ValueError, match="candidate_source_changed_during_qualification"):
        qualification._require_source_checkout_stable(identity, None)


def test_task9_fixture_provenance_is_not_reported_as_candidate_runtime(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    provenance = qualification.task9_fixture_provenance(identity)
    assert provenance["probe_scope"] == "separate_task9_fixture"
    assert provenance["candidate_runtime_evidence"] is False
    assert provenance["source_sha"] == identity["source_sha"]
    assert len(provenance["probe_script_sha256"]) == 64


@pytest.mark.parametrize("log_content", [b"", b"pre-existing"])
def test_task10_preflight_refuses_existing_app_state_without_deleting_it(
    tmp_path, monkeypatch, log_content
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    private = (
        tmp_path
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True)
    existing_log = private / "runtime.log"
    existing_log.write_bytes(log_content)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )
    assert reason == "existing_ai_private_state"
    assert existing_log.read_bytes() == log_content
    assert calls == []


def test_task10_preflight_allows_only_empty_private_directory_left_by_task9(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    private = (
        tmp_path
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    (bundle / ".env").write_text(
        (bundle / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["pgrep", "-x"]:
            return SimpleNamespace(returncode=1, stdout="")
        if argv[0] == "/usr/sbin/lsof":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )
    assert reason is None
    assert len(calls) == 6


def test_task9_reset_removes_only_approved_empty_runtime_log_after_recording_evidence(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    log = private / "runtime.log"
    log.touch(mode=0o600)
    evidence = []
    monkeypatch.setattr(qualification.os, "getuid", lambda: log.stat().st_uid)

    def safe_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    def record_before_unlink(value):
        assert log.exists()
        evidence.append(value)

    result = qualification.reset_task9_diagnostic_residue(
        home=home, record=record_before_unlink, runner=safe_runner
    )
    assert result["action"] == "reset"
    assert len(evidence) == 1
    residue = evidence[0]["residue"][0]
    assert residue["canonical_path"] == str(log.resolve())
    assert residue["file_type"] == "regular"
    assert residue["size_bytes"] == 0
    assert residue["sha256"] == hashlib.sha256(b"").hexdigest()
    assert all(key in residue for key in ("owner_uid", "mode", "atime_ns", "mtime_ns", "ctime_ns"))
    assert not log.exists()


@pytest.mark.parametrize("state_name", ["process.json", "api-key", "unknown", "runtime.log"])
def test_task9_reset_blocks_unapproved_private_state_without_mutation(tmp_path, state_name):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    target = private / state_name
    target.write_bytes(b"unsafe residue" if state_name != "runtime.log" else b"not empty")
    evidence = []

    def safe_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(
            home=home, record=evidence.append, runner=safe_runner
        )
    assert target.exists()
    assert target.read_bytes()
    assert evidence == []


def test_task9_reset_is_idempotent_for_empty_private_directory(tmp_path):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)

    def safe_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    assert (
        qualification.reset_task9_diagnostic_residue(home=home, runner=safe_runner)["action"]
        == "clean"
    )
    assert (
        qualification.reset_task9_diagnostic_residue(home=home, runner=safe_runner)["action"]
        == "clean"
    )


@pytest.mark.parametrize(
    ("blocked_command", "expected_calls"),
    [
        (["pgrep", "-x", "WireclawAI"], 1),
        (["pgrep", "-x", "llama-server"], 2),
        (["lsof", "-nP", "-iTCP@127.0.0.1:8767", "-sTCP:LISTEN"], 3),
    ],
)
def test_task9_reset_blocks_live_process_or_listener_without_mutation(
    tmp_path, blocked_command, expected_calls
):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    log = private / "runtime.log"
    log.touch(mode=0o600)
    calls = []

    def runner(argv, **_kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0 if argv == blocked_command else 1, stdout="pid\n")

    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(home=home, runner=runner)
    assert len(calls) == expected_calls
    assert log.exists()


@pytest.mark.parametrize("name", ["api-key", "process.json", "unexpected"])
def test_task9_reset_blocks_sensitive_or_unknown_files_without_mutation(tmp_path, name):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    item = private / name
    item.write_bytes(b"secret-or-unknown")

    def safe_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(home=home, runner=safe_runner)
    assert item.exists()


def test_task9_reset_blocks_symlinks_wrong_owner_and_wrong_mode(tmp_path, monkeypatch):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    log = private / "runtime.log"
    log.symlink_to(tmp_path / "outside")

    def safe_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    with pytest.raises(OSError):
        qualification.reset_task9_diagnostic_residue(home=home, runner=safe_runner)
    assert log.is_symlink()
    log.unlink()
    log.touch(mode=0o600)
    private.chmod(0o755)
    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(home=home, runner=safe_runner)
    private.chmod(0o700)
    monkeypatch.setattr(qualification.os, "getuid", lambda: log.stat().st_uid + 1)
    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(home=home, runner=safe_runner)
    assert log.exists()


def test_task9_reset_blocks_symlinked_private_directory(tmp_path):
    qualification = qualification_module()
    home = tmp_path / "home"
    target = tmp_path / "outside"
    target.mkdir()
    containers = home / "Library/Containers"
    containers.mkdir(parents=True)
    (containers / "com.wireclaw.WireclawAI").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(home=home)


def test_task9_reset_blocks_runtime_log_with_unsafe_mode(tmp_path):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    log = private / "runtime.log"
    log.touch(mode=0o644)
    log.chmod(0o644)

    def safe_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(home=home, runner=safe_runner)
    assert log.exists()


def test_task9_reset_blocks_host_receipt_and_preserves_log(tmp_path):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    log = private / "runtime.log"
    log.touch(mode=0o600)
    receipt = home / "Library/Application Support/Wireclaw/run/ai-host-receipt.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("receipt")
    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(home=home)
    assert log.exists()


def test_task9_reset_failure_while_recording_evidence_leaves_residue(tmp_path):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    log = private / "runtime.log"
    log.touch(mode=0o600)

    def safe_runner(argv, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="")

    def failed_record(_value):
        raise OSError("evidence write failed")

    with pytest.raises(OSError):
        qualification.reset_task9_diagnostic_residue(
            home=home, record=failed_record, runner=safe_runner
        )
    assert log.exists()


def test_task9_reset_late_process_change_leaves_recorded_residue_untouched(tmp_path):
    qualification = qualification_module()
    home = tmp_path / "home"
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    log = private / "runtime.log"
    log.touch(mode=0o600)
    calls = 0
    evidence = []

    def runner(argv, **_kwargs):
        nonlocal calls
        calls += 1
        return SimpleNamespace(returncode=0 if calls == 4 else 1, stdout="pid\n")

    with pytest.raises(ValueError):
        qualification.reset_task9_diagnostic_residue(
            home=home, record=evidence.append, runner=runner
        )
    assert log.exists()
    assert evidence[0]["residue"][0]["sha256"] == hashlib.sha256(b"").hexdigest()


def test_task9_runner_persists_reset_evidence_before_native_probe(tmp_path, monkeypatch):
    qualification = qualification_module()
    evidence_root = tmp_path / "evidence"
    residue = {
        "canonical_path": "/private/test/runtime.log",
        "file_type": "regular",
        "size_bytes": 0,
        "owner_uid": 502,
        "mode": 0o600,
        "atime_ns": 1,
        "mtime_ns": 2,
        "ctime_ns": 3,
        "sha256": hashlib.sha256(b"").hexdigest(),
    }
    calls = 0

    def reset(*, record):
        nonlocal calls
        calls += 1
        record({"action": "reset", "residue": [residue]})
        return {"action": "reset", "residue": [residue]}

    def native_probe(*_args, **_kwargs):
        assert (
            json.loads((evidence_root / "task9-reset-before.json").read_text())["residue"][0]
            == residue
        )
        return SimpleNamespace(
            stdout=b"Task 9 signed App Sandbox isolation: PASS\n", stderr=b"", returncode=0
        )

    monkeypatch.setattr(qualification, "reset_task9_diagnostic_residue", reset)
    monkeypatch.setattr(qualification.sys, "platform", "darwin")
    monkeypatch.setattr(qualification.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(qualification.subprocess, "run", native_probe)
    status, reason, output = qualification._run_task9_probe(evidence_root)
    assert status == "PASS" and reason is None
    assert "TASK9_RESET_EVIDENCE=" in output
    assert (
        json.loads((evidence_root / "task9-reset-after.json").read_text())["residue"][0] == residue
    )
    assert calls == 2


def test_task9_reset_has_no_process_signaling_authority():
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("def reset_task9_diagnostic_residue(")
    end = source.index("\ndef task9_fixture_provenance", start)
    body = source[start:end]
    assert not any(token in body for token in ("kill(", "SIGTERM", "SIGKILL", "os.kill", "signal."))


def test_task10_preflight_refuses_unsafe_empty_private_directory(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    private = (
        tmp_path
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o755)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )
    assert reason == "existing_ai_private_state"
    assert calls == []


@pytest.mark.parametrize(
    "state_name", ["api-key", "process.json", "task9-probe.json", "task9-private-write"]
)
def test_task10_preflight_refuses_existing_private_lifecycle_state(tmp_path, state_name):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    private = (
        tmp_path
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    (private / state_name).write_bytes(b"existing")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )
    assert reason == "existing_ai_private_state"
    assert calls == []


def test_task10_preflight_refuses_live_helper_after_empty_private_directory(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    private = (
        tmp_path
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv == ["pgrep", "-x", "WireclawAI"]:
            return SimpleNamespace(returncode=0, stdout="12345\n")
        return SimpleNamespace(returncode=1, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )
    assert reason == "existing_ai_process"
    assert calls == [["pgrep", "-x", "WireclawAI"]]


def test_task10_preflight_refuses_trusted_host_receipt(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    run_dir = tmp_path / "Library/Application Support/Wireclaw/run"
    run_dir.mkdir(parents=True, mode=0o700)
    (run_dir / "ai-host-receipt.json").write_text("receipt", encoding="utf-8")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )
    assert reason == "existing_wireclaw_lifecycle_state"
    assert calls == []


def test_task10_preflight_refuses_existing_compose_container_state(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    env_file = bundle / ".env.example"
    (bundle / ".env").write_text(env_file.read_text(encoding="utf-8"), encoding="utf-8")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["pgrep", "-x"]:
            return SimpleNamespace(returncode=1, stdout="")
        if argv[0] == "/usr/sbin/lsof":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="existing-container-id\n")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )
    assert reason == "existing_compose_state"
    compose_call = calls[-1]
    assert compose_call[-3:] == ["ps", "-aq", "wireclaw-core"]
    assert compose_call[compose_call.index("--env-file") + 1] == str(bundle / ".env")


def test_task10_preflight_queries_only_exact_project_and_checks_ports(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    env_file = bundle / ".env"
    env_file.write_text((bundle / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    project_name = "wireclaw-qualification-a1b2c3d4e5f6"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[:2] == ["pgrep", "-x"]:
            return SimpleNamespace(returncode=1, stdout="")
        if argv[0] == "/usr/sbin/lsof":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name=project_name,
        runner=fake_run,
    )

    assert reason is None
    lsof_calls = [argv for argv, _kwargs in calls if argv[0] == "/usr/sbin/lsof"]
    assert len(lsof_calls) == 3
    assert {argv[2] for argv in lsof_calls} == {
        "-iTCP:8765",
        "-iTCP:8766",
        "-iTCP:8767",
    }
    compose_argv, compose_kwargs = calls[-1]
    assert compose_argv[0:2] == ["docker", "compose"]
    assert compose_argv[compose_argv.index("--env-file") + 1] == str(env_file)
    assert compose_argv[compose_argv.index("-f") + 1] == str(bundle / "compose.yaml")
    assert compose_argv[-3:] == ["ps", "-aq", "wireclaw-core"]
    assert compose_kwargs["env"]["COMPOSE_PROJECT_NAME"] == project_name


def test_task10_preflight_ignores_inherited_wireclaw_compose_overrides(tmp_path, monkeypatch):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    (bundle / ".env").write_text(
        (bundle / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    monkeypatch.setenv("WIRECLAW_DATA_ROOT", "/outside/private/data")
    monkeypatch.setenv("WIRECLAW_PORT", "9999")
    monkeypatch.setenv("WIRECLAW_AI_PORT", "9888")
    monkeypatch.setenv("COMPOSE_PROFILES", "unexpected")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[:2] == ["pgrep", "-x"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if argv[0] == "/usr/sbin/lsof":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )

    assert reason is None
    lsof_calls = [argv for argv, _kwargs in calls if argv[0] == "/usr/sbin/lsof"]
    assert {argv[2] for argv in lsof_calls} == {
        "-iTCP:8765",
        "-iTCP:8766",
        "-iTCP:8767",
    }
    for _argv, kwargs in calls:
        assert "WIRECLAW_DATA_ROOT" not in kwargs["env"]
        assert "WIRECLAW_PORT" not in kwargs["env"]
        assert "WIRECLAW_AI_PORT" not in kwargs["env"]
        assert "COMPOSE_PROFILES" not in kwargs["env"]


def test_task10_preflight_blocks_port_conflict_independent_of_compose_project(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    (bundle / ".env").write_text(
        (bundle / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["pgrep", "-x"]:
            return SimpleNamespace(returncode=1, stdout="")
        if argv[0] == "/usr/sbin/lsof" and "-iTCP:8765" in argv:
            return SimpleNamespace(returncode=0, stdout="listener\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )

    assert reason == "existing_host_port_conflict"
    assert not any(argv[:2] == ["docker", "compose"] for argv in calls)


def test_task10_preflight_fails_closed_when_lsof_cannot_check_host_ports(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    (bundle / ".env").write_text(
        (bundle / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["pgrep", "-x"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if argv[0] == "/usr/sbin/lsof":
            return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    reason = qualification.task10_shared_state_preflight(
        bundle,
        identity,
        home=tmp_path,
        project_name="wireclaw-qualification-a1b2c3d4e5f6",
        runner=fake_run,
    )

    assert reason == "native_probe_dependency_unavailable"
    assert not any(argv[:2] == ["docker", "compose"] for argv in calls)


def test_task10_runner_materializes_private_config_before_scoped_preflight(tmp_path, monkeypatch):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    original_tree_hash = qualification.tree_sha256(bundle)
    temporary_root = tmp_path / "Wireclaw qualification with spaces-run"
    temporary_root.mkdir(mode=0o700)
    temporary_root.chmod(0o700)
    monkeypatch.setattr(qualification.sys, "platform", "darwin")
    monkeypatch.setattr(qualification.platform, "machine", lambda: "arm64")
    monkeypatch.setenv("WIRECLAW_DATA_ROOT", "/outside/private/data")
    monkeypatch.setenv("WIRECLAW_PORT", "9999")
    monkeypatch.setenv("COMPOSE_PROFILES", "unexpected")

    def private_mkdtemp(*, prefix, dir=None):
        if dir is None:
            return str(temporary_root)
        private_copy_root = Path(dir) / "task10-private-copy"
        private_copy_root.mkdir(mode=0o700)
        return str(private_copy_root)

    monkeypatch.setattr(qualification.tempfile, "mkdtemp", private_mkdtemp)
    preflight_observed = {}
    command_observed = []

    def fake_preflight(copy, candidate_identity, *, project_name):
        env_file = copy / ".env"
        assert copy != bundle
        assert env_file.is_file()
        assert env_file.stat().st_mode & 0o777 == 0o600
        raw = env_file.read_text(encoding="utf-8")
        assert "WIRECLAW_PROVIDER_API_KEY=" not in raw
        assert f'WIRECLAW_DATA_ROOT="{temporary_root / "isolated case data"}"' in raw
        assert project_name.startswith("wireclaw-qualification-")
        assert candidate_identity == identity
        assert qualification.tree_sha256(bundle) == original_tree_hash
        preflight_observed.update(
            copy=copy,
            project_name=project_name,
            env=raw,
        )
        return None

    monkeypatch.setattr(qualification, "task10_shared_state_preflight", fake_preflight)

    def fake_run(argv, **kwargs):
        command_observed.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=b"Task 10 packaged inference/Core integration: PASS\n",
            stderr=b"",
        )

    monkeypatch.setattr(qualification.subprocess, "run", fake_run)
    status, reason, observations = qualification._task10_result_in_copy(bundle, identity)

    assert (status, reason) == ("PASS", None)
    assert preflight_observed["copy"] != bundle
    assert len(command_observed) == 1
    assert all(
        kwargs["env"]["COMPOSE_PROJECT_NAME"] == preflight_observed["project_name"]
        for _argv, kwargs in command_observed
    )
    for _argv, kwargs in command_observed:
        assert "WIRECLAW_DATA_ROOT" not in kwargs["env"]
        assert "WIRECLAW_PORT" not in kwargs["env"]
        assert "COMPOSE_PROFILES" not in kwargs["env"]
    assert all(
        argv[1] == str(ROOT / "scripts/qualify_macos_embedded_ai.py")
        for argv, _ in command_observed
    )
    assert all(argv[-1] == str(preflight_observed["copy"]) for argv, _ in command_observed)
    assert observations["private_candidate_copy"] is True
    assert observations["compose_project_name"] == preflight_observed["project_name"]
    assert not (bundle / ".env").exists()
    assert qualification.tree_sha256(bundle) == original_tree_hash


def test_task10_copy_runner_stops_after_private_copy_preflight_when_shared_state_exists(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    monkeypatch.setattr(qualification.sys, "platform", "darwin")
    monkeypatch.setattr(qualification.platform, "machine", lambda: "arm64")
    temporary_root = tmp_path / "qualification-copy"
    temporary_root.mkdir(mode=0o700)

    def private_mkdtemp(*, prefix, dir=None):
        if dir is None:
            return str(temporary_root)
        private_copy_root = Path(dir) / "task10-private-copy"
        private_copy_root.mkdir(mode=0o700)
        return str(private_copy_root)

    monkeypatch.setattr(qualification.tempfile, "mkdtemp", private_mkdtemp)
    copied = {}

    def preflight(copy, *_args, **_kwargs):
        copied["path"] = copy
        return "existing_ai_private_state"

    monkeypatch.setattr(qualification, "task10_shared_state_preflight", preflight)
    assert qualification._task10_result_in_copy(bundle, identity) == (
        "NOT_RUN",
        "existing_ai_private_state",
        {},
    )
    assert copied["path"] != bundle
    assert not temporary_root.exists()


@pytest.mark.parametrize(
    "reason",
    (
        "existing_ai_private_state",
        "existing_wireclaw_lifecycle_state",
        "existing_ai_process",
        "existing_compose_state",
        "existing_host_port_conflict",
    ),
)
def test_task10_preflight_reason_produces_valid_not_run_report(tmp_path, monkeypatch, reason):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    monkeypatch.setattr(qualification, "verify_frozen_signatures", lambda *_args: None)
    monkeypatch.setattr(qualification, "_candidate_source_checkout", lambda _identity: None)
    results = qualification.run_supported_checks(
        bundle,
        identity,
        tmp_path / "preflight-evidence",
        source_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
        task9_probe=lambda: ("NOT_RUN", "native_host_required", ""),
        task10_probe=lambda *_args: ("NOT_RUN", reason, {}),
    )
    assert results["eai14"][11]["status"] == "NOT_RUN"
    assert results["eai14"][11]["not_run_reason"] == reason
    qualification.validate_results(results, identity, tmp_path / "preflight-evidence")


def test_source_suite_handler_cannot_pass_candidate_qualification(tmp_path, monkeypatch):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    evidence_root = tmp_path / "source-evidence"
    row = qualification.empty_results(identity)["eai14"][12]
    qualification.run_fixed_source_suite("eai14-13", row, identity, evidence_root, runner=fake_run)
    argv, kwargs = calls[0]
    assert argv[:3] == [qualification.sys.executable, "-m", "pytest"]
    assert (
        "tests/packaging/test_macos_launchers.py::test_env_parser_handles_home_and_paths_with_spaces"
        in argv
    )
    assert "shell" not in kwargs
    assert kwargs["cwd"] == qualification.ROOT
    assert row["status"] == "NOT_RUN"
    assert row["not_run_reason"] == "candidate_bound_evidence_unavailable"
    evidence = json.loads((evidence_root / row["evidence"][0]["path"]).read_text())
    assert evidence["candidate_identity_sha256"] == identity["candidate_identity_sha256"]
    assert evidence["observations"]["evidence_scope"] == "source_regression_only"
    assert evidence["status"] == "PASS"


def test_startup_acquisition_check_allows_only_fixed_loopback_probe_and_packaged_load(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    assert (
        qualification.verify_no_startup_download_path(bundle, identity)[
            "external_download_commands_found"
        ]
        is False
    )
    launch = tmp_path / "launch/macos"
    launch.mkdir(parents=True)
    (launch / "start.sh").write_text(
        'if curl --silent --fail --header "Origin: http://127.0.0.1:$APP_PORT" '
        '"http://127.0.0.1:$BRIDGE_PORT/v1/health" >/dev/null 2>&1; then\n',
        encoding="utf-8",
    )
    (launch / "common.sh").write_text(
        'docker load --input "$release_dir/core-image.tar"\n', encoding="utf-8"
    )
    monkeypatch.setattr(qualification, "ROOT", tmp_path)

    for forbidden in (
        "curl --fail https://example.invalid/core.tar",
        "wget https://example.invalid/core.tar",
        "docker pull wireclaw-core:latest",
        "docker image pull wireclaw-core:latest",
        "docker buildx build .",
        "git -C /tmp clone https://example.invalid/release",
        "docker compose build wireclaw-core",
        "docker compose --profile packaged build wireclaw-core",
        "docker compose up -d --pull always",
        "python3 scripts/build_embedded_ai.py",
    ):
        (launch / "start.sh").write_text(forbidden + "\n", encoding="utf-8")
        try:
            qualification.verify_no_startup_download_path(bundle, identity)
        except ValueError as error:
            assert str(error) == "startup_download_path_detected", forbidden
        else:
            pytest.fail(f"startup acquisition was accepted: {forbidden}")


def test_fixed_source_suite_uses_repository_venv_when_current_python_lacks_pytest(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    monkeypatch.setattr(qualification.importlib.util, "find_spec", lambda _name: None)
    identity = {"candidate_identity_sha256": "c" * 64}
    row = {"evidence": []}
    evidence_root = tmp_path / "evidence"
    qualification.run_fixed_source_suite("eai14-02", row, identity, evidence_root)
    evidence = json.loads((evidence_root / "source-regressions/eai14-02.json").read_text())
    assert evidence["status"] == "PASS"
    assert evidence["candidate_identity_sha256"] == identity["candidate_identity_sha256"]


def test_orchestrator_runs_fixed_source_and_static_handlers_without_native_host(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    calls = []
    monkeypatch.setattr(qualification, "verify_frozen_signatures", lambda *_args: None)
    monkeypatch.setattr(qualification, "_candidate_source_checkout", lambda _identity: None)

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0)

    evidence_root = tmp_path / "orchestrated-evidence"
    results = qualification.run_supported_checks(
        bundle,
        identity,
        evidence_root,
        source_runner=fake_run,
        task9_probe=lambda: ("NOT_RUN", "native_host_required", ""),
        task10_probe=lambda *_args: ("NOT_RUN", "native_host_required", {}),
    )
    assert len(calls) == len(qualification.SOURCE_TESTS)
    assert results["eai14"][9]["status"] == "NOT_RUN"
    assert results["eai14"][13]["status"] == "NOT_RUN"
    assert results["eai14"][15]["status"] == "NOT_RUN"
    assert results["eai14"][9]["evidence"]
    assert results["eai14"][15]["evidence"]
    assert results["sandbox"][8]["status"] == "PASS"
    assert results["eai14"][6]["status"] == "NOT_RUN"
    assert results["eai14"][8]["not_run_reason"] == "operator_evidence_missing"
    qualification.validate_results(results, identity, evidence_root)


def test_task10_evidence_only_passes_candidate_bound_persistence_and_space_checks(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    monkeypatch.setattr(qualification, "verify_frozen_signatures", lambda *_args: None)
    monkeypatch.setattr(qualification, "_candidate_source_checkout", lambda _identity: None)
    observations = {
        "candidate_identity_sha256": identity["candidate_identity_sha256"],
        "private_candidate_copy": True,
        "compose_project_name": "wireclaw-qualification-a1b2c3d4e5f6",
        "copy_path_contains_spaces": True,
        "private_case_sentinel_preserved": True,
        "task10_start_status_stop_runs": 2,
        "task10_restart": "PASS",
        "production_model_loaded": True,
        "metal_active": True,
        "core_reachable": True,
        "listener": "127.0.0.1:8767",
        "cleanup_verified": True,
    }
    evidence_root = tmp_path / "task10-evidence"
    results = qualification.run_supported_checks(
        bundle,
        identity,
        evidence_root,
        source_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
        task9_probe=lambda: ("NOT_RUN", "native_host_required", ""),
        task10_probe=lambda *_args: ("PASS", None, observations),
    )
    assert results["eai14"][9]["status"] == "NOT_RUN"
    assert results["eai14"][11]["status"] == "PASS"
    assert results["eai14"][12]["status"] == "PASS"
    assert results["eai14"][13]["status"] == "NOT_RUN"
    assert results["eai14"][15]["status"] == "NOT_RUN"
    persistence = json.loads(
        (evidence_root / results["eai14"][11]["evidence"][-1]["path"]).read_text()
    )["observations"]
    assert set(persistence) == {
        "candidate_identity_sha256",
        "private_case_sentinel_preserved",
        "task10_start_status_stop_runs",
        "task10_restart",
    }
    paths = json.loads((evidence_root / results["eai14"][12]["evidence"][-1]["path"]).read_text())[
        "observations"
    ]
    assert set(paths) == {
        "candidate_identity_sha256",
        "private_candidate_copy",
        "compose_project_name",
        "copy_path_contains_spaces",
        "task10_start_status_stop_runs",
    }
    qualification.validate_results(results, identity, evidence_root)


def test_task9_pass_records_fixture_provenance_and_candidate_entitlement_pair(
    tmp_path, monkeypatch
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    monkeypatch.setattr(qualification, "verify_frozen_signatures", lambda *_args: None)
    monkeypatch.setattr(qualification, "_candidate_source_checkout", lambda _identity: None)
    evidence_root = tmp_path / "task9-evidence"
    results = qualification.run_supported_checks(
        bundle,
        identity,
        evidence_root,
        source_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
        task9_probe=lambda: ("PASS", None, "helper denied docker.sock: DENIED"),
        task10_probe=lambda *_args: ("NOT_RUN", "native_host_required", {}),
    )
    row = results["sandbox"][4]
    evidence = json.loads((evidence_root / row["evidence"][0]["path"]).read_text())
    observations = evidence["observations"]
    assert observations["probe_scope"] == "separate_task9_fixture"
    assert observations["candidate_runtime_evidence"] is False
    assert observations["candidate_signed_entitlements_checked_separately"] is True
    assert observations["candidate_identity_sha256"] == identity["candidate_identity_sha256"]
    qualification.validate_results(results, identity, evidence_root)


def test_operator_workflow_requires_candidate_bound_fixed_native_evidence(tmp_path, monkeypatch):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    evidence_root = tmp_path / "collected-evidence"
    evidence_root.mkdir(mode=0o700)
    operator_root = tmp_path / "operator-evidence"
    operator_root.mkdir(mode=0o700)
    ui = operator_root / "ui-ready.png"
    wireshark_full = operator_root / "full-capture.png"
    wireshark_evidence = operator_root / "evidence-capture.png"
    for path in (ui, wireshark_full, wireshark_evidence):
        path.write_bytes(png_1x1())
    comparison = operator_root / "comparison.md"
    comparison.write_text(
        "# Human reviewed comparison\\n"
        "Cases: high_rtt, server_wait, midstream\\n"
        "Traceability and uncertainty retained.\\n",
        encoding="utf-8",
    )
    case_paths = {}
    for case_id in ("high_rtt", "server_wait", "midstream"):
        path = operator_root / f"{case_id}.json"
        path.write_text(json.dumps(operator_case_report(case_id, identity)))
        case_paths[case_id] = path
    operator_json = {}
    for check_id, record in {
        "eai14-10": {
            "schema_version": 1,
            "candidate_identity_sha256": identity["candidate_identity_sha256"],
            "model_sha256": identity["signed_app"]["model_sha256"],
            "llama_server_sha256": identity["signed_app"]["llama_server_sha256"],
            "provider_mode": "embedded_local",
            "scenario_id": "wireclaw-eai14-10-0123456789abcdef",
            "managed_helper_stopped_via_verified_host_primitive": True,
            "rules_only_analysis_completed": True,
            "safe_restart_succeeded": True,
            "case_data_preserved": True,
        },
        "eai14-14": {
            "schema_version": 1,
            "candidate_identity_sha256": identity["candidate_identity_sha256"],
            "model_sha256": identity["signed_app"]["model_sha256"],
            "llama_server_sha256": identity["signed_app"]["llama_server_sha256"],
            "provider_mode": "embedded_local",
            "scenario_id": "wireclaw-eai14-14-0123456789abcdef",
            "port_conflict_fallback_completed": True,
            "model_hash_tamper_fallback_completed": True,
            "original_candidate_unchanged": True,
            "loopback_only": True,
            "case_data_preserved": True,
        },
        "eai14-16": {
            "schema_version": 1,
            "candidate_identity_sha256": identity["candidate_identity_sha256"],
            "model_sha256": identity["signed_app"]["model_sha256"],
            "llama_server_sha256": identity["signed_app"]["llama_server_sha256"],
            "provider_mode": "embedded_local",
            "scenario_id": "wireclaw-privacy-0123456789abcdef",
            "reviewed_surfaces": [
                "model_context",
                "api_responses",
                "case_database",
                "runtime_logs",
                "core_logs",
                "browser_status",
                "reports",
            ],
            "sentinel_absent_from_all_surfaces": True,
        },
    }.items():
        path = operator_root / f"{check_id}.json"
        path.write_text(json.dumps(record))
        operator_json[check_id] = path

    def artifact(path, media_type):
        return {
            "path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "media_type": media_type,
        }

    manifest = {
        "schema_version": 1,
        "candidate_identity_sha256": identity["candidate_identity_sha256"],
        "operator": "release-operator",
        "attestation": qualification.OPERATOR_ATTESTATION,
        "checks": {
            "eai14-07": {
                "status": "PASS",
                "assertions": {"ready_visible": True},
                "artifacts": [artifact(ui, "image/png")],
            },
            "eai14-08": {
                "status": "PASS",
                "assertions": {
                    "cases": ["high_rtt", "server_wait", "midstream"],
                    "comparison_reviewed": True,
                    "traceability_and_uncertainty_retained": True,
                },
                "artifacts": [
                    artifact(comparison, "text/markdown"),
                    *[artifact(path, "application/json") for path in case_paths.values()],
                ],
            },
            "eai14-09": {
                "status": "PASS",
                "assertions": {
                    "full_capture_action_opened": True,
                    "evidence_capture_action_opened": True,
                },
                "artifacts": [
                    artifact(wireshark_full, "image/png"),
                    artifact(wireshark_evidence, "image/png"),
                ],
            },
            "eai14-10": {
                "status": "PASS",
                "assertions": qualification.OPERATOR_ASSERTIONS["eai14-10"],
                "artifacts": [artifact(operator_json["eai14-10"], "application/json")],
            },
            "eai14-14": {
                "status": "PASS",
                "assertions": qualification.OPERATOR_ASSERTIONS["eai14-14"],
                "artifacts": [artifact(operator_json["eai14-14"], "application/json")],
            },
            "eai14-16": {
                "status": "PASS",
                "assertions": qualification.OPERATOR_ASSERTIONS["eai14-16"],
                "artifacts": [artifact(operator_json["eai14-16"], "application/json")],
            },
        },
    }
    manifest_path = operator_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(qualification, "verify_frozen_signatures", lambda *_args: None)
    monkeypatch.setattr(qualification, "_candidate_source_checkout", lambda _identity: None)
    result = qualification.run_supported_checks(
        bundle,
        identity,
        evidence_root,
        source_match=None,
        source_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
        task9_probe=lambda: ("NOT_RUN", "native_host_required", ""),
        task10_probe=lambda *_args: ("NOT_RUN", "native_host_required", {}),
        operator_evidence_dir=operator_root,
    )
    assert [result["eai14"][index]["status"] for index in (6, 7, 8, 9, 13, 15)] == [
        "PASS",
        "PASS",
        "PASS",
        "PASS",
        "PASS",
        "PASS",
    ]
    assert all(
        row["candidate_identity_sha256"] == identity["candidate_identity_sha256"]
        for row in (
            result["eai14"][6],
            result["eai14"][7],
            result["eai14"][8],
            result["eai14"][9],
            result["eai14"][13],
            result["eai14"][15],
        )
    )
    qualification.validate_results(result, identity, evidence_root)
    evidence = json.loads((evidence_root / result["eai14"][6]["evidence"][0]["path"]).read_text())
    assert evidence["observations"]["result_basis"] == "operator_attested"
    assert evidence["observations"]["visual_content_validation"] == "NOT_RUN"


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (
            lambda data: data.update(candidate_identity_sha256="f" * 64),
            "candidate_identity_mismatch",
        ),
        (
            lambda data: data["checks"]["eai14-07"]["assertions"].update(ready_visible=False),
            "operator_evidence_invalid",
        ),
        (
            lambda data: data["checks"]["eai14-07"]["assertions"].update(ready_visible=1),
            "operator_evidence_invalid",
        ),
        (
            lambda data: data["checks"]["eai14-08"]["assertions"].update(cases=["high_rtt"]),
            "operator_evidence_invalid",
        ),
        (
            lambda data: data["checks"]["eai14-10"]["assertions"].update(
                rules_only_analysis_completed=False
            ),
            "operator_evidence_invalid",
        ),
        (
            lambda data: data["checks"]["eai14-14"]["assertions"].update(
                original_candidate_unchanged=False
            ),
            "operator_evidence_invalid",
        ),
        (
            lambda data: data["checks"]["eai14-16"]["assertions"].update(
                sentinel_absent_from_all_surfaces=False
            ),
            "operator_evidence_invalid",
        ),
        (lambda data: data["checks"]["eai14-09"]["artifacts"].pop(), "operator_evidence_invalid"),
        (
            lambda data: data["checks"]["eai14-07"]["artifacts"][0].update(path="../proof.png"),
            "operator_evidence_invalid",
        ),
    ],
)
def test_operator_workflow_rejects_unbound_or_incomplete_evidence(tmp_path, mutate, reason):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    operator_root = tmp_path / "operator-evidence"
    operator_root.mkdir(mode=0o700)
    png = operator_root / "proof.png"
    png.write_bytes(png_1x1())
    comparison = operator_root / "comparison.md"
    comparison.write_text("high_rtt server_wait midstream reviewed", encoding="utf-8")
    reports = []
    for case_id in ("high_rtt", "server_wait", "midstream"):
        report = operator_root / f"{case_id}.json"
        report.write_text(json.dumps(operator_case_report(case_id, identity)))
        reports.append(report)
    native_reports = {}
    for check_id in ("eai14-10", "eai14-14", "eai14-16"):
        report = operator_root / f"{check_id}.json"
        report.write_text(json.dumps(operator_native_report(check_id, identity)))
        native_reports[check_id] = report

    def item(path, kind):
        return {
            "path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "media_type": kind,
        }

    manifest = {
        "schema_version": 1,
        "candidate_identity_sha256": identity["candidate_identity_sha256"],
        "operator": "operator",
        "attestation": qualification.OPERATOR_ATTESTATION,
        "checks": {
            "eai14-07": {
                "status": "PASS",
                "assertions": {"ready_visible": True},
                "artifacts": [item(png, "image/png")],
            },
            "eai14-08": {
                "status": "PASS",
                "assertions": {
                    "cases": ["high_rtt", "server_wait", "midstream"],
                    "comparison_reviewed": True,
                    "traceability_and_uncertainty_retained": True,
                },
                "artifacts": [
                    item(comparison, "text/markdown"),
                    *[item(p, "application/json") for p in reports],
                ],
            },
            "eai14-09": {
                "status": "PASS",
                "assertions": {
                    "full_capture_action_opened": True,
                    "evidence_capture_action_opened": True,
                },
                "artifacts": [item(png, "image/png"), item(png, "image/png")],
            },
            "eai14-10": {
                "status": "PASS",
                "assertions": qualification.OPERATOR_ASSERTIONS["eai14-10"],
                "artifacts": [item(native_reports["eai14-10"], "application/json")],
            },
            "eai14-14": {
                "status": "PASS",
                "assertions": qualification.OPERATOR_ASSERTIONS["eai14-14"],
                "artifacts": [item(native_reports["eai14-14"], "application/json")],
            },
            "eai14-16": {
                "status": "PASS",
                "assertions": qualification.OPERATOR_ASSERTIONS["eai14-16"],
                "artifacts": [item(native_reports["eai14-16"], "application/json")],
            },
        },
    }
    mutate(manifest)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    results = qualification.empty_results(identity)
    with pytest.raises(ValueError, match=reason):
        qualification.collect_operator_evidence(
            bundle, identity, operator_root, evidence_root, results, manifest=manifest
        )
    assert list(evidence_root.iterdir()) == []


def test_operator_screenshot_png_crc_is_validated_and_not_visually_claimed(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    operator_root = tmp_path / "operator-evidence"
    evidence_root = tmp_path / "evidence"
    operator_root.mkdir(mode=0o700)
    evidence_root.mkdir(mode=0o700)
    malformed = bytearray(png_1x1())
    malformed[-1] ^= 0x01
    source = operator_root / "screenshot.png"
    source.write_bytes(malformed)
    artifact = {
        "path": source.name,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "media_type": "image/png",
    }
    with pytest.raises(ValueError, match="operator_evidence_invalid"):
        qualification._operator_artifact(
            operator_root, evidence_root, "eai14-07", artifact, identity
        )


def test_validation_rejects_operator_pass_without_fixed_attachment_set(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    results = qualification.empty_results(identity)
    row = results["eai14"][6]
    row["status"] = "PASS"
    row["not_run_reason"] = None
    row["evidence"] = [{"path": "fake.json", "sha256": "a" * 64}]
    with pytest.raises(ValueError, match="qualification_evidence_missing"):
        qualification.validate_results(results, identity)


def test_candidate_identity_checks_model_and_helper_hashes_against_bytes(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    metadata_path = bundle / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["signed_app"]["llama_server_sha256"] = "f" * 64
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as stream:
        stream.add(bundle, arcname=".")
    with pytest.raises(ValueError, match="candidate_release_artifact_identity_mismatch"):
        qualification.candidate_identity(bundle, archive)


def test_destructive_fixture_must_be_isolated_from_candidate_and_temp_root(tmp_path):
    qualification = qualification_module()
    bundle, _ = candidate_fixture(tmp_path)
    temp_root = tmp_path / "qualification-tmp"
    temp_root.mkdir(mode=0o700)
    fixture = qualification.copy_destructive_fixture(bundle, temp_root, "tamper")
    qualification.validate_destructive_fixture(bundle, fixture, temp_root)
    with pytest.raises(ValueError, match="destructive_fixture_not_isolated"):
        qualification.validate_destructive_fixture(bundle, bundle, temp_root)
    outside = tmp_path / "outside-fixture"
    outside.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="destructive_fixture_not_isolated"):
        qualification.validate_destructive_fixture(bundle, outside, temp_root)
    copied_model = fixture / "bundle/ai/WireclawAI.app/Contents/Resources/ai/model.gguf"
    copied_model.write_bytes(b"tampered fixture")
    assert (bundle / "ai/WireclawAI.app/Contents/Resources/ai/model.gguf").read_bytes() == b"model"


def test_evidence_is_written_per_check_without_mutating_candidate(tmp_path):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    identity = qualification.candidate_identity(bundle, archive)
    results = qualification.empty_results(identity)
    output = tmp_path / "qualification-output"
    qualification.write_evidence(results, output)
    assert (output / "eai14/eai14-01.json").is_file()
    assert (output / "sandbox/exact_parent_helper_entitlements.json").is_file()
    assert (output / "qualification.json").is_file()
    assert qualification.candidate_identity(bundle, archive) == identity
    with pytest.raises(ValueError, match="qualification_output_exists"):
        qualification.write_evidence(results, output)


def test_signing_status_does_not_promote_adhoc_to_production_pass(tmp_path):
    qualification = qualification_module()
    bundle, _ = candidate_fixture(tmp_path)
    status = qualification.signing_status(bundle)
    assert status == {
        "development_signing": "PASS",
        "hardened_runtime_production": "NOT_RUN",
        "developer_id": "NOT_RUN",
        "production_qualification": "NOT_RUN",
        "notarization": "NOT_RUN",
        "stapling": "NOT_RUN",
    }
    metadata_path = bundle / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["signed_app"]["production_qualification"] = "PASS"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="adhoc_signing_status_invalid"):
        qualification.signing_status(bundle)


def test_developer_id_without_notarization_credentials_stays_not_run(tmp_path):
    qualification = qualification_module()
    bundle, _ = candidate_fixture(tmp_path)
    metadata_path = bundle / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["signed_app"].update(
        {
            "signing_mode": "developer-id",
            "signing_identity": "Developer ID Application: Example (TEAM)",
            "hardened_runtime": True,
            "developer_id_validation": "PASS",
        }
    )
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    assert qualification.signing_status(bundle) == {
        "development_signing": "NOT_RUN",
        "hardened_runtime_production": "PASS",
        "developer_id": "PASS",
        "production_qualification": "NOT_RUN",
        "notarization": "NOT_RUN",
        "stapling": "NOT_RUN",
    }


@pytest.mark.parametrize("forged_field", ("production_qualification", "notarization", "stapling"))
def test_developer_id_metadata_cannot_forge_release_qualification(tmp_path, forged_field):
    qualification = qualification_module()
    bundle, _ = candidate_fixture(tmp_path)
    metadata_path = bundle / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["signed_app"].update(
        {
            "signing_mode": "developer-id",
            "signing_identity": "Developer ID Application: Example (TEAM)",
            "hardened_runtime": True,
            "developer_id_validation": "PASS",
        }
    )
    metadata["signed_app"][forged_field] = "PASS"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    status = qualification.signing_status(bundle)
    assert status[forged_field] == "NOT_RUN"
    assert status["production_qualification"] == "NOT_RUN"


def test_production_qualification_is_derived_from_complete_candidate_check_evidence(
    tmp_path,
):
    qualification = qualification_module()
    bundle, archive = candidate_fixture(tmp_path)
    metadata_path = bundle / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["signed_app"].update(
        {
            "signing_mode": "developer-id",
            "signing_identity": "Developer ID Application: Example (TEAM)",
            "hardened_runtime": True,
            "developer_id_validation": "PASS",
            "production_qualification": "PASS",
        }
    )
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    archive.unlink()
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as stream:
        stream.add(bundle, arcname=".")
    identity = qualification.candidate_identity(bundle, archive)
    results = qualification.empty_results(identity)
    assert results["signing_status"]["production_qualification"] == "NOT_RUN"
    for section in ("eai14", "sandbox"):
        for row in results[section]:
            row["status"] = "PASS"
            row["evidence"] = [{"path": "evidence.json", "sha256": "b" * 64}]
    status = qualification.signing_status_from_identity(identity, results)
    assert status["production_qualification"] == "NOT_RUN"
    assert status["notarization"] == "NOT_RUN"
    assert status["stapling"] == "NOT_RUN"


def test_task10_check_observations_are_narrowly_mapped_to_candidate_evidence():
    qualification = qualification_module()
    identity_sha = "a" * 64
    persistence = qualification.task10_observations_for_check(
        "eai14-12",
        {
            "candidate_identity_sha256": identity_sha,
            "private_candidate_copy": True,
            "compose_project_name": "wireclaw-qualification-a1b2c3d4e5f6",
            "copy_path_contains_spaces": True,
            "private_case_sentinel_preserved": True,
            "task10_start_status_stop_runs": 2,
            "task10_restart": "PASS",
        },
    )
    assert persistence == {
        "candidate_identity_sha256": identity_sha,
        "private_case_sentinel_preserved": True,
        "task10_start_status_stop_runs": 2,
        "task10_restart": "PASS",
    }
    path_spaces = qualification.task10_observations_for_check(
        "eai14-13",
        {
            "candidate_identity_sha256": identity_sha,
            "private_candidate_copy": True,
            "compose_project_name": "wireclaw-qualification-a1b2c3d4e5f6",
            "copy_path_contains_spaces": True,
            "private_case_sentinel_preserved": True,
            "task10_start_status_stop_runs": 2,
            "task10_restart": "PASS",
        },
    )
    assert path_spaces == {
        "candidate_identity_sha256": identity_sha,
        "private_candidate_copy": True,
        "compose_project_name": "wireclaw-qualification-a1b2c3d4e5f6",
        "copy_path_contains_spaces": True,
        "task10_start_status_stop_runs": 2,
    }


def test_candidate_freeze_records_signed_app_and_bundle_identity(tmp_path):
    freezer_path = ROOT / "scripts/freeze_embedded_ai_candidate.py"
    spec = importlib.util.spec_from_file_location("candidate_freezer_identity", freezer_path)
    assert spec is not None and spec.loader is not None
    freezer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(freezer)
    bundle, archive = candidate_fixture(tmp_path)
    archive.unlink()
    result = freezer.freeze_candidate(bundle, archive, codesign_runner=ad_hoc_codesign_runner)
    assert result["signed_app"]["bundle_identifier"] == "com.wireclaw.WireclawAI"
    assert result["signed_app"]["signing_mode"] == "adhoc"
    assert len(result["signed_app"]["bundle_tree_sha256"]) == 64
    assert len(result["signed_app"]["signed_code"]) == 3
    qualification = qualification_module()
    identity = qualification.candidate_identity(bundle, archive)
    qualification.validate_frozen_metadata(result, identity)
    frozen_identity = qualification.candidate_identity(bundle, archive, frozen_metadata=result)
    assert frozen_identity["freeze_metadata_sha256"]
    assert frozen_identity["signed_app"]["signed_code"][0]["signature"] == "adhoc"
    qualification.validate_frozen_metadata(result, frozen_identity)
    qualification.verify_frozen_signatures(
        bundle, frozen_identity, codesign_runner=ad_hoc_codesign_runner
    )

    def substituted_identity(argv, **kwargs):
        details = ad_hoc_codesign_runner(argv, **kwargs)
        if "-dv" in argv and Path(argv[-1]).name == "llama-server":
            details.stderr = details.stderr.replace("Identifier=llama-server", "Identifier=wrong")
        return details

    with pytest.raises(ValueError, match="candidate_signed_code_identity_mismatch"):
        qualification.verify_frozen_signatures(
            bundle, frozen_identity, codesign_runner=substituted_identity
        )


def test_candidate_freeze_rejects_false_development_signing_status(tmp_path):
    freezer_path = ROOT / "scripts/freeze_embedded_ai_candidate.py"
    freezer = module_at(freezer_path, "candidate_freezer_signing_status")
    bundle, archive = candidate_fixture(tmp_path)
    archive.unlink()
    metadata_path = bundle / "release-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["signed_app"]["hardened_runtime"] = True
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="candidate_signing_status_invalid"):
        freezer.freeze_candidate(bundle, archive, codesign_runner=ad_hoc_codesign_runner)
