#!/usr/bin/env python3
"""Build and validate per-check native EAI.14 evidence for one frozen candidate.

This tool records operator/native-runner evidence; it never marks an unperformed
check PASS. The live acceptance checks are intentionally opt-in and must be run
against a frozen candidate after exact-head CI.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs/post-v1/embedded-local-ai.md"
STATUSES = {"PASS", "FAIL", "BLOCKED", "NOT_RUN"}

EAI14_CHECKS = (
    ("eai14-01", "no separately installed model runtime is required"),
    ("eai14-02", "no network model download occurs on first normal launch"),
    ("eai14-03", "packaged model/runtime hashes match release metadata"),
    ("eai14-04", "launcher starts embedded AI automatically"),
    ("eai14-05", "Metal/native runtime identity is recorded"),
    ("eai14-06", "Docker core reaches the loopback-only AI service through the approved host path"),
    ("eai14-07", "UI reports Local embedded AI ready"),
    ("eai14-08", "representative AI-assisted cases complete and retain valid evidence links"),
    ("eai14-09", "Full Capture and Evidence Capture native Wireshark actions still work"),
    ("eai14-10", "stopping the AI process causes safe rules-only degradation"),
    ("eai14-11", "restarting restores embedded AI without case corruption"),
    ("eai14-12", "stop/start preserves cases and model assets"),
    ("eai14-13", "paths containing spaces are accepted"),
    ("eai14-14", "port-conflict and hash-tamper cases degrade safely"),
    ("eai14-15", "no LAN listener exists for the model or application"),
    ("eai14-16", "accepted privacy/security sentinel checks pass"),
)

# Security isolation checks required by the approved sandbox design, recorded
# independently from the product-level EAI.14 acceptance checks.
SANDBOX_CHECKS = (
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
UNAVAILABLE_CHECKS = {}
OPERATOR_CHECKS = (
    "eai14-07",
    "eai14-08",
    "eai14-09",
    "eai14-10",
    "eai14-14",
    "eai14-16",
)
OPERATOR_ATTESTATION = "I performed these native checks against the identified candidate and reviewed each attached artifact."
OPERATOR_PROCEDURE = {
    "eai14-07": "Launch the frozen candidate normally; capture a screenshot showing Local embedded AI ready.",
    "eai14-08": "Run high_rtt, server_wait, and midstream through the frozen app; attach each bounded report with valid evidence links and a human-reviewed none-versus-embedded_local comparison covering ranking, explanation, traceability, and uncertainty.",
    "eai14-09": "From representative findings, activate both Open Full Capture in Wireshark and Open Evidence Capture in Wireshark; attach one screenshot for each opened capture.",
    "eai14-10": "Use a private candidate copy and unique Compose project. Start normally, verify the host receipt/helper identity, then invoke only the trusted launch/macos/ai_lifecycle.py stop operation with that exact receipt and helper path while leaving Core running. Confirm a representative analysis completes in rules-only mode, restart through the normal launcher, and attach the candidate-bound JSON receipt. Never signal a PID manually.",
    "eai14-14": "Use two private candidate copies and unique Compose projects. In one, create a disposable loopback-only listener on 127.0.0.1:8767 to force the AI port conflict. In the other, alter only the copied model bytes to force integrity failure. Confirm each launch degrades to deterministic analysis, the original frozen bundle/archive hashes stay unchanged, no non-loopback listener appears, and case data remains. Attach the candidate-bound JSON receipt; never attach credentials.",
    "eai14-16": "Run the approved privacy sentinel against the frozen candidate; inspect prompt/context, API responses, case database, runtime logs, Core logs, browser/public status, and reports. Attach a candidate-bound JSON receipt with only the synthetic sentinel ID and the exact reviewed surfaces; never attach credential values.",
}
OPERATOR_ASSERTIONS = {
    "eai14-07": {"ready_visible": True},
    "eai14-08": {
        "cases": ["high_rtt", "server_wait", "midstream"],
        "comparison_reviewed": True,
        "traceability_and_uncertainty_retained": True,
    },
    "eai14-09": {
        "full_capture_action_opened": True,
        "evidence_capture_action_opened": True,
    },
    "eai14-10": {
        "managed_helper_stopped_via_verified_host_primitive": True,
        "rules_only_analysis_completed": True,
        "safe_restart_succeeded": True,
        "case_data_preserved": True,
    },
    "eai14-14": {
        "port_conflict_fallback_completed": True,
        "model_hash_tamper_fallback_completed": True,
        "original_candidate_unchanged": True,
        "loopback_only": True,
        "case_data_preserved": True,
    },
    "eai14-16": {
        "synthetic_sentinel_injected": True,
        "required_surfaces_reviewed": True,
        "sentinel_absent_from_all_surfaces": True,
    },
}

FIXED_HANDLERS = {
    "eai14-01": "task10_packaged_launch",
    "eai14-02": "verify_no_startup_download_path",
    "eai14-03": "verify_packaged_runtime_hashes",
    "eai14-04": "task10_packaged_launch",
    "eai14-05": "task10_metal_inference",
    "eai14-06": "task10_core_reachability",
    "eai14-11": "task10_restart_preservation",
    "eai14-12": "task10_candidate_copy_restart_preservation",
    "eai14-13": "task10_candidate_copy_space_path",
    "eai14-15": "task10_loopback_listener",
    "eai14-07": "operator_attested_native_ui_evidence",
    "eai14-08": "operator_attested_corpus_comparison",
    "eai14-09": "operator_attested_native_wireshark_actions",
    "eai14-10": "operator_attested_candidate_rules_only_fallback",
    "eai14-14": "operator_attested_candidate_conflict_and_tamper_fallback",
    "eai14-16": "operator_attested_candidate_privacy_sentinel",
    "exact_parent_helper_entitlements": "verify_signed_sandbox_entitlements",
    "docker_engine_control_sockets_denied": "task9_native_sandbox_probe",
    "wireclaw_state_and_host_bridge_state_denied": "task9_native_sandbox_probe",
    "core_api_and_host_bridge_network_denied": "task9_native_sandbox_probe",
    "packaged_assets_and_bounded_private_writes": "task9_native_sandbox_probe",
    "secret_handoff_and_cleanup_boundary": "task9_native_sandbox_probe",
    "host_receipt_and_verified_signal_lifecycle": "task9_native_sandbox_probe",
    "fixed_loopback_listener_and_core_reachability": "task9_task10_native_probes",
    "vmnetd_informational_only": "verify_vmnetd_probe_boundary",
}

SOURCE_TESTS = {
    "eai14-02": (
        "tests/packaging/test_macos_launchers.py::test_start_loads_and_uses_the_packaged_image_without_rebuilding",
    ),
    "eai14-10": (
        "tests/packaging/test_macos_launchers.py::test_core_unhealthy_embedded_start_removes_key_and_retries_rules_only",
        "tests/packaging/test_macos_launchers.py::test_readiness_loss_uses_verified_stop_before_cleanup_and_falls_back",
        "tests/packaging/test_macos_launchers.py::test_wrapper_start_failure_falls_back_without_retaining_the_ephemeral_key",
    ),
    "eai14-12": (
        "tests/packaging/test_macos_launchers.py::test_stop_and_uninstall_preserve_case_data_and_ignore_reused_pid",
    ),
    "eai14-13": (
        "tests/packaging/test_macos_launchers.py::test_env_parser_handles_home_and_paths_with_spaces",
    ),
    "eai14-14": (
        "tests/packaging/test_macos_launchers.py::test_start_rejects_busy_ports_and_missing_configured_wireshark",
        "tests/packaging/test_embedded_ai_build.py::test_runtime_manifest_commit_or_resource_tamper_fails_closed",
        "tests/packaging/test_release_bundle_contract.py::test_native_qualification_fixture_contracts_reject_bad_provider_integration",
    ),
    "eai14-16": (
        "tests/acceptance/test_embedded_ai_contract.py::test_exact_embedded_provider_request_and_persisted_audit_exclude_private_sentinels",
        "tests/acceptance/test_embedded_ai_contract.py::test_api_responses_and_case_database_exclude_provider_credentials",
    ),
}

TASK10_CHECKS = (
    "eai14-01",
    "eai14-04",
    "eai14-05",
    "eai14-06",
    "eai14-11",
    "eai14-12",
    "eai14-13",
    "eai14-15",
)
TASK9_CHECKS = tuple(
    key for key, handler in FIXED_HANDLERS.items() if handler == "task9_native_sandbox_probe"
)
NATIVE_NOT_RUN_REASONS = {
    "native_host_required",
    "candidate_source_not_exact_head",
    "candidate_source_checkout_dirty",
    "native_probe_precondition_unmet",
    "native_probe_dependency_unavailable",
    "operator_evidence_missing",
    "existing_ai_private_state",
    "existing_wireclaw_lifecycle_state",
    "existing_ai_process",
    "existing_compose_state",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stream_sha256(stream, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(chunk_size), b""):
        digest.update(block)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("candidate_bundle_invalid")
    digest = hashlib.sha256()
    digest.update(b".\x00")
    digest.update(stat.S_IMODE(root.stat().st_mode).to_bytes(4, "big"))
    digest.update(b"D")
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("candidate_symlink_invalid")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        mode = stat.S_IMODE(path.stat().st_mode)
        digest.update(mode.to_bytes(4, "big"))
        if path.is_file():
            digest.update(b"F")
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        elif path.is_dir():
            digest.update(b"D")
        else:
            raise ValueError("candidate_file_type_invalid")
    return digest.hexdigest()


def verify_archive_matches_bundle(bundle: Path, archive: Path) -> None:
    """Require the frozen tar to contain precisely the current bundle bytes."""
    bundle = Path(bundle)
    expected = {
        path.relative_to(bundle).as_posix(): path
        for path in bundle.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    expected_directories = {
        path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_dir()
    }
    expected_modes = {
        path.relative_to(bundle).as_posix() or ".": stat.S_IMODE(path.stat().st_mode)
        for path in (bundle, *bundle.rglob("*"))
    }
    try:
        with tarfile.open(archive, "r:") as stream:
            members = stream.getmembers()
            actual_names = [member.name.rstrip("/") for member in members]
            if len(actual_names) != len(set(actual_names)):
                raise ValueError("candidate_archive_content_mismatch")
            actual = {}
            actual_directories = set()
            actual_modes = {}
            for member in members:
                name = member.name.rstrip("/")
                if not name:
                    raise ValueError("candidate_archive_content_mismatch")
                archive_path = Path(name)
                parts = archive_path.parts
                if parts and parts[0] == ".":
                    parts = parts[1:]
                if parts and parts[0] == bundle.name:
                    parts = parts[1:]
                path = Path(*parts) if parts else Path(".")
                relative_name = path.as_posix()
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError("candidate_archive_content_mismatch")
                expected_mode = expected_modes.get(relative_name)
                if expected_mode is None or member.mode != expected_mode:
                    raise ValueError("candidate_archive_content_mismatch")
                actual_modes[relative_name] = member.mode
                if member.isdir():
                    if path.parts:
                        actual_directories.add(relative_name)
                    continue
                local_file = expected.get(relative_name)
                if local_file is None or member.size != local_file.stat().st_size:
                    raise ValueError("candidate_archive_content_mismatch")
                extracted = stream.extractfile(member)
                if extracted is None:
                    raise ValueError("candidate_archive_content_mismatch")
                actual[relative_name] = _stream_sha256(extracted)
    except (OSError, tarfile.TarError, EOFError):
        raise ValueError("candidate_archive_content_mismatch") from None
    if (
        set(actual) != set(expected)
        or actual_directories != expected_directories
        or actual_modes != expected_modes
        or any(actual[name] != _sha256(path) for name, path in expected.items())
    ):
        raise ValueError("candidate_archive_content_mismatch")


def _release_metadata(bundle: Path) -> dict:
    try:
        value = json.loads((bundle / "release-metadata.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        raise ValueError("candidate_release_metadata_invalid") from None
    if not isinstance(value, dict):
        raise ValueError("candidate_release_metadata_invalid")
    return value


def _signed_code_identity(bundle: Path, app: Path, signed_app: dict) -> list[dict]:
    parent_entitlements = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.server": True,
    }
    helper_entitlements = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.inherit": True,
    }
    targets = [
        (app, parent_entitlements),
        (app / "Contents/MacOS/WireclawAI", parent_entitlements),
        (app / "Contents/MacOS/llama-server", helper_entitlements),
    ]
    frameworks = app / "Contents/Frameworks"
    if frameworks.exists():
        targets.extend(
            (path, None)
            for path in sorted(frameworks.rglob("*"))
            if path.is_file() and (path.suffix == ".dylib" or os.access(path, os.X_OK))
        )
    mode = signed_app.get("signing_mode")
    return [
        {
            "path": path.relative_to(bundle).as_posix(),
            "sha256": tree_sha256(path) if path == app else _sha256(path),
            "signing_identity": signed_app.get("signing_identity"),
            "signing_mode": mode,
            "hardened_runtime": mode == "developer-id",
            "entitlements_sha256": (
                hashlib.sha256(
                    json.dumps(entitlements, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                if entitlements is not None
                else None
            ),
        }
        for path, entitlements in targets
    ]


def candidate_identity(bundle: Path, archive: Path, *, frozen_metadata: dict | None = None) -> dict:
    """Calculate identity from actual bytes and signed-app release metadata."""
    bundle = Path(bundle)
    archive = Path(archive)
    if bundle.is_symlink() or archive.is_symlink() or not archive.is_file():
        raise ValueError("candidate_artifact_invalid")
    bundle = bundle.resolve(strict=True)
    archive = archive.resolve(strict=True)
    if bundle == archive or bundle in archive.parents or archive in bundle.parents:
        raise ValueError("candidate_artifact_overlap")
    verify_archive_matches_bundle(bundle, archive)
    metadata = _release_metadata(bundle)
    source_sha = metadata.get("source_sha")
    signed_app = metadata.get("signed_app")
    embedded_ai = metadata.get("embedded_ai")
    if (
        not isinstance(source_sha, str)
        or not re.fullmatch(r"[0-9a-f]{40}", source_sha)
        or not isinstance(signed_app, dict)
        or signed_app.get("path") != "ai/WireclawAI.app"
        or signed_app.get("bundle_identifier") != "com.wireclaw.WireclawAI"
        or not isinstance(embedded_ai, dict)
    ):
        raise ValueError("candidate_release_metadata_invalid")
    app = bundle / signed_app["path"]
    if app.is_symlink() or not app.is_dir():
        raise ValueError("candidate_signed_app_missing")
    for key in ("model_sha256", "llama_server_sha256"):
        if not isinstance(signed_app.get(key), str) or not re.fullmatch(
            r"[0-9a-f]{64}", signed_app[key]
        ):
            raise ValueError("candidate_release_metadata_invalid")
    model_path = app / "Contents/Resources/ai/model.gguf"
    helper_path = app / "Contents/MacOS/llama-server"
    if (
        model_path.is_symlink()
        or helper_path.is_symlink()
        or not model_path.is_file()
        or not helper_path.is_file()
        or _sha256(model_path) != signed_app["model_sha256"]
        or _sha256(helper_path) != signed_app["llama_server_sha256"]
    ):
        raise ValueError("candidate_release_artifact_identity_mismatch")
    app_identity = {
        "bundle_identifier": signed_app["bundle_identifier"],
        "signing_mode": signed_app.get("signing_mode"),
        "signing_identity": signed_app.get("signing_identity"),
        "hardened_runtime": signed_app.get("hardened_runtime"),
        "developer_id_validation": signed_app.get("developer_id_validation", "NOT_RUN"),
        # These are qualification results, not artifact identity. Ignore
        # release-metadata assertions; native evidence must establish them.
        "production_qualification": "NOT_RUN",
        "notarization": "NOT_RUN",
        "stapling": "NOT_RUN",
        "model_sha256": signed_app["model_sha256"],
        "llama_server_sha256": signed_app["llama_server_sha256"],
        "bundle_tree_sha256": tree_sha256(app),
        "signed_code": _signed_code_identity(bundle, app, signed_app),
    }
    if app_identity["signing_mode"] == "adhoc":
        if app_identity["hardened_runtime"] is not False or any(
            app_identity[key] != "NOT_RUN"
            for key in (
                "developer_id_validation",
                "production_qualification",
                "notarization",
                "stapling",
            )
        ):
            raise ValueError("adhoc_signing_status_invalid")
    elif app_identity["signing_mode"] == "developer-id":
        if app_identity["hardened_runtime"] is not True:
            raise ValueError("developer_id_signing_status_invalid")
    else:
        raise ValueError("candidate_signing_mode_invalid")
    frozen_metadata_sha256 = None
    if frozen_metadata is not None:
        validate_frozen_metadata(
            frozen_metadata,
            {
                "source_sha": source_sha,
                "bundle_tree_sha256": tree_sha256(bundle),
                "archive_sha256": _sha256(archive),
                "embedded_ai": embedded_ai,
                "signed_app": app_identity,
            },
        )
        app_identity["signed_code"] = frozen_metadata["signed_app"]["signed_code"]
        canonical_freeze = json.dumps(
            frozen_metadata, sort_keys=True, separators=(",", ":")
        ).encode()
        frozen_metadata_sha256 = hashlib.sha256(canonical_freeze).hexdigest()
    identity_body = {
        "source_sha": source_sha,
        "bundle_tree_sha256": tree_sha256(bundle),
        "archive_sha256": _sha256(archive),
        "signed_app": app_identity,
        "embedded_ai": embedded_ai,
        "freeze_metadata_sha256": frozen_metadata_sha256,
    }
    canonical = json.dumps(identity_body, sort_keys=True, separators=(",", ":")).encode()
    return {**identity_body, "candidate_identity_sha256": hashlib.sha256(canonical).hexdigest()}


def verify_candidate_unchanged(
    bundle: Path, archive: Path, before: dict, *, frozen_metadata: dict | None = None
) -> None:
    if tree_sha256(bundle) != before.get("bundle_tree_sha256"):
        raise ValueError("candidate_bundle_identity_mismatch")
    if _sha256(archive) != before.get("archive_sha256"):
        raise ValueError("candidate_archive_identity_mismatch")
    after = candidate_identity(bundle, archive, frozen_metadata=frozen_metadata)
    if after["bundle_tree_sha256"] != before.get("bundle_tree_sha256"):
        raise ValueError("candidate_bundle_identity_mismatch")
    if after["archive_sha256"] != before.get("archive_sha256"):
        raise ValueError("candidate_archive_identity_mismatch")
    if after["candidate_identity_sha256"] != before.get("candidate_identity_sha256"):
        raise ValueError("candidate_identity_mismatch")


def verify_frozen_signatures(
    bundle: Path, identity: dict, *, codesign_runner=subprocess.run
) -> None:
    """Recheck signatures, signer identity, runtime flags, and exact entitlements."""
    app = Path(bundle) / "ai/WireclawAI.app"
    signing_mode = identity["signed_app"]["signing_mode"]
    spec = importlib.util.spec_from_file_location(
        "wireclaw_native_signing_verifier", ROOT / "scripts/build_macos_ai_app.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("candidate_signature_verifier_unavailable")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    try:
        verifier.verify_signed_bundle(app, mode=signing_mode, runner=codesign_runner)
    except (OSError, ValueError, TypeError):
        raise ValueError("candidate_signature_invalid") from None

    bundle = Path(bundle).resolve(strict=True)
    for expected in identity["signed_app"].get("signed_code", []):
        relative = Path(expected.get("path", ""))
        target = bundle / relative
        if relative.is_absolute() or ".." in relative.parts or not target.exists():
            raise ValueError("candidate_signed_code_identity_mismatch")
        try:
            details = codesign_runner(
                ["/usr/bin/codesign", "-dv", "--verbose=4", str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            raise ValueError("candidate_signed_code_identity_mismatch") from None
        detail_text = details.stdout + details.stderr
        identifier = re.search(r"^Identifier=(.+)$", detail_text, flags=re.MULTILINE)
        authority = re.search(r"^Authority=(.+)$", detail_text, flags=re.MULTILINE)
        team = re.search(r"^TeamIdentifier=(.+)$", detail_text, flags=re.MULTILINE)
        signature = re.search(r"^Signature=(.+)$", detail_text, flags=re.MULTILINE)
        actual = {
            "identifier": identifier.group(1) if identifier else None,
            "authority": authority.group(1) if authority else None,
            "team_id": team.group(1) if team else None,
            "signature": signature.group(1) if signature else None,
        }
        if details.returncode or any(actual[key] != expected.get(key) for key in actual):
            raise ValueError("candidate_signed_code_identity_mismatch")


def signing_status(bundle: Path) -> dict:
    metadata = _release_metadata(Path(bundle))
    signed = metadata.get("signed_app")
    if not isinstance(signed, dict):
        raise ValueError("candidate_release_metadata_invalid")
    mode = signed.get("signing_mode")
    if mode == "adhoc":
        if signed.get("hardened_runtime") is not False:
            raise ValueError("adhoc_signing_status_invalid")
        if any(
            signed.get(key, "NOT_RUN") != "NOT_RUN"
            for key in (
                "developer_id_validation",
                "production_qualification",
                "notarization",
                "stapling",
            )
        ):
            raise ValueError("adhoc_signing_status_invalid")
        return {
            "development_signing": "PASS",
            "hardened_runtime_production": "NOT_RUN",
            "developer_id": "NOT_RUN",
            "production_qualification": "NOT_RUN",
            "notarization": "NOT_RUN",
            "stapling": "NOT_RUN",
        }
    if mode == "developer-id":
        developer_id = signed.get("developer_id_validation", "NOT_RUN")
        return {
            "development_signing": "NOT_RUN",
            "hardened_runtime_production": "PASS"
            if signed.get("hardened_runtime") is True and developer_id == "PASS"
            else "NOT_RUN",
            "developer_id": developer_id,
            "production_qualification": "NOT_RUN",
            "notarization": "NOT_RUN",
            "stapling": "NOT_RUN",
        }
    raise ValueError("candidate_signing_mode_invalid")


def signing_status_from_identity(identity: dict, results: dict | None = None) -> dict:
    """Derive statuses from artifact identity and completed qualification rows."""
    signed = identity.get("signed_app")
    if not isinstance(signed, dict):
        raise ValueError("candidate_signing_mode_invalid")
    mode = signed.get("signing_mode")
    if mode == "adhoc":
        return {
            "development_signing": "PASS",
            "hardened_runtime_production": "NOT_RUN",
            "developer_id": "NOT_RUN",
            "production_qualification": "NOT_RUN",
            "notarization": "NOT_RUN",
            "stapling": "NOT_RUN",
        }
    if mode == "developer-id":
        developer_id = signed.get("developer_id_validation", "NOT_RUN")
        checks_complete = bool(results) and all(
            isinstance(row, dict)
            and row.get("status") == "PASS"
            and bool(row.get("evidence"))
            and row.get("candidate_identity_sha256") == identity.get("candidate_identity_sha256")
            for section in ("eai14", "sandbox")
            for row in results.get(section, [])
        )
        notarization = "NOT_RUN"
        stapling = "NOT_RUN"
        production_gates = results.get("production_release_gates") if results else None
        production = (
            "PASS"
            if checks_complete
            and signed.get("hardened_runtime") is True
            and developer_id == "PASS"
            and production_gates
            == {
                "notarization": "PASS",
                "stapling": "PASS",
                "official_benchmark": "PASS",
            }
            else "NOT_RUN"
        )
        return {
            "development_signing": "NOT_RUN",
            "hardened_runtime_production": "PASS"
            if signed.get("hardened_runtime") is True and developer_id == "PASS"
            else "NOT_RUN",
            "developer_id": developer_id,
            "production_qualification": production,
            "notarization": notarization,
            "stapling": stapling,
        }
    raise ValueError("candidate_signing_mode_invalid")


def _result(check_id: str, title: str, identity: dict) -> dict:
    handler = FIXED_HANDLERS.get(check_id)
    return {
        "id": check_id,
        "title": title,
        "status": "NOT_RUN",
        "handler": handler or "unavailable",
        "not_run_reason": (
            "handler_not_executed"
            if handler
            else UNAVAILABLE_CHECKS.get(check_id, "fixed_native_handler_unavailable")
        ),
        "candidate_identity_sha256": identity["candidate_identity_sha256"],
        "evidence": [],
    }


def empty_results(identity: dict) -> dict:
    return {
        "schema_version": 1,
        "candidate_identity": identity,
        "qualification_host": {"os": sys.platform, "architecture": platform.machine()},
        "signing_status": signing_status_from_identity(identity),
        "eai14": [_result(*check, identity) for check in EAI14_CHECKS],
        "sandbox": [_result(check, check, identity) for check in SANDBOX_CHECKS],
    }


def task10_observations_for_check(check_id: str, observations: dict) -> dict:
    """Limit packaged-runner evidence to facts observed for the named check."""
    if check_id == "eai14-12":
        fields = (
            "candidate_identity_sha256",
            "private_case_sentinel_preserved",
            "task10_start_status_stop_runs",
            "task10_restart",
        )
    elif check_id == "eai14-13":
        fields = (
            "candidate_identity_sha256",
            "private_candidate_copy",
            "copy_path_contains_spaces",
            "task10_start_status_stop_runs",
        )
    else:
        fields = tuple(observations)
    return {field: observations[field] for field in fields if field in observations}


def _record_handler_evidence(
    root: Path,
    section: str,
    row: dict,
    identity: dict,
    observations: dict,
    handler: str,
    *,
    status: str = "PASS",
) -> None:
    evidence_path = Path(section) / f"{row['id']}.json"
    target = root / evidence_path
    _write_json(
        target,
        {
            "schema_version": 1,
            "check_id": row["id"],
            "candidate_identity_sha256": identity["candidate_identity_sha256"],
            "handler": handler,
            "status": status,
            "observations": observations,
        },
    )
    row["status"] = status
    row["handler"] = handler
    row["not_run_reason"] = None
    source_evidence = [
        item
        for item in row.get("evidence", [])
        if isinstance(item, dict) and item.get("path", "").startswith("source-regressions/")
    ]
    row["evidence"] = [
        *source_evidence,
        {"path": evidence_path.as_posix(), "sha256": _sha256(target)},
    ]


def _operator_artifact(
    operator_root: Path,
    evidence_root: Path,
    check_id: str,
    artifact: dict,
    identity: dict,
) -> dict:
    if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "media_type"}:
        raise ValueError("operator_evidence_invalid")
    relative = Path(artifact.get("path", ""))
    if (
        not relative.parts
        or relative.is_absolute()
        or ".." in relative.parts
        or len(relative.as_posix()) > 180
        or not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", "")))
    ):
        raise ValueError("operator_evidence_invalid")
    source = operator_root / relative
    try:
        resolved_root = operator_root.resolve(strict=True)
        resolved = source.resolve(strict=True)
    except OSError:
        raise ValueError("operator_evidence_invalid") from None
    if (
        source.is_symlink()
        or any(
            part.is_symlink() for part in (source, *source.parents) if part != operator_root.parent
        )
        or resolved_root not in resolved.parents
        or not resolved.is_file()
        or resolved.stat().st_size <= 0
        or resolved.stat().st_size > 8 * 1024 * 1024
        or _sha256(resolved) != artifact["sha256"]
    ):
        raise ValueError("operator_evidence_invalid")
    media_type = artifact["media_type"]
    content = resolved.read_bytes()
    if media_type == "image/png":
        _validate_operator_png(content)
    elif media_type == "application/json":
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, UnicodeError):
            raise ValueError("operator_evidence_invalid") from None
        expected_case = relative.stem
        if check_id in {"eai14-10", "eai14-14", "eai14-16"}:
            common = {
                "schema_version",
                "candidate_identity_sha256",
                "model_sha256",
                "llama_server_sha256",
                "provider_mode",
                "scenario_id",
            }
            special_fields = {
                "eai14-10": {
                    "managed_helper_stopped_via_verified_host_primitive",
                    "rules_only_analysis_completed",
                    "safe_restart_succeeded",
                    "case_data_preserved",
                },
                "eai14-14": {
                    "port_conflict_fallback_completed",
                    "model_hash_tamper_fallback_completed",
                    "original_candidate_unchanged",
                    "loopback_only",
                    "case_data_preserved",
                },
                "eai14-16": {
                    "reviewed_surfaces",
                    "sentinel_absent_from_all_surfaces",
                },
            }[check_id]
            exact_values = {
                "eai14-10": {
                    "managed_helper_stopped_via_verified_host_primitive": True,
                    "rules_only_analysis_completed": True,
                    "safe_restart_succeeded": True,
                    "case_data_preserved": True,
                },
                "eai14-14": {
                    "port_conflict_fallback_completed": True,
                    "model_hash_tamper_fallback_completed": True,
                    "original_candidate_unchanged": True,
                    "loopback_only": True,
                    "case_data_preserved": True,
                },
                "eai14-16": {
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
            }[check_id]
            expected_scenario = {
                "eai14-10": r"wireclaw-eai14-10-[0-9a-f]{16}",
                "eai14-14": r"wireclaw-eai14-14-[0-9a-f]{16}",
                "eai14-16": r"wireclaw-privacy-[0-9a-f]{16}",
            }[check_id]
            if (
                not isinstance(payload, dict)
                or set(payload) != common | special_fields
                or type(payload.get("schema_version")) is not int
                or payload.get("schema_version") != 1
                or payload.get("candidate_identity_sha256") != identity["candidate_identity_sha256"]
                or payload.get("model_sha256") != identity["signed_app"]["model_sha256"]
                or payload.get("llama_server_sha256")
                != identity["signed_app"]["llama_server_sha256"]
                or payload.get("provider_mode") != "embedded_local"
                or not re.fullmatch(expected_scenario, str(payload.get("scenario_id", "")))
                or any(payload.get(key) != value for key, value in exact_values.items())
            ):
                raise ValueError("operator_evidence_invalid")
        if check_id == "eai14-16":
            expected_case = "privacy-sentinel"
        required_case_fields = {
            "schema_version",
            "case_id",
            "candidate_identity_sha256",
            "model_sha256",
            "llama_server_sha256",
            "provider_mode",
            "original_capture_sha256_before",
            "original_capture_sha256_after",
            "evidence_ids",
            "findings",
        }
        evidence_ids = payload.get("evidence_ids") if isinstance(payload, dict) else None
        findings = payload.get("findings") if isinstance(payload, dict) else None
        if check_id not in {"eai14-10", "eai14-14", "eai14-16"} and (
            (
                check_id != "eai14-16"
                and expected_case not in {"high_rtt", "server_wait", "midstream"}
            )
            or not isinstance(payload, dict)
            or set(payload) != required_case_fields
            or type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != 1
            or payload.get("case_id") != expected_case
            or payload.get("candidate_identity_sha256") != identity["candidate_identity_sha256"]
            or payload.get("model_sha256") != identity["signed_app"]["model_sha256"]
            or payload.get("llama_server_sha256") != identity["signed_app"]["llama_server_sha256"]
            or payload.get("provider_mode") != "embedded_local"
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(payload.get("original_capture_sha256_before", ""))
            )
            or payload.get("original_capture_sha256_before")
            != payload.get("original_capture_sha256_after")
            or not isinstance(evidence_ids, list)
            or not evidence_ids
            or len(evidence_ids) > 128
            or any(
                not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item)
                for item in evidence_ids
            )
            or len(set(evidence_ids)) != len(evidence_ids)
            or not isinstance(findings, list)
            or not findings
            or len(findings) > 128
            or any(
                not isinstance(finding, dict)
                or set(finding) != {"finding_id", "evidence_ids"}
                or not isinstance(finding["finding_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", finding["finding_id"])
                or not isinstance(finding["evidence_ids"], list)
                or not finding["evidence_ids"]
                or any(item not in evidence_ids for item in finding["evidence_ids"])
                for finding in findings
            )
        ):
            raise ValueError("operator_evidence_invalid")
    elif media_type == "text/markdown":
        try:
            text = content.decode("utf-8")
        except UnicodeError:
            raise ValueError("operator_evidence_invalid") from None
        if (
            len(text) > 64 * 1024
            or not all(case in text for case in ("high_rtt", "server_wait", "midstream"))
            or not re.search(r"traceability", text, re.IGNORECASE)
            or not re.search(r"uncertainty", text, re.IGNORECASE)
            or re.search(r"(?:WIRECLAW_PROVIDER_API_KEY=|Bearer\s+|bridge[_ -]?token)", text, re.I)
        ):
            raise ValueError("operator_evidence_invalid")
    else:
        raise ValueError("operator_evidence_invalid")
    destination_relative = Path("operator") / check_id / relative.name
    destination = evidence_root / destination_relative
    if destination.exists() or destination.is_symlink():
        raise ValueError("operator_evidence_invalid")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copyfile(resolved, destination)
    destination.chmod(0o600)
    return {"path": destination_relative.as_posix(), "sha256": _sha256(destination)}


def _validate_operator_png(content: bytes) -> None:
    """Validate bounded PNG framing/CRCs; pixel meaning remains operator-attested."""
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("operator_evidence_invalid")
    offset = 8
    saw_ihdr = False
    saw_idat = False
    saw_iend = False
    width = height = bit_depth = color_type = 0
    compressed = bytearray()
    while offset < len(content):
        if len(content) - offset < 12:
            raise ValueError("operator_evidence_invalid")
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        kind = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        if length > 8 * 1024 * 1024 or end > len(content):
            raise ValueError("operator_evidence_invalid")
        payload = content[offset + 8 : offset + 8 + length]
        crc = struct.unpack(">I", content[offset + 8 + length : end])[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != crc:
            raise ValueError("operator_evidence_invalid")
        if not saw_ihdr:
            if kind != b"IHDR" or length != 13:
                raise ValueError("operator_evidence_invalid")
            width, height = struct.unpack(">II", payload[:8])
            if not 1 <= width <= 16384 or not 1 <= height <= 16384 or width * height > 16_777_216:
                raise ValueError("operator_evidence_invalid")
            bit_depth, color_type = payload[8], payload[9]
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                bit_depth not in valid_depths.get(color_type, set())
                or payload[10] != 0
                or payload[11] != 0
                or payload[12] != 0
            ):
                raise ValueError("operator_evidence_invalid")
            saw_ihdr = True
        elif kind == b"IDAT":
            saw_idat = True
            compressed.extend(payload)
        elif kind == b"IEND":
            if length != 0 or not saw_idat or end != len(content):
                raise ValueError("operator_evidence_invalid")
            saw_iend = True
            break
        offset = end
    if not saw_ihdr or not saw_idat or not saw_iend:
        raise ValueError("operator_evidence_invalid")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    expected_bytes = ((width * channels * bit_depth + 7) // 8 + 1) * height
    if expected_bytes > 64 * 1024 * 1024:
        raise ValueError("operator_evidence_invalid")
    try:
        inflater = zlib.decompressobj()
        decoded = inflater.decompress(bytes(compressed), expected_bytes + 1)
    except zlib.error:
        raise ValueError("operator_evidence_invalid") from None
    if (
        len(decoded) != expected_bytes
        or not inflater.eof
        or inflater.unconsumed_tail
        or inflater.unused_data
    ):
        raise ValueError("operator_evidence_invalid")


def collect_operator_evidence(
    bundle: Path,
    identity: dict,
    operator_root: Path,
    evidence_root: Path,
    results: dict,
    *,
    manifest: dict | None = None,
) -> None:
    """Collect strict, candidate-bound attestations for the three manual UI checks."""
    operator_root = Path(operator_root)
    evidence_root = Path(evidence_root)
    if operator_root.is_symlink() or not operator_root.is_dir():
        raise ValueError("operator_evidence_invalid")
    resolved_operator = operator_root.resolve(strict=True)
    resolved_evidence = evidence_root.resolve(strict=True)
    resolved_bundle = Path(bundle).resolve(strict=True)
    if (
        resolved_operator in (resolved_bundle, *resolved_bundle.parents)
        or resolved_bundle in resolved_operator.parents
    ):
        raise ValueError("operator_evidence_invalid")
    if (
        resolved_operator in resolved_evidence.parents
        or resolved_evidence in resolved_operator.parents
    ):
        raise ValueError("operator_evidence_invalid")
    if manifest is None:
        manifest_path = operator_root / "manifest.json"
        if (
            manifest_path.is_symlink()
            or not manifest_path.is_file()
            or manifest_path.stat().st_size > 64 * 1024
        ):
            raise ValueError("operator_evidence_invalid")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ValueError("operator_evidence_invalid") from None
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {"schema_version", "candidate_identity_sha256", "operator", "attestation", "checks"}
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
        or manifest.get("candidate_identity_sha256") != identity["candidate_identity_sha256"]
        or not isinstance(manifest.get("operator"), str)
        or not re.fullmatch(r"[A-Za-z0-9 ._@-]{1,80}", manifest["operator"])
        or manifest.get("attestation") != OPERATOR_ATTESTATION
        or not isinstance(manifest.get("checks"), dict)
        or set(manifest["checks"]) != set(OPERATOR_CHECKS)
    ):
        raise ValueError(
            "candidate_identity_mismatch"
            if isinstance(manifest, dict)
            and manifest.get("candidate_identity_sha256") != identity["candidate_identity_sha256"]
            else "operator_evidence_invalid"
        )
    expected_assertions = {
        "eai14-07": {"ready_visible": True},
        "eai14-08": {
            "cases": ["high_rtt", "server_wait", "midstream"],
            "comparison_reviewed": True,
            "traceability_and_uncertainty_retained": True,
        },
        "eai14-09": {
            "full_capture_action_opened": True,
            "evidence_capture_action_opened": True,
        },
        "eai14-10": {
            "managed_helper_stopped_via_verified_host_primitive": True,
            "rules_only_analysis_completed": True,
            "safe_restart_succeeded": True,
            "case_data_preserved": True,
        },
        "eai14-14": {
            "port_conflict_fallback_completed": True,
            "model_hash_tamper_fallback_completed": True,
            "original_candidate_unchanged": True,
            "loopback_only": True,
            "case_data_preserved": True,
        },
        "eai14-16": {
            "synthetic_sentinel_injected": True,
            "required_surfaces_reviewed": True,
            "sentinel_absent_from_all_surfaces": True,
        },
    }
    required_media = {
        "eai14-07": {"image/png"},
        "eai14-08": {"text/markdown", "application/json"},
        "eai14-09": {"image/png"},
        "eai14-10": {"application/json"},
        "eai14-14": {"application/json"},
        "eai14-16": {"application/json"},
    }
    stage = Path(tempfile.mkdtemp(prefix=".operator-stage-", dir=evidence_root))
    stage.chmod(0o700)
    prepared = {}
    try:
        for check_id in OPERATOR_CHECKS:
            item = manifest["checks"][check_id]
            assertions = item.get("assertions") if isinstance(item, dict) else None
            assertions_valid = isinstance(assertions, dict) and (
                (
                    check_id == "eai14-07"
                    and set(assertions) == {"ready_visible"}
                    and assertions.get("ready_visible") is True
                )
                or (
                    check_id == "eai14-08"
                    and set(assertions)
                    == {"cases", "comparison_reviewed", "traceability_and_uncertainty_retained"}
                    and assertions.get("cases") == ["high_rtt", "server_wait", "midstream"]
                    and assertions.get("comparison_reviewed") is True
                    and assertions.get("traceability_and_uncertainty_retained") is True
                )
                or (
                    check_id == "eai14-09"
                    and set(assertions)
                    == {"full_capture_action_opened", "evidence_capture_action_opened"}
                    and assertions.get("full_capture_action_opened") is True
                    and assertions.get("evidence_capture_action_opened") is True
                )
                or (
                    check_id == "eai14-10"
                    and set(assertions)
                    == {
                        "managed_helper_stopped_via_verified_host_primitive",
                        "rules_only_analysis_completed",
                        "safe_restart_succeeded",
                        "case_data_preserved",
                    }
                    and all(value is True for value in assertions.values())
                )
                or (
                    check_id == "eai14-14"
                    and set(assertions)
                    == {
                        "port_conflict_fallback_completed",
                        "model_hash_tamper_fallback_completed",
                        "original_candidate_unchanged",
                        "loopback_only",
                        "case_data_preserved",
                    }
                    and all(value is True for value in assertions.values())
                )
                or (
                    check_id == "eai14-16"
                    and set(assertions)
                    == {
                        "synthetic_sentinel_injected",
                        "required_surfaces_reviewed",
                        "sentinel_absent_from_all_surfaces",
                    }
                    and assertions.get("synthetic_sentinel_injected") is True
                    and assertions.get("required_surfaces_reviewed") is True
                    and assertions.get("sentinel_absent_from_all_surfaces") is True
                )
            )
            if (
                not isinstance(item, dict)
                or set(item) != {"status", "assertions", "artifacts"}
                or item.get("status") not in {"PASS", "FAIL"}
                or not assertions_valid
                or not isinstance(item.get("artifacts"), list)
                or not item["artifacts"]
            ):
                raise ValueError("operator_evidence_invalid")
            copied = [
                _operator_artifact(operator_root, stage, check_id, artifact, identity)
                for artifact in item["artifacts"]
            ]
            media = {artifact["media_type"] for artifact in item["artifacts"]}
            if not required_media[check_id].issubset(media):
                raise ValueError("operator_evidence_invalid")
            if (
                check_id == "eai14-08"
                and len(
                    [
                        artifact
                        for artifact in item["artifacts"]
                        if artifact["media_type"] == "application/json"
                    ]
                )
                != 3
            ):
                raise ValueError("operator_evidence_invalid")
            if check_id == "eai14-09" and (
                len(copied) != 2 or len({item["path"] for item in copied}) != 2
            ):
                raise ValueError("operator_evidence_invalid")
            if check_id == "eai14-16" and (
                len(copied) != 1
                or len(
                    [
                        artifact
                        for artifact in item["artifacts"]
                        if artifact["media_type"] == "application/json"
                    ]
                )
                != 1
            ):
                raise ValueError("operator_evidence_invalid")
            if check_id in {"eai14-10", "eai14-14", "eai14-16"} and len(copied) != 1:
                raise ValueError("operator_evidence_invalid")
            prepared[check_id] = (item, copied)
        staged_operator = stage / "operator"
        final_operator = evidence_root / "operator"
        if final_operator.exists() or final_operator.is_symlink():
            raise ValueError("operator_evidence_invalid")
        os.replace(staged_operator, final_operator)
        for check_id in OPERATOR_CHECKS:
            item, copied = prepared[check_id]
            row = results["eai14"][int(check_id[-2:]) - 1]
            _record_handler_evidence(
                evidence_root,
                "eai14",
                row,
                identity,
                {
                    "operator": manifest["operator"],
                    "attestation": OPERATOR_ATTESTATION,
                    "result_basis": "operator_attested",
                    "assertions": expected_assertions[check_id],
                    "artifact_sha256": [item["sha256"] for item in copied],
                    "artifact_container_validation": "PASS",
                    "visual_content_validation": "NOT_RUN",
                    "operator_semantic_review": (
                        "PASS"
                        if check_id in {"eai14-10", "eai14-14", "eai14-16"}
                        else "NOT_APPLICABLE"
                    ),
                },
                FIXED_HANDLERS[check_id],
                status=item["status"],
            )
            row["evidence"].extend(copied)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return None


def run_fixed_source_suite(
    check_id: str,
    row: dict,
    identity: dict,
    evidence_root: Path,
    *,
    runner=subprocess.run,
) -> None:
    test_ids = SOURCE_TESTS.get(check_id)
    if not test_ids:
        raise ValueError("qualification_handler_unavailable")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key, re.IGNORECASE)
    }
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    try:
        has_pytest = importlib.util.find_spec("pytest") is not None
    except (ImportError, ValueError):
        has_pytest = False
    if has_pytest:
        test_python = sys.executable
    else:
        venv_candidates = (
            ROOT / ".venv/bin/python",
            ROOT / ".venv/Scripts/python.exe",
        )
        test_python_path = next((path for path in venv_candidates if path.is_file()), None)
        test_python = str(test_python_path) if test_python_path else sys.executable
    argv = [test_python, "-m", "pytest", "-q", *test_ids]
    try:
        result = runner(
            argv,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            check=False,
        )
        passed = result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        passed = False
    observations = {
        "evidence_scope": "source_regression_only",
        "candidate_qualification": "NOT_ESTABLISHED",
        "test_ids": list(test_ids),
        "exit_status": "PASS" if passed else "FAIL",
        "command_kind": "fixed_pytest_nodeids",
    }
    evidence_path = Path("source-regressions") / f"{check_id}.json"
    target = evidence_root / evidence_path
    _write_json(
        target,
        {
            "schema_version": 1,
            "check_id": check_id,
            "candidate_identity_sha256": identity["candidate_identity_sha256"],
            "handler": "fixed_source_pytest_regression_suite",
            "status": observations["exit_status"],
            "observations": observations,
        },
    )
    row["status"] = "NOT_RUN"
    row["not_run_reason"] = UNAVAILABLE_CHECKS.get(check_id, "candidate_bound_evidence_unavailable")
    row["evidence"].append({"path": evidence_path.as_posix(), "sha256": _sha256(target)})


def verify_no_startup_download_path(bundle: Path, identity: dict) -> dict:
    metadata = _release_metadata(bundle)
    app = bundle / metadata["signed_app"]["path"]
    runtime = json.loads(
        (app / "Contents/Resources/ai/runtime-manifest.json").read_text(encoding="utf-8")
    )
    policy = runtime.get("policy")
    if not isinstance(policy, dict) or policy.get("network_downloads") is not False:
        raise ValueError("packaged_runtime_network_policy_invalid")
    startup_sources = (ROOT / "launch/macos/start.sh", ROOT / "launch/macos/common.sh")
    forbidden = re.compile(
        r"\bwget\b|\bgit\b[^\n]*\bclone\b"
        r"|\bdocker\s+(?:image\s+)?(?:pull|build(?:x)?)\b"
        r"|\bdocker\s+compose\b[^\n]*(?:\bpull\b|\bbuild\b)"
        r"|(?:^|\s)--(?:build|pull)\b|build_embedded_ai\.py"
    )
    approved_bridge_health_probe = re.compile(
        r"^\s*if\s+curl\s+--silent\s+--fail\s+--header "
        r'"Origin: http://127\.0\.0\.1:\$APP_PORT"\s+'
        r'"http://127\.0\.0\.1:\$BRIDGE_PORT/v1/health" '
        r">/dev/null 2>&1; then\s*$"
    )
    for path in startup_sources:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise ValueError("startup_source_unavailable") from None
        if forbidden.search(text):
            raise ValueError("startup_download_path_detected")
        logical_lines = re.sub(r"\\\r?\n[ \t]*", " ", text).splitlines()
        for line in logical_lines:
            if re.search(r"\bcurl\b", line) and not approved_bridge_health_probe.fullmatch(line):
                raise ValueError("startup_download_path_detected")
    return {
        "candidate_identity_sha256": identity["candidate_identity_sha256"],
        "runtime_download_policy": False,
        "fixed_startup_sources_checked": ["launch/macos/start.sh", "launch/macos/common.sh"],
        "external_download_commands_found": False,
    }


def _candidate_source_checkout(identity: dict) -> str | None:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "candidate_source_not_exact_head"
    if head.returncode or head.stdout.strip() != identity.get("source_sha"):
        return "candidate_source_not_exact_head"
    if status.returncode or status.stdout.strip():
        return "candidate_source_checkout_dirty"
    return None


def _require_source_checkout_stable(identity: dict, before: str | None) -> None:
    """Reject evidence if the checked-out source changes during collection."""
    after = _candidate_source_checkout(identity)
    if before != after:
        raise ValueError("candidate_source_changed_during_qualification")


def _mark_not_run(row: dict, reason: str) -> None:
    if reason not in NATIVE_NOT_RUN_REASONS:
        raise ValueError("qualification_not_run_reason_invalid")
    row["status"] = "NOT_RUN"
    row["not_run_reason"] = reason
    row["evidence"] = [
        item
        for item in row.get("evidence", [])
        if isinstance(item, dict) and item.get("path", "").startswith("source-regressions/")
    ]


def _run_task9_probe() -> tuple[str, str | None, str]:
    if sys.platform != "darwin" or platform.machine() != "arm64":
        return "NOT_RUN", "native_host_required", ""
    command = [sys.executable, str(ROOT / "scripts/qualify_macos_embedded_ai.py")]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key, re.IGNORECASE)
    }
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            timeout=1800,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "NOT_RUN", "native_probe_dependency_unavailable", ""
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    if len(output.encode("utf-8", errors="replace")) > 8192:
        return "FAIL", None, "native_probe_output_unbounded"
    if "SKIP" in output:
        return "NOT_RUN", "native_probe_precondition_unmet", output
    if result.returncode or "Task 9 signed App Sandbox isolation: PASS" not in output:
        return "FAIL", None, "native_task9_probe_failed"
    return "PASS", None, output


def task9_fixture_provenance(identity: dict) -> dict:
    """Describe the separate Task 9 probe fixture, never as candidate runtime."""
    probe_script = ROOT / "scripts/qualify_macos_embedded_ai.py"
    return {
        "probe_scope": "separate_task9_fixture",
        "candidate_runtime_evidence": False,
        "source_sha": identity["source_sha"],
        "probe_script_sha256": _sha256(probe_script),
    }


def task10_shared_state_preflight(
    bundle: Path,
    identity: dict,
    *,
    home: Path | None = None,
    runner=subprocess.run,
) -> str | None:
    """Fail closed before launching the same-bundle-ID app on a shared host."""
    home = Path.home() if home is None else Path(home)
    private = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    if private.is_symlink() or private.exists():
        return "existing_ai_private_state"
    run_dir = home / "Library/Application Support/Wireclaw/run"
    if run_dir.is_symlink() or (
        run_dir.exists() and (not run_dir.is_dir() or any(run_dir.iterdir()))
    ):
        return "existing_wireclaw_lifecycle_state"
    environment = {
        key: value
        for key, value in os.environ.items()
        if not re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key, re.IGNORECASE)
    }
    for process_name in ("WireclawAI", "llama-server"):
        try:
            process = runner(
                ["pgrep", "-x", process_name],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "native_probe_dependency_unavailable"
        if process.returncode == 0 and process.stdout.strip():
            return "existing_ai_process"
        if len(process.stdout) > 4096:
            return "native_probe_dependency_unavailable"
        if process.returncode not in (0, 1):
            return "native_probe_dependency_unavailable"
    try:
        containers = runner(
            [
                "docker",
                "compose",
                "--env-file",
                str(Path(bundle) / ".env"),
                "-f",
                str(Path(bundle) / "compose.yaml"),
                "ps",
                "-aq",
                "wireclaw-core",
            ],
            cwd=bundle,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "native_probe_dependency_unavailable"
    if containers.returncode or len(containers.stdout) > 4096:
        return "native_probe_dependency_unavailable"
    if containers.stdout.strip():
        return "existing_compose_state"
    return None


def verify_vmnetd_probe_boundary() -> dict:
    probe = ROOT / "ai/macos/WireclawAI/native_isolation_darwin_test.go"
    try:
        source = probe.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ValueError("vmnetd_probe_source_unavailable") from None
    vmnetd_lines = [line.strip() for line in source.splitlines() if "vmnetd" in line.lower()]
    if not any(
        "targets vmnetd or sends any protocol bytes." in line for line in vmnetd_lines
    ) or any(not line.startswith("//") for line in vmnetd_lines):
        raise ValueError("vmnetd_probe_boundary_unverified")
    if re.search(r"(?:Dial|connect)[^(]*\([^\n]*vmnetd", source, re.IGNORECASE):
        raise ValueError("vmnetd_probe_boundary_unverified")
    return {"vmnetd_targeted": False, "protocol_bytes_sent": False}


def _task10_result_in_copy(bundle: Path, identity: dict) -> tuple[str, str | None, dict]:
    if sys.platform != "darwin" or platform.machine() != "arm64":
        return "NOT_RUN", "native_host_required", {}
    preflight = task10_shared_state_preflight(bundle, identity)
    if preflight is not None:
        return "NOT_RUN", preflight, {}
    temporary_root = Path(tempfile.mkdtemp(prefix="Wireclaw qualification with spaces-"))
    temporary_root.chmod(0o700)
    fixture_root = None
    preserve_fixture = False
    try:
        fixture_root = copy_destructive_fixture(bundle, temporary_root, "task10") / "bundle"
        env_file = fixture_root / ".env"
        if not env_file.is_file() or env_file.is_symlink():
            return "NOT_RUN", "native_probe_dependency_unavailable", {}
        raw = env_file.read_text(encoding="utf-8")
        if re.search(r"(?m)^WIRECLAW_PROVIDER_API_KEY=.+$", raw):
            return "NOT_RUN", "native_probe_precondition_unmet", {}
        data_root = temporary_root / "isolated case data"
        data_root.mkdir(mode=0o700)
        sentinel = data_root / ".wireclaw-task13-preserve"
        sentinel.write_bytes(b"task13-private-copy-persistence-v1\n")
        updated_lines = []
        replaced = False
        for line in raw.splitlines():
            if line.startswith("WIRECLAW_DATA_ROOT="):
                if replaced:
                    return "NOT_RUN", "native_probe_precondition_unmet", {}
                updated_lines.append(f'WIRECLAW_DATA_ROOT="{data_root}"')
                replaced = True
            else:
                updated_lines.append(line)
        if not replaced:
            return "NOT_RUN", "native_probe_precondition_unmet", {}
        env_file.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
        env_file.chmod(0o600)
        qualifier = fixture_root / "scripts/qualify_macos_embedded_ai.py"
        if not qualifier.is_file():
            return "NOT_RUN", "native_probe_dependency_unavailable", {}
        environment = {
            key: value
            for key, value in os.environ.items()
            if not re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key, re.IGNORECASE)
        }
        project_name = (
            "wireclaw-qualification-"
            + hashlib.sha256(str(temporary_root).encode()).hexdigest()[:12]
        )
        environment["COMPOSE_PROJECT_NAME"] = project_name

        def run_once() -> tuple[str, str | None]:
            result = subprocess.run(
                [sys.executable, str(qualifier), "--task10-release-root", str(fixture_root)],
                cwd=fixture_root,
                env=environment,
                capture_output=True,
                timeout=1800,
                check=False,
            )
            output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
            if len(output.encode("utf-8", errors="replace")) > 8192:
                return "FAIL", "native_task10_output_unbounded"
            if (
                "Task 10 packaged inference/Core integration: PASS" in output
                and not result.returncode
            ):
                return "PASS", None
            not_run = re.search(
                r"Task 10 packaged inference/Core integration: NOT_RUN \(([a-z0-9_ -]{1,80})\)",
                output,
            )
            if not_run and result.returncode == 0:
                return "NOT_RUN", "native_probe_dependency_unavailable"
            return "FAIL", "native_task10_integration_failed"

        first_status, first_reason = run_once()
        if first_status != "PASS":
            preserve_fixture = first_status == "FAIL"
            return first_status, first_reason, {"failure": first_reason or "native_task10_not_run"}
        if sentinel.read_bytes() != b"task13-private-copy-persistence-v1\n":
            preserve_fixture = True
            return "FAIL", None, {"failure": "native_task10_case_data_not_preserved"}
        return (
            "PASS",
            None,
            {
                "candidate_identity_sha256": identity["candidate_identity_sha256"],
                "private_candidate_copy": True,
                "copy_path_contains_spaces": " " in str(fixture_root),
                "private_case_sentinel_preserved": True,
                "task10_start_status_stop_runs": 2,
                "task10_restart": "PASS",
            },
        )
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError, ValueError):
        preserve_fixture = fixture_root is not None
        return "FAIL", None, {"failure": "native_task10_integration_failed"}
    finally:
        # Preserve a failed fixture for local diagnosis. Successful and preflight
        # NOT_RUN runs have no active helper/container and can be removed safely.
        if not preserve_fixture:
            shutil.rmtree(temporary_root, ignore_errors=True)


def _verify_packaged_runtime(bundle: Path, identity: dict) -> dict:
    metadata = _release_metadata(bundle)
    app = bundle / metadata["signed_app"]["path"]
    embedded = metadata["embedded_ai"]
    model_path = app / "Contents/Resources/ai/model.gguf"
    model_manifest_path = app / "Contents/Resources/ai/model-manifest.json"
    runtime_manifest_path = app / "Contents/Resources/ai/runtime-manifest.json"
    try:
        model_manifest = json.loads(model_manifest_path.read_text(encoding="utf-8"))
        runtime_manifest = json.loads(runtime_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        raise ValueError("packaged_runtime_manifest_invalid") from None
    expected_model_hash = identity["signed_app"]["model_sha256"]
    if (
        embedded.get("model", {}).get("sha256") != expected_model_hash
        or model_manifest.get("artifact", {}).get("sha256") != expected_model_hash
        or _sha256(model_path) != expected_model_hash
        or runtime_manifest.get("revision") != embedded.get("runtime", {}).get("revision")
    ):
        raise ValueError("packaged_runtime_identity_mismatch")
    runtime_files = runtime_manifest.get("files")
    release_files = embedded.get("runtime", {}).get("files")
    if not isinstance(runtime_files, list) or not isinstance(release_files, list):
        raise ValueError("packaged_runtime_manifest_invalid")
    if [item.get("path") for item in runtime_files if isinstance(item, dict)] != [
        item.get("path") for item in release_files if isinstance(item, dict)
    ]:
        raise ValueError("packaged_runtime_identity_mismatch")
    runtime_hashes = []
    contents = app / "Contents"
    for item in runtime_files:
        if not isinstance(item, dict):
            raise ValueError("packaged_runtime_manifest_invalid")
        relative = item.get("path")
        if relative == "macos-arm64/llama-server":
            target = contents / "MacOS/llama-server"
        elif isinstance(relative, str) and relative.startswith("macos-arm64/"):
            target = contents / "Frameworks" / relative.removeprefix("macos-arm64/")
        else:
            raise ValueError("packaged_runtime_manifest_invalid")
        if (
            target.is_symlink()
            or not target.is_file()
            or item.get("sha256") != _sha256(target)
            or item.get("size_bytes") != target.stat().st_size
        ):
            raise ValueError("packaged_runtime_identity_mismatch")
        runtime_hashes.append({"path": relative, "sha256": item["sha256"]})
    return {
        "model_sha256": expected_model_hash,
        "model_manifest_sha256": _sha256(model_manifest_path),
        "runtime_manifest_sha256": _sha256(runtime_manifest_path),
        "runtime_files": runtime_hashes,
    }


def run_supported_checks(
    bundle: Path,
    identity: dict,
    evidence_root: Path,
    *,
    source_match: str | None = None,
    source_runner=subprocess.run,
    task9_probe=_run_task9_probe,
    task10_probe=_task10_result_in_copy,
    operator_evidence_dir: Path | None = None,
) -> dict:
    """Run fixed source/native handlers; leave unavailable UI/case checks NOT_RUN."""
    bundle = Path(bundle)
    evidence_root = Path(evidence_root)
    if evidence_root.is_symlink() or (evidence_root.exists() and any(evidence_root.iterdir())):
        raise ValueError("qualification_evidence_dir_invalid")
    evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    evidence_root.chmod(0o700)
    verify_frozen_signatures(bundle, identity)
    results = empty_results(identity)
    for check_id in OPERATOR_CHECKS:
        _mark_not_run(results["eai14"][int(check_id[-2:]) - 1], "operator_evidence_missing")
    try:
        runtime_observations = _verify_packaged_runtime(bundle, identity)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        runtime_observations = {"failure": str(error)[:80]}
        _record_handler_evidence(
            evidence_root,
            "eai14",
            results["eai14"][2],
            identity,
            runtime_observations,
            FIXED_HANDLERS["eai14-03"],
            status="FAIL",
        )
    else:
        _record_handler_evidence(
            evidence_root,
            "eai14",
            results["eai14"][2],
            identity,
            runtime_observations,
            FIXED_HANDLERS["eai14-03"],
        )
    _record_handler_evidence(
        evidence_root,
        "sandbox",
        results["sandbox"][0],
        identity,
        {
            "signature_validation": "PASS",
            "parent_entitlements": {
                "com.apple.security.app-sandbox": True,
                "com.apple.security.network.server": True,
            },
            "helper_entitlements": {
                "com.apple.security.app-sandbox": True,
                "com.apple.security.inherit": True,
            },
        },
        FIXED_HANDLERS["exact_parent_helper_entitlements"],
    )

    source_match = _candidate_source_checkout(identity) if source_match is None else source_match
    source_check_ids = (*tuple(SOURCE_TESTS), "eai14-02")
    pending_download_observations = None
    if source_match is not None:
        for check_id in source_check_ids:
            _mark_not_run(results["eai14"][int(check_id[-2:]) - 1], source_match)
        for check_id in TASK10_CHECKS:
            _mark_not_run(results["eai14"][int(check_id[-2:]) - 1], source_match)
        for index in range(1, 9):
            _mark_not_run(results["sandbox"][index], source_match)
    else:
        for check_id in SOURCE_TESTS:
            row = results["eai14"][int(check_id[-2:]) - 1]
            run_fixed_source_suite(check_id, row, identity, evidence_root, runner=source_runner)
        try:
            download_observations = verify_no_startup_download_path(bundle, identity)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            download_observations = {"failure": str(error)[:80]}
            _record_handler_evidence(
                evidence_root,
                "eai14",
                results["eai14"][1],
                identity,
                download_observations,
                FIXED_HANDLERS["eai14-02"],
                status="FAIL",
            )
        else:
            # Outbound denial is corroborated by the Task 9 probe below.
            download_observations["outbound_denial_required"] = True
            pending_download_observations = download_observations
        try:
            vmnetd_observations = verify_vmnetd_probe_boundary()
        except ValueError as error:
            _record_handler_evidence(
                evidence_root,
                "sandbox",
                results["sandbox"][8],
                identity,
                {"failure": str(error)[:80]},
                FIXED_HANDLERS["vmnetd_informational_only"],
                status="FAIL",
            )
        else:
            _record_handler_evidence(
                evidence_root,
                "sandbox",
                results["sandbox"][8],
                identity,
                vmnetd_observations,
                FIXED_HANDLERS["vmnetd_informational_only"],
            )

        task9_status, task9_reason, task9_output = task9_probe()
        if task9_status == "PASS":
            task9_observations = {
                "native_probe": "Task 9 signed App Sandbox isolation fixture",
                "candidate_identity_sha256": identity["candidate_identity_sha256"],
                **task9_fixture_provenance(identity),
                "probe_output_sha256": hashlib.sha256(task9_output.encode()).hexdigest(),
                "candidate_signed_entitlements_checked_separately": True,
            }
            for index, check_id in enumerate(SANDBOX_CHECKS[1:7], start=1):
                if check_id == "docker_engine_control_sockets_denied" and not re.search(
                    r"docker\.sock: DENIED", task9_output
                ):
                    _mark_not_run(results["sandbox"][index], "native_probe_dependency_unavailable")
                    continue
                _record_handler_evidence(
                    evidence_root,
                    "sandbox",
                    results["sandbox"][index],
                    identity,
                    task9_observations,
                    FIXED_HANDLERS[check_id],
                )
        elif task9_status == "FAIL":
            for index, check_id in enumerate(SANDBOX_CHECKS[1:7], start=1):
                _record_handler_evidence(
                    evidence_root,
                    "sandbox",
                    results["sandbox"][index],
                    identity,
                    {"failure": task9_reason or "native_task9_probe_failed"},
                    FIXED_HANDLERS[check_id],
                    status="FAIL",
                )
        else:
            for index in range(1, 7):
                _mark_not_run(
                    results["sandbox"][index],
                    task9_reason or "native_probe_dependency_unavailable",
                )

        task10_status, task10_reason, task10_observations = task10_probe(bundle, identity)
        if task10_status == "PASS":
            for check_id in TASK10_CHECKS:
                _record_handler_evidence(
                    evidence_root,
                    "eai14",
                    results["eai14"][int(check_id[-2:]) - 1],
                    identity,
                    task10_observations_for_check(check_id, task10_observations),
                    FIXED_HANDLERS[check_id],
                )
            if task9_status == "PASS":
                _record_handler_evidence(
                    evidence_root,
                    "sandbox",
                    results["sandbox"][7],
                    identity,
                    {
                        "task9": "PASS",
                        "task10": "PASS",
                        "candidate_identity_sha256": identity["candidate_identity_sha256"],
                    },
                    FIXED_HANDLERS["fixed_loopback_listener_and_core_reachability"],
                )
            else:
                _mark_not_run(
                    results["sandbox"][7],
                    task9_reason or "native_probe_precondition_unmet",
                )
        elif task10_status == "FAIL":
            for check_id in TASK10_CHECKS:
                _record_handler_evidence(
                    evidence_root,
                    "eai14",
                    results["eai14"][int(check_id[-2:]) - 1],
                    identity,
                    task10_observations or {"failure": "native_task10_integration_failed"},
                    FIXED_HANDLERS[check_id],
                    status="FAIL",
                )
            _mark_not_run(
                results["sandbox"][7],
                task9_reason or "native_probe_precondition_unmet",
            )
        else:
            for check_id in TASK10_CHECKS:
                _mark_not_run(
                    results["eai14"][int(check_id[-2:]) - 1],
                    task10_reason or "native_probe_dependency_unavailable",
                )
            _mark_not_run(
                results["sandbox"][7],
                task10_reason or "native_probe_dependency_unavailable",
            )
        if pending_download_observations and task9_status == "PASS":
            _record_handler_evidence(
                evidence_root,
                "eai14",
                results["eai14"][1],
                identity,
                {**pending_download_observations, "sandbox_outbound_denied": True},
                FIXED_HANDLERS["eai14-02"],
            )
        elif pending_download_observations:
            _mark_not_run(results["eai14"][1], task9_reason or "native_host_required")
    if operator_evidence_dir is not None and source_match is None:
        collect_operator_evidence(
            bundle,
            identity,
            operator_evidence_dir,
            evidence_root,
            results,
        )
    elif source_match is not None:
        for check_id in OPERATOR_CHECKS:
            _mark_not_run(results["eai14"][int(check_id[-2:]) - 1], source_match)
    results["signing_status"] = signing_status_from_identity(identity, results)
    return results


def validate_results(results: dict, identity: dict, evidence_root: Path | None = None) -> None:
    if not isinstance(results, dict) or results.get("schema_version") != 1:
        raise ValueError("qualification_schema_invalid")
    if set(results) != {
        "schema_version",
        "candidate_identity",
        "qualification_host",
        "signing_status",
        "eai14",
        "sandbox",
    }:
        raise ValueError("qualification_schema_invalid")
    if results.get("candidate_identity") != identity:
        raise ValueError("candidate_identity_mismatch")
    host = results.get("qualification_host")
    if (
        not isinstance(host, dict)
        or set(host) != {"os", "architecture"}
        or host != {"os": sys.platform, "architecture": platform.machine()}
    ):
        raise ValueError("qualification_host_mismatch")
    signing = results.get("signing_status")
    if (
        not isinstance(signing, dict)
        or set(signing)
        != {
            "development_signing",
            "hardened_runtime_production",
            "developer_id",
            "production_qualification",
            "notarization",
            "stapling",
        }
        or any(not isinstance(value, str) or value not in STATUSES for value in signing.values())
    ):
        raise ValueError("qualification_signing_status_invalid")
    if signing != signing_status_from_identity(identity, results):
        raise ValueError("qualification_signing_status_mismatch")
    if evidence_root is not None and Path(evidence_root).is_symlink():
        raise ValueError("qualification_evidence_identity_mismatch")
    for field, expected in (
        ("eai14", EAI14_CHECKS),
        ("sandbox", tuple((key, key) for key in SANDBOX_CHECKS)),
    ):
        rows = results.get(field)
        if not isinstance(rows, list) or [
            row.get("id") for row in rows if isinstance(row, dict)
        ] != [check[0] for check in expected]:
            raise ValueError(f"{field}_coverage_invalid")
        for row, (_check_id, title) in zip(rows, expected, strict=True):
            if not isinstance(row, dict) or set(row) != {
                "id",
                "title",
                "status",
                "handler",
                "not_run_reason",
                "candidate_identity_sha256",
                "evidence",
            }:
                raise ValueError("qualification_schema_invalid")
            if (
                row.get("title") != title
                or row.get("candidate_identity_sha256") != identity["candidate_identity_sha256"]
            ):
                raise ValueError("candidate_identity_mismatch")
            if not isinstance(row.get("status"), str) or row["status"] not in STATUSES:
                raise ValueError("qualification_status_invalid")
            if row["status"] == "NOT_RUN":
                valid_not_run = (
                    row.get("id") in UNAVAILABLE_CHECKS
                    and row.get("handler") == "unavailable"
                    and row.get("not_run_reason")
                    in {UNAVAILABLE_CHECKS[row["id"]], *NATIVE_NOT_RUN_REASONS}
                ) or (
                    row.get("handler") == FIXED_HANDLERS.get(row["id"])
                    and row.get("not_run_reason")
                    in {
                        "handler_not_executed",
                        "candidate_bound_evidence_unavailable",
                        *NATIVE_NOT_RUN_REASONS,
                    }
                )
                if not valid_not_run:
                    raise ValueError("qualification_handler_status_invalid")
            elif (
                row.get("handler") != FIXED_HANDLERS.get(row["id"])
                or row.get("not_run_reason") is not None
            ):
                raise ValueError("qualification_handler_status_invalid")
            evidence = row.get("evidence")
            if not isinstance(evidence, list) or (row["status"] != "NOT_RUN" and not evidence):
                raise ValueError("qualification_evidence_missing")
            if row["status"] != "NOT_RUN" and row["id"] in OPERATOR_CHECKS:
                paths = [item.get("path") for item in evidence if isinstance(item, dict)]
                expected_record = f"eai14/{row['id']}.json"
                operator_paths = [
                    path
                    for path in paths
                    if isinstance(path, str) and path.startswith(f"operator/{row['id']}/")
                ]
                required_count = {
                    "eai14-07": 1,
                    "eai14-08": 4,
                    "eai14-09": 2,
                    "eai14-10": 1,
                    "eai14-14": 1,
                    "eai14-16": 1,
                }[row["id"]]
                if (
                    expected_record not in paths
                    or len(operator_paths) != required_count
                    or any(Path(path).name.startswith(".") for path in operator_paths)
                ):
                    raise ValueError("qualification_evidence_missing")
            for item in evidence:
                if (
                    not isinstance(item, dict)
                    or set(item) != {"path", "sha256"}
                    or not isinstance(item.get("path"), str)
                    or len(item["path"]) > 240
                ):
                    raise ValueError("qualification_evidence_invalid")
                relative = Path(item["path"])
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
                ):
                    raise ValueError("qualification_evidence_invalid")
                if evidence_root is not None:
                    path = evidence_root / relative
                    root = evidence_root.resolve(strict=True)
                    try:
                        resolved = path.resolve(strict=True)
                    except OSError:
                        raise ValueError("qualification_evidence_identity_mismatch") from None
                    if (
                        any(
                            part.is_symlink()
                            for part in (path, *path.parents)
                            if part != evidence_root.parent
                        )
                        or root not in resolved.parents
                        or not resolved.is_file()
                        or _sha256(resolved) != item["sha256"]
                    ):
                        raise ValueError("qualification_evidence_identity_mismatch")


def create_destructive_fixture_root(temp_root: Path, label: str) -> Path:
    temp_root = Path(temp_root)
    if (
        temp_root.is_symlink()
        or not temp_root.is_dir()
        or stat.S_IMODE(temp_root.stat().st_mode) & 0o077
        or not re.fullmatch(r"[a-z0-9-]{1,32}", label)
    ):
        raise ValueError("destructive_fixture_root_invalid")
    root = Path(tempfile.mkdtemp(prefix=f"wireclaw-{label}-", dir=temp_root))
    root.chmod(0o700)
    return root


def copy_destructive_fixture(candidate: Path, temp_root: Path, label: str) -> Path:
    """Copy a candidate into a private temp directory for destructive probes."""
    candidate = Path(candidate)
    before = tree_sha256(candidate)
    root = create_destructive_fixture_root(temp_root, label)
    try:
        shutil.copytree(candidate, root / "bundle", symlinks=True)
        validate_destructive_fixture(candidate, root, temp_root)
        if tree_sha256(root / "bundle") != before or tree_sha256(candidate) != before:
            raise ValueError("destructive_fixture_copy_invalid")
    except (OSError, ValueError):
        shutil.rmtree(root, ignore_errors=True)
        raise
    return root


def validate_destructive_fixture(candidate: Path, fixture: Path, temp_root: Path) -> None:
    candidate = Path(candidate).resolve(strict=True)
    fixture = Path(fixture)
    temp_root = Path(temp_root).resolve(strict=True)
    if fixture.is_symlink() or not fixture.is_dir():
        raise ValueError("destructive_fixture_not_isolated")
    fixture = fixture.resolve(strict=True)
    if (
        fixture in (candidate, temp_root)
        or fixture in candidate.parents
        or candidate in fixture.parents
        or temp_root not in fixture.parents
        or fixture.parent != temp_root
        or stat.S_IMODE(fixture.stat().st_mode) & 0o077
    ):
        raise ValueError("destructive_fixture_not_isolated")
    if any(path.is_symlink() for path in fixture.rglob("*")):
        raise ValueError("destructive_fixture_not_isolated")


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def write_evidence(results: dict, destination: Path) -> None:
    destination = Path(destination)
    if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
        raise ValueError("qualification_output_invalid")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("qualification_output_exists")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    for section in ("eai14", "sandbox"):
        for row in results[section]:
            _write_json(destination / section / f"{row['id']}.json", row)
    _write_json(destination / "qualification.json", results)


def validate_frozen_metadata(recorded: dict, identity: dict) -> None:
    if (
        not isinstance(recorded, dict)
        or recorded.get("frozen") is not True
        or recorded.get("source_sha") != identity["source_sha"]
        or recorded.get("bundle_tree_sha256") != identity["bundle_tree_sha256"]
        or recorded.get("archive_sha256") != identity["archive_sha256"]
        or recorded.get("embedded_ai") != identity["embedded_ai"]
    ):
        raise ValueError("candidate_identity_mismatch")
    signed = recorded.get("signed_app")
    if not isinstance(signed, dict):
        raise ValueError("candidate_identity_mismatch")
    expected_app = identity["signed_app"]
    if any(signed.get(key) != value for key, value in expected_app.items() if key != "signed_code"):
        raise ValueError("candidate_identity_mismatch")
    rows = signed.get("signed_code")
    expected_rows = expected_app.get("signed_code")
    if not isinstance(rows, list) or len(rows) != len(expected_rows):
        raise ValueError("candidate_signed_code_identity_mismatch")
    for actual, expected in zip(rows, expected_rows, strict=True):
        if not isinstance(actual, dict) or not isinstance(expected, dict):
            raise ValueError("candidate_signed_code_identity_mismatch")
        if any(
            actual.get(key) != expected.get(key)
            for key in (
                "path",
                "sha256",
                "signing_mode",
                "hardened_runtime",
                "entitlements_sha256",
            )
        ):
            raise ValueError("candidate_signed_code_identity_mismatch")
        if not isinstance(actual.get("identifier"), str) or not actual["identifier"]:
            raise ValueError("candidate_signed_code_identity_mismatch")
        if actual.get("signing_mode") == "adhoc":
            if actual.get("signature") != "adhoc" or actual.get("team_id") not in (
                None,
                "not set",
                "-",
            ):
                raise ValueError("candidate_signed_code_identity_mismatch")
        elif (
            actual.get("authority") != expected_app.get("signing_identity")
            or not isinstance(actual.get("team_id"), str)
            or actual["team_id"] in {"not set", "-"}
        ):
            raise ValueError("candidate_signed_code_identity_mismatch")


def validate_output_isolated(bundle: Path, archive: Path, *outputs: Path) -> None:
    bundle = Path(bundle).resolve(strict=True)
    archive = Path(archive).resolve(strict=True)
    for output in outputs:
        output = Path(output)
        resolved = output.resolve(strict=False)
        if (
            output.is_symlink()
            or resolved in (bundle, archive)
            or bundle in resolved.parents
            or archive in resolved.parents
        ):
            raise ValueError("qualification_output_overlaps_candidate")


def validate_input_isolated(bundle: Path, archive: Path, *inputs: Path) -> None:
    bundle = Path(bundle).resolve(strict=True)
    archive = Path(archive).resolve(strict=True)
    for input_path in inputs:
        input_path = Path(input_path)
        resolved = input_path.resolve(strict=False)
        if (
            input_path.is_symlink()
            or resolved in (bundle, archive)
            or resolved in bundle.parents
            or resolved in archive.parents
            or bundle in resolved.parents
            or archive in resolved.parents
        ):
            raise ValueError("qualification_input_overlaps_candidate")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-bundle", type=Path, required=True)
    parser.add_argument("--candidate-archive", type=Path, required=True)
    parser.add_argument("--candidate-metadata", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--operator-evidence-dir", type=Path)
    parser.add_argument("--print-operator-procedure", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.print_operator_procedure:
        for check_id in OPERATOR_CHECKS:
            print(f"{check_id}: {OPERATOR_PROCEDURE[check_id]}")
        print(f"Use a fixed-schema manifest and attest exactly: {OPERATOR_ATTESTATION}")
        return 0
    try:
        validate_output_isolated(
            args.candidate_bundle,
            args.candidate_archive,
            args.evidence_dir,
            args.output,
        )
        validate_input_isolated(
            args.candidate_bundle,
            args.candidate_archive,
            args.candidate_metadata,
            args.evidence_dir,
            *([args.operator_evidence_dir] if args.operator_evidence_dir else []),
        )
        recorded = json.loads(args.candidate_metadata.read_text(encoding="utf-8"))
        identity = candidate_identity(
            args.candidate_bundle, args.candidate_archive, frozen_metadata=recorded
        )
        verify_candidate_unchanged(
            args.candidate_bundle,
            args.candidate_archive,
            identity,
            frozen_metadata=recorded,
        )
        source_before = _candidate_source_checkout(identity)
        results = run_supported_checks(
            args.candidate_bundle,
            identity,
            args.evidence_dir,
            source_match=source_before,
            operator_evidence_dir=args.operator_evidence_dir,
        )
        _require_source_checkout_stable(identity, source_before)
        # Live/UI/destructive checks without fixed safe handlers remain NOT_RUN.
        validate_results(results, identity, args.evidence_dir)
        verify_candidate_unchanged(
            args.candidate_bundle,
            args.candidate_archive,
            identity,
            frozen_metadata=recorded,
        )
        verify_frozen_signatures(args.candidate_bundle, identity)
        write_evidence(results, args.output)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    statuses = [row["status"] for section in ("eai14", "sandbox") for row in results[section]]
    if not statuses or "FAIL" in statuses:
        overall = "FAIL"
    elif "BLOCKED" in statuses:
        overall = "BLOCKED"
    elif "NOT_RUN" in statuses:
        overall = "NOT_RUN"
    else:
        overall = "PASS"
    print(f"Native macOS embedded-AI qualification evidence: {overall}")
    not_run = [
        f"{row['id']} ({row['not_run_reason']})"
        for section in ("eai14", "sandbox")
        for row in results[section]
        if row["status"] == "NOT_RUN"
    ]
    if not_run:
        print(f"NOT_RUN checks ({len(not_run)}): " + ", ".join(not_run))
    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
