"""Gate 4 real-capture golden RCA outcomes over deterministic Gate 1/2 evidence."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from generate import generate as generate_baseline
from generate_gate2 import generate as generate_gate2
from jsonschema import Draft202012Validator
from wireclaw_analyzer import Analyzer
from wireclaw_api.investigation import build_investigation_result

pytestmark = pytest.mark.skipif(
    not shutil.which("tshark") or not shutil.which("capinfos"),
    reason="requires real TShark and capinfos",
)
ROOT = Path(__file__).resolve().parents[2]


def _summary(report):
    conclusion = report["conclusion"]
    primary = next(
        (
            finding["category"]
            for finding in report["findings"]
            if finding["statement"] == conclusion["statement"]
            and finding["evidence_ids"] == conclusion["evidence_ids"]
        ),
        None,
    )
    attribution = report.get("time_attribution")
    return {
        "capture_quality": report["capture_quality"]["state"],
        "conclusion_type": conclusion["type"],
        "confidence": conclusion["confidence"],
        "fault_domains": conclusion["fault_domains"],
        "primary_category": primary,
        "finding_categories": [finding["category"] for finding in report["findings"]],
        "time_segments": [segment["name"] for segment in attribution["segments"]]
        if attribution
        else [],
        "has_remaining_hypotheses": bool(report["remaining_hypotheses"]),
    }


def test_gate4_real_capture_golden_rca_cases(tmp_path):
    gate2 = generate_gate2(tmp_path / "gate2-fixtures")
    baseline = generate_baseline(tmp_path / "gate1-fixtures")
    expected = json.loads((ROOT / "tests/golden/gate4/rules_cases.json").read_text())
    schema = json.loads((ROOT / "contracts/investigation-result.schema.json").read_text())
    validator = Draft202012Validator(schema)

    cases = {
        "clean_tcp": ("application is slow", gate2["clean_tcp"]),
        "loss_tcp": ("application is slow", gate2["loss_tcp"]),
        "reordered_tcp": ("application is slow", gate2["reordered_tcp"]),
        "high_rtt": ("application is slow", gate2["high_rtt"]),
        "server_wait": ("application is slow", gate2["server_wait"]),
        "window_tcp": ("download throughput is slow", gate2["window_tcp"]),
        "reset_tcp": ("users disconnect", gate2["reset_tcp"]),
        "dns_delay": ("DNS name resolution is slow", gate2["dns_delay"]),
        "tls_delay": ("TLS handshake is slow", gate2["tls_delay"]),
        "tls_retry": ("TLS handshake retries", gate2["tls_retry"]),
        "failed_tcp": ("cannot connect", gate2["failed_tcp"]),
        "pmtud_signals": ("large transfers stall", gate2["pmtud_signals"]),
        "midstream": ("application is slow", baseline["midstream"]),
    }

    actual = {}
    for name, (symptom, capture) in cases.items():
        case_root = tmp_path / "cases" / name
        incoming = case_root / "incoming"
        incoming.mkdir(parents=True)
        source = incoming / f"{name}.capture"
        source.write_bytes(capture)
        analyzer = Analyzer(case_root)
        identity = analyzer.ingest_capture(Path("incoming") / source.name)
        original = analyzer.store.capture_path(identity)
        before = original.read_bytes()
        assert hashlib.sha256(before).hexdigest() == identity

        baseline_result = analyzer.analyze(identity)
        diagnostic_result = analyzer.diagnose(identity)
        evidence = [*baseline_result["evidence"], *diagnostic_result["evidence"]]
        versions = {
            "analyzer": baseline_result["analyzer_version"],
            "tshark": baseline_result["tool_versions"]["tshark"]["version"],
            "capinfos": baseline_result["tool_versions"]["capinfos"]["version"],
        }
        report = build_investigation_result(
            case_id=f"golden-{name}",
            symptom=symptom,
            evidence=evidence,
            analyzer_versions=versions,
        )
        validator.validate(report)
        assert report == build_investigation_result(
            case_id=f"golden-{name}",
            symptom=symptom,
            evidence=evidence,
            analyzer_versions=versions,
        )
        assert original.read_bytes() == before
        actual[name] = _summary(report)

    assert actual == expected
