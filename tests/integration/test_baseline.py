import hashlib
import json
import shutil
from pathlib import Path

import pytest
from generate import NAMES, generate
from wireclaw_analyzer import Analyzer, AnalyzerError, Limits

pytestmark = pytest.mark.skipif(
    not shutil.which("tshark") or not shutil.which("capinfos"),
    reason="requires real TShark and capinfos",
)
ROOT = Path(__file__).resolve().parents[2]


def prepared(tmp_path, *, limits=None):
    fixtures = generate(tmp_path / "incoming")
    analyzer = Analyzer(tmp_path, **({"limits": limits} if limits else {}))
    return analyzer, fixtures


@pytest.mark.parametrize("name", NAMES)
def test_golden_and_reproducibility(tmp_path, name):
    analyzer, fixtures = prepared(tmp_path)
    identity = analyzer.ingest_capture(Path("incoming") / f"{name}.capture")
    assert identity == hashlib.sha256(fixtures[name]).hexdigest()
    assert json.loads(
        (tmp_path / "cases" / identity / "normalized" / "capture-identity.json").read_text()
    ) == {"capture_sha256": identity, "file_bytes": len(fixtures[name])}
    before = analyzer.store.capture_path(identity).read_bytes()
    result = analyzer.analyze(identity)
    assert result == analyzer.analyze(identity)
    assert before == analyzer.store.capture_path(identity).read_bytes() == fixtures[name]
    assert not analyzer.store.capture_path(identity).stat().st_mode & 0o222
    assert (
        json.loads(
            (tmp_path / "cases" / identity / "normalized" / "capture-summary.json").read_text()
        )
        == result
    )
    assert result["tool_versions"]["tshark"]["available"]
    assert result["tool_versions"]["capinfos"]["available"]
    assert result["analyzer_version"] == "0.1.0"
    for item in result["evidence"]:
        analyzer.validator.validate(item)
    # All evidence values, IDs, scope, limitations and summaries compared. Only host
    # availability/version fields are excluded; compatibility versions are recorded separately.
    actual = [
        {k: v for k, v in item.items() if k != "source"}
        | {"source": {k: v for k, v in item["source"].items() if k != "version"}}
        for item in result["evidence"]
    ]
    expected = json.loads((ROOT / "tests" / "golden" / f"{name}.json").read_text())
    assert actual == expected


@pytest.mark.parametrize("name", ("malformed", "damaged_record", "unsupported"))
def test_malformed_intake_leaves_no_original(tmp_path, name):
    analyzer, _ = prepared(tmp_path)
    with pytest.raises(AnalyzerError):
        analyzer.ingest_capture(Path("incoming") / f"{name}.capture")
    assert not list(tmp_path.glob("cases/*/original/capture"))
    assert not list((tmp_path / "work").iterdir())


def test_source_change_does_not_modify_original(tmp_path):
    analyzer, _ = prepared(tmp_path)
    source = tmp_path / "incoming/healthy.capture"
    identity = analyzer.ingest_capture(source)
    source.write_bytes(b"changed")
    assert analyzer.analyze(identity)["evidence"][0]["value"]["packet_count"] == 7


def test_intake_is_content_based_and_hostile_name_is_data(tmp_path):
    analyzer, fixtures = prepared(tmp_path)
    source = tmp_path / "incoming/$(touch injected); --help.txt"
    source.write_bytes(fixtures["healthy"])
    identity = analyzer.ingest_capture(source)
    assert analyzer.analyze(identity)["evidence"][0]["value"]["format"] == "pcap"
    assert not (tmp_path / "injected").exists()
    assert analyzer.ingest_capture(source) == identity


def test_mutated_managed_original_is_detected(tmp_path):
    analyzer, _ = prepared(tmp_path)
    identity = analyzer.ingest_capture(Path("incoming/healthy.capture"))
    target = analyzer.store.capture_path(identity)
    target.chmod(0o644)
    target.write_bytes(b"tampered")
    with pytest.raises(AnalyzerError, match="capture_integrity_failure"):
        analyzer.analyze(identity)


@pytest.mark.parametrize(
    "limits,code",
    [
        (Limits(max_capture_bytes=10), "capture_size_limit"),
        (Limits(max_packets=2), "packet_result_limit"),
    ],
)
def test_capture_limits(tmp_path, limits, code):
    analyzer, _ = prepared(tmp_path, limits=limits)
    with pytest.raises(AnalyzerError, match=code):
        analyzer.ingest_capture(Path("incoming/healthy.capture"))


def test_capabilities_and_quality_order(tmp_path):
    analyzer, _ = prepared(tmp_path)
    identity = analyzer.ingest_capture(Path("incoming/healthy.capture"))
    result = analyzer.analyze(identity)
    methods = (
        analyzer.get_capture_metadata,
        analyzer.assess_capture_quality,
        analyzer.list_protocols,
        analyzer.list_endpoints,
        analyzer.list_conversations,
    )
    for method, expected in zip(methods, result["evidence"], strict=True):
        assert method(identity) == expected
    assert result["evidence"][1]["value"]["state"] == "good"
    assert len(result["evidence"][3]["value"]["endpoints"]) == 5
    assert len(result["evidence"][4]["value"]["conversations"]) == 3


def test_quality_limits_do_not_become_fault_claims(tmp_path):
    analyzer, _ = prepared(tmp_path)
    identity = analyzer.ingest_capture(Path("incoming/checksum_offload.capture"))
    quality = analyzer.assess_capture_quality(identity)["value"]
    assert quality["state"] == "limited"
    assert quality["checks"]["checksum_anomalies"]["frame_refs"] == [1, 2, 3]
    assert quality["checks"]["checksum_anomalies"]["offload_cause"] == "unknown"


def test_independent_fixture_observations(tmp_path):
    analyzer, _ = prepared(tmp_path)
    healthy = analyzer.analyze(analyzer.ingest_capture(Path("incoming/healthy.capture")))
    assert healthy["evidence"][0]["value"]["wire_bytes"] == 469
    assert healthy["evidence"][0]["value"]["duration_seconds"] == 0.6
    stacks = healthy["evidence"][2]["value"]["protocols"]
    assert {p["protocol"]: p["packets"] for p in stacks} == {
        "eth": 7,
        "ethertype": 7,
        "ip": 5,
        "ipv6": 2,
        "tcp": 3,
        "udp": 4,
        "dns": 2,
        "data": 2,
    }
    for name, state, check, expected_frames in (
        ("empty", "insufficient", "truncation", []),
        ("truncated", "limited", "truncation", list(range(1, 8))),
        ("midstream", "limited", "midstream_indicators", [1]),
        ("incomplete_handshake", "limited", "incomplete_handshakes", [1, 2]),
        ("timestamp_regression", "limited", "timestamp_regressions", list(range(2, 8))),
        ("checksum_offload", "limited", "checksum_anomalies", [1, 2, 3]),
        ("one_sided", "limited", "one_sided_conversations", [1, 2]),
    ):
        identity = analyzer.ingest_capture(Path("incoming") / f"{name}.capture")
        quality = analyzer.assess_capture_quality(identity)["value"]
        assert quality["state"] == state
        assert quality["checks"][check]["frame_refs"] == expected_frames
    drops = analyzer.analyze(analyzer.ingest_capture(Path("incoming/drops.capture")))
    assert drops["evidence"][0]["value"]["capture_drops"] == 3
    assert drops["evidence"][1]["value"]["state"] == "limited"
