"""Real TShark 4.2.2 semantic expectations; all G2 tasks and Gate 1 regressions."""

import hashlib
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from generate import generate as generate_baseline
from generate_gate2 import NAMES, dns_message, generate, handshake, hello, tcp, timed_pcap
from wireclaw_analyzer import (
    Analyzer,
    AnalyzerError,
    Capability,
    DiagnosticLimits,
    DiagnosticRequest,
)
from wireclaw_analyzer.runner import Operation

pytestmark = pytest.mark.skipif(
    not shutil.which("tshark") or not shutil.which("capinfos"),
    reason="requires real TShark and capinfos",
)
ROOT = Path(__file__).resolve().parents[2]


def prepare(tmp_path, name, **kwargs):
    captures = generate(tmp_path / "incoming")
    analyzer = Analyzer(tmp_path, **kwargs)
    identity = analyzer.ingest_capture(Path("incoming") / f"{name}.capture")
    assert identity == hashlib.sha256(captures[name]).hexdigest()
    return analyzer, identity


def value(result, cap):
    return next(e["value"] for e in result["evidence"] if e["category"] == cap)


def semantic(evidence):
    return [
        {**item, "source": {k: v for k, v in item["source"].items() if k != "version"}}
        for item in evidence
    ]


@pytest.mark.parametrize("name", NAMES)
def test_gate2_golden_reproducibility_schema_traceability(tmp_path, name):
    analyzer, identity = prepare(tmp_path, name)
    original = analyzer.store.capture_path(identity).read_bytes()
    result = analyzer.diagnose(identity)
    assert result == analyzer.diagnose(identity)
    assert original == analyzer.store.capture_path(identity).read_bytes()
    assert not analyzer.store.capture_path(identity).stat().st_mode & 0o222
    assert (
        json.loads((tmp_path / f"cases/{identity}/normalized/diagnostics.json").read_text())
        == result
    )
    assert result["tool_versions"]["tshark"]["available"]
    assert result["configuration"]["two_pass"] is True
    assert result["configuration"]["decryption"] is False
    assert result["capture_quality_evidence_id"].endswith("assess_capture_quality")
    assert {e["source"]["capability"] for e in result["evidence"]} == {c.value for c in Capability}
    for item in result["evidence"]:
        analyzer.validator.validate(item)
        assert item["value"]["capture_sha256"] == identity
        assert item["epistemic_class"] in ("observed", "derived")
        assert item["source"]["version"] == result["tool_versions"]["tshark"]["version"]
        assert item["display_filter"]
        assert item["value"]["calculation"]
    expected = json.loads((ROOT / f"tests/golden/gate2/{name}.json").read_text())
    assert semantic(result["evidence"]) == expected
    serialized = json.dumps(result)
    assert "example.invalid" not in serialized  # hostname contents intentionally not extracted
    assert "network is congested" not in serialized


def test_clean_independent_measurements_and_negative_conditions(tmp_path):
    analyzer, identity = prepare(tmp_path, "clean_tcp")
    result = analyzer.diagnose(identity)
    setup = value(result, "analyze_tcp_establishment")
    assert setup["establishment_seconds"] == 0.02
    assert (setup["syn_frame"], setup["synack_frame"], setup["final_ack_frame"]) == (1, 2, 3)
    assert value(result, "analyze_tcp_health")["retransmission_union_count"] == 0
    assert value(result, "analyze_rtt")["median_seconds"] == 0.01
    assert value(result, "analyze_rtt")["sample_count"] == 4
    assert value(result, "analyze_window_behavior")["indicators"]["zero_window"] == []
    assert value(result, "analyze_tcp_resets")["count"] == 0
    throughput = value(result, "analyze_throughput")["directions"]
    assert [
        (t["wire_bytes"], t["tcp_payload_bytes"], t["unique_observed_payload_bytes"])
        for t in throughput
    ] == [(244, 20, 20), (200, 30, 30)]
    assert [t["unique_acknowledged_payload_bytes"] for t in throughput] == [20, 30]
    assert throughput[0]["tcp_goodput_approx_bits_per_second"] == 2000
    assert all(t["application_goodput_bits_per_second"] is None for t in throughput)
    assert [m["mss_bytes"] for m in value(result, "analyze_mss")["records"]] == [1460, 1460]
    assert value(result, "analyze_dns")["transactions"] == []
    assert value(result, "analyze_tls_handshakes")["state"] == "not_observable"
    assert value(result, "analyze_pmtud_signals")["records"] == []
    assert value(result, "analyze_fragmentation")["records"] == []


def test_loss_reordering_expert_classes_and_sequence_union(tmp_path):
    analyzer, identity = prepare(tmp_path, "loss_tcp")
    result = analyzer.diagnose(identity)
    health = value(result, "analyze_tcp_health")
    assert health["indicators"]["retransmission"]["frame_refs"] == [5, 11, 13]
    assert health["indicators"]["fast_retransmission"]["frame_refs"] == [11]
    assert health["indicators"]["spurious_retransmission"]["frame_refs"] == [13]
    assert health["indicators"]["duplicate_ack"]["frame_refs"] == [8, 9, 10]
    assert health["retransmission_union_count"] == 3
    sent = value(result, "analyze_throughput")["directions"][0]
    assert (
        sent["tcp_payload_bytes"],
        sent["unique_observed_payload_bytes"],
        sent["overlapping_payload_bytes"],
    ) == (100, 40, 60)
    assert sent["unique_acknowledged_payload_bytes"] == 40
    other = analyzer.diagnose(analyzer.ingest_capture(Path("incoming/reordered_tcp.capture")))
    assert value(other, "analyze_tcp_health")["indicators"]["out_of_order"]["frame_refs"] == [5]
    assert value(other, "analyze_tcp_health")["retransmission_union_count"] == 0
    assert (
        value(other, "analyze_throughput")["directions"][0]["unique_observed_payload_bytes"] == 40
    )
    assert value(other, "analyze_pmtud_signals")["records"] == []


def test_window_constraint_and_server_wait_are_distinct(tmp_path):
    analyzer, identity = prepare(tmp_path, "window_tcp")
    window = value(analyzer.diagnose(identity), "analyze_window_behavior")
    assert window["indicators"] == {
        "zero_window": [6, 8],
        "zero_window_probe": [7],
        "window_full": [5],
    }
    span = window["directions"][1]["zero_window_intervals"][0]
    assert span == {
        "start_frame": 6,
        "reopen_frame": 9,
        "observed_seconds": 1.0,
        "state": "reopened",
    }
    assert window["directions"][1]["advertiser"]["address"] == "192.0.2.2"
    wait = analyzer.diagnose(analyzer.ingest_capture(Path("incoming/server_wait.capture")))
    assert value(wait, "analyze_window_behavior")["indicators"]["zero_window"] == []
    assert value(wait, "analyze_rtt")["median_seconds"] == 0.01
    high = analyzer.diagnose(analyzer.ingest_capture(Path("incoming/high_rtt.capture")))
    assert value(high, "analyze_rtt")["median_seconds"] == 0.2
    assert value(high, "analyze_tcp_establishment")["establishment_seconds"] == 0.4


def test_dns_delay_failure_retry_and_no_timeout_claim(tmp_path):
    analyzer, identity = prepare(tmp_path, "dns_delay")
    tx = value(analyzer.diagnose(identity), "analyze_dns")["transactions"][0]
    assert (tx["query_frame"], tx["response_frame"], tx["elapsed_seconds"]) == (1, 2, 1.5)
    assert tx["tool_dns_time_seconds"] == 1.5 and tx["response_code"] == 0
    retry = analyzer.diagnose(analyzer.ingest_capture(Path("incoming/dns_retry.capture")))
    txs = value(retry, "analyze_dns")["transactions"]
    assert txs[0]["response_code"] == 2
    assert txs[1]["original_query_frame"] == 1 and txs[1]["response_frame"] == 3
    assert txs[1]["elapsed_seconds"] is None
    assert txs[2]["state"] == "unanswered_in_capture"


def test_reset_before_and_after_setup(tmp_path):
    analyzer, identity = prepare(tmp_path, "reset_tcp")
    r = value(analyzer.diagnose(identity), "analyze_tcp_resets")["resets"][0]
    assert r["frame"] == 6 and r["sender"]["address"] == "192.0.2.2" and r["ack"]
    assert r["phase"] == "after_establishment" and r["seconds_since_established"] == 0.08
    failed = analyzer.diagnose(analyzer.ingest_capture(Path("incoming/failed_tcp.capture")))
    assert value(failed, "analyze_tcp_establishment")["state"] == "reset_during_establishment"
    assert value(failed, "analyze_tcp_establishment")["establishment_seconds"] is None
    assert value(failed, "analyze_tcp_resets")["resets"][0]["phase"] == "during_establishment"


def test_tls_delay_is_separate_from_tcp_and_retries_are_indicators(tmp_path):
    analyzer, identity = prepare(tmp_path, "tls_delay")
    result = analyzer.diagnose(identity)
    assert value(result, "analyze_tcp_establishment")["establishment_seconds"] == 0.02
    tls = value(result, "analyze_tls_handshakes")
    assert tls["attempts"][0]["client_hello_to_server_hello_seconds"] == 1.0
    assert tls["attempts"][0]["tcp_established_to_client_hello_seconds"] == 0.08
    assert tls["session_completion"] == "unknown"
    assert tls["attempts"][0]["visible_handshake_interval_seconds"] is None
    retry = value(
        analyzer.diagnose(analyzer.ingest_capture(Path("incoming/tls_retry.capture"))),
        "analyze_tls_handshakes",
    )
    assert retry["repeated_client_hello_frames"] == [8]
    assert retry["alerts"][0]["frame"] == 9 and retry["alerts"][0]["descriptions"] == [40]


def test_pmtud_direct_signals_and_fragment_units(tmp_path):
    analyzer, identity = prepare(tmp_path, "pmtud_signals")
    result = analyzer.diagnose(identity)
    records = value(result, "analyze_pmtud_signals")["records"]
    assert [(r["frame"], r["kind"], r["mtu_bytes"]) for r in records] == [
        (2, "fragmentation_needed", 1200),
        (3, "packet_too_big", 1280),
    ]
    assert records[1]["source"] == "2001:db8::2"
    assert [
        e["scope"].get("tcp_stream")
        for e in result["evidence"]
        if e["category"] == "analyze_tcp_health"
    ] == [0]
    fragments = value(
        analyzer.diagnose(analyzer.ingest_capture(Path("incoming/fragments.capture"))),
        "analyze_fragmentation",
    )["records"]
    assert [(r["family"], r["offset_units_8_bytes"], r["more"]) for r in fragments] == [
        ("ipv4", 0, True),
        ("ipv4", 2, False),
        ("ipv6", 0, True),
        ("ipv6", 2, False),
    ]


@pytest.mark.parametrize(
    "name",
    [
        "empty",
        "midstream",
        "truncated",
        "checksum_offload",
        "timestamp_regression",
        "mixed_protocols",
    ],
)
def test_gate1_limitations_are_retained_and_missing_data_is_explicit(tmp_path, name):
    generate_baseline(tmp_path / "incoming")
    analyzer = Analyzer(tmp_path)
    identity = analyzer.ingest_capture(Path("incoming") / f"{name}.capture")
    result = analyzer.diagnose(identity)
    assert result["capture_quality_state"] != "good"
    if name == "midstream":
        assert value(result, "analyze_tcp_establishment")["state"] == "midstream"
        assert value(result, "analyze_tcp_establishment")["establishment_seconds"] is None
    if name == "timestamp_regression":
        assert value(result, "analyze_throughput")["directions"][0]["wire_bits_per_second"] is None
    for e in result["evidence"]:
        analyzer.validator.validate(e)
        assert e["limitations"]


@pytest.mark.parametrize(
    "limits,code",
    [
        (DiagnosticLimits(max_records=1), "diagnostic_evidence_record_limit"),
        (DiagnosticLimits(max_evidence_items=1), "diagnostic_evidence_record_limit"),
        (DiagnosticLimits(max_evidence_bytes=100), "diagnostic_evidence_byte_limit"),
    ],
)
def test_diagnostic_limit_failure_preserves_baseline_and_original(tmp_path, limits, code):
    analyzer, identity = prepare(tmp_path, "clean_tcp", diagnostic_limits=limits)
    with pytest.raises(AnalyzerError, match=code):
        analyzer.diagnose(identity)
    assert analyzer.store.verify(identity).exists()
    assert (tmp_path / f"cases/{identity}/normalized/capture-summary.json").exists()
    assert not (tmp_path / f"cases/{identity}/normalized/diagnostics.json").exists()


def test_fixed_capabilities_scoped_request_and_diagnostic_tool_failure(tmp_path):
    analyzer, identity = prepare(tmp_path, "clean_tcp")
    result = analyzer.run_diagnostic(DiagnosticRequest(identity, Capability.RTT, 0))
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["scope"]["tcp_stream"] == 0
    with pytest.raises(AnalyzerError, match="invalid_diagnostic_request"):
        analyzer.run_diagnostic({"capability": "sh -c id"})
    run = analyzer.runner.run

    def fail(operation, capture=None):
        if operation is Operation.DIAGNOSTICS:
            raise AnalyzerError("tool_output_limit", operation.value, "tshark")
        return run(operation, capture)

    with (
        patch.object(analyzer.runner, "run", side_effect=fail),
        pytest.raises(AnalyzerError, match="tool_output_limit"),
    ):
        analyzer.diagnose(identity)
    assert analyzer.analyze(identity)["evidence"][1]["value"]["state"] == "good"


def test_reassembled_tls_has_contributing_frames_without_payload(tmp_path):
    frames = handshake()
    ch = hello(1)
    frames += [
        (100_000, tcp(payload=ch[:20], flags=24)),
        (120_000, tcp(seq=121, payload=ch[20:], flags=24)),
    ]
    (tmp_path / "split.capture").write_bytes(timed_pcap(frames))
    analyzer = Analyzer(tmp_path)
    result = analyzer.diagnose(analyzer.ingest_capture(Path("split.capture")))
    tls = value(result, "analyze_tls_handshakes")
    assert tls["visible_messages"][0]["frame"] == 5
    assert tls["visible_messages"][0]["reassembly_frame_refs"] == [4, 5]
    assert tls["attempts"][0]["tcp_established_to_client_hello_seconds"] == 0.1


def test_real_syn_repetition_keeps_initial_attempt_timing(tmp_path):
    analyzer, identity = prepare(tmp_path, "syn_retry")
    result = analyzer.diagnose(identity)
    setup = value(result, "analyze_tcp_establishment")
    assert setup["syn_repeated_frames"] == [2]
    assert setup["syn_to_synack_seconds"] == 0.2
    assert setup["establishment_seconds"] == 0.21
    assert value(result, "analyze_tcp_health")["indicators"]["retransmission"]["frame_refs"] == [2]


def test_real_dns_over_tcp_and_coalesced_messages_are_not_flattened(tmp_path):
    query = dns_message()
    response = dns_message(response=True)
    for coalesced in (False, True):
        q = len(query).to_bytes(2, "big") + query
        if coalesced:
            extra = dns_message(43)
            q += len(extra).to_bytes(2, "big") + extra
        response_payload = len(response).to_bytes(2, "big") + response
        frames = [
            (0, tcp(seq=100, ack=0, flags=2, dport=53)),
            (10_000, tcp("192.0.2.2", "192.0.2.1", seq=200, ack=101, flags=18, sport=53)),
            (20_000, tcp(dport=53)),
            (40_000, tcp(payload=q, flags=24, dport=53)),
            (
                1_540_000,
                tcp(
                    "192.0.2.2",
                    "192.0.2.1",
                    seq=201,
                    ack=101 + len(q),
                    flags=24,
                    sport=53,
                    payload=response_payload,
                ),
            ),
        ]
        name = f"dns-tcp-{coalesced}.capture"
        (tmp_path / name).write_bytes(timed_pcap(frames))
        analyzer = Analyzer(tmp_path)
        value_ = value(analyzer.diagnose(analyzer.ingest_capture(Path(name))), "analyze_dns")
        if coalesced:
            assert value_["ambiguous_message_frames"] == [4]
            assert value_["transactions"] == []
        else:
            assert value_["transactions"][0]["transport"] == "tcp"
            assert value_["transactions"][0]["elapsed_seconds"] == 1.5
            assert value_["transactions"][0]["frame_refs"] == [4, 5]


def test_fragment_fixture_reassembled_transport_checksums_are_valid(tmp_path):
    analyzer, identity = prepare(tmp_path, "fragments")
    quality = analyzer.assess_capture_quality(identity)["value"]
    assert quality["checks"]["checksum_anomalies"]["frame_refs"] == []


def test_real_dns_sequences_separate_names_types_retries_and_resolvers(tmp_path):
    analyzer, identity = prepare(tmp_path, "dns_sequences")
    result = analyzer.diagnose(identity)
    output = value(result, "analyze_dns")
    assert len(output["name_resolution_sequences"]) == 3
    related, unrelated, missing = output["name_resolution_sequences"]
    assert related["transaction_query_frames"] == [1, 3, 6, 7]
    assert related["query_types"] == [1, 28]
    assert unrelated["transaction_query_frames"] == [2]
    assert missing["transaction_query_frames"] == [9]
    assert len({s["query_name_id"] for s in output["name_resolution_sequences"]}) == 3
    assert related["resolvers"] == [
        {"address": "192.0.2.53", "port": 53},
        {"address": "192.0.2.54", "port": 53},
    ]
    assert related["repeated_same_type_resolver_attempts"] == [
        {"query_frame": 6, "previous_query_frame": 1}
    ]
    assert related["resolver_or_transport_changes"][0]["to_query_frame"] == 7
    by_frame = {t["query_frame"]: t for t in output["transactions"]}
    assert by_frame[1]["state"] == by_frame[9]["state"] == "unanswered_in_capture"
    assert by_frame[7]["elapsed_seconds"] == 0.05
    assert by_frame[1]["transaction_id"] == by_frame[2]["transaction_id"]
    assert by_frame[1]["query_name_id"] != by_frame[2]["query_name_id"]
    assert all(
        name not in json.dumps(result)
        for name in ("related.invalid", "unrelated.invalid", "missing.invalid")
    )


@pytest.mark.parametrize("name", ["dns_quote4", "dns_quote6"])
def test_real_quoted_dns_is_decoded_by_tshark_but_excluded_from_live_evidence(tmp_path, name):
    analyzer, identity = prepare(tmp_path, name)
    raw = analyzer.runner.run(Operation.DIAGNOSTICS, analyzer.store.capture_path(identity))
    from wireclaw_analyzer.diagnostic_fields import EXTRA_FIELDS
    from wireclaw_analyzer.runner import FIELDS

    fields = FIELDS + EXTRA_FIELDS
    # The test must exercise real inner DNS dissection, not just absence of decoding.
    assert all(line.split("\t")[fields.index("dns.id")] for line in raw.splitlines())
    assert all(line.split("\t")[fields.index("dns.qry.name")] for line in raw.splitlines())
    result = analyzer.diagnose(identity)
    dns = value(result, "analyze_dns")
    assert next(e for e in result["evidence"] if e["category"] == "analyze_dns")["frame_refs"] == []
    assert dns["transactions"] == dns["name_resolution_sequences"] == []
    assert dns["ambiguous_message_frames"] == dns["orphan_response_frames"] == []
    assert len(value(result, "analyze_pmtud_signals")["records"]) == 2


def test_real_cname_target_identity_correlates_without_inventing_answer_chain(tmp_path):
    analyzer, identity = prepare(tmp_path, "dns_cname")
    dns = value(analyzer.diagnose(identity), "analyze_dns")
    assert dns["transactions"][0]["cname_target_ids"] == [dns["transactions"][1]["query_name_id"]]
    assert len(dns["name_resolution_sequences"]) == 2
    assert "alias.invalid" not in json.dumps(dns)


def test_real_reset_reconnect_keeps_observed_stream_and_frame_relationship(tmp_path):
    analyzer, identity = prepare(tmp_path, "reset_reconnect")
    resets = [
        e for e in analyzer.diagnose(identity)["evidence"] if e["category"] == "analyze_tcp_resets"
    ]
    assert len(resets) == 2
    assert resets[1]["value"]["observed_reconnect_attempts"] == [
        {"prior_reset_frame": 6, "prior_tcp_stream": 0, "syn_frame": 7, "seconds_since_reset": 0.1}
    ]
    assert resets[1]["value"]["resets"][0]["frame"] == 10


def test_real_dns_truncation_and_tcp_attempt_are_correlated_without_causal_claim(tmp_path):
    analyzer, identity = prepare(tmp_path, "dns_tcp_fallback")
    dns = value(analyzer.diagnose(identity), "analyze_dns")
    assert [t["transport"] for t in dns["transactions"]] == ["udp", "tcp"]
    assert dns["transactions"][0]["truncated_response"]
    assert len(dns["name_resolution_sequences"]) == 1
    change = dns["name_resolution_sequences"][0]["resolver_or_transport_changes"][0]
    assert change["transport_changed"] and change["previous_truncated_response"]
    assert dns["transactions"][1]["elapsed_seconds"] == 0.01


@pytest.mark.parametrize("name,expected", [("tls_clean", 0.02), ("tls12_clean", 0.01)])
def test_real_clean_tls12_and_tls13_have_decoded_handshakes_and_limited_completion(
    tmp_path, name, expected
):
    analyzer, identity = prepare(tmp_path, name)
    tls = value(analyzer.diagnose(identity), "analyze_tls_handshakes")
    assert [m["types"] for m in tls["visible_messages"]] == [[1], [2]]
    assert tls["attempts"][0]["client_hello_to_server_hello_seconds"] == expected
    assert tls["session_completion"] == "unknown"
