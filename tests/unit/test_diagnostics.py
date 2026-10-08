"""R-F006..010/R-F017: independent numeric expectations and conservative missing data."""

import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from wireclaw_analyzer import AnalyzerError, Capability, DiagnosticLimits, DiagnosticRequest
from wireclaw_analyzer import diagnostics as d
from wireclaw_analyzer.runner import FIELDS

LIMITS = DiagnosticLimits()
SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/evidence.schema.json").read_text()
)
VALIDATOR = Draft202012Validator(SCHEMA)


def line(frame=1, time="0", **fields):
    defaults = {
        "frame.number": str(frame),
        "frame.time_epoch": str(time),
        "frame.len": "54",
        "frame.cap_len": "54",
        "frame.protocols": "eth:ip:tcp",
        "ip.src": "192.0.2.1",
        "ip.dst": "192.0.2.2",
        "tcp.srcport": "50000",
        "tcp.dstport": "443",
        "tcp.stream": "0",
        "tcp.flags.ack": "1",
        "tcp.seq_raw": "101",
        "tcp.ack_raw": "201",
        "ip.proto": "6",
    }
    defaults.update(fields)
    return "\t".join(str(defaults.get(f, "")) for f in FIELDS + d.EXTRA_FIELDS)


def parse(*entries):
    return d.packets("\n".join(entries), 100_000, LIMITS, "0" * 64)


def reverse(**fields):
    return {
        "ip.src": "192.0.2.2",
        "ip.dst": "192.0.2.1",
        "tcp.srcport": "443",
        "tcp.dstport": "50000",
        "tcp.seq_raw": "201",
        "tcp.ack_raw": "101",
        **fields,
    }


def setup():
    return parse(
        line(
            **{"tcp.flags.syn": "1", "tcp.flags.ack": "0", "tcp.seq_raw": "100", "tcp.ack_raw": "0"}
        ),
        line(2, ".01", **reverse(**{"tcp.flags.syn": "1", "tcp.seq_raw": "200"})),
        line(3, ".02"),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("tcp.len", "-1"),
        ("tcp.len", "wat"),
        ("tcp.seq_raw", "4294967296"),
        ("tcp.window_size_scalefactor", "-3"),
        ("tcp.window_size_value", "65536"),
        ("tcp.analysis.ack_rtt", "nan"),
        ("tcp.analysis.ack_rtt", "1e999"),
        ("tcp.flags.reset", "yes"),
        ("tcp.analysis.retransmission", "arbitrary payload"),
        ("dns.id", "65536"),
        ("dns.response_to", "0"),
        ("dns.response_to", "2"),
        ("dns.time", "inf"),
        ("icmp.mtu", "65536"),
        ("icmpv6.mtu", "-1"),
        ("tls.handshake.type", "256"),
        ("tls.alert_message.desc", "$(id)"),
        ("frame.time_epoch", "1e999"),
    ],
)
def test_untrusted_numeric_fields_rejected(field, value):
    with pytest.raises(AnalyzerError):
        parse(line(**{field: value}))


def test_structural_parser_bounds_and_occurrences():
    with pytest.raises(AnalyzerError, match="invalid_diagnostic_output"):
        parse("missing columns")
    with pytest.raises(AnalyzerError, match="packet_result_limit"):
        d.packets(line() + "\n" + line(2), 1, LIMITS)
    with pytest.raises(AnalyzerError, match="diagnostic_occurrence_limit"):
        parse(line(**{"tls.handshake.type": ",".join(["1"] * 65)}))
    assert parse(line(**{"tls.handshake.type": "1,2,20"}))[0]["fields"]["tls.handshake.type"] == [
        1,
        2,
        20,
    ]
    nested = parse(line(**{"ip.src": "192.0.2.1,192.0.2.3"}))
    assert nested[0]["unsupported_diagnostic_layer"]
    assert not d.Index(nested).tcp


@pytest.mark.parametrize("cap", list(Capability))
def test_empty_capture_is_schema_valid_and_has_no_numeric_claim(cap):
    req = DiagnosticRequest("0" * 64, cap)
    evidence = d.build(
        req.capture_id, [], "4.2.2", {"limitations": ["empty capture"]}, LIMITS, VALIDATOR, req
    )
    assert len(evidence) == 1
    VALIDATOR.validate(evidence[0])
    assert evidence[0]["frame_refs"] == []
    assert "empty capture" in evidence[0]["limitations"]
    assert evidence == d.build(
        req.capture_id, [], "4.2.2", {"limitations": ["empty capture"]}, LIMITS, VALIDATOR, req
    )


def test_establishment_matches_sequence_numbers_and_repeated_syn():
    rows = setup()
    result = d.establishment(rows)
    assert result["state"] == "established"
    assert (result["syn_frame"], result["synack_frame"], result["final_ack_frame"]) == (1, 2, 3)
    assert result["establishment_seconds"] == 0.02
    rows[2]["fields"]["tcp.ack_raw"] = [999]
    assert d.establishment(rows)["state"] == "incomplete"
    assert d.establishment(rows)["establishment_seconds"] is None
    rows[2]["fields"]["tcp.flags.reset"] = [True]
    assert d.establishment(rows)["state"] == "reset_during_establishment"
    assert d.establishment(rows[2:])["state"] == "midstream"
    rows[2]["syn"], rows[2]["ack"] = True, False
    rows[2]["fields"]["tcp.seq_raw"] = [100]
    assert d.establishment(rows)["syn_repeated_frames"] == [3]


def test_timestamp_regression_withholds_lifecycle_rates_and_window_duration():
    rows = setup()
    rows[1]["time"] = Decimal("1")
    result = d.establishment(rows)
    assert result["state"] == "established"
    assert result["establishment_seconds"] is None
    assert d.throughput(rows, result)["directions"][0]["duration_seconds"] is None
    rows[0]["syn"] = False
    rows[0]["fields"]["tcp.window_size"] = [0]
    rows[2]["fields"]["tcp.window_size"] = [100]
    rows[2]["time"] = Decimal("-.01")
    assert d.windows(rows)["directions"][0]["zero_window_intervals"][0]["observed_seconds"] is None


def test_health_union_does_not_double_count_or_call_reordering_loss():
    rows = parse(
        line(
            **{
                "tcp.analysis.retransmission": "1",
                "tcp.analysis.fast_retransmission": "1",
                "tcp.len": "20",
            }
        ),
        line(2, **{"tcp.analysis.out_of_order": "1"}),
        line(3),
    )
    result = d.health(rows)
    assert result["retransmission_union_count"] == 1
    assert result["indicators"]["out_of_order"] == {
        "count": 1,
        "frame_refs": [2],
        "fraction_of_stream_frames": 1 / 3,
    }
    assert result["data_packets"] == 1
    assert d.health(rows[1:])["retransmission_union_count"] == 0


def test_ack_rtt_has_exact_samples_percentile_direction_and_rejections():
    rows = parse(
        line(),
        line(2, ".1", **reverse(**{"tcp.analysis.ack_rtt": ".1", "tcp.analysis.acks_frame": "1"})),
        line(3, ".2"),
        line(4, ".5", **reverse(**{"tcp.analysis.ack_rtt": ".3", "tcp.analysis.acks_frame": "3"})),
    )
    result = d.rtt(rows, d.Index(rows))
    assert result["sample_count"] == 2
    assert result["median_seconds"] == 0.2
    assert result["p95_seconds"] == 0.3
    assert [(s["ack_frame"], s["segment_frame"]) for s in result["samples"]] == [(2, 1), (4, 3)]
    rows[0]["fields"]["tcp.analysis.retransmission"] = [True]
    rows[2]["stream"] = 5
    rejected = d.rtt(rows, d.Index(rows))
    assert rejected["sample_count"] == 0
    assert rejected["rejected_ack_frames"] == [2, 4]


def test_windows_advertiser_reopen_extrema_and_missing_scale():
    rows = parse(
        line(
            **{
                "tcp.window_size": "0",
                "tcp.window_size_scalefactor": "-1",
                "tcp.analysis.zero_window": "1",
            }
        ),
        line(2, ".5", **{"tcp.window_size": "0"}),
        line(3, "1", **{"tcp.window_size": "1000"}),
    )
    result = d.windows(rows)
    a = result["directions"][0]
    assert a["scaling_factors"] == [-1]
    assert a["extreme_frame_refs"] == [1, 3]
    assert a["zero_window_intervals"] == [
        {"start_frame": 1, "reopen_frame": 3, "observed_seconds": 1.0, "state": "reopened"}
    ]
    assert (
        d.windows(rows[:2])["directions"][0]["zero_window_intervals"][0]["state"]
        == "open_at_capture_end"
    )
    assert d.windows(parse(line()))["directions"][0]["sample_count"] == 0


def test_resets_preserve_direction_flags_and_lifecycle():
    rows = setup()
    rows.extend(parse(line(**{"tcp.flags.reset": "1", "tcp.flags.ack": "0"})))
    rows[-1]["frame"], rows[-1]["time"] = 4, Decimal(".1")
    result = d.resets(rows, d.establishment(rows), d.Index(rows))
    assert result["count"] == 1
    r = result["resets"][0]
    assert r["sender"]["address"] == "192.0.2.1"
    assert r["ack"] is False and r["rst"] is True
    assert r["phase"] == "after_establishment"
    assert r["seconds_since_established"] == 0.08


def test_throughput_overlapping_ranges_ack_approximation_and_no_application_claim():
    rows = parse(
        line(**{"tcp.len": "20"}),
        line(2, ".1", **{"tcp.seq_raw": "111", "tcp.len": "20"}),
        line(
            3, ".2", **{"tcp.seq_raw": "101", "tcp.len": "20", "tcp.analysis.retransmission": "1"}
        ),
        line(4, ".3", **reverse(**{"tcp.ack_raw": "126"})),
    )
    result = d.throughput(rows, d.establishment(rows))["directions"][0]
    assert result["tcp_payload_bytes"] == 60
    assert result["unique_observed_payload_bytes"] == 30
    assert result["overlapping_payload_bytes"] == 30
    assert result["unique_acknowledged_payload_bytes"] == 25
    assert result["expert_marked_retransmitted_payload_bytes"] == 20
    assert result["tcp_goodput_approx_bits_per_second"] == pytest.approx(25 * 8 / 0.3)
    assert result["application_goodput_bits_per_second"] is None
    rows[1]["captured_bytes"] = 30
    assert (
        d.throughput(rows, d.establishment(rows))["directions"][0]["unique_observed_payload_bytes"]
        is None
    )
    assert d.union_length([(100, 120), (110, 130), (100, 120)]) == 30


def test_sequence_wrap_and_ambiguous_half_space_withhold_goodput():
    rows = parse(
        line(**{"tcp.seq_raw": str(2**32 - 10), "tcp.len": "20"}),
        line(2, ".1", **{"tcp.seq_raw": "10", "tcp.len": "10"}),
    )
    value = d.throughput(rows, d.establishment(rows))["directions"][0]
    assert value["unique_observed_payload_bytes"] == 30
    assert value["unique_acknowledged_payload_bytes"] is None
    rows[1]["fields"]["tcp.seq_raw"] = [2**31]
    assert (
        d.throughput(rows, d.establishment(rows))["directions"][0]["unique_observed_payload_bytes"]
        is None
    )


def udp_line(frame=1, time="0", **fields):
    return line(
        frame,
        time,
        **{
            "frame.protocols": "eth:ip:udp:dns",
            "tcp.stream": "",
            "tcp.srcport": "",
            "tcp.dstport": "",
            "tcp.flags.ack": "",
            "udp.stream": "0",
            "udp.srcport": "53000",
            "udp.dstport": "53",
            "ip.proto": "17",
            "dns.id": "42",
            "dns.flags.response": "0",
            **fields,
        },
    )


def dns_response(frame=2, time=".5", **fields):
    return udp_line(
        frame,
        time,
        **{
            "ip.src": "192.0.2.2",
            "ip.dst": "192.0.2.1",
            "udp.srcport": "53",
            "udp.dstport": "53000",
            "dns.flags.response": "1",
            "dns.response_to": "1",
            "dns.flags.rcode": "2",
            "dns.time": ".5",
            **fields,
        },
    )


def test_dns_reciprocal_links_retries_and_collision_protection():
    rows = parse(
        udp_line(**{"dns.response_in": "3"}),
        udp_line(2, ".1", **{"dns.retransmit_request": "1", "dns.retransmit_request_in": "1"}),
        dns_response(3),
        udp_line(4, "1", **{"dns.id": "43"}),
    )
    tx = d.dns(d.Index(rows))["transactions"]
    assert tx[0]["elapsed_seconds"] == 0.5 and tx[0]["response_code"] == 2
    assert tx[1]["state"] == "response_linked_to_original_query"
    assert tx[1]["elapsed_seconds"] is None and tx[1]["frame_refs"] == [1, 2, 3]
    assert tx[2]["state"] == "unanswered_in_capture"
    rows[2]["dst_port"] = 54000
    assert d.dns(d.Index(rows))["transactions"][0]["state"] == "ambiguous_link"


def test_dns_multimessage_orphan_and_negative_timing():
    rows = parse(
        udp_line(**{"dns.id": "42,43", "dns.flags.response": "0,0"}),
        dns_response(**{"dns.response_to": ""}),
    )
    value = d.dns(d.Index(rows))
    assert value["ambiguous_message_frames"] == [1]
    assert value["orphan_response_frames"] == [2]
    rows = parse(udp_line(time="1", **{"dns.response_in": "2"}), dns_response(time=".5"))
    assert d.dns(d.Index(rows))["transactions"][0]["elapsed_seconds"] is None


def test_tls_message_completion_intervals_retries_alerts_and_reassembly_refs():
    rows = setup()
    rows.extend(
        parse(
            line(**{"tls.handshake.type": "1"}),
            line(
                2,
                "1",
                **reverse(
                    **{
                        "tls.handshake.type": "2,20",
                        "tls.alert_message.level": "2",
                        "tls.alert_message.desc": "40",
                        "tls.record.content_type": "21",
                    }
                ),
            ),
        )
    )
    for f, r in enumerate(rows[3:], 4):
        r["frame"] = f
        r["time"] += Decimal(".1")
    rows[4]["fields"]["tcp.segment"] = [4]
    value = d.tls(rows, d.establishment(rows), d.Index(rows))
    assert value["attempts"][0]["tcp_established_to_client_hello_seconds"] == 0.08
    assert value["attempts"][0]["client_hello_to_server_hello_seconds"] == 1.0
    assert value["visible_messages"][1]["types"] == [2, 20]
    assert value["visible_messages"][1]["reassembly_frame_refs"] == [4]
    assert value["alerts"][0]["descriptions"] == [40]
    assert value["session_completion"] == "unknown"
    assert d.tls(setup(), d.establishment(setup()), d.Index(setup()))["state"] == "not_observable"


def test_network_signals_do_not_assign_quoted_streams_or_force_mtu_diagnosis():
    rows = parse(
        line(
            **{
                "frame.protocols": "eth:ip:icmp:ip:tcp",
                "icmp.type": "3",
                "icmp.code": "4",
                "icmp.mtu": "1200",
                "ip.src": "192.0.2.1,192.0.2.2",
                "ip.len": "56,1500",
            }
        )
    )
    assert rows[0]["transport"] == "other"
    assert not d.Index(rows).tcp
    signals = d.network(d.Index(rows), Capability.PMTUD)
    assert signals["records"][0]["mtu_bytes"] == 1200
    assert signals["packet_size_patterns"][0]["maximum_ip_bytes"] == 56
    rows[0]["fields"]["icmp.code"] = [3]
    assert d.network(d.Index(rows), Capability.PMTUD)["records"] == []
    rows[0]["fields"]["ip.flags.mf"] = [True]
    assert d.network(d.Index(rows), Capability.FRAGMENTATION)["records"][0]["more"]
    direct = parse(line(**{"ip.flags.mf": "1"}))
    assert d.network(d.Index(direct), Capability.FRAGMENTATION)["records"][0]["more"]
    tcp_rows = parse(line(**{"tcp.options.mss_val": "1460"}))
    assert d.network(d.Index(tcp_rows), Capability.MSS)["records"][0]["mss_bytes"] == 1460


def test_bounded_frame_refs_use_range_and_internal_filter():
    rows = parse(*(line(f, str(f), **{"tcp.len": "0"}) for f in range(1, 20)))
    req = DiagnosticRequest("0" * 64, Capability.ESTABLISHMENT)
    result = d.build(
        req.capture_id, rows, "4.2.2", {}, DiagnosticLimits(max_frame_refs=2), VALIDATOR, req
    )[0]
    assert result["frame_refs"] == []
    assert result["value"]["supporting_frame_range"] == {
        "start": 1,
        "end": 19,
        "selection": "tcp.stream == 0",
    }
    assert result["scope"]["tcp_stream"] == 0


@pytest.mark.parametrize(
    "values", [{"max_records": 0}, {"max_frame_refs": True}, {"max_evidence_bytes": 1.5}]
)
def test_diagnostic_limits_are_typed_positive(values):
    with pytest.raises(AnalyzerError, match="invalid_diagnostic_limits"):
        DiagnosticLimits(**values)


@pytest.mark.parametrize(
    "cap,stream",
    [("arbitrary", None), (Capability.RTT, True), (Capability.RTT, -1), (Capability.DNS, 1)],
)
def test_request_cannot_supply_arbitrary_command_or_filter(cap, stream):
    with pytest.raises(AnalyzerError):
        DiagnosticRequest("0" * 64, cap, stream)


def test_result_record_byte_and_missing_stream_limits():
    rows = setup()
    req = DiagnosticRequest("0" * 64, Capability.ESTABLISHMENT)
    with pytest.raises(AnalyzerError, match="diagnostic_evidence_record_limit"):
        d.build(req.capture_id, rows, "4.2.2", {}, DiagnosticLimits(max_records=1), VALIDATOR, req)
    with pytest.raises(AnalyzerError, match="diagnostic_evidence_byte_limit"):
        d.build(
            req.capture_id,
            rows,
            "4.2.2",
            {},
            DiagnosticLimits(max_evidence_bytes=10),
            VALIDATOR,
            req,
        )
    with pytest.raises(AnalyzerError, match="tcp_stream_unavailable"):
        d.build(
            req.capture_id,
            rows,
            "4.2.2",
            {},
            LIMITS,
            VALIDATOR,
            DiagnosticRequest(req.capture_id, Capability.RTT, 20),
        )


def test_many_streams_index_capture_once_and_per_stream_work_is_linear():
    class CountRows(list):
        visits = 0

        def __iter__(self):
            for row in super().__iter__():
                self.visits += 1
                yield row

    rows = CountRows(parse(*(line(i + 1, str(i), **{"tcp.stream": str(i)}) for i in range(600))))
    req = DiagnosticRequest("0" * 64, Capability.THROUGHPUT)
    result = d.build(req.capture_id, rows, "4.2.2", {}, LIMITS, VALIDATOR, req)
    assert len(result) == 600
    assert rows.visits == len(rows)  # full capture touched only by Index
    assert all(e["value"]["directions"][0]["packets"] == 1 for e in result)


def test_sequence_union_sorts_once_and_consumes_input_once():
    class Intervals:
        count = 0

        def __iter__(self):
            for n in range(10_000, 0, -1):
                self.count += 1
                yield n, n + 10

    ranges = Intervals()
    assert d.union_length(ranges) == 10_009
    assert ranges.count == 10_000


def test_negative_tool_timing_is_observed_but_never_aggregated():
    rows = parse(
        line(time="1"),
        line(2, ".5", **reverse(**{"tcp.analysis.ack_rtt": "-.5", "tcp.analysis.acks_frame": "1"})),
    )
    value = d.rtt(rows, d.Index(rows))
    assert value["sample_count"] == 0 and value["rejected_ack_frames"] == [2]


def test_stream_identity_inconsistency_is_rejected_before_per_stream_passes():
    rows = parse(line(), line(2, **{"tcp.srcport": "50001"}))
    with pytest.raises(AnalyzerError, match="inconsistent_tcp_stream_identity"):
        d.Index(rows)


def test_missing_endpoint_cannot_become_unvalidated_scope():
    with pytest.raises(AnalyzerError, match="invalid_diagnostic_output"):
        parse(line(**{"tcp.srcport": ""}))


def test_nested_frame_arrays_are_bounded_without_silent_sampling():
    rows = parse(*(line(f, **{"tcp.analysis.retransmission": "1"}) for f in range(1, 4)))
    req = DiagnosticRequest("0" * 64, Capability.HEALTH)
    with pytest.raises(AnalyzerError, match="diagnostic_frame_reference_limit"):
        d.build(
            req.capture_id, rows, "4.2.2", {}, DiagnosticLimits(max_frame_refs=2), VALIDATOR, req
        )


@pytest.mark.parametrize("name", ["Example.INVALID", "example.invalid.", "EXAMPLE.invalid."])
def test_dns_identity_normalizes_case_and_root_dot(name):
    assert d.name_identity(name, "0" * 64) == d.name_identity("example.invalid", "0" * 64)
    assert d.name_identity(name, "0" * 64) != d.name_identity(name, "1" * 64)
    assert d.name_identity(name, "0" * 64) != d.name_identity("other.invalid", "0" * 64)


@pytest.mark.parametrize(
    "name",
    ["", "a..b", "a." * 128, "a" * 64, "$(touch x)", "a\\000b", "a\x00b", "a\tb", "é.invalid"],
)
def test_dns_names_fail_safely_without_echoing_untrusted_text(name):
    with pytest.raises(AnalyzerError, match="invalid_dns_name") as error:
        d.name_identity(name, "0" * 64)
    assert name not in str(error.value) if name else True


def test_dns_text_occurrences_are_bounded_and_pseudonymized_during_parse():
    with pytest.raises(AnalyzerError, match="diagnostic_occurrence_limit"):
        parse(udp_line(**{"dns.qry.name": ",".join(["example.invalid"] * 65)}))
    rows = parse(udp_line(**{"dns.qry.name": "Example.invalid."}))
    assert "example.invalid" not in repr(rows).lower()
    assert first_identity(rows) == d.name_identity("example.invalid", "0" * 64)


def first_identity(rows):
    return d.first(rows[0], "dns.qry.name")


@pytest.mark.parametrize("stack", ["eth:ip:icmp:ip:udp:dns", "eth:ipv6:icmpv6:ipv6:udp:dns"])
def test_quoted_dns_never_enters_transactions_or_sequences(stack):
    rows = parse(
        udp_line(**{"frame.protocols": stack, "dns.qry.name": "example.invalid"}),
        dns_response(**{"frame.protocols": stack, "dns.qry.name": "example.invalid"}),
    )
    result = d.dns(d.Index(rows))
    assert result["transactions"] == result["name_resolution_sequences"] == []
    assert result["ambiguous_message_frames"] == result["orphan_response_frames"] == []
    assert not any(row["fields"]["dns.qry.name"] for row in rows)


def test_dns_different_name_collision_cannot_pair_or_link_retry():
    rows = parse(
        udp_line(**{"dns.qry.name": "one.invalid", "dns.response_in": "3"}),
        udp_line(
            2,
            ".1",
            **{
                "dns.qry.name": "two.invalid",
                "dns.retransmit_request": "1",
                "dns.retransmit_request_in": "1",
            },
        ),
        dns_response(3, **{"dns.qry.name": "two.invalid"}),
    )
    result = d.dns(d.Index(rows))
    assert result["transactions"][0]["state"] == "ambiguous_link"
    assert result["transactions"][1]["state"] == "unanswered_in_capture"
    assert len(result["name_resolution_sequences"]) == 2


def test_dns_sequences_retain_order_and_withhold_regressed_timing():
    rows = parse(
        udp_line(time="1", **{"dns.qry.name": "one.invalid", "dns.qry.type": "28"}),
        udp_line(2, ".5", **{"dns.qry.name": "one.invalid", "dns.qry.type": "1"}),
        udp_line(3, "2", **{"dns.qry.name": "one.invalid", "dns.qry.type": "1"}),
    )
    result = d.dns(d.Index(rows))
    sequence = result["name_resolution_sequences"][0]
    assert sequence["transaction_query_frames"] == [1, 2, 3]
    assert sequence["query_types"] == [1, 28]
    assert sequence["observed_span_seconds"] is None
    assert not sequence["timing_reliable"]
    assert sequence["repeated_same_type_resolver_attempts"] == [
        {"query_frame": 3, "previous_query_frame": 2}
    ]
    assert all(t["state"] == "unanswered_in_capture" for t in result["transactions"])


def test_many_dns_names_are_grouped_in_one_transaction_pass_and_use_bounded_scope():
    class CountRows(list):
        visits = 0

        def __iter__(self):
            for row in super().__iter__():
                self.visits += 1
                yield row

    rows = parse(
        *(udp_line(f, str(f), **{"dns.qry.name": f"name{f % 100}.invalid"}) for f in range(1, 3001))
    )
    index = d.Index(rows)
    result = d.dns(index)
    transactions = CountRows(result["transactions"])
    sequences = d.dns_sequences(transactions, index, LIMITS)
    assert len(sequences) == 100
    assert transactions.visits == len(transactions)
    assert sum(len(s["transaction_query_frames"]) for s in sequences) == 3000
    small = d.dns_sequences(transactions, index, DiagnosticLimits(max_frame_refs=2))
    assert all(s["frame_refs"] == [] and s["supporting_frame_range"] for s in small)
    assert all(s["transaction_query_frames"] == [] and s["transaction_count"] == 30 for s in small)
    req = DiagnosticRequest("0" * 64, Capability.DNS)
    with pytest.raises(AnalyzerError, match="diagnostic_evidence_record_limit"):
        d.build(req.capture_id, rows, "4.2.2", {}, DiagnosticLimits(max_records=10), VALIDATOR, req)


@pytest.mark.parametrize("name", ["odd!name.invalid", "a..b", "a" * 255, "a\\000b"])
def test_unsupported_dns_name_preserves_numeric_transaction_without_raw_name(name):
    rows = parse(
        udp_line(**{"dns.qry.name": name, "dns.response_in": "2", "dns.qry.type": "1"}),
        dns_response(**{"dns.qry.name": name, "dns.qry.type": "1"}),
    )
    result = d.dns(d.Index(rows))
    tx = result["transactions"][0]
    assert tx["query_name_id"] is None
    assert tx["response_frame"] == 2 and tx["elapsed_seconds"] == 0.5
    assert tx["transaction_id"] == 42 and tx["response_code"] == 2
    assert tx["limitations"] and result["name_resolution_sequences"] == []
    assert name not in repr(rows) and name not in json.dumps(result)


def test_unsupported_cname_withholds_identity_correlation_without_discarding_response():
    rows = parse(
        udp_line(**{"dns.qry.name": "example.invalid", "dns.response_in": "2"}),
        dns_response(**{"dns.qry.name": "example.invalid", "dns.cname": "odd!alias.invalid"}),
    )
    result = d.dns(d.Index(rows))
    tx = result["transactions"][0]
    assert tx["query_name_id"] is None and tx["cname_target_ids"] == []
    assert tx["elapsed_seconds"] == 0.5 and tx["response_code"] == 2
    assert result["name_resolution_sequences"] == []
    assert any("CNAME" in limitation for limitation in tx["limitations"])


def test_icmp_quote_inner_fragment_is_not_outer_but_outer_fragment_is_retained():
    fields = {
        "frame.protocols": "eth:ip:icmp:ip:udp",
        "ip.flags.mf": "0,1",
        "ip.frag_offset": "0,2",
        "ip.id": "1,99",
    }
    rows = parse(line(**fields))
    assert d.network(d.Index(rows), Capability.FRAGMENTATION)["records"] == []
    fields.update({"ip.flags.mf": "1,1", "ip.frag_offset": "0,2"})
    record = d.network(d.Index(parse(line(**fields))), Capability.FRAGMENTATION)["records"][0]
    assert record["more"] and record["offset_units_8_bytes"] == 0 and record["identification"] == 1


def test_ipv6_quote_inner_fragment_is_excluded_without_outer_fragment_extension():
    fields = {
        "frame.protocols": "eth:ipv6:icmpv6:ipv6:ipv6.fraghdr:udp",
        "ip.src": "",
        "ip.dst": "",
        "ipv6.src": "2001:db8::1,2001:db8::2",
        "ipv6.dst": "2001:db8::2,2001:db8::1",
        "ipv6.nxt": "58,44",
        "ipv6.fraghdr.ident": "99",
        "ipv6.fraghdr.offset": "2",
        "ipv6.fraghdr.more": "1",
    }
    rows = parse(line(**fields))
    assert d.network(d.Index(rows), Capability.FRAGMENTATION)["records"] == []
    fields.update(
        {
            "frame.protocols": "eth:ipv6:ipv6.fraghdr:icmpv6:ipv6:ipv6.fraghdr:udp",
            "ipv6.nxt": "44,44",
            "ipv6.fraghdr.ident": "77,99",
            "ipv6.fraghdr.offset": "0,2",
            "ipv6.fraghdr.more": "1,1",
        }
    )
    record = d.network(d.Index(parse(line(**fields))), Capability.FRAGMENTATION)["records"][0]
    assert record["identification"] == 77 and record["offset_units_8_bytes"] == 0 and record["more"]


def test_nonzero_icmpv6_ptb_code_is_not_a_valid_signal():
    rows = parse(
        line(**{"frame.protocols": "eth:ip:icmpv6", "icmpv6.type": "2", "icmpv6.code": "1"})
    )
    assert d.network(d.Index(rows), Capability.PMTUD)["records"] == []


def test_exact_capture_network_support_and_bounded_range_filter():
    rows = setup()
    rows.extend(parse(line(**{"tcp.options.mss_val": "1460"})))
    rows[3]["frame"] = 4
    req = DiagnosticRequest("0" * 64, Capability.MSS)
    record = d.build(req.capture_id, rows, "4.2.2", {}, LIMITS, VALIDATOR, req)[0]
    assert record["frame_refs"] == [4] and record["display_filter"] == "frame.number == 4"
    for row in rows:
        row["fields"]["tcp.options.mss_val"] = [1460]
    record = d.build(
        req.capture_id, rows, "4.2.2", {}, DiagnosticLimits(max_frame_refs=2), VALIDATOR, req
    )[0]
    assert record["frame_refs"] == []
    assert record["value"]["supporting_frame_range"] == {
        "start": 1,
        "end": 4,
        "selection": "tcp.options.mss_val",
    }


def test_unsupported_original_retry_name_withholds_sequence_only():
    rows = parse(
        udp_line(**{"dns.response_in": "3", "dns.qry.name": "odd!name.invalid"}),
        udp_line(
            2,
            ".1",
            **{
                "dns.retransmit_request": "1",
                "dns.retransmit_request_in": "1",
                "dns.qry.name": "example.invalid",
            },
        ),
        dns_response(3, **{"dns.qry.name": "example.invalid"}),
    )
    result = d.dns(d.Index(rows))
    assert [t["response_frame"] for t in result["transactions"]] == [3, 3]
    assert all(t["query_name_id"] is None and t["limitations"] for t in result["transactions"])
    assert result["name_resolution_sequences"] == []


@pytest.mark.parametrize("unsupported", ["dns", "nested"])
def test_unsupported_domain_does_not_mask_structural_corruption(unsupported):
    entry = (
        udp_line(**{"dns.qry.name": "odd!name.invalid", "dns.id": "not-a-number"})
        if unsupported == "dns"
        else line(**{"frame.protocols": "eth:ip:ip:tcp", "tcp.len": "not-a-number"})
    )
    with pytest.raises(AnalyzerError) as error:
        parse(entry)
    assert error.value.code == "invalid_diagnostic_output"
    assert "odd!name.invalid" not in str(error.value)
