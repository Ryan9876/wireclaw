import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from wireclaw_analyzer import AnalyzerError, normalize
from wireclaw_analyzer.runner import FIELDS


def test_hostile_protocol_text_rejected():
    columns = {key: "" for key in FIELDS}
    columns.update(
        {
            "frame.number": "1",
            "frame.time_epoch": "1",
            "frame.len": "1",
            "frame.cap_len": "1",
            "frame.protocols": "$(touch injected)",
        }
    )
    with pytest.raises(AnalyzerError, match="invalid_packet_output"):
        normalize.packets("\t".join(columns.values()), 10)


@pytest.mark.parametrize("text", ["\x00", "incomplete\tcolumns", "a\n" * 10])
def test_malformed_tool_output(text):
    with pytest.raises(AnalyzerError):
        normalize.packets(text, 1)


def test_decimal_timestamp_duration():
    rows = [
        {
            "src": "192.0.2.1",
            "dst": "192.0.2.2",
            "src_port": 1,
            "dst_port": 2,
            "transport": "tcp",
            "stream": 0,
            "wire_bytes": 1,
            "frame": i + 1,
            "time": Decimal(time),
        }
        for i, time in enumerate(("1700000000.000000001", "1700000000.000000002"))
    ]
    assert normalize.conversations(rows)["conversations"][0]["duration_seconds"] == 1e-9


def test_evidence_schema_rejects_inferred_packet_facts():
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "contracts/evidence.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)
    Draft202012Validator.check_schema(schema)
    with pytest.raises(ValidationError):
        validator.validate({"epistemic_class": "inferred"})


@pytest.mark.parametrize("stream_count", [1, 3000])
def test_many_interleaved_tcp_streams_have_bounded_row_visits(stream_count):
    # Count iterable work rather than timing: a rescan per conversation exceeds
    # this constant-pass budget, even if it happens to run quickly on a host.
    class CountedRows(list):
        visits = 0

        def __iter__(self):
            for row in super().__iter__():
                self.visits += 1
                assert self.visits <= 12 * len(self), "unbounded per-conversation packet rescan"
                yield row

    rows = CountedRows()
    expected_midstream, expected_incomplete = [], []
    for phase in range(3):
        for stream in range(stream_count):
            kind = stream % 3
            if (kind == 1 and phase > 0) or (kind == 2 and phase > 1):
                continue
            reverse = phase == 1
            frame = len(rows) + 1
            rows.append(
                {
                    "src": "192.0.2.2" if reverse else "192.0.2.1",
                    "dst": "192.0.2.1" if reverse else "192.0.2.2",
                    "src_port": 443 if reverse else 10000 + stream,
                    "dst_port": 10000 + stream if reverse else 443,
                    "transport": "tcp",
                    "stream": stream,
                    "wire_bytes": 54,
                    "captured_bytes": 54,
                    "frame": frame,
                    "time": Decimal(frame),
                    "syn": kind != 1 and phase < 2,
                    "ack": kind == 1 or phase > 0,
                    "malformed": False,
                    "bad_checksum": False,
                }
            )
            if kind == 1:
                expected_midstream.append(frame)
            elif kind == 2:
                expected_incomplete.append(frame)
    inventory = normalize.conversations(rows)
    assert len(inventory["conversations"]) == stream_count
    rows.visits = 0
    quality = normalize.quality({"capture_drops": None}, rows, inventory)
    assert quality["checks"]["midstream_indicators"]["frame_refs"] == expected_midstream
    assert quality["checks"]["incomplete_handshakes"]["frame_refs"] == expected_incomplete
    assert rows.visits <= 12 * len(rows)


@pytest.mark.parametrize("column", ["ip.proto", "ipv6.nxt"])
@pytest.mark.parametrize("value", ["-1", "256", "not-a-number"])
def test_network_protocol_number_is_validated(column, value):
    columns = dict.fromkeys(FIELDS, "")
    columns.update(
        {
            "frame.number": "1",
            "frame.time_epoch": "1",
            "frame.len": "54",
            "frame.cap_len": "54",
            "frame.protocols": "ip",
            "ip.src" if column == "ip.proto" else "ipv6.src": "192.0.2.1"
            if column == "ip.proto"
            else "2001:db8::1",
            column: value,
        }
    )
    with pytest.raises(AnalyzerError, match="invalid_packet_output"):
        normalize.packets("\t".join(columns.values()), 10)


def test_ipv6_extension_protocols_do_not_collapse():
    rows = [
        {
            "src": "2001:db8::1",
            "dst": "2001:db8::2",
            "src_port": None,
            "dst_port": None,
            "stream": None,
            "transport": "other",
            "ip_protocol": 0,
            "protocols": ["eth", "ipv6", "ipv6.hopopts", protocol],
            "frame": i + 1,
            "time": Decimal(i),
            "wire_bytes": 64,
        }
        for i, protocol in enumerate(("icmpv6", "sctp"))
    ]
    inventory = normalize.conversations(rows)
    assert len(inventory["conversations"]) == 2
    assert [c["network_protocol"]["dissector"] for c in inventory["conversations"]] == [
        "icmpv6",
        "sctp",
    ]


def test_non_transport_payload_layers_do_not_split_same_protocol():
    rows = [
        {
            "src": src,
            "dst": dst,
            "src_port": None,
            "dst_port": None,
            "stream": None,
            "transport": "other",
            "ip_protocol": 1,
            "protocols": stack,
            "frame": i + 1,
            "time": Decimal(i),
            "wire_bytes": 64,
        }
        for i, (src, dst, stack) in enumerate(
            (
                ("192.0.2.1", "192.0.2.2", ["eth", "ip", "icmp", "data"]),
                ("192.0.2.2", "192.0.2.1", ["eth", "vlan", "ip", "icmp"]),
            )
        )
    ]
    conv = normalize.conversations(rows)["conversations"]
    assert len(conv) == 1
    assert conv[0]["network_protocol"] == {"number": 1}
    assert conv[0]["a_to_b_packets"] == conv[0]["b_to_a_packets"] == 1
