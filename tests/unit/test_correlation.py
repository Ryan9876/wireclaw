import pytest
from wireclaw_api.correlation import correlate_tcp, estimate_clock_alignment


def packet(frame, time, src, dst, sport, dport, flags, seq, ack=0, payload=0):
    return {
        "frame": frame,
        "time": time,
        "src": src,
        "dst": dst,
        "src_port": sport,
        "dst_port": dport,
        "syn": "S" in flags,
        "ack": "A" in flags,
        "seq_raw": seq,
        "ack_raw": ack,
        "payload_len": payload,
    }


def test_correlate_tcp_matches_exact_bidirectional_flow_observations():
    client = {
        "id": "client-id",
        "vantage_type": "client",
        "observations": [packet(1, 10.0, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100)],
    }
    server = {
        "id": "server-id",
        "vantage_type": "server",
        "observations": [packet(8, 10.2, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100)],
    }
    result = correlate_tcp([client, server], [])
    assert len(result) == 1
    assert result[0]["capture_ids"] == ["client-id", "server-id"]
    assert result[0]["matched_packets"] == 1
    assert result[0]["vantages"] == ["client", "server"]


def test_correlation_provenance_uses_evidence_linked_to_each_matched_frame():
    client = {
        "id": "client-id",
        "vantage_type": "client",
        "observations": [packet(99, 10.0, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100)],
    }
    server = {
        "id": "server-id",
        "vantage_type": "server",
        "observations": [packet(199, 10.2, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100)],
    }
    evidence = [
        *(
            {
                "id": f"client-unrelated-{index:02d}",
                "capture_id": "client-id",
                "frame_refs": [index + 1],
            }
            for index in range(12)
        ),
        {"id": "client-syn", "capture_id": "client-id", "frame_refs": [99]},
        *(
            {
                "id": f"server-unrelated-{index:02d}",
                "capture_id": "server-id",
                "frame_refs": [index + 101],
            }
            for index in range(12)
        ),
        {"id": "server-syn", "capture_id": "server-id", "frame_refs": [199]},
    ]

    result = correlate_tcp([client, server], evidence)

    assert result[0]["capture_evidence_ids"] == {
        "client-id": ["client-syn"],
        "server-id": ["server-syn"],
    }
    assert result[0]["evidence_ids"] == ["client-syn", "server-syn"]


def test_correlate_tcp_does_not_match_same_ports_with_different_sequence():
    captures = [
        {
            "id": "a",
            "observations": [packet(1, 1.0, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100)],
        },
        {
            "id": "b",
            "observations": [packet(1, 1.1, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 900)],
        },
    ]
    assert correlate_tcp(captures, []) == []


def test_reused_tuple_with_new_syn_sequence_keeps_connection_epochs_separate():
    first_syn = packet(1, 1.0, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100)
    second_syn = packet(5, 5.0, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 900)
    result = correlate_tcp(
        [
            {"id": "client", "observations": [first_syn, second_syn]},
            {
                "id": "server",
                "observations": [first_syn | {"frame": 9}, second_syn | {"frame": 13}],
            },
        ],
        [],
    )
    assert len(result) == 2
    assert [
        {
            key: {"frame": value["frame"], "time": value["time"]}
            for key, value in row["matched_frames"][0].items()
        }
        for row in result
    ] == [
        {"client": {"frame": 1, "time": 1.0}, "server": {"frame": 9, "time": 1.0}},
        {"client": {"frame": 5, "time": 5.0}, "server": {"frame": 13, "time": 5.0}},
    ]


def test_clock_alignment_requires_enough_matches_and_reports_uncertainty():
    result = estimate_clock_alignment(
        [{"reference_time": value, "observed_time": value + 4.25} for value in (1, 3, 5, 7)]
    )
    assert result["offset_seconds"] == pytest.approx(4.25)
    assert result["uncertainty_seconds"] == pytest.approx(0)
    assert result["matched_count"] == 4
    assert result["usable"] is True
    assert estimate_clock_alignment([{"reference_time": 1, "observed_time": 2}])["usable"] is False


def test_clock_alignment_with_jitter_material_to_delay_is_not_usable():
    result = estimate_clock_alignment(
        [
            {"reference_time": 1, "observed_time": 1.0},
            {"reference_time": 2, "observed_time": 2.5},
            {"reference_time": 3, "observed_time": 3.0},
            {"reference_time": 4, "observed_time": 5.0},
        ],
        claimed_delay_seconds=0.2,
    )
    assert result["usable"] is False


def test_clock_alignment_rejects_material_offset_disagreement_and_regression():
    disagreement = estimate_clock_alignment(
        [
            {"reference_time": 0, "observed_time": 1.0},
            {"reference_time": 1, "observed_time": 2.0},
            {"reference_time": 2, "observed_time": 4.0},
        ]
    )
    regression = estimate_clock_alignment(
        [
            {"reference_time": 0, "observed_time": 1.0},
            {"reference_time": 1, "observed_time": 2.0},
            {"reference_time": 2, "observed_time": 3.0, "timing_regression": True},
        ]
    )
    assert disagreement["usable"] is False
    assert regression["usable"] is False


def test_clock_alignment_uses_repeated_packet_identity_to_tolerate_one_delayed_packet():
    result = estimate_clock_alignment(
        [
            {"reference_time": 1.0, "observed_time": 1.01},
            {"reference_time": 2.0, "observed_time": 2.01},
            {"reference_time": 3.0, "observed_time": 0.1},
            {"reference_time": 4.0, "observed_time": 4.01},
            {"reference_time": 5.0, "observed_time": 5.01},
        ]
    )
    assert result["offset_seconds"] == pytest.approx(0.01)
    assert result["matched_count"] == 4
    assert result["uncertainty_seconds"] == pytest.approx(0)
    assert result["usable"] is True
