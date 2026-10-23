from wireclaw_api.correlation import correlate_tcp
from wireclaw_api.investigation import build_investigation_result, localize_tcp_correlations


def matched(kind, client_time, server_time, *, offset=0.0, uncertainty=0.001):
    syn = kind in ("syn", "syn_ack")
    ack = kind == "syn_ack"
    return {
        "capture_ids": ["client", "server"],
        "capture_vantages": {"client": "client", "server": "server"},
        "capture_evidence_ids": {
            "client": [f"ev-{kind}-client"],
            "server": [f"ev-{kind}-server"],
        },
        "evidence_ids": [f"ev-{kind}-client", f"ev-{kind}-server"],
        "matching_strength": "exact_packet_signature",
        "matched_frames": [
            {
                "client": {
                    "frame": 1 if not ack else 8,
                    "time": client_time,
                    "syn": syn,
                    "ack": ack,
                    "src": "192.0.2.2" if ack else "192.0.2.1",
                    "dst": "192.0.2.1" if ack else "192.0.2.2",
                    "src_port": 443 if ack else 50000,
                    "dst_port": 50000 if ack else 443,
                    "seq_raw": 900 if ack else 100,
                    "ack_raw": 101 if ack else 0,
                },
                "server": {
                    "frame": 3 if not ack else 10,
                    "time": server_time,
                    "syn": syn,
                    "ack": ack,
                    "src": "192.0.2.2" if ack else "192.0.2.1",
                    "dst": "192.0.2.1" if ack else "192.0.2.2",
                    "src_port": 443 if ack else 50000,
                    "dst_port": 50000 if ack else 443,
                    "seq_raw": 900 if ack else 100,
                    "ack_raw": 101 if ack else 0,
                },
            }
        ],
        "clock_alignment": {
            "offset_seconds": offset,
            "uncertainty_seconds": uncertainty,
            "matched_count": 4,
            "usable": True,
        },
        "limitations": [],
    }


def test_server_response_delay_requires_exact_syn_and_syn_ack_at_both_vantages():
    findings = localize_tcp_correlations(
        [matched("syn", 0.0, 0.01), matched("syn_ack", 3.22, 3.21)]
    )
    finding = next(item for item in findings if item["category"] == "tcp.server_response_delay")
    assert finding["fault_domains"] == ["server_application"]
    assert set(finding["evidence_ids"]) == {
        "ev-syn-client",
        "ev-syn-server",
        "ev-syn_ack-client",
        "ev-syn_ack-server",
    }
    assert "3.2" in finding["statement"]


def test_unusable_clock_alignment_keeps_cross_vantage_timing_inconclusive():
    syn = matched("syn", 0.0, 0.01)
    syn_ack = matched("syn_ack", 3.22, 3.21)
    syn_ack["clock_alignment"]["usable"] = False
    assert localize_tcp_correlations([syn, syn_ack]) == []


def test_prompt_server_syn_ack_and_late_client_observation_supports_return_path():
    findings = localize_tcp_correlations([matched("syn", 0.0, 0.01), matched("syn_ack", 3.2, 0.1)])
    finding = next(item for item in findings if item["category"] == "tcp.return_path_delay")
    assert finding["fault_domains"] == ["network_path"]
    assert "return path" in finding["statement"]


def test_real_packet_identity_alignment_allows_a_delayed_return_path_handshake():
    def packet(frame, timestamp, src, dst, sport, dport, flags, seq, ack=0, payload=0):
        return {
            "frame": frame,
            "time": timestamp,
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

    client_calibration = [
        packet(index, float(index), "192.0.2.10", "192.0.2.20", 51000, 80, "PA", index * 10, 1, 10)
        for index in range(1, 6)
    ]
    server_calibration = [
        item | {"frame": item["frame"] + 20, "time": item["time"] + 0.01}
        for item in client_calibration
    ]
    client_packets = [
        *client_calibration,
        packet(10, 10.0, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100),
        packet(11, 13.2, "192.0.2.2", "192.0.2.1", 443, 50000, "SA", 900, 101),
        packet(12, 13.21, "192.0.2.1", "192.0.2.2", 50000, 443, "A", 101, 901),
        packet(13, 13.22, "192.0.2.1", "192.0.2.2", 50000, 443, "PA", 101, 901, 10),
        packet(14, 13.23, "192.0.2.1", "192.0.2.2", 50000, 443, "PA", 111, 901, 10),
    ]
    server_packets = [
        *server_calibration,
        packet(30, 10.01, "192.0.2.1", "192.0.2.2", 50000, 443, "S", 100),
        packet(31, 10.1, "192.0.2.2", "192.0.2.1", 443, 50000, "SA", 900, 101),
        packet(32, 10.11, "192.0.2.1", "192.0.2.2", 50000, 443, "A", 101, 901),
        packet(33, 10.12, "192.0.2.1", "192.0.2.2", 50000, 443, "PA", 101, 901, 10),
        packet(34, 10.13, "192.0.2.1", "192.0.2.2", 50000, 443, "PA", 111, 901, 10),
    ]
    correlations = correlate_tcp(
        [
            {
                "id": "client",
                "vantage_type": "client",
                "evidence_ids": ["c1", "c2"],
                "observations": client_packets,
            },
            {
                "id": "server",
                "vantage_type": "server",
                "evidence_ids": ["s1", "s2"],
                "observations": server_packets,
            },
        ],
        [
            {
                "id": f"{source}-frame-{packet_row['frame']}",
                "capture_id": source,
                "frame_refs": [packet_row["frame"]],
            }
            for source, packet_rows in (("client", client_packets), ("server", server_packets))
            for packet_row in packet_rows
        ],
    )
    assert correlations
    assert all(item["clock_alignment"]["usable"] for item in correlations)
    findings = localize_tcp_correlations(correlations)
    assert [item["category"] for item in findings] == ["tcp.return_path_delay"]


def test_missing_packet_matches_and_retransmission_alone_do_not_localize():
    syn = matched("syn", 0.0, 0.01)
    retransmission_only = {
        "capture_ids": ["client", "server"],
        "evidence_ids": ["ev-retransmission"],
        "matching_strength": "retransmission_label",
        "matched_frames": [],
        "clock_alignment": {"usable": True, "matched_count": 9},
    }
    assert localize_tcp_correlations([syn, retransmission_only]) == []


def test_syn_and_syn_ack_from_different_tcp_flows_do_not_localize():
    syn = matched("syn", 0.0, 0.01)
    syn_ack = matched("syn_ack", 3.22, 3.21)
    for correlation, client_port, server_port, seq, ack_raw in (
        (syn, 50000, 443, 100, 0),
        (syn_ack, 50001, 8443, 900, 101),
    ):
        client_packet = correlation["matched_frames"][0]["client"]
        server_packet = correlation["matched_frames"][0]["server"]
        source, destination = (
            ("192.0.2.1", "192.0.2.2")
            if client_packet["syn"] and not client_packet["ack"]
            else ("192.0.2.2", "192.0.2.1")
        )
        client_packet.update(
            src=source,
            dst=destination,
            src_port=client_port if source == "192.0.2.1" else server_port,
            dst_port=server_port if destination == "192.0.2.2" else client_port,
            seq_raw=seq,
            ack_raw=ack_raw,
        )
        server_packet.update(client_packet)

    assert localize_tcp_correlations([syn, syn_ack]) == []


def test_extra_capture_does_not_raise_support_without_constraining_observations():
    syn = matched("syn", 0.0, 0.01)
    extra = matched("syn", 0.0, 0.01) | {"capture_ids": ["client", "unknown"]}
    assert localize_tcp_correlations([syn]) == []
    assert localize_tcp_correlations([syn, extra]) == []


def test_deterministic_report_exposes_correlation_provenance_and_localized_finding():
    correlations = [matched("syn", 0.0, 0.01), matched("syn_ack", 3.22, 3.21)]
    evidence = [
        {
            "id": evidence_id,
            "capture_id": "client" if evidence_id.endswith("client") else "server",
            "category": "analyze_tcp_establishment",
            "epistemic_class": "derived",
            "source": {
                "capability": "analyze_tcp_establishment",
                "tool": "tshark",
                "version": "4.2",
            },
            "scope": {"tcp_stream": 0},
            "value": {"state": "established"},
            "frame_refs": [
                8
                if evidence_id == "ev-syn_ack-client"
                else 10
                if evidence_id == "ev-syn_ack-server"
                else 1
                if evidence_id.endswith("client")
                else 3
            ],
            "limitations": [],
        }
        for evidence_id in (
            "ev-syn-client",
            "ev-syn-server",
            "ev-syn_ack-client",
            "ev-syn_ack-server",
        )
    ]
    result = build_investigation_result(
        case_id="case-1",
        symptom="slow connection",
        evidence=evidence,
        correlations=correlations,
        capture_count=2,
    )
    finding = next(
        item for item in result["findings"] if item["category"] == "tcp.server_response_delay"
    )
    assert set(finding["evidence_ids"]) == {item["id"] for item in evidence}
    assert result["cross_vantage"]["correlations"] == correlations
    assert result["cross_vantage"]["observed_capture_count"] == 2
    assert result["cross_vantage"]["support"] == "stronger"


def test_correlations_with_evidence_owned_by_the_wrong_capture_are_rejected():
    correlations = [matched("syn", 0.0, 0.01), matched("syn_ack", 3.22, 3.21)]
    evidence = [
        {
            "id": evidence_id,
            "capture_id": "client" if evidence_id.endswith("client") else "server",
            "category": "analyze_tcp_establishment",
            "epistemic_class": "derived",
            "frame_refs": [
                8
                if evidence_id == "ev-syn_ack-client"
                else 10
                if evidence_id == "ev-syn_ack-server"
                else 1
                if evidence_id.endswith("client")
                else 3
            ],
        }
        for correlation in correlations
        for evidence_id in correlation["evidence_ids"]
    ]
    next(item for item in evidence if item["id"] == "ev-syn_ack-server")["capture_id"] = "client"

    result = build_investigation_result(
        case_id="case-1",
        symptom="slow connection",
        evidence=evidence,
        correlations=correlations,
        capture_count=2,
    )

    assert not any(
        descriptor.get("server", {}).get("ack") is True
        for correlation in result["cross_vantage"]["correlations"]
        for descriptor in correlation.get("matched_frames", [])
    )
    assert not any(
        finding["category"] in {"tcp.server_response_delay", "tcp.return_path_delay"}
        for finding in result["findings"]
    )


def test_correlations_without_evidence_for_the_matched_frame_are_rejected():
    correlations = [matched("syn", 0.0, 0.01), matched("syn_ack", 3.22, 3.21)]
    evidence = [
        {
            "id": evidence_id,
            "capture_id": "client" if evidence_id.endswith("client") else "server",
            "category": "analyze_tcp_establishment",
            "epistemic_class": "derived",
            "frame_refs": [
                8
                if evidence_id == "ev-syn_ack-client"
                else 10
                if evidence_id == "ev-syn_ack-server"
                else 1
                if evidence_id.endswith("client")
                else 3
            ],
        }
        for correlation in correlations
        for evidence_id in correlation["evidence_ids"]
    ]
    next(item for item in evidence if item["id"] == "ev-syn_ack-server")["frame_refs"] = [99]

    result = build_investigation_result(
        case_id="case-1",
        symptom="slow connection",
        evidence=evidence,
        correlations=correlations,
        capture_count=2,
    )

    assert not any(
        descriptor.get("server", {}).get("ack") is True
        for correlation in result["cross_vantage"]["correlations"]
        for descriptor in correlation.get("matched_frames", [])
    )
    assert not any(
        finding["category"] in {"tcp.server_response_delay", "tcp.return_path_delay"}
        for finding in result["findings"]
    )


def test_correlated_packets_without_usable_localization_are_not_reported_as_unmatched():
    correlations = [matched("syn", 0.0, 0.01)]
    evidence = [
        {
            "id": evidence_id,
            "capture_id": "client" if evidence_id.endswith("client") else "server",
            "frame_refs": [1 if evidence_id.endswith("client") else 3],
        }
        for evidence_id in correlations[0]["evidence_ids"]
    ]
    result = build_investigation_result(
        case_id="case-1",
        symptom="slow connection",
        evidence=evidence,
        correlations=correlations,
        capture_count=2,
    )
    assert result["cross_vantage"]["correlations"] == correlations
    assert any("correlated" in item.lower() for item in result["cross_vantage"]["limitations"])
    assert not any(
        "no exact packet" in item.lower() for item in result["cross_vantage"]["limitations"]
    )
