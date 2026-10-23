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
                },
                "server": {
                    "frame": 3 if not ack else 10,
                    "time": server_time,
                    "syn": syn,
                    "ack": ack,
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
            "category": "analyze_tcp_establishment",
            "epistemic_class": "derived",
            "source": {
                "capability": "analyze_tcp_establishment",
                "tool": "tshark",
                "version": "4.2",
            },
            "scope": {"tcp_stream": 0},
            "value": {"state": "established"},
            "frame_refs": [1, 3],
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
        case_id="case-1", symptom="slow connection", evidence=evidence, correlations=correlations
    )
    finding = next(
        item for item in result["findings"] if item["category"] == "tcp.server_response_delay"
    )
    assert set(finding["evidence_ids"]) == {item["id"] for item in evidence}
    assert result["cross_vantage"]["correlations"] == correlations
    assert result["cross_vantage"]["observed_capture_count"] == 2
    assert result["cross_vantage"]["support"] == "stronger"
