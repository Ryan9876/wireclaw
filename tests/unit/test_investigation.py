import copy

from wireclaw_api.investigation import build_investigation_result, rank_candidates


def ev(eid, category, value, stream=None, quality=None, limitations=None, filt=None, epi="derived"):
    scope = {} if stream is None else {"tcp_stream": stream}
    return {
        "id": eid,
        "category": category,
        "epistemic_class": epi,
        "source": {"capability": category, "tool": "test", "version": "1"},
        "scope": scope,
        "value": value,
        "display_filter": filt,
        "limitations": limitations or [],
    }


def quality(state="good", limitations=None):
    return ev(
        "ev_quality",
        "assess_capture_quality",
        {"state": state},
        limitations=limitations,
        filt="frame",
    )


def check_shape(result):
    assert result["schema_version"] == "1.0"
    assert result["capture_quality"]["state"] in {"good", "limited", "insufficient"}
    assert result["conclusion"]["type"] in {"supported_finding", "insufficient_evidence"}
    assert result["conclusion"]["confidence"] in {"high", "medium", "low"}
    assert isinstance(result["findings"], list)
    for f in result["findings"]:
        assert f["evidence_ids"]
        assert f["confidence"] in {"high", "medium", "low"}
        w = f["wireshark"]
        if w["applicable"]:
            assert all(
                w[k]
                for k in ("full_capture", "evidence_capture", "copy_filter", "show_packet_evidence")
            )
            assert w["display_filter"]
    if result["time_attribution"]:
        ta = result["time_attribution"]
        assert ta["total_ms"] >= 0
        assert abs(ta["total_ms"] - sum(s["duration_ms"] for s in ta["segments"])) < 1e-9
        assert all(
            s["measurement_class"] in {"observed", "derived", "inferred"} for s in ta["segments"]
        )


def test_high_rtt_rank_and_determinism():
    evidence = [
        quality(),
        ev(
            "ev_rtt0",
            "analyze_rtt",
            {"median_seconds": 0.01, "sample_count": 4},
            0,
            filt="tcp.stream == 0",
        ),
        ev(
            "ev_rtt1",
            "analyze_rtt",
            {"median_seconds": 0.2, "sample_count": 8},
            1,
            filt="tcp.stream == 1",
        ),
        ev(
            "ev_est1",
            "analyze_tcp_establishment",
            {"state": "established", "establishment_seconds": 0.4},
            1,
            filt="tcp.stream == 1",
        ),
    ]
    r1 = build_investigation_result(case_id="a" * 32, symptom="the app is slow", evidence=evidence)
    r2 = build_investigation_result(
        case_id="a" * 32, symptom="the app is slow", evidence=copy.deepcopy(evidence)
    )
    assert r1 == r2
    assert rank_candidates("slow", evidence)[0].tcp_stream == 1
    assert r1["conclusion"]["type"] == "supported_finding"
    assert r1["findings"][0]["category"] == "tcp.rtt"
    check_shape(r1)


def test_zero_window_beats_generic_rtt_for_throughput():
    evidence = [
        quality(),
        ev(
            "ev_win",
            "analyze_window_behavior",
            {"indicators": {"zero_window": [6, 8], "window_full": [5]}},
            0,
            filt="tcp.stream == 0",
        ),
        ev(
            "ev_rtt",
            "analyze_rtt",
            {"median_seconds": 0.18, "sample_count": 5},
            0,
            filt="tcp.stream == 0",
        ),
    ]
    result = build_investigation_result(
        case_id="b" * 32, symptom="bandwidth is terrible", evidence=evidence
    )
    assert result["findings"][0]["category"] == "tcp.receive_window"
    assert result["conclusion"]["confidence"] == "high"
    check_shape(result)


def test_insufficient_quality_never_primary_diagnosis():
    evidence = [
        quality("insufficient", ["trace starts midstream"]),
        ev(
            "ev_reset",
            "analyze_tcp_resets",
            {"count": 1},
            0,
            filt="tcp.stream == 0 && tcp.flags.reset == 1",
        ),
    ]
    result = build_investigation_result(
        case_id="c" * 32, symptom="users disconnect", evidence=evidence
    )
    assert result["conclusion"]["type"] == "insufficient_evidence"
    assert result["conclusion"]["confidence"] == "low"
    assert result["remaining_hypotheses"]
    assert all(h["next_evidence"] for h in result["remaining_hypotheses"])
    assert "capture_observability" in result["conclusion"]["fault_domains"]
    check_shape(result)


def test_dns_delay_is_not_claimed_as_user_root_cause():
    evidence = [
        quality(),
        ev(
            "ev_dns",
            "analyze_dns",
            {"transactions": [{"elapsed_seconds": 1.5, "response_code": 0, "state": "complete"}]},
            filt="dns",
        ),
    ]
    result = build_investigation_result(case_id="d" * 32, symptom="app is slow", evidence=evidence)
    assert result["findings"][0]["category"] == "dns.timing"
    assert result["conclusion"]["confidence"] == "medium"
    assert "does not by itself prove" in result["findings"][0]["alternate_explanations"][0]
    assert result["time_attribution"]["segments"][0]["name"] == "dns"
    check_shape(result)


def test_symptom_text_cannot_create_fact():
    evidence = [quality()]
    for symptom in ("DNS is slow", "network is broken", "reset timeout TLS bandwidth"):
        result = build_investigation_result(case_id="e" * 32, symptom=symptom, evidence=evidence)
        assert result["conclusion"]["type"] == "insufficient_evidence"
        assert result["findings"] == []
        assert result["remaining_hypotheses"]
        assert all(h["evidence_ids"] == [] for h in result["remaining_hypotheses"])
        check_shape(result)


def test_reordering_caps_retransmission_confidence():
    evidence = [
        quality(),
        ev(
            "ev_health",
            "analyze_tcp_health",
            {
                "retransmission_union_count": 3,
                "indicators": {
                    "out_of_order": {"frame_refs": [5]},
                    "duplicate_ack": {"frame_refs": [8, 9]},
                },
            },
            0,
            filt="tcp.stream == 0",
        ),
    ]
    result = build_investigation_result(
        case_id="f" * 32, symptom="intermittent slow transfer", evidence=evidence
    )
    f = result["findings"][0]
    assert f["category"] == "tcp.retransmission"
    assert f["confidence"] == "medium"
    assert any("Reordering" in x for x in f["alternate_explanations"])
    check_shape(result)


def test_time_attribution_does_not_double_count_unknown_user_time():
    evidence = [
        quality(),
        ev(
            "ev_est",
            "analyze_tcp_establishment",
            {"state": "established", "establishment_seconds": 0.02},
            0,
            filt="tcp.stream == 0",
        ),
        ev(
            "ev_tls",
            "analyze_tls_handshakes",
            {
                "attempts": [
                    {
                        "tcp_established_to_client_hello_seconds": 0.08,
                        "client_hello_to_server_hello_seconds": 1.0,
                    }
                ],
                "alerts": [],
                "repeated_client_hello_frames": [],
            },
            0,
            filt="tcp.stream == 0 && tls",
        ),
    ]
    result = build_investigation_result(case_id="1" * 32, symptom="slow TLS", evidence=evidence)
    ta = result["time_attribution"]
    assert [s["name"] for s in ta["segments"]] == ["tcp_establishment", "tls_establishment"]
    assert ta["total_ms"] == 1100.0
    assert any("subtotal" in x for x in ta["limitations"])
    check_shape(result)


def test_baseline_inventory_ranking_uses_explicit_context_without_excluding_small_flow():
    evidence = [
        quality(),
        ev(
            "ev_conv",
            "list_conversations",
            {
                "conversations": [
                    {
                        "transport": "tcp",
                        "stream": 0,
                        "a": {"address": "192.0.2.1", "port": 51000},
                        "b": {"address": "192.0.2.20", "port": 443},
                        "wire_bytes": 5000000,
                        "duration_seconds": 8.0,
                        "a_to_b_packets": 200,
                        "b_to_a_packets": 180,
                    },
                    {
                        "transport": "tcp",
                        "stream": 1,
                        "a": {"address": "192.0.2.1", "port": 52000},
                        "b": {"address": "192.0.2.99", "port": 8443},
                        "wire_bytes": 180,
                        "duration_seconds": 0.2,
                        "a_to_b_packets": 2,
                        "b_to_a_packets": 1,
                    },
                ]
            },
            filt="tcp",
        ),
    ]
    ranked = rank_candidates("failure talking to 192.0.2.99 port 8443", evidence)
    assert [candidate.tcp_stream for candidate in ranked[:2]] == [1, 0]
    assert "explicit_endpoint_match" in ranked[0].reasons
    assert "explicit_port_match" in ranked[0].reasons


def test_low_confidence_observation_does_not_become_primary_diagnosis():
    evidence = [
        quality(),
        ev(
            "ev_health",
            "analyze_tcp_health",
            {
                "retransmission_union_count": 0,
                "indicators": {
                    "out_of_order": {"frame_refs": [5]},
                    "duplicate_ack": {"frame_refs": [8]},
                },
            },
            0,
            filt="tcp.stream == 0",
        ),
    ]
    result = build_investigation_result(
        case_id="2" * 32, symptom="intermittent issue", evidence=evidence
    )
    assert result["findings"][0]["category"] == "tcp.reordering"
    assert result["findings"][0]["confidence"] == "low"
    assert result["conclusion"]["type"] == "insufficient_evidence"
    assert result["remaining_hypotheses"]
    check_shape(result)
