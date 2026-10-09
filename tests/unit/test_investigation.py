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
    assert result["findings"][0]["confidence"] == "low"
    assert result["conclusion"]["type"] == "insufficient_evidence"
    assert result["conclusion"]["confidence"] == "low"
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


def test_candidate_ranking_includes_relevant_udp_conversation():
    evidence = [
        quality(),
        ev(
            "ev_conv_udp",
            "list_conversations",
            {
                "conversations": [
                    {
                        "transport": "tcp",
                        "stream": 0,
                        "a": {"address": "192.0.2.1", "port": 51000},
                        "b": {"address": "192.0.2.20", "port": 443},
                        "wire_bytes": 900000,
                        "duration_seconds": 10.0,
                        "a_to_b_packets": 100,
                        "b_to_a_packets": 100,
                    },
                    {
                        "transport": "udp",
                        "stream": 7,
                        "a": {"address": "192.0.2.1", "port": 53000},
                        "b": {"address": "192.0.2.99", "port": 5353},
                        "wire_bytes": 120,
                        "duration_seconds": 0.1,
                        "a_to_b_packets": 1,
                        "b_to_a_packets": 1,
                    },
                ]
            },
            filt="tcp || udp",
        ),
    ]
    ranked = rank_candidates("failure talking to 192.0.2.99 port 5353", evidence)
    assert ranked[0].transport == "udp"
    assert ranked[0].stream == 7
    assert ranked[0].tcp_stream is None
    assert "explicit_endpoint_match" in ranked[0].reasons
    assert "explicit_port_match" in ranked[0].reasons


def test_unlinked_dns_delay_is_not_primary_for_generic_slow_symptom():
    evidence = [
        quality(),
        ev(
            "ev_conv_healthy",
            "list_conversations",
            {
                "conversations": [
                    {
                        "transport": "tcp",
                        "stream": 0,
                        "a": {"address": "192.0.2.1", "port": 50000},
                        "b": {"address": "192.0.2.2", "port": 443},
                        "wire_bytes": 500,
                        "duration_seconds": 0.2,
                        "a_to_b_packets": 3,
                        "b_to_a_packets": 3,
                    }
                ]
            },
            filt="tcp",
        ),
        ev(
            "ev_dns_unlinked",
            "analyze_dns",
            {"transactions": [{"elapsed_seconds": 1.5, "response_code": 0, "state": "complete"}]},
            filt="dns",
        ),
    ]
    result = build_investigation_result(
        case_id="3" * 32, symptom="application is slow", evidence=evidence
    )
    assert result["findings"][0]["category"] == "dns.timing"
    assert result["findings"][0]["confidence"] == "low"
    assert result["conclusion"]["type"] == "insufficient_evidence"


def test_candidate_and_finding_bounds_are_reported_as_limitations():
    conversations = []
    evidence = [quality()]
    for stream_id in range(10):
        conversations.append(
            {
                "transport": "tcp",
                "stream": stream_id,
                "a": {"address": "192.0.2.1", "port": 50000 + stream_id},
                "b": {"address": "192.0.2.2", "port": 443},
                "wire_bytes": 1000 + stream_id,
                "duration_seconds": 2.0,
                "a_to_b_packets": 3,
                "b_to_a_packets": 3,
            }
        )
        evidence.extend(
            [
                ev(
                    f"ev_reset_{stream_id}",
                    "analyze_tcp_resets",
                    {"count": 1},
                    stream_id,
                    filt=f"tcp.stream == {stream_id}",
                ),
                ev(
                    f"ev_rtt_{stream_id}",
                    "analyze_rtt",
                    {"median_seconds": 0.2, "sample_count": 4},
                    stream_id,
                    filt=f"tcp.stream == {stream_id}",
                ),
                ev(
                    f"ev_est_{stream_id}",
                    "analyze_tcp_establishment",
                    {"state": "failed", "establishment_seconds": None},
                    stream_id,
                    filt=f"tcp.stream == {stream_id}",
                ),
            ]
        )
    evidence.append(
        ev(
            "ev_many_conversations",
            "list_conversations",
            {"conversations": conversations},
            filt="tcp",
        )
    )
    result = build_investigation_result(
        case_id="4" * 32, symptom="connections fail and are slow", evidence=evidence
    )
    assert len(result["findings"]) == 16
    assert any("top 8 of 10 conversations" in item for item in result["limitations"])
    assert any("top 16 of" in item for item in result["limitations"])


def test_tls_retry_omits_misleading_establishment_duration():
    evidence = [
        quality(),
        ev(
            "ev_est_tls_retry",
            "analyze_tcp_establishment",
            {"state": "established", "establishment_seconds": 0.02},
            0,
            filt="tcp.stream == 0",
        ),
        ev(
            "ev_tls_retry",
            "analyze_tls_handshakes",
            {
                "attempts": [
                    {
                        "client_hello_frame": 4,
                        "client_hello_to_server_hello_seconds": 1.0,
                        "tcp_established_to_client_hello_seconds": 0.08,
                    },
                    {
                        "client_hello_frame": 8,
                        "client_hello_to_server_hello_seconds": None,
                        "tcp_established_to_client_hello_seconds": 1.18,
                    },
                ],
                "alerts": [{"frame": 9, "descriptions": [40]}],
                "repeated_client_hello_frames": [8],
            },
            0,
            filt="tcp.stream == 0 && tls",
        ),
    ]
    result = build_investigation_result(
        case_id="5" * 32, symptom="TLS handshake is slow", evidence=evidence
    )
    assert result["findings"][0]["category"] == "tls.handshake"
    assert result["time_attribution"] is not None
    assert [segment["name"] for segment in result["time_attribution"]["segments"]] == [
        "tcp_establishment"
    ]
    assert any("stage is omitted" in item for item in result["time_attribution"]["limitations"])


def test_candidate_ranking_includes_nonstream_ip_conversation():
    evidence = [
        quality(),
        ev(
            "ev_conv_other",
            "list_conversations",
            {
                "conversations": [
                    {
                        "transport": "tcp",
                        "stream": 0,
                        "a": {"address": "192.0.2.1", "port": 51000},
                        "b": {"address": "192.0.2.20", "port": 443},
                        "wire_bytes": 900000,
                        "duration_seconds": 10.0,
                        "a_to_b_packets": 100,
                        "b_to_a_packets": 100,
                    },
                    {
                        "transport": "other",
                        "stream": None,
                        "a": {"address": "192.0.2.1", "port": None},
                        "b": {"address": "198.51.100.77", "port": None},
                        "network_protocol": {"number": 1},
                        "wire_bytes": 84,
                        "duration_seconds": 0.0,
                        "a_to_b_packets": 1,
                        "b_to_a_packets": 1,
                    },
                ]
            },
            filt="ip",
        ),
    ]
    ranked = rank_candidates("failure involving 198.51.100.77", evidence)
    assert ranked[0].transport == "other"
    assert ranked[0].stream is None
    assert ranked[0].tcp_stream is None
    assert "explicit_endpoint_match" in ranked[0].reasons


def test_finding_domain_and_epistemic_class_expose_existing_rules_without_new_diagnosis():
    evidence = [
        quality(),
        ev(
            "ev_rtt_domain",
            "analyze_rtt",
            {"median_seconds": 0.2, "sample_count": 8},
            0,
            filt="tcp.stream == 0",
        ),
    ]
    report = build_investigation_result(
        case_id="a" * 32, symptom="application is slow", evidence=evidence
    )
    finding = report["findings"][0]
    assert finding["fault_domains"] == report["conclusion"]["fault_domains"]
    assert finding["epistemic_class"] == "inferred"
    assert finding["confidence"] == report["conclusion"]["confidence"]
    check_shape(report)


def test_report_schema_remains_compatible_with_persisted_gate4_findings():
    report = build_investigation_result(
        case_id="a" * 32,
        symptom="users disconnect",
        evidence=[quality(), ev("ev_reset_legacy", "analyze_tcp_resets", {"count": 1}, 0)],
    )
    for finding in report["findings"]:
        finding.pop("fault_domains")
        finding.pop("epistemic_class")
    check_shape(report)
