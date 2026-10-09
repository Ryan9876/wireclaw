from wireclaw_api.investigation import rank_candidates


def test_candidate_ranking_supports_explicit_ipv6_context():
    evidence = [
        {
            "id": "ev_quality",
            "category": "assess_capture_quality",
            "epistemic_class": "derived",
            "source": {"capability": "assess_capture_quality", "tool": "test", "version": "1"},
            "scope": {},
            "value": {"state": "good"},
            "display_filter": "frame",
            "limitations": [],
        },
        {
            "id": "ev_conversations",
            "category": "list_conversations",
            "epistemic_class": "observed",
            "source": {"capability": "list_conversations", "tool": "test", "version": "1"},
            "scope": {},
            "value": {
                "conversations": [
                    {
                        "transport": "tcp",
                        "stream": 3,
                        "a": {"address": "2001:db8::1", "port": 53000},
                        "b": {"address": "2001:db8::99", "port": 443},
                        "wire_bytes": 200,
                        "duration_seconds": 0.2,
                        "a_to_b_packets": 2,
                        "b_to_a_packets": 1,
                    },
                    {
                        "transport": "tcp",
                        "stream": 4,
                        "a": {"address": "2001:db8::1", "port": 54000},
                        "b": {"address": "2001:db8::20", "port": 443},
                        "wire_bytes": 900000,
                        "duration_seconds": 10.0,
                        "a_to_b_packets": 100,
                        "b_to_a_packets": 100,
                    },
                ]
            },
            "display_filter": "tcp",
            "limitations": [],
        },
    ]

    ranked = rank_candidates("slow connection to [2001:db8::99]:443", evidence)

    assert ranked[0].tcp_stream == 3
    assert "explicit_endpoint_match" in ranked[0].reasons
    assert "explicit_port_match" in ranked[0].reasons
