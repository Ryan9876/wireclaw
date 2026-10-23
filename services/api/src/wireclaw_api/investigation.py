"""Deterministic Gate 4 investigation rules over normalized Wireclaw evidence.

This module deliberately consumes only normalized evidence.  It does not parse captures,
run packet tools, infer facts from free text, or call a model provider.
"""

from __future__ import annotations

import contextlib
import math
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

RTT_HIGH_SECONDS = 0.150
STAGE_DELAY_SECONDS = 1.000
MAX_CANDIDATES = 8
MAX_FINDINGS = 16
MIN_PRIMARY_CONFIDENCE = "medium"
DEFAULT_MAX_DISPLAY_FILTER_CHARS = 2_048


def localize_tcp_correlations(correlations: list[dict]) -> list[dict]:
    """Derive bounded TCP timing findings only from exact, clock-usable matches."""
    by_connection = defaultdict(dict)
    connection_meta = {}
    connection_matches = defaultdict(list)
    for correlation in correlations:
        if correlation.get("matching_strength") != "exact_packet_signature":
            continue
        if len(correlation.get("capture_ids", [])) != 2:
            continue
        alignment = correlation.get("clock_alignment", {})
        if not alignment.get("usable") or alignment.get("matched_count", 0) < 3:
            continue
        frames = correlation.get("matched_frames", [])
        if len(frames) != 1:
            continue
        pair = tuple(correlation["capture_ids"])
        capture_evidence = correlation.get("capture_evidence_ids", {})
        if not all(capture_evidence.get(capture_id) for capture_id in pair):
            continue
        descriptors = frames[0]
        packets = [descriptors.get(capture_id) for capture_id in pair]
        if not all(isinstance(packet, dict) for packet in packets):
            continue
        reference = packets[0]
        try:
            src = (reference["src"], int(reference["src_port"]))
            dst = (reference["dst"], int(reference["dst_port"]))
            if reference.get("syn") is True and reference.get("ack") is False:
                connection_key = (src, dst, int(reference["seq_raw"]))
            elif reference.get("syn") is True and reference.get("ack") is True:
                connection_key = (dst, src, (int(reference["ack_raw"]) - 1) & 0xFFFFFFFF)
            else:
                continue
            if not 0 <= connection_key[2] <= 0xFFFFFFFF:
                continue
            for packet in packets[1:]:
                packet_identity = (
                    packet["src"],
                    int(packet["src_port"]),
                    packet["dst"],
                    int(packet["dst_port"]),
                    int(packet["seq_raw"]),
                    int(packet["ack_raw"]),
                )
                reference_identity = (
                    reference["src"],
                    int(reference["src_port"]),
                    reference["dst"],
                    int(reference["dst_port"]),
                    int(reference["seq_raw"]),
                    int(reference["ack_raw"]),
                )
                if packet_identity != reference_identity:
                    raise ValueError("capture_packet_identity_mismatch")
        except (KeyError, TypeError, ValueError):
            continue
        connection = (pair, connection_key)
        connection_matches[connection].append(correlation)
        for capture_id in pair:
            packet = descriptors.get(capture_id)
            is_syn = packet.get("syn") is True and packet.get("ack") is False
            is_syn_ack = packet.get("syn") is True and packet.get("ack") is True
            if is_syn:
                by_connection[connection].setdefault("syn", {})[capture_id] = packet
            elif is_syn_ack:
                by_connection[connection].setdefault("syn_ack", {})[capture_id] = packet
            connection_meta[connection] = correlation

    findings = []
    for connection, events in by_connection.items():
        pair, _connection_key = connection
        syn = events.get("syn", {})
        syn_ack = events.get("syn_ack", {})
        if set(syn) != set(pair) or set(syn_ack) != set(pair):
            continue
        vantages = connection_meta[connection].get("capture_vantages", {})
        client_id = next((item for item in pair if vantages.get(item) == "client"), None)
        server_id = next((item for item in pair if vantages.get(item) == "server"), None)
        if client_id is None or server_id is None:
            continue
        try:
            client_syn = float(syn[client_id]["time"])
            server_syn = float(syn[server_id]["time"])
            client_syn_ack = float(syn_ack[client_id]["time"])
            server_syn_ack = float(syn_ack[server_id]["time"])
            alignment = connection_meta[connection]["clock_alignment"]
            offset = float(alignment["offset_seconds"])
            if pair[1] != server_id:
                offset = -offset
            server_syn_client_clock = server_syn - offset
            server_syn_ack_client_clock = server_syn_ack - offset
            client_delay = client_syn_ack - client_syn
            server_delay = server_syn_ack - server_syn
            forward_gap = server_syn_client_clock - client_syn
            return_gap = client_syn_ack - server_syn_ack_client_clock
            timing_tolerance = max(0.100, float(alignment.get("uncertainty_seconds") or 0) * 2)
        except (KeyError, TypeError, ValueError):
            continue
        if (
            client_delay < 0
            or server_delay < 0
            or forward_gap < -timing_tolerance
            or return_gap < -timing_tolerance
        ):
            continue
        evidence_ids = sorted(
            {
                evidence_id
                for correlation in correlations
                if tuple(correlation.get("capture_ids", [])) == pair
                and correlation in connection_matches[connection]
                for evidence_id in correlation.get("evidence_ids", [])
                if isinstance(evidence_id, str) and evidence_id
            }
        )
        if len(evidence_ids) < 4:
            continue
        if (
            server_delay >= STAGE_DELAY_SECONDS
            and abs(server_delay - client_delay) <= timing_tolerance
            and forward_gap <= timing_tolerance
            and return_gap <= timing_tolerance
        ):
            findings.append(
                {
                    "category": "tcp.server_response_delay",
                    "title": "Server response delay observed across capture points",
                    "statement": (
                        f"Both client and server captures observed the SYN promptly; the server's SYN-ACK followed about {server_delay:.1f} seconds later. "
                        "This supports a server/listener-side delay and makes the client-to-server path less likely."
                    ),
                    "confidence": "high",
                    "fault_domains": ["server_application"],
                    "evidence_ids": evidence_ids,
                    "capture_ids": list(pair),
                    "matched_frames": [
                        frame
                        for correlation in connection_matches[connection]
                        for frame in correlation.get("matched_frames", [])
                    ],
                    "limitations": [
                        "Timing is based on exact matched packet observations and usable clock alignment; capture placement and unsampled network devices remain limitations."
                    ],
                }
            )
        elif (
            server_delay < STAGE_DELAY_SECONDS
            and forward_gap <= timing_tolerance
            and return_gap >= STAGE_DELAY_SECONDS
        ):
            findings.append(
                {
                    "category": "tcp.return_path_delay",
                    "title": "Return-path delay observed across capture points",
                    "statement": (
                        f"The server capture observed its SYN-ACK after about {server_delay:.1f} seconds, while the client capture observed it after about {client_delay:.1f} seconds. "
                        "This supports delay on the return path between the capture points."
                    ),
                    "confidence": "medium",
                    "fault_domains": ["network_path"],
                    "evidence_ids": evidence_ids,
                    "capture_ids": list(pair),
                    "matched_frames": [
                        frame
                        for correlation in connection_matches[connection]
                        for frame in correlation.get("matched_frames", [])
                    ],
                    "limitations": [
                        "The captures bound the delay to the return path between their observation points but do not identify a specific device."
                    ],
                }
            )
    return findings


@dataclass(frozen=True)
class Candidate:
    transport: str
    stream: int | None
    conversation_index: int
    score: int
    reasons: tuple[str, ...]
    capture_id: str | None = None

    @property
    def tcp_stream(self) -> int | None:
        return self.stream if self.transport == "tcp" and isinstance(self.stream, int) else None


@dataclass(frozen=True)
class RuleFinding:
    priority: int
    title: str
    category: str
    confidence: str
    statement: str
    fault_domains: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    affected_scope: dict[str, Any]
    alternate_explanations: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    recommended_validation: tuple[str, ...] = ()
    display_filter: str | None = None


_SYMPTOM_TERMS = {
    "slow": ("slow", "latency", "lag", "performance", "delay"),
    "intermittent": ("intermittent", "random", "occasional", "sometimes"),
    "disconnect": ("disconnect", "reset", "timeout", "drop", "dropped"),
    "connect": ("cannot connect", "can't connect", "connection fail", "failed connect"),
    "throughput": ("throughput", "bandwidth", "transfer", "download", "upload"),
    "dns": ("dns", "name resolution", "resolve", "resolver"),
    "tls": ("tls", "ssl", "certificate", "handshake"),
}


def _families(symptom: str) -> set[str]:
    text = " ".join(symptom.casefold().split())
    found = {name for name, terms in _SYMPTOM_TERMS.items() if any(term in text for term in terms)}
    return found or {"general"}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) and value >= 0 else None


def _frames(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, int) and item > 0]


def _scope_stream(item: dict[str, Any]) -> int | None:
    scope = item.get("scope")
    if not isinstance(scope, dict):
        return None
    stream = scope.get("tcp_stream")
    return stream if isinstance(stream, int) and stream >= 0 else None


def _by_category(evidence: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in evidence:
        category = item.get("category")
        if isinstance(category, str):
            grouped[category].append(item)
    for items in grouped.values():
        items.sort(key=lambda item: (str(item.get("id", "")), _scope_stream(item) or -1))
    return dict(grouped)


def _by_stream(
    evidence: Iterable[dict[str, Any]],
) -> dict[tuple[str | None, int], list[dict[str, Any]]]:
    grouped: dict[tuple[str | None, int], list[dict[str, Any]]] = defaultdict(list)
    for item in evidence:
        stream = _scope_stream(item)
        if stream is not None:
            capture_id = item.get("capture_id")
            grouped[(capture_id if isinstance(capture_id, str) else None, stream)].append(item)
    for items in grouped.values():
        items.sort(key=lambda item: (str(item.get("category", "")), str(item.get("id", ""))))
    return dict(grouped)


def _indicator_frames(value: dict[str, Any], name: str) -> list[int]:
    indicators = value.get("indicators")
    if not isinstance(indicators, dict):
        return []
    indicator = indicators.get(name)
    if isinstance(indicator, dict):
        return _frames(indicator.get("frame_refs"))
    return _frames(indicator)


def _quality(evidence: list[dict[str, Any]]) -> tuple[str, list[str], list[str]]:
    items = _by_category(evidence).get("assess_capture_quality", [])
    if not items:
        return "insufficient", ["Capture-quality evidence is unavailable."], []
    item = items[0]
    value = item.get("value") if isinstance(item.get("value"), dict) else {}
    state = value.get("state")
    if state not in {"good", "limited", "insufficient"}:
        state = "insufficient"
    limitations: list[str] = []
    for source in (item.get("limitations"), value.get("limitations")):
        if isinstance(source, list):
            for entry in source:
                if isinstance(entry, str) and entry and entry not in limitations:
                    limitations.append(entry)
    return state, limitations, [item["id"]] if isinstance(item.get("id"), str) else []


def _explicit_context(symptom: str) -> tuple[set[str], set[int]]:
    text = symptom.casefold()
    addresses: set[str] = set()
    for token in re.findall(r"[0-9a-f:.]+", text):
        candidate = token.strip(".,;()[]{}<>")
        with contextlib.suppress(ValueError):
            addresses.add(str(ip_address(candidate)))
    port_tokens = [
        *re.findall(r"\bport\s+(\d{1,5})\b", text),
        *re.findall(r"\]:(\d{1,5})\b", text),
        *re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:(\d{1,5})\b", text),
    ]
    ports = {int(match) for match in port_tokens if 0 < int(match) <= 65535}
    return addresses, ports


def _conversations(
    evidence: Iterable[dict[str, Any]],
) -> list[tuple[int, dict[str, Any], str | None]]:
    conversations: list[tuple[int, dict[str, Any], str | None]] = []
    index = 0
    for item in evidence:
        if item.get("category") != "list_conversations":
            continue
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        records = value.get("conversations") if isinstance(value.get("conversations"), list) else []
        for record in records:
            if not isinstance(record, dict):
                continue
            transport = record.get("transport")
            if not isinstance(transport, str) or not transport:
                continue
            capture_id = item.get("capture_id")
            conversations.append(
                (index, record, capture_id if isinstance(capture_id, str) else None)
            )
            index += 1
    return conversations


def _conversation_signals(
    conversation: dict[str, Any] | None,
    families: set[str],
    addresses: set[str],
    ports: set[int],
) -> tuple[int, list[str]]:
    if not conversation:
        return 0, []
    transport = conversation.get("transport")
    transport = transport if isinstance(transport, str) and transport else "other"
    score = 1
    reasons = [f"{transport}_conversation"]
    endpoints = [
        endpoint
        for endpoint in (conversation.get("a"), conversation.get("b"))
        if isinstance(endpoint, dict)
    ]
    endpoint_addresses = {
        endpoint.get("address")
        for endpoint in endpoints
        if isinstance(endpoint.get("address"), str)
    }
    endpoint_ports = {
        endpoint.get("port") for endpoint in endpoints if isinstance(endpoint.get("port"), int)
    }
    if addresses & endpoint_addresses:
        score += 10
        reasons.append("explicit_endpoint_match")
    if ports & endpoint_ports:
        score += 6
        reasons.append("explicit_port_match")
    if transport == "tcp" and 443 in endpoint_ports and ({"tls", "slow", "connect"} & families):
        score += 2
        reasons.append("tls_service_relevance")
    if transport in {"tcp", "udp"} and 53 in endpoint_ports and "dns" in families:
        score += 3
        reasons.append("dns_service_relevance")
    duration = _number(conversation.get("duration_seconds"))
    if (
        duration is not None
        and duration >= STAGE_DELAY_SECONDS
        and {"slow", "intermittent"} & families
    ):
        score += 2
        reasons.append("long_conversation")
    wire_bytes = conversation.get("wire_bytes")
    if isinstance(wire_bytes, int) and wire_bytes > 0:
        # Volume is a weak rank signal only. Small control/failure conversations remain eligible.
        score += min(3, max(0, int(math.log10(wire_bytes))))
        reasons.append("observed_volume")
    directional = (conversation.get("a_to_b_packets"), conversation.get("b_to_a_packets"))
    if all(isinstance(value, int) for value in directional) and 0 in directional:
        score += 2 if {"connect", "disconnect", "intermittent"} & families else 1
        reasons.append("one_direction_observed")
    return score, reasons


def _candidate_signals(items: list[dict[str, Any]], families: set[str]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    for item in items:
        category = item.get("category")
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        if category == "analyze_tcp_resets":
            count = value.get("count")
            if isinstance(count, int) and count > 0:
                points = 8 if "disconnect" in families else 5
                score += points
                reasons.append("tcp_reset")
        elif category == "analyze_tcp_establishment":
            state = value.get("state")
            elapsed = _number(value.get("establishment_seconds"))
            repeated = _frames(value.get("repeated_syn_frames"))
            if state not in (None, "established", "midstream"):
                score += 6
                reasons.append("tcp_setup_failure")
            if repeated:
                score += 5 if {"slow", "connect", "intermittent"} & families else 3
                reasons.append("syn_retry")
            if elapsed is not None and elapsed >= STAGE_DELAY_SECONDS:
                score += 4
                reasons.append("slow_tcp_setup")
        elif category == "analyze_tcp_health":
            retrans = value.get("retransmission_union_count")
            if isinstance(retrans, int) and retrans > 0:
                score += 5 if {"slow", "throughput", "intermittent"} & families else 3
                reasons.append("retransmission")
            if _indicator_frames(value, "out_of_order"):
                score += 2
                reasons.append("out_of_order")
        elif category == "analyze_rtt":
            median = _number(value.get("median_seconds"))
            if median is not None and median >= RTT_HIGH_SECONDS:
                score += 5 if "slow" in families else 3
                reasons.append("high_rtt")
        elif category == "analyze_window_behavior":
            if _indicator_frames(value, "zero_window"):
                score += 6 if {"slow", "throughput"} & families else 4
                reasons.append("zero_window")
            if _indicator_frames(value, "window_full"):
                score += 2
                reasons.append("window_full")
        elif category == "analyze_tls_handshakes":
            attempts = value.get("attempts") if isinstance(value.get("attempts"), list) else []
            delayed = any(
                (_number(attempt.get("client_hello_to_server_hello_seconds")) or 0)
                >= STAGE_DELAY_SECONDS
                for attempt in attempts
                if isinstance(attempt, dict)
            )
            alerts = value.get("alerts") if isinstance(value.get("alerts"), list) else []
            retry = _frames(value.get("repeated_client_hello_frames"))
            if delayed or alerts or retry:
                score += 5 if "tls" in families or "slow" in families else 3
                reasons.append("tls_handshake_condition")
    return score, sorted(set(reasons))


def _rank_candidates_all(symptom: str, evidence: list[dict[str, Any]]) -> list[Candidate]:
    families = _families(symptom)
    addresses, ports = _explicit_context(symptom)
    stream_items = _by_stream(evidence)
    conversations = _conversations(evidence)
    candidates = []
    represented_tcp_streams: set[tuple[str | None, int]] = set()

    for conversation_index, conversation, capture_id in conversations:
        transport = conversation.get("transport")
        stream = conversation.get("stream")
        stream = stream if isinstance(stream, int) and stream >= 0 else None
        if transport == "tcp" and stream is not None:
            stream_key = (capture_id, stream)
            represented_tcp_streams.add(stream_key)
            anomaly_score, anomaly_reasons = _candidate_signals(
                stream_items.get(stream_key, []), families
            )
        else:
            anomaly_score, anomaly_reasons = 0, []
        context_score, context_reasons = _conversation_signals(
            conversation, families, addresses, ports
        )
        reasons = tuple(sorted(set(anomaly_reasons + context_reasons)))
        candidates.append(
            Candidate(
                transport,
                stream,
                conversation_index,
                anomaly_score + context_score,
                reasons,
                capture_id,
            )
        )

    next_index = len(conversations)
    missing_streams = sorted(
        set(stream_items) - represented_tcp_streams,
        key=lambda key: (key[0] or "", key[1]),
    )
    for offset, (capture_id, stream) in enumerate(missing_streams):
        anomaly_score, anomaly_reasons = _candidate_signals(
            stream_items.get((capture_id, stream), []), families
        )
        candidates.append(
            Candidate(
                "tcp",
                stream,
                next_index + offset,
                anomaly_score,
                tuple(anomaly_reasons),
                capture_id,
            )
        )

    return sorted(
        candidates,
        key=lambda candidate: (
            -candidate.score,
            candidate.transport,
            candidate.stream is None,
            candidate.stream if candidate.stream is not None else -1,
            candidate.conversation_index,
        ),
    )


def rank_candidates(symptom: str, evidence: list[dict[str, Any]]) -> list[Candidate]:
    return _rank_candidates_all(symptom, evidence)[:MAX_CANDIDATES]


def _confidence(base: str, quality: str, *, ambiguous: bool = False) -> str:
    levels = ["low", "medium", "high"]
    index = levels.index(base)
    if quality == "limited":
        index = min(index, 1)
    elif quality == "insufficient":
        index = 0
    if ambiguous:
        index = min(index, 1)
    return levels[index]


def _evidence_id(item: dict[str, Any]) -> str | None:
    value = item.get("id")
    return value if isinstance(value, str) and value else None


def _stream_item(index, stream_key, category: str):
    return next(
        (item for item in index.get(stream_key, []) if item.get("category") == category), None
    )


def _frame_filter(frames: Iterable[int], max_chars: int) -> str | None:
    ordered = sorted({frame for frame in frames if type(frame) is int and frame > 0})
    if not ordered:
        return None
    runs: list[tuple[int, int]] = []
    first = previous = ordered[0]
    for frame in ordered[1:]:
        if frame == previous + 1:
            previous = frame
            continue
        runs.append((first, previous))
        first = previous = frame
    runs.append((first, previous))
    clauses = [
        f"frame.number == {start}"
        if start == end
        else f"(frame.number >= {start} && frame.number <= {end})"
        for start, end in runs
    ]
    exact = " || ".join(clauses)
    if len(exact) <= max_chars:
        return exact
    # A bounded frame interval is the deterministic last resort for large sparse
    # evidence sets. The interval is capped so it cannot become a capture-wide filter.
    end = min(ordered[-1], ordered[0] + 4095)
    bounded = f"frame.number >= {ordered[0]} && frame.number <= {end}"
    return bounded if len(bounded) <= max_chars else None


def _value_frames(value: Any) -> list[int]:
    found: set[int] = set()

    def visit(node: Any, depth: int = 0):
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                if key == "frame_refs" and isinstance(child, list):
                    found.update(frame for frame in child if type(frame) is int and frame > 0)
                elif key in {"query_frame", "response_frame"} and type(child) is int and child > 0:
                    found.add(child)
                elif isinstance(child, (dict, list)):
                    visit(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                visit(child, depth + 1)

    visit(value)
    return sorted(found)


def _safe_evidence_filter(items: list[dict[str, Any]], max_chars: int) -> str | None:
    filters = [
        item.get("display_filter")
        for item in items
        if isinstance(item.get("display_filter"), str)
        and item.get("display_filter")
        and len(item["display_filter"]) <= max_chars
        and not any(ord(char) < 32 or ord(char) == 127 for char in item["display_filter"])
    ]
    return filters[0] if filters else None


def _finding_filter(finding: RuleFinding, cited: list[dict[str, Any]], max_chars: int):
    if (
        finding.display_filter
        and len(finding.display_filter) <= max_chars
        and not any(ord(char) < 32 or ord(char) == 127 for char in finding.display_filter)
    ):
        return finding.display_filter
    stream = finding.affected_scope.get("tcp_stream")
    if type(stream) is int and stream >= 0:
        return f"tcp.stream == {stream}"
    frames = _value_frames([item.get("value") for item in cited])
    precise = _frame_filter(frames, max_chars)
    return precise or _safe_evidence_filter(cited, max_chars)


def _finding_dict(
    number: int,
    finding: RuleFinding,
    evidence_map: dict[str, dict[str, Any]],
    max_display_filter_chars: int,
):
    cited = [evidence_map[eid] for eid in finding.evidence_ids if eid in evidence_map]
    display_filter = _finding_filter(finding, cited, max_display_filter_chars)
    applicable = bool(display_filter)
    return {
        "id": f"finding_{number:03d}",
        "title": finding.title,
        "category": finding.category,
        "confidence": finding.confidence,
        "epistemic_class": "inferred",
        "fault_domains": list(finding.fault_domains),
        "statement": finding.statement,
        "affected_scope": finding.affected_scope,
        "evidence_ids": list(finding.evidence_ids),
        "alternate_explanations": list(finding.alternate_explanations),
        "limitations": list(finding.limitations),
        "recommended_validation": list(finding.recommended_validation),
        "wireshark": {
            "applicable": applicable,
            "full_capture": applicable,
            "evidence_capture": applicable,
            "copy_filter": applicable,
            "show_packet_evidence": applicable,
            "display_filter": display_filter,
        },
    }


def _transaction_filter(transactions: list[dict[str, Any]], max_chars: int) -> str | None:
    frames = _value_frames(transactions)
    precise = _frame_filter(frames, max_chars)
    if precise:
        return precise
    for transaction in transactions:
        value = transaction.get("display_filter")
        if (
            isinstance(value, str)
            and value
            and len(value) <= max_chars
            and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            return value
    return None


def _dns_findings(grouped, quality, families, max_display_filter_chars) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for item in grouped.get("analyze_dns", []):
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        transactions = (
            value.get("transactions") if isinstance(value.get("transactions"), list) else []
        )
        slow = []
        failures = []
        for tx in transactions:
            if not isinstance(tx, dict):
                continue
            elapsed = _number(tx.get("elapsed_seconds"))
            if elapsed is not None and elapsed >= STAGE_DELAY_SECONDS:
                slow.append((tx, elapsed))
            state = tx.get("state")
            rcode = tx.get("response_code")
            if state == "unanswered_in_capture" or (isinstance(rcode, int) and rcode != 0):
                failures.append(tx)
        eid = _evidence_id(item)
        if eid and slow:
            worst = max(elapsed for _, elapsed in slow)
            findings.append(
                RuleFinding(
                    70 if "dns" in families or "slow" in families else 55,
                    "Slow DNS transaction observed",
                    "dns.timing",
                    _confidence("medium" if "dns" in families else "low", quality),
                    f"At least one DNS transaction took {worst * 1000:.0f} ms in the capture.",
                    ("dns",),
                    (eid,),
                    {},
                    (
                        "The capture does not by itself prove that this lookup delayed the user-visible transaction.",
                    ),
                    tuple(item.get("limitations", []))
                    if isinstance(item.get("limitations"), list)
                    else (),
                    (
                        "Align the affected application transaction with this DNS lookup to confirm user-impact timing.",
                    ),
                    _transaction_filter([tx for tx, _ in slow], max_display_filter_chars),
                )
            )
        if eid and failures:
            findings.append(
                RuleFinding(
                    80 if "dns" in families or "connect" in families else 60,
                    "DNS failure or unanswered query observed",
                    "dns.failure",
                    _confidence("medium" if "dns" in families else "low", quality, ambiguous=True),
                    f"The capture contains {len(failures)} DNS transaction(s) with a failure code or no linked response.",
                    ("dns",),
                    (eid,),
                    {},
                    (
                        "An unanswered query in one capture does not prove resolver or path failure outside the capture viewpoint.",
                    ),
                    tuple(item.get("limitations", []))
                    if isinstance(item.get("limitations"), list)
                    else (),
                    (
                        "Correlate the failed lookup with the affected connection attempt and resolver-side logs if available.",
                    ),
                    _transaction_filter(failures, max_display_filter_chars),
                )
            )
    return findings


def _stream_findings(candidates, stream_index, quality, families) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for candidate in candidates:
        stream = candidate.tcp_stream
        if stream is None:
            continue
        scope = {"tcp_stream": stream}
        if candidate.capture_id is not None:
            scope["capture_id"] = candidate.capture_id
        stream_key = (candidate.capture_id, stream)
        bonus = min(candidate.score, 10)

        establishment = _stream_item(stream_index, stream_key, "analyze_tcp_establishment")
        if establishment:
            value = (
                establishment.get("value") if isinstance(establishment.get("value"), dict) else {}
            )
            eid = _evidence_id(establishment)
            state = value.get("state")
            elapsed = _number(value.get("establishment_seconds"))
            retries = _frames(value.get("repeated_syn_frames"))
            if eid and state not in (None, "established", "midstream"):
                findings.append(
                    RuleFinding(
                        (88 if "connect" in families or "disconnect" in families else 70) + bonus,
                        "TCP connection establishment did not complete normally",
                        "tcp.establishment_failure",
                        _confidence("medium", quality),
                        f"TCP stream {stream} has establishment state {state!r} rather than a completed handshake.",
                        ("local_network", "network_path", "server_application"),
                        (eid,),
                        scope,
                        (
                            "A missing or reset handshake can reflect path loss, server/listener behavior, filtering, or capture incompleteness.",
                        ),
                        tuple(establishment.get("limitations", []))
                        if isinstance(establishment.get("limitations"), list)
                        else (),
                        (
                            "Capture the same attempt at the server side to distinguish path loss from server/listener behavior.",
                        ),
                    )
                )
            elif eid and ((elapsed is not None and elapsed >= STAGE_DELAY_SECONDS) or retries):
                detail = []
                if elapsed is not None:
                    detail.append(f"establishment took {elapsed * 1000:.0f} ms")
                if retries:
                    detail.append(f"repeated SYN evidence appears in {len(retries)} frame(s)")
                findings.append(
                    RuleFinding(
                        (78 if "slow" in families or "connect" in families else 62) + bonus,
                        "TCP connection setup delay observed",
                        "tcp.establishment_delay",
                        _confidence("medium", quality),
                        f"TCP stream {stream}: " + " and ".join(detail) + ".",
                        ("local_network", "network_path", "server_application"),
                        (eid,),
                        scope,
                        (
                            "The client-side capture alone may not distinguish path loss from a delayed server response to SYN.",
                        ),
                        tuple(establishment.get("limitations", []))
                        if isinstance(establishment.get("limitations"), list)
                        else (),
                        (
                            "Capture the handshake at both endpoints or inspect server/listener timing for the same attempt.",
                        ),
                    )
                )

        health = _stream_item(stream_index, stream_key, "analyze_tcp_health")
        if health:
            value = health.get("value") if isinstance(health.get("value"), dict) else {}
            eid = _evidence_id(health)
            retrans = value.get("retransmission_union_count")
            out_of_order = _indicator_frames(value, "out_of_order")
            dup_ack = _indicator_frames(value, "duplicate_ack")
            if eid and isinstance(retrans, int) and retrans > 0:
                findings.append(
                    RuleFinding(
                        (75 if {"slow", "throughput", "intermittent"} & families else 58) + bonus,
                        "TCP retransmission indicators observed",
                        "tcp.retransmission",
                        _confidence("medium", quality, ambiguous=bool(out_of_order)),
                        f"TCP stream {stream} contains {retrans} unique retransmission-indicator frame(s).",
                        ("local_network", "network_path"),
                        (eid,),
                        scope,
                        tuple(
                            item
                            for item in (
                                "Reordering can produce retransmission-like symptoms."
                                if out_of_order
                                else None,
                                "Capture perspective cannot localize the physical hop where loss occurred.",
                            )
                            if item
                        ),
                        tuple(health.get("limitations", []))
                        if isinstance(health.get("limitations"), list)
                        else (),
                        (
                            "Compare a simultaneous server-side capture or interface counters to determine where loss/reordering occurs.",
                        ),
                    )
                )
            elif eid and out_of_order and dup_ack:
                findings.append(
                    RuleFinding(
                        55 + bonus,
                        "Packet reordering indicators observed",
                        "tcp.reordering",
                        _confidence("low", quality),
                        f"TCP stream {stream} shows out-of-order and duplicate-ACK indicators without a unique retransmission count.",
                        ("network_path",),
                        (eid,),
                        scope,
                        ("A single-ended capture cannot establish where reordering occurred.",),
                        tuple(health.get("limitations", []))
                        if isinstance(health.get("limitations"), list)
                        else (),
                        (
                            "Compare both endpoint captures to confirm sequence arrival order across the path.",
                        ),
                    )
                )

        rtt = _stream_item(stream_index, stream_key, "analyze_rtt")
        if rtt:
            value = rtt.get("value") if isinstance(rtt.get("value"), dict) else {}
            eid = _evidence_id(rtt)
            median = _number(value.get("median_seconds"))
            samples = value.get("sample_count")
            if eid and median is not None and median >= RTT_HIGH_SECONDS:
                findings.append(
                    RuleFinding(
                        (72 if "slow" in families else 54) + bonus,
                        "High transport RTT observed",
                        "tcp.rtt",
                        _confidence("medium", quality),
                        f"TCP stream {stream} has a measured median ACK RTT of {median * 1000:.0f} ms"
                        + (f" across {samples} sample(s)." if isinstance(samples, int) else "."),
                        ("local_network", "network_path"),
                        (eid,),
                        scope,
                        (
                            f"The {RTT_HIGH_SECONDS * 1000:.0f} ms rule threshold is a diagnostic heuristic, not proof of a network fault.",
                            "Path distance and capture location can legitimately produce higher RTT.",
                        ),
                        tuple(rtt.get("limitations", []))
                        if isinstance(rtt.get("limitations"), list)
                        else (),
                        (
                            "Compare RTT from the same path under a known-good reproduction or from the opposite endpoint.",
                        ),
                    )
                )

        window = _stream_item(stream_index, stream_key, "analyze_window_behavior")
        if window:
            value = window.get("value") if isinstance(window.get("value"), dict) else {}
            eid = _evidence_id(window)
            zeros = _indicator_frames(value, "zero_window")
            if eid and zeros:
                findings.append(
                    RuleFinding(
                        (82 if {"slow", "throughput"} & families else 65) + bonus,
                        "Receiver zero-window condition observed",
                        "tcp.receive_window",
                        _confidence("high", quality),
                        f"TCP stream {stream} contains {len(zeros)} zero-window indicator frame(s), showing the receiver temporarily stopped accepting data.",
                        ("unknown",),
                        (eid,),
                        scope,
                        (
                            "Endpoint role is not inferred from the packet condition alone; the constrained receiver may be client or server-side.",
                        ),
                        tuple(window.get("limitations", []))
                        if isinstance(window.get("limitations"), list)
                        else (),
                        (
                            "Identify the advertising endpoint and inspect its receive/application consumption behavior during the stall.",
                        ),
                    )
                )

        resets = _stream_item(stream_index, stream_key, "analyze_tcp_resets")
        if resets:
            value = resets.get("value") if isinstance(resets.get("value"), dict) else {}
            eid = _evidence_id(resets)
            count = value.get("count")
            if eid and isinstance(count, int) and count > 0:
                findings.append(
                    RuleFinding(
                        (92 if "disconnect" in families else 74) + bonus,
                        "TCP reset observed",
                        "tcp.reset",
                        _confidence("high", quality, ambiguous=True),
                        f"TCP stream {stream} contains {count} reset event(s).",
                        ("unknown",),
                        (eid,),
                        scope,
                        (
                            "A reset proves connection termination, not why the endpoint or an intermediary sent it.",
                            "A later SYN does not establish application-session continuity or causality.",
                        ),
                        tuple(resets.get("limitations", []))
                        if isinstance(resets.get("limitations"), list)
                        else (),
                        (
                            "Correlate the reset timestamp with endpoint/application logs and, if needed, captures on both sides.",
                        ),
                    )
                )

        tls = _stream_item(stream_index, stream_key, "analyze_tls_handshakes")
        if tls:
            value = tls.get("value") if isinstance(tls.get("value"), dict) else {}
            eid = _evidence_id(tls)
            attempts = value.get("attempts") if isinstance(value.get("attempts"), list) else []
            delay = max(
                [
                    _number(attempt.get("client_hello_to_server_hello_seconds")) or 0
                    for attempt in attempts
                    if isinstance(attempt, dict)
                ]
                or [0]
            )
            alerts = value.get("alerts") if isinstance(value.get("alerts"), list) else []
            retries = _frames(value.get("repeated_client_hello_frames"))
            if eid and (delay >= STAGE_DELAY_SECONDS or alerts or retries):
                pieces = []
                if delay >= STAGE_DELAY_SECONDS:
                    pieces.append(f"ClientHello-to-ServerHello reached {delay * 1000:.0f} ms")
                if retries:
                    pieces.append(f"{len(retries)} repeated ClientHello indicator(s) were observed")
                if alerts:
                    pieces.append(f"{len(alerts)} TLS alert record(s) were observed")
                findings.append(
                    RuleFinding(
                        (76 if "tls" in families or "slow" in families else 58) + bonus,
                        "TLS handshake condition observed",
                        "tls.handshake",
                        _confidence("medium", quality),
                        f"TCP stream {stream}: " + "; ".join(pieces) + ".",
                        ("server_application", "local_network", "network_path"),
                        (eid,),
                        scope,
                        (
                            "Encrypted session usability/completion is not established from visible handshake metadata alone.",
                            "Handshake response delay can include endpoint processing and network RTT.",
                        ),
                        tuple(tls.get("limitations", []))
                        if isinstance(tls.get("limitations"), list)
                        else (),
                        (
                            "Compare transport RTT with TLS timing and inspect server-side TLS/application logs for the same connection.",
                        ),
                    )
                )
        http = _stream_item(stream_index, stream_key, "analyze_http_timing")
        if http:
            value = http.get("value") if isinstance(http.get("value"), dict) else {}
            transactions = (
                value.get("transactions") if isinstance(value.get("transactions"), list) else []
            )
            eid = _evidence_id(http)
            delayed = [
                tx
                for tx in transactions
                if isinstance(tx, dict)
                and (_number(tx.get("request_to_first_response_seconds")) or 0)
                >= STAGE_DELAY_SECONDS
            ]
            if eid and delayed:
                transaction = delayed[0]
                seconds = _number(transaction["request_to_first_response_seconds"])
                request_range = transaction.get("request_frame_range", {})
                request_completion = request_range.get("end")
                first_response = transaction.get("first_response_frame")
                frames = [request_completion, first_response]
                if any(not isinstance(frame, int) or frame < 1 for frame in frames):
                    continue
                display_filter = transaction.get("display_filter")
                findings.append(
                    RuleFinding(
                        91 + bonus,
                        "HTTP server/application response wait measured",
                        "server.application_wait",
                        _confidence("medium", quality),
                        f"TCP stream {stream} has a measured {seconds * 1000:.0f} ms interval from HTTP request completion at frame {frames[0]} to the first correlated response at frame {frames[1]}.",
                        ("server_application",),
                        (eid,),
                        {**scope, "request_frame": frames[0], "response_frame": frames[1]},
                        (
                            "The capture localizes the interval to the visible server/application boundary but cannot distinguish the endpoint from a downstream dependency.",
                        ),
                        tuple(http.get("limitations", [])),
                        (
                            "Compare synchronized server-side capture and application or load-balancer timing for this transaction.",
                        ),
                        display_filter if isinstance(display_filter, str) else None,
                    )
                )
    return findings


def _capture_findings(grouped, quality, quality_limitations, quality_ids) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    if quality != "good" and quality_ids:
        findings.append(
            RuleFinding(
                100 if quality == "insufficient" else 68,
                "Capture observability limits the investigation",
                "capture.quality",
                "high" if quality == "insufficient" else "medium",
                f"Capture quality is {quality}; material conclusions must account for the listed observability limitations.",
                ("capture_observability",),
                tuple(quality_ids),
                {},
                (),
                tuple(quality_limitations),
                (
                    "Collect a complete bidirectional capture covering the full failure/slow transaction when feasible.",
                ),
            )
        )

    for item in grouped.get("analyze_pmtud_signals", []):
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        records = value.get("records") if isinstance(value.get("records"), list) else []
        eid = _evidence_id(item)
        if eid and records:
            findings.append(
                RuleFinding(
                    64,
                    "Explicit PMTUD control signal observed",
                    "network.pmtud",
                    _confidence("medium", quality),
                    f"The capture contains {len(records)} ICMP fragmentation-needed or Packet Too Big signal(s).",
                    ("local_network", "network_path"),
                    (eid,),
                    {},
                    (
                        "A PMTUD control message is path evidence but does not by itself prove an MTU black hole or user-impact root cause.",
                    ),
                    tuple(item.get("limitations", []))
                    if isinstance(item.get("limitations"), list)
                    else (),
                    (
                        "Verify whether affected flows honor the advertised MTU and whether larger packets subsequently make progress.",
                    ),
                )
            )
    return findings


def _time_attribution(candidates, stream_index, grouped) -> dict[str, Any] | None:
    segments: list[dict[str, Any]] = []
    limitations: list[str] = []
    tcp_candidate = next(
        (candidate for candidate in candidates if candidate.tcp_stream is not None), None
    )
    if tcp_candidate is not None:
        stream = tcp_candidate.tcp_stream
        stream_key = (tcp_candidate.capture_id, stream)
        establishment = _stream_item(stream_index, stream_key, "analyze_tcp_establishment")
        if establishment:
            value = (
                establishment.get("value") if isinstance(establishment.get("value"), dict) else {}
            )
            seconds = _number(value.get("establishment_seconds"))
            eid = _evidence_id(establishment)
            if seconds is not None and eid:
                segments.append(
                    {
                        "name": "tcp_establishment",
                        "duration_ms": round(seconds * 1000, 6),
                        "measurement_class": establishment.get("epistemic_class", "derived"),
                        "evidence_ids": [eid],
                    }
                )
        tls = _stream_item(stream_index, stream_key, "analyze_tls_handshakes")
        if tls:
            value = tls.get("value") if isinstance(tls.get("value"), dict) else {}
            attempts = value.get("attempts") if isinstance(value.get("attempts"), list) else []
            retries = _frames(value.get("repeated_client_hello_frames"))
            alerts = value.get("alerts") if isinstance(value.get("alerts"), list) else []
            if retries or alerts or len(attempts) > 1:
                limitations.append(
                    "Repeated/retried/alerted TLS metadata prevents one deterministic non-overlapping TLS-establishment duration; that stage is omitted rather than treating the first ServerHello as completed establishment."
                )
            else:
                usable = []
                for attempt in attempts:
                    if not isinstance(attempt, dict):
                        continue
                    before = _number(attempt.get("tcp_established_to_client_hello_seconds"))
                    hello = _number(attempt.get("client_hello_to_server_hello_seconds"))
                    if before is not None and hello is not None:
                        usable.append(before + hello)
                    elif hello is not None:
                        usable.append(hello)
                eid = _evidence_id(tls)
                if usable and eid:
                    seconds = usable[0]
                    segments.append(
                        {
                            "name": "tls_establishment",
                            "duration_ms": round(seconds * 1000, 6),
                            "measurement_class": tls.get("epistemic_class", "derived"),
                            "evidence_ids": [eid],
                        }
                    )
                    limitations.append(
                        "TLS attribution ends at the first visible ServerHello milestone; encrypted session completion is not assumed."
                    )
        http = _stream_item(stream_index, stream_key, "analyze_http_timing")
        if http:
            value = http.get("value") if isinstance(http.get("value"), dict) else {}
            transactions = (
                value.get("transactions") if isinstance(value.get("transactions"), list) else []
            )
            measured = [
                transaction
                for transaction in transactions
                if isinstance(transaction, dict)
                and _number(transaction.get("request_to_first_response_seconds")) is not None
            ]
            eid = _evidence_id(http)
            if measured and eid:
                seconds = _number(measured[0]["request_to_first_response_seconds"])
                segments.append(
                    {
                        "name": "server_application_wait",
                        "duration_ms": round(seconds * 1000, 6),
                        "measurement_class": "derived",
                        "evidence_ids": [eid],
                    }
                )
                limitations.append(
                    "HTTP request-to-first-response timing localizes delay to the visible server/application boundary; the capture cannot distinguish that endpoint from a downstream dependency."
                )
        if segments:
            limitations.append(
                "Time attribution is a non-overlapping measured stage subtotal for the top-ranked TCP stream, not complete user-visible transaction time."
            )
    elif grouped.get("analyze_dns"):
        item = grouped["analyze_dns"][0]
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        transactions = (
            value.get("transactions") if isinstance(value.get("transactions"), list) else []
        )
        complete = [
            tx
            for tx in transactions
            if isinstance(tx, dict) and _number(tx.get("elapsed_seconds")) is not None
        ]
        eid = _evidence_id(item)
        if len(complete) == 1 and eid:
            seconds = _number(complete[0].get("elapsed_seconds"))
            segments.append(
                {
                    "name": "dns",
                    "duration_ms": round(seconds * 1000, 6),
                    "measurement_class": item.get("epistemic_class", "derived"),
                    "evidence_ids": [eid],
                }
            )
            limitations.append(
                "The DNS interval is measured, but no application transaction linkage is inferred from timing or transaction ID alone."
            )
    if not segments:
        return None
    for segment in segments:
        if segment["measurement_class"] not in {"observed", "derived", "inferred"}:
            segment["measurement_class"] = "derived"
    return {
        "total_ms": round(sum(segment["duration_ms"] for segment in segments), 6),
        "segments": segments,
        "limitations": limitations,
    }


def _dedupe(strings: Iterable[str]) -> list[str]:
    result = []
    for value in strings:
        if isinstance(value, str) and value and value not in result:
            result.append(value)
    return result


def _primary(findings: list[RuleFinding], quality: str):
    if quality == "insufficient":
        return {
            "type": "insufficient_evidence",
            "statement": "The capture does not provide enough observability for a reliable primary fault-domain conclusion.",
            "confidence": "low",
            "fault_domains": ["capture_observability", "unknown"],
            "evidence_ids": list(findings[0].evidence_ids) if findings else [],
        }
    levels = {"low": 0, "medium": 1, "high": 2}
    supported = [
        finding
        for finding in findings
        if finding.category != "capture.quality"
        and levels[finding.confidence] >= levels[MIN_PRIMARY_CONFIDENCE]
    ]
    if not supported:
        return {
            "type": "insufficient_evidence",
            "statement": "No deterministic condition in the available evidence is sufficient to support a primary diagnosis.",
            "confidence": "low",
            "fault_domains": ["unknown"],
            "evidence_ids": [],
        }
    finding = supported[0]
    return {
        "type": "supported_finding",
        "statement": finding.statement,
        "confidence": finding.confidence,
        "fault_domains": list(finding.fault_domains),
        "evidence_ids": list(finding.evidence_ids),
    }


def _remaining_hypotheses(
    conclusion: dict[str, Any],
    findings: list[RuleFinding],
    families: set[str],
    quality: str,
) -> list[dict[str, Any]]:
    """List unresolved explanations without upgrading them to findings.

    Hypotheses are intentionally separate from findings: they can be plausible without
    having enough support for a diagnostic conclusion. Symptom text may select which
    hypotheses are relevant, but it never supplies evidence.
    """
    if conclusion["type"] != "insufficient_evidence":
        return []

    hypotheses: list[dict[str, Any]] = []

    def add(statement, domains, evidence_ids=(), next_evidence=()):
        key = (statement, tuple(domains))
        if any((item["statement"], tuple(item["fault_domains"])) == key for item in hypotheses):
            return
        hypotheses.append(
            {
                "statement": statement,
                "fault_domains": list(domains),
                "evidence_ids": list(evidence_ids),
                "next_evidence": list(next_evidence),
            }
        )

    if quality == "insufficient":
        add(
            "The capture may be missing the traffic or direction needed to distinguish the actual fault domain.",
            ("capture_observability", "unknown"),
            tuple(conclusion.get("evidence_ids", [])),
            ("Collect a complete bidirectional capture covering the full affected transaction.",),
        )

    # Preserve ambiguity exposed by observed conditions without presenting the alternatives
    # as established findings.
    for finding in findings:
        if finding.category == "tcp.reset":
            add(
                "The observed reset could originate from an endpoint/application decision or from an intermediary; the capture does not establish which.",
                ("client", "network_path", "server_application"),
                finding.evidence_ids,
                finding.recommended_validation,
            )
        elif finding.category == "tcp.establishment_failure":
            add(
                "Connection establishment failure could reflect path/filtering loss or server/listener behavior.",
                ("local_network", "network_path", "server_application"),
                finding.evidence_ids,
                finding.recommended_validation,
            )
        elif finding.category == "tcp.retransmission":
            add(
                "Loss and packet reordering remain competing explanations until capture perspective is corroborated.",
                ("local_network", "network_path", "capture_observability"),
                finding.evidence_ids,
                finding.recommended_validation,
            )

    # When deterministic evidence does not identify a supported condition, list the
    # meaningful symptom-specific boundaries that remain open.
    if not hypotheses or not findings:
        if "dns" in families:
            add(
                "Name-resolution delay or failure remains possible but is not established by the available evidence.",
                ("dns",),
                (),
                (
                    "Capture the complete DNS query/response sequence for the affected lookup or collect resolver logs.",
                ),
            )
        elif "tls" in families:
            add(
                "TLS endpoint processing and transport/path delay remain possible contributors, but the available evidence does not discriminate them.",
                ("server_application", "network_path"),
                (),
                (
                    "Capture the full TCP/TLS handshake and compare transport RTT with TLS milestone timing.",
                ),
            )
        elif {"disconnect", "connect"} & families:
            add(
                "Endpoint/listener behavior and network-path interruption remain plausible connection-failure domains.",
                ("client", "local_network", "network_path", "server_application"),
                (),
                (
                    "Capture the same failed attempt at both endpoints and correlate endpoint/application logs.",
                ),
            )
        elif {"slow", "throughput"} & families:
            add(
                "Network transport delay/loss and server/application wait remain plausible contributors to the reported slowness.",
                ("local_network", "network_path", "server_application"),
                (),
                (
                    "Capture the full request/response interval and collect application or load-balancer timing for the same transaction.",
                ),
            )
        else:
            add(
                "The available packet evidence does not discriminate among client, path, and server/application causes.",
                ("client", "network_path", "server_application", "unknown"),
                (),
                (
                    "Reproduce with a complete bidirectional capture and a precise affected transaction/time window.",
                ),
            )

    return hypotheses[:8]


def build_investigation_result(
    *,
    case_id: str,
    symptom: str,
    evidence: list[dict[str, Any]],
    analyzer_versions: dict[str, str] | None = None,
    max_display_filter_chars: int = DEFAULT_MAX_DISPLAY_FILTER_CHARS,
    correlations: list[dict] | None = None,
    capture_count: int = 0,
) -> dict[str, Any]:
    """Assemble a deterministic, schema-shaped investigation result.

    Symptom text affects prioritization only.  It never creates an evidence fact.
    """

    grouped = _by_category(evidence)
    evidence_map = {
        item["id"]: item for item in evidence if isinstance(item.get("id"), str) and item.get("id")
    }
    valid_correlations = []
    for item in (correlations or [])[:500]:
        if not isinstance(item, dict):
            continue
        capture_ids = item.get("capture_ids")
        capture_evidence_ids = item.get("capture_evidence_ids")
        evidence_ids = item.get("evidence_ids")
        if (
            not isinstance(capture_ids, list)
            or len(capture_ids) != 2
            or not all(isinstance(capture_id, str) for capture_id in capture_ids)
            or not isinstance(capture_evidence_ids, dict)
            or not isinstance(evidence_ids, list)
            or not all(isinstance(evidence_id, str) for evidence_id in evidence_ids)
        ):
            continue
        cited_ids = set()
        provenance_valid = True
        matched_frames = item.get("matched_frames")
        if not isinstance(matched_frames, list) or not matched_frames:
            continue
        for capture_id in capture_ids:
            source_ids = capture_evidence_ids.get(capture_id)
            if not isinstance(source_ids, list) or not source_ids:
                provenance_valid = False
                break
            for evidence_id in source_ids:
                record = evidence_map.get(evidence_id) if isinstance(evidence_id, str) else None
                if not record or record.get("capture_id") != capture_id:
                    provenance_valid = False
                    break
                cited_ids.add(evidence_id)
            if not provenance_valid:
                break
            for descriptor in matched_frames:
                packet = descriptor.get(capture_id) if isinstance(descriptor, dict) else None
                frame = packet.get("frame") if isinstance(packet, dict) else None
                if (
                    type(frame) is not int
                    or frame <= 0
                    or not any(
                        frame in evidence_map[evidence_id].get("frame_refs", [])
                        for evidence_id in source_ids
                    )
                ):
                    provenance_valid = False
                    break
            if not provenance_valid:
                break
        if provenance_valid and cited_ids == set(evidence_ids):
            valid_correlations.append(item)
    localized = localize_tcp_correlations(valid_correlations)
    stream_index = _by_stream(evidence)
    families = _families(symptom)
    quality, quality_limitations, quality_ids = _quality(evidence)
    all_candidates = _rank_candidates_all(symptom, evidence)
    candidates = all_candidates[:MAX_CANDIDATES]
    truncation_limitations = []
    if len(all_candidates) > MAX_CANDIDATES:
        truncation_limitations.append(
            f"Candidate conversation ranking was limited to the top {MAX_CANDIDATES} of {len(all_candidates)} conversations; lower-ranked conversations were not evaluated for Gate 4 findings."
        )

    findings = []
    findings.extend(_capture_findings(grouped, quality, quality_limitations, quality_ids))
    findings.extend(_dns_findings(grouped, quality, families, max_display_filter_chars))
    findings.extend(_stream_findings(candidates, stream_index, quality, families))
    for item in localized:
        findings.append(
            RuleFinding(
                96 if item["confidence"] == "high" else 88,
                item["title"],
                item["category"],
                item["confidence"],
                item["statement"],
                tuple(item["fault_domains"]),
                tuple(item["evidence_ids"]),
                {"capture_ids": item["capture_ids"], "matched_frames": item["matched_frames"]},
                (
                    "Capture placement and unobserved dependencies can leave alternate explanations.",
                ),
                tuple(item["limitations"]),
                (
                    "Validate the same TCP handshake at the listed capture points and compare endpoint logs.",
                ),
                "tcp",
            )
        )
    findings.sort(
        key=lambda finding: (
            -finding.priority,
            finding.category,
            finding.evidence_ids,
            tuple(sorted(finding.affected_scope.items())),
        )
    )
    total_findings = len(findings)
    if total_findings > MAX_FINDINGS:
        truncation_limitations.append(
            f"Finding output was limited to the top {MAX_FINDINGS} of {total_findings} supported observations."
        )
    findings = findings[:MAX_FINDINGS]

    rendered = [
        _finding_dict(number, finding, evidence_map, max_display_filter_chars)
        for number, finding in enumerate(findings, start=1)
    ]
    conclusion = _primary(findings, quality)
    remaining_hypotheses = _remaining_hypotheses(conclusion, findings, families, quality)

    limitations = _dedupe(
        [
            *truncation_limitations,
            *quality_limitations,
            *(limitation for finding in findings for limitation in finding.limitations),
        ]
    )
    recommendations = _dedupe(
        recommendation for finding in findings for recommendation in finding.recommended_validation
    )
    if conclusion["type"] == "insufficient_evidence":
        recommendations = _dedupe(
            [
                *recommendations,
                *(
                    item
                    for hypothesis in remaining_hypotheses
                    for item in hypothesis["next_evidence"]
                ),
            ]
        )
        if not recommendations:
            recommendations = [
                "Collect a complete bidirectional reproduction that includes the relevant handshake and user-visible transaction interval."
            ]

    versions = {
        str(key): str(value)
        for key, value in sorted((analyzer_versions or {}).items())
        if isinstance(key, str) and isinstance(value, (str, int, float))
    }
    return {
        "schema_version": "1.0",
        "case_id": case_id,
        "status": "complete",
        "symptom": symptom,
        "capture_quality": {
            "state": quality,
            "evidence_ids": quality_ids,
            "limitations": quality_limitations,
        },
        "conclusion": conclusion,
        "time_attribution": _time_attribution(candidates, stream_index, grouped),
        "findings": rendered,
        "cross_vantage": {
            "correlations": valid_correlations,
            "support": "stronger" if localized else "unchanged",
            "observed_capture_count": len(
                {
                    capture_id
                    for item in valid_correlations
                    for capture_id in item.get("capture_ids", [])
                }
            ),
            "limitations": (
                [
                    (
                        "TCP packets correlated across capture points, but timing or vantage evidence did not support localization; per-capture findings remain separate."
                        if valid_correlations
                        else "No exact packet-level cross-capture match was established; per-capture findings remain separate."
                    )
                ]
                if capture_count > 1 and not localized
                else []
            ),
        },
        "remaining_hypotheses": remaining_hypotheses,
        "limitations": limitations,
        "recommended_next_evidence": recommendations,
        "analyzer_versions": versions,
    }
