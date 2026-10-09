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


@dataclass(frozen=True)
class Candidate:
    tcp_stream: int
    score: int
    reasons: tuple[str, ...]


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


def _by_stream(evidence: Iterable[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for item in evidence:
        stream = _scope_stream(item)
        if stream is not None:
            grouped[stream].append(item)
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
    ports = {
        int(match)
        for match in re.findall(r"(?:\bport\s+|[:/])(\d{1,5})\b", text)
        if 0 < int(match) <= 65535
    }
    return addresses, ports


def _tcp_conversations(evidence: Iterable[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    conversations: dict[int, dict[str, Any]] = {}
    for item in evidence:
        if item.get("category") != "list_conversations":
            continue
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        records = value.get("conversations") if isinstance(value.get("conversations"), list) else []
        for record in records:
            if not isinstance(record, dict) or record.get("transport") != "tcp":
                continue
            stream = record.get("stream")
            if isinstance(stream, int) and stream >= 0:
                conversations.setdefault(stream, record)
    return conversations


def _conversation_signals(
    conversation: dict[str, Any] | None,
    families: set[str],
    addresses: set[str],
    ports: set[int],
) -> tuple[int, list[str]]:
    if not conversation:
        return 0, []
    score = 1
    reasons = ["tcp_conversation"]
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
    if 443 in endpoint_ports and ({"tls", "slow", "connect"} & families):
        score += 2
        reasons.append("tls_service_relevance")
    if 53 in endpoint_ports and "dns" in families:
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


def rank_candidates(symptom: str, evidence: list[dict[str, Any]]) -> list[Candidate]:
    families = _families(symptom)
    addresses, ports = _explicit_context(symptom)
    stream_items = _by_stream(evidence)
    conversations = _tcp_conversations(evidence)
    candidates = []
    for stream in sorted(set(stream_items) | set(conversations)):
        anomaly_score, anomaly_reasons = _candidate_signals(stream_items.get(stream, []), families)
        context_score, context_reasons = _conversation_signals(
            conversations.get(stream), families, addresses, ports
        )
        reasons = tuple(sorted(set(anomaly_reasons + context_reasons)))
        candidates.append(Candidate(stream, anomaly_score + context_score, reasons))
    return sorted(candidates, key=lambda candidate: (-candidate.score, candidate.tcp_stream))[
        :MAX_CANDIDATES
    ]


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


def _stream_item(index: dict[int, list[dict[str, Any]]], stream: int, category: str):
    return next((item for item in index.get(stream, []) if item.get("category") == category), None)


def _packet_applicable(items: list[dict[str, Any]]) -> tuple[bool, str | None]:
    filters = [
        item.get("display_filter") for item in items if isinstance(item.get("display_filter"), str)
    ]
    return bool(filters), filters[0] if filters else None


def _finding_dict(number: int, finding: RuleFinding, evidence_map: dict[str, dict[str, Any]]):
    cited = [evidence_map[eid] for eid in finding.evidence_ids if eid in evidence_map]
    applicable, display_filter = _packet_applicable(cited)
    return {
        "id": f"finding_{number:03d}",
        "title": finding.title,
        "category": finding.category,
        "confidence": finding.confidence,
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


def _dns_findings(grouped, quality, families) -> list[RuleFinding]:
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
                    _confidence("medium", quality),
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
                )
            )
        if eid and failures:
            findings.append(
                RuleFinding(
                    80 if "dns" in families or "connect" in families else 60,
                    "DNS failure or unanswered query observed",
                    "dns.failure",
                    _confidence("high", quality, ambiguous=True),
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
                )
            )
    return findings


def _stream_findings(candidates, stream_index, quality, families) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for candidate in candidates:
        stream = candidate.tcp_stream
        scope = {"tcp_stream": stream}
        bonus = min(candidate.score, 10)

        establishment = _stream_item(stream_index, stream, "analyze_tcp_establishment")
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

        health = _stream_item(stream_index, stream, "analyze_tcp_health")
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

        rtt = _stream_item(stream_index, stream, "analyze_rtt")
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

        window = _stream_item(stream_index, stream, "analyze_window_behavior")
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

        resets = _stream_item(stream_index, stream, "analyze_tcp_resets")
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

        tls = _stream_item(stream_index, stream, "analyze_tls_handshakes")
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
    if candidates:
        stream = candidates[0].tcp_stream
        establishment = _stream_item(stream_index, stream, "analyze_tcp_establishment")
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
        tls = _stream_item(stream_index, stream, "analyze_tls_handshakes")
        if tls:
            value = tls.get("value") if isinstance(tls.get("value"), dict) else {}
            attempts = value.get("attempts") if isinstance(value.get("attempts"), list) else []
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
                seconds = min(usable)
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


def _dedupe(strings: Iterable[str], limit: int = 16) -> list[str]:
    result = []
    for value in strings:
        if isinstance(value, str) and value and value not in result:
            result.append(value)
            if len(result) >= limit:
                break
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
) -> dict[str, Any]:
    """Assemble a deterministic, schema-shaped investigation result.

    Symptom text affects prioritization only.  It never creates an evidence fact.
    """

    grouped = _by_category(evidence)
    stream_index = _by_stream(evidence)
    families = _families(symptom)
    quality, quality_limitations, quality_ids = _quality(evidence)
    candidates = rank_candidates(symptom, evidence)

    findings = []
    findings.extend(_capture_findings(grouped, quality, quality_limitations, quality_ids))
    findings.extend(_dns_findings(grouped, quality, families))
    findings.extend(_stream_findings(candidates, stream_index, quality, families))
    findings.sort(
        key=lambda finding: (
            -finding.priority,
            finding.category,
            finding.evidence_ids,
            tuple(sorted(finding.affected_scope.items())),
        )
    )
    findings = findings[:MAX_FINDINGS]

    evidence_map = {
        item["id"]: item for item in evidence if isinstance(item.get("id"), str) and item.get("id")
    }
    rendered = [
        _finding_dict(number, finding, evidence_map)
        for number, finding in enumerate(findings, start=1)
    ]
    conclusion = _primary(findings, quality)
    remaining_hypotheses = _remaining_hypotheses(conclusion, findings, families, quality)

    limitations = _dedupe(
        [
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
        "remaining_hypotheses": remaining_hypotheses,
        "limitations": limitations,
        "recommended_next_evidence": recommendations,
        "analyzer_versions": versions,
    }
