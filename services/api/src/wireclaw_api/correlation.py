"""Conservative, deterministic matching of packet observations across captures."""

from __future__ import annotations

from collections import defaultdict
from statistics import median


def _endpoint(ip, port):
    return str(ip), int(port)


def _packet_descriptor(packet):
    return {
        "frame": packet.get("frame"),
        "time": float(packet["time"]),
        "src": packet.get("src"),
        "dst": packet.get("dst"),
        "src_port": packet.get("src_port"),
        "dst_port": packet.get("dst_port"),
        "syn": bool(packet.get("syn")),
        "ack": bool(packet.get("ack")),
        "rst": bool(packet.get("rst")),
        "fin": bool(packet.get("fin")),
        "seq_raw": packet.get("seq_raw"),
        "ack_raw": packet.get("ack_raw"),
        "payload_len": packet.get("payload_len"),
    }


def _signature(packet):
    source = _endpoint(packet["src"], packet["src_port"])
    destination = _endpoint(packet["dst"], packet["dst_port"])
    sequence = packet.get("seq_raw")
    acknowledgment = packet.get("ack_raw")
    payload_length = packet.get("payload_len")
    if sequence is None or acknowledgment is None or payload_length is None:
        raise ValueError("incomplete_tcp_identity")
    endpoints = tuple(sorted((source, destination)))
    direction = 0 if source == endpoints[0] else 1
    return (
        endpoints,
        direction,
        bool(packet.get("syn")),
        bool(packet.get("ack")),
        bool(packet.get("rst")),
        bool(packet.get("fin")),
        int(sequence),
        int(acknowledgment),
        int(payload_length),
    )


def correlate_tcp(captures: list[dict], evidence: list[dict]) -> list[dict]:
    """Return exact packet-signature matches; timing never establishes identity."""
    del evidence  # Packet observations are supplied on capture rows by the analyzer adapter.
    indexed = []
    for capture in captures:
        by_signature = defaultdict(list)
        timing_regression = any(
            packet.get("timing_regression") for packet in capture.get("observations", [])
        )
        for packet in capture.get("observations", []):
            try:
                by_signature[_signature(packet)].append(packet)
            except (KeyError, TypeError, ValueError):
                continue
        indexed.append((capture, by_signature, timing_regression))

    candidates = defaultdict(list)
    for index, (capture, observations, timing_regression) in enumerate(indexed):
        for signature, packets in observations.items():
            if len(packets) == 1:
                candidates[signature].append((index, capture, packets[0], timing_regression))

    pairs = defaultdict(list)
    for signature, matches in candidates.items():
        if len(matches) < 2:
            continue
        matches.sort(key=lambda match: str(match[1].get("id", "")))
        for left_index, left in enumerate(matches):
            for right in matches[left_index + 1 :]:
                if left[1].get("id") == right[1].get("id"):
                    continue
                pair = (str(left[1].get("id", "")), str(right[1].get("id", "")))
                pairs[pair].append((signature, left, right))

    correlations = []
    for capture_ids, matches in sorted(pairs.items()):
        first_capture = matches[0][1][1]
        second_capture = matches[0][2][1]
        alignment = estimate_clock_alignment(
            [
                {
                    "reference_time": float(left[2]["time"]),
                    "observed_time": float(right[2]["time"]),
                    "timing_regression": left[2].get("timing_regression", False)
                    or right[2].get("timing_regression", False)
                    or left[3]
                    or right[3],
                }
                for _, left, right in matches
            ]
        )
        for _, left, right in matches:
            correlations.append(
                {
                    "capture_ids": list(capture_ids),
                    "evidence_ids": sorted(
                        {
                            evidence_id
                            for capture in (first_capture, second_capture)
                            for evidence_id in capture.get("evidence_ids", [])[:8]
                            if isinstance(evidence_id, str) and evidence_id
                        }
                    ),
                    "source_artifact_ids": [
                        first_capture.get("original_artifact_id"),
                        second_capture.get("original_artifact_id"),
                    ],
                    "matched_packets": 1,
                    "vantages": sorted(
                        {
                            str(first_capture.get("vantage_type", "unknown")),
                            str(second_capture.get("vantage_type", "unknown")),
                        }
                    ),
                    "capture_evidence_ids": {
                        capture_ids[0]: list(first_capture.get("evidence_ids", [])[:8]),
                        capture_ids[1]: list(second_capture.get("evidence_ids", [])[:8]),
                    },
                    "capture_vantages": {
                        capture_ids[0]: first_capture.get("vantage_type", "unknown"),
                        capture_ids[1]: second_capture.get("vantage_type", "unknown"),
                    },
                    "matched_frames": [
                        {
                            capture_ids[0]: {
                                **_packet_descriptor(left[2]),
                            },
                            capture_ids[1]: {
                                **_packet_descriptor(right[2]),
                            },
                        }
                    ],
                    "matching_method": "direction_normalized_tuple_flags_sequence_ack_payload",
                    "matching_strength": "exact_packet_signature",
                    "clock_alignment": alignment,
                    "limitations": [
                        "Exact tuple, direction, flags, sequence, acknowledgment, and payload length matched; NAT or tuple translation is not correlated."
                    ],
                }
            )
    return correlations


def estimate_clock_alignment(
    matches: list[dict], *, claimed_delay_seconds: float | None = None
) -> dict:
    offsets = []
    for match in matches:
        try:
            offset = float(match["observed_time"]) - float(match["reference_time"])
        except (KeyError, TypeError, ValueError):
            continue
        if offset == offset and abs(offset) != float("inf"):
            offsets.append(offset)
    if not offsets:
        return {
            "offset_seconds": None,
            "uncertainty_seconds": None,
            "matched_count": 0,
            "usable": False,
        }
    initial_offset = median(offsets)
    inliers = [value for value in offsets if abs(value - initial_offset) <= 0.05]
    stable_offsets = inliers if len(inliers) >= 3 else offsets
    offset = median(stable_offsets)
    uncertainty = max(abs(value - offset) for value in stable_offsets)
    enough = len(inliers) >= 3
    no_regression = not any(match.get("timing_regression") for match in matches)
    delay_bound = claimed_delay_seconds is None or (
        claimed_delay_seconds > 0 and uncertainty <= claimed_delay_seconds / 4
    )
    return {
        "offset_seconds": offset,
        "uncertainty_seconds": uncertainty,
        "matched_count": len(inliers) if enough else len(offsets),
        "usable": enough and uncertainty <= 0.05 and delay_bound and no_regression,
    }
