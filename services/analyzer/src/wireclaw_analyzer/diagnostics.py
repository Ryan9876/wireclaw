"""Pure Gate 2 evidence: indexed packet facts and explicit reproducible calculations."""

import hashlib
import hmac
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from itertools import pairwise
from statistics import median

from . import normalize
from .diagnostic_fields import EXTRA_FIELDS
from .errors import AnalyzerError
from .runner import FIELDS


class Capability(Enum):
    DNS = "analyze_dns"
    ESTABLISHMENT = "analyze_tcp_establishment"
    HEALTH = "analyze_tcp_health"
    RTT = "analyze_rtt"
    WINDOW = "analyze_window_behavior"
    RESETS = "analyze_tcp_resets"
    THROUGHPUT = "analyze_throughput"
    MSS = "analyze_mss"
    FRAGMENTATION = "analyze_fragmentation"
    PMTUD = "analyze_pmtud_signals"
    TLS = "analyze_tls_handshakes"


@dataclass(frozen=True)
class DiagnosticLimits:
    max_evidence_items: int = 5_000
    max_records: int = 20_000
    max_evidence_bytes: int = 16 * 1024 * 1024
    max_field_occurrences: int = 64
    max_frame_refs: int = 256

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise AnalyzerError("invalid_diagnostic_limits")


@dataclass(frozen=True)
class DiagnosticRequest:
    capture_id: str
    capability: Capability
    tcp_stream: int | None = None

    def __post_init__(self):
        import re

        if not isinstance(self.capture_id, str) or not re.fullmatch(
            "[a-f0-9]{64}", self.capture_id
        ):
            raise AnalyzerError("invalid_capture_id")
        if not isinstance(self.capability, Capability):
            raise AnalyzerError("invalid_capability")
        if self.tcp_stream is not None and (
            type(self.tcp_stream) is not int
            or not 0 <= self.tcp_stream <= 2**31 - 1
            or self.capability in (Capability.DNS, Capability.FRAGMENTATION, Capability.PMTUD)
        ):
            raise AnalyzerError("invalid_stream_parameter")


# Bounds reflect the registered Wireshark field types, not arbitrary text acceptance.
BOOLS = {
    "tcp.flags.reset",
    "tcp.flags.fin",
    "dns.flags.response",
    "dns.flags.truncated",
    "ip.flags.df",
    "ip.flags.mf",
    "ipv6.fraghdr.more",
}
LABELS = {f for f in EXTRA_FIELDS if f.startswith("tcp.analysis.")} - {
    "tcp.analysis.ack_rtt",
    "tcp.analysis.acks_frame",
    "tcp.analysis.bytes_in_flight",
}
LABELS.add("dns.retransmit_request")
TIMES = {"tcp.analysis.ack_rtt", "dns.time"}
SIGNED = {"tcp.window_size_scalefactor"}
UINT8 = {
    "tcp.options.wscale.shift",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
    "tls.handshake.type",
    "tls.record.content_type",
    "tls.alert_message.level",
    "tls.alert_message.desc",
}
UINT16 = {
    "tcp.window_size_value",
    "tcp.options.mss_val",
    "dns.id",
    "dns.flags.rcode",
    "dns.qry.type",
    "ip.len",
    "icmp.mtu",
    "ipv6.plen",
    "tls.handshake.extensions.supported_version",
}
REFS = {
    "tcp.analysis.acks_frame",
    "dns.response_in",
    "dns.response_to",
    "dns.retransmit_request_in",
    "tcp.segment",
    "tls.segment",
}


DNS_NAMES = {"dns.qry.name", "dns.cname"}


def name_identity(name, capture_id):
    """Bounded conservative DNS presentation syntax; raw text never leaves parsing."""
    if not isinstance(name, str) or not 1 <= len(name) <= 254:
        raise AnalyzerError("invalid_dns_name")
    normalized = name[:-1] if name.endswith(".") else name
    if normalized:
        if len(normalized) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", label) for label in normalized.split(".")
        ):
            raise AnalyzerError("invalid_dns_name")
    elif name != ".":
        raise AnalyzerError("invalid_dns_name")
    if not isinstance(capture_id, str) or not re.fullmatch("[a-f0-9]{64}", capture_id):
        raise AnalyzerError("invalid_capture_id")
    # Domain separation prevents reuse as a general content hash. Capture salt is public:
    # pseudonymization minimizes disclosure, but does not prevent dictionary guesses.
    key = hashlib.sha256(b"wireclaw-dns-name-v1\0" + bytes.fromhex(capture_id)).digest()
    return hmac.new(key, normalized.lower().encode("ascii"), hashlib.sha256).hexdigest()


def packets(text: str, maximum: int, limits: DiagnosticLimits, capture_id=None) -> list[dict]:
    """Reject malformed numeric fields; do not flatten multi-message DNS frames silently."""
    raw_rows = []
    base_lines = []
    fields = FIELDS + EXTRA_FIELDS
    for line in text.splitlines():
        if len(raw_rows) >= maximum:
            raise AnalyzerError("packet_result_limit")
        columns = line.split("\t")
        if len(columns) != len(fields):
            raise AnalyzerError("invalid_diagnostic_output")
        raw = dict(zip(fields, columns, strict=True))
        # ICMP errors contain quoted inner headers. TCP/UDP quoted in them is not a stream.
        stack = raw["frame.protocols"].split(":")
        quoted = "icmp" in stack or "icmpv6" in stack
        if (
            any("," in raw[f] for f in ("tcp.stream", "udp.stream", "ip.src", "ipv6.src"))
            and not quoted
        ):
            raise AnalyzerError("unsupported_nested_diagnostic_headers")
        base = [raw[f].split(",", 1)[0] for f in FIELDS]
        if quoted:
            for field in (
                "tcp.stream",
                "udp.stream",
                "tcp.srcport",
                "tcp.dstport",
                "udp.srcport",
                "udp.dstport",
                "tcp.flags.syn",
                "tcp.flags.ack",
            ):
                base[FIELDS.index(field)] = ""
        if (
            quoted
            and "ipv6" in stack
            and ("ip" not in stack or stack.index("ipv6") < stack.index("ip"))
        ):
            for field in ("ip.src", "ip.dst", "ip.proto"):
                base[FIELDS.index(field)] = ""
        try:
            if not math.isfinite(float(Decimal(raw["frame.time_epoch"]))):
                raise ValueError
        except (ValueError, InvalidOperation, OverflowError):
            raise AnalyzerError("invalid_diagnostic_output") from None
        base_lines.append("\t".join(base))
        values = {}
        try:
            for field in (*EXTRA_FIELDS, "tcp.seq_raw", "tcp.ack_raw"):
                parts = raw[field].split(",") if raw[field] else []
                if len(parts) > limits.max_field_occurrences:
                    raise AnalyzerError("diagnostic_occurrence_limit")
                parsed = []
                for part in parts:
                    if field in DNS_NAMES:
                        if quoted:
                            continue
                        value = name_identity(part, capture_id)
                    elif field in TIMES:
                        value = Decimal(part)
                        if not value.is_finite() or not math.isfinite(float(value)):
                            raise ValueError
                    elif field in BOOLS | LABELS:
                        if part not in ("0", "1", "True", "False"):
                            raise ValueError
                        value = part in ("1", "True")
                    else:
                        value = int(part, 0) if part.startswith("0x") else int(part)
                        lower = -2 if field in SIGNED else 0
                        upper = 255 if field in UINT8 else 65535 if field in UINT16 else 2**32 - 1
                        if not lower <= value <= upper or (field in REFS and value < 1):
                            raise ValueError
                    parsed.append(value)
                values[field] = parsed
            if quoted:
                for field in values:
                    if field.startswith(("tcp.", "dns.")):
                        values[field] = []
            raw_rows.append(values)
        except (ValueError, InvalidOperation, OverflowError):
            raise AnalyzerError("invalid_diagnostic_output") from None
    base_rows = normalize.packets("\n".join(base_lines), maximum)
    for row, values in zip(base_rows, raw_rows, strict=True):
        if row["transport"] in ("tcp", "udp") and any(
            row[k] is None for k in ("src", "dst", "src_port", "dst_port")
        ):
            raise AnalyzerError("invalid_diagnostic_output")
        if values.get("tcp.len") and values["tcp.len"][0] > row["wire_bytes"]:
            raise AnalyzerError("invalid_diagnostic_output")
        row["fields"] = values
        # A frame can contain multiple DNS messages; independent field arrays cannot
        # establish message boundaries. Explicitly withhold transaction pairing then.
        row["dns_ambiguous"] = any(
            len(values[f]) > 1
            for f in (
                "dns.id",
                "dns.flags.response",
                "dns.response_to",
                "dns.response_in",
                "dns.qry.name",
                "dns.qry.type",
            )
        )
        row["timing_regression"] = False
    for previous, row in pairwise(base_rows):
        if row["time"] < previous["time"]:
            row["timing_regression"] = True
    for row in base_rows:
        for field in REFS:
            if any(frame > len(base_rows) for frame in row["fields"][field]):
                raise AnalyzerError("invalid_diagnostic_output")
    return base_rows


def first(row, field):
    return next(iter(row["fields"].get(field, [])), None)


def flag(row, field):
    return any(row["fields"].get(field, []))


def endpoint(row, source=True):
    prefix = "src" if source else "dst"
    return {"address": row[prefix], "port": row[f"{prefix}_port"]}


def direction(row):
    return {"sender": endpoint(row), "receiver": endpoint(row, False)}


def interval(start, end, reliable=True):
    if start is None or end is None or not reliable or end["time"] < start["time"]:
        return None
    value = float(end["time"] - start["time"])
    return value if math.isfinite(value) else None


class Index:
    """One packet pass; every per-stream pass then touches only that stream's rows."""

    def __init__(self, rows):
        self.frames = {}
        self.tcp = defaultdict(list)
        self.dns = []
        self.network = []
        self.clock_regressions = {}
        self.reconnects = defaultdict(list)
        identities = {}
        previous_time = None
        regressions = 0
        last_reset = {}
        for row in rows:
            self.frames[row["frame"]] = row
            regressions += int(previous_time is not None and row["time"] < previous_time)
            self.clock_regressions[row["frame"]] = regressions
            previous_time = row["time"]
            if row["transport"] == "tcp" and row["stream"] is not None:
                identity = tuple(
                    sorted(((row["src"], row["src_port"]), (row["dst"], row["dst_port"])))
                )
                if row["stream"] in identities and identities[row["stream"]] != identity:
                    raise AnalyzerError("inconsistent_tcp_stream_identity")
                identities[row["stream"]] = identity
                self.tcp[row["stream"]].append(row)
                # Correlate observed reconnect attempts by client address and server tuple;
                # source ephemeral port may change. No causal failure claim is made.
                if row["syn"] and not row["ack"]:
                    key = (row["src"], row["dst"], row["dst_port"])
                    reset = last_reset.get(key)
                    if reset and reset["stream"] != row["stream"]:
                        self.reconnects[row["stream"]].append(
                            {
                                "prior_reset_frame": reset["frame"],
                                "prior_tcp_stream": reset["stream"],
                                "syn_frame": row["frame"],
                                "seconds_since_reset": interval(reset, row),
                            }
                        )
                if flag(row, "tcp.flags.reset"):
                    for key in (
                        (row["src"], row["dst"], row["dst_port"]),
                        (row["dst"], row["src"], row["src_port"]),
                    ):
                        last_reset[key] = row
            if row["fields"].get("dns.id"):
                self.dns.append(row)
            if row["src"]:
                self.network.append(row)


def establishment(rows):
    reliable = not any(b["time"] < a["time"] for a, b in pairwise(rows))
    syn = synack = final = reset = None
    repeats = []
    for r in rows:
        if flag(r, "tcp.flags.reset") and final is None and reset is None:
            reset = r
        if r["syn"] and not r["ack"]:
            if syn is None:
                syn = r
            elif endpoint(r) == endpoint(syn) and first(r, "tcp.seq_raw") == first(
                syn, "tcp.seq_raw"
            ):
                repeats.append(r["frame"])
        if syn and synack is None and r["syn"] and r["ack"] and endpoint(r) == endpoint(syn, False):
            seq = first(syn, "tcp.seq_raw")
            if seq is not None and first(r, "tcp.ack_raw") == (seq + 1) % 2**32:
                synack = r
        if (
            synack
            and final is None
            and not r["syn"]
            and r["ack"]
            and not flag(r, "tcp.flags.reset")
        ) and endpoint(r) == endpoint(syn):
            seq = first(synack, "tcp.seq_raw")
            if (
                seq is not None
                and first(r, "tcp.ack_raw") == (seq + 1) % 2**32
                and first(r, "tcp.seq_raw") == first(synack, "tcp.ack_raw")
            ):
                final = r
    state = (
        "established"
        if final and (reset is None or reset["frame"] > final["frame"])
        else "reset_during_establishment"
        if reset and syn
        else "incomplete"
        if syn
        else "midstream"
    )
    return {
        "state": state,
        "syn_frame": syn["frame"] if syn else None,
        "synack_frame": synack["frame"] if synack else None,
        "final_ack_frame": final["frame"] if final and state == "established" else None,
        "syn_repeated_frames": repeats,
        "reset_frame": reset["frame"] if reset else None,
        "syn_to_synack_seconds": interval(syn, synack, reliable),
        "establishment_seconds": interval(syn, final, reliable) if state == "established" else None,
        "timing_reliable": reliable,
        "calculation": "Match reverse SYN/ACK acknowledgment to SYN seq+1 and final ACK seq/ack to SYN/ACK; duration=final ACK time-initial SYN time. Repeated SYN means same direction/sequence, not proven physical loss.",
        "limitations": [
            "Incomplete means not observed before capture end, not a proven timeout.",
            "Simultaneous-open and repeated connection epochs in one tool stream are not reconstructed.",
        ]
        + ([] if reliable else ["Timestamp regression prevents interval attribution."]),
    }


def health(rows):
    indicators = {}
    for name in (
        "retransmission",
        "fast_retransmission",
        "spurious_retransmission",
        "duplicate_ack",
        "out_of_order",
    ):
        refs = [r["frame"] for r in rows if flag(r, f"tcp.analysis.{name}")]
        indicators[name] = {
            "count": len(refs),
            "frame_refs": refs,
            "fraction_of_stream_frames": len(refs) / len(rows) if rows else None,
        }
    marked = sorted(
        {
            f
            for name in ("retransmission", "fast_retransmission", "spurious_retransmission")
            for f in indicators[name]["frame_refs"]
        }
    )
    flight = [
        {"frame": r["frame"], "bytes": first(r, "tcp.analysis.bytes_in_flight"), **direction(r)}
        for r in rows
        if first(r, "tcp.analysis.bytes_in_flight") is not None
    ]
    return {
        "indicators": indicators,
        "retransmission_union_count": len(marked),
        "retransmission_union_frames": marked,
        "packets": len(rows),
        "data_packets": sum((first(r, "tcp.len") or 0) > 0 for r in rows),
        "bytes_in_flight_samples": flight,
        "calculation": "Count frames labeled by each TShark tcp.analysis field; fraction=count/all stream frames (including control frames). Union retransmission classes without double counting. Bytes in flight are tool estimates.",
        "limitations": [
            "Expert indicators are suspected conditions, not independent proof of physical loss or its location.",
            "Duplicate ACKs and out-of-order indicators alone do not establish loss; capture drops/offload can affect analysis.",
        ],
    }


def rtt(rows, index):
    samples = []
    rejected = []
    for r in rows:
        measurement = first(r, "tcp.analysis.ack_rtt")
        if measurement is None:
            continue
        f = first(r, "tcp.analysis.acks_frame")
        segment = index.frames.get(f)
        if (
            measurement < 0
            or segment is None
            or segment["stream"] != r["stream"]
            or segment["transport"] != "tcp"
            or endpoint(segment) != endpoint(r, False)
            or f >= r["frame"]
            or not r["ack"]
            or flag(r, "tcp.flags.reset")
            or any(
                flag(segment, f"tcp.analysis.{name}")
                for name in ("retransmission", "fast_retransmission", "spurious_retransmission")
            )
            or interval(segment, r) is None
        ):
            rejected.append(r["frame"])
            continue
        samples.append(
            {
                "ack_frame": r["frame"],
                "segment_frame": f,
                "seconds": float(measurement),
                "data_sender": endpoint(segment),
            }
        )
    groups = defaultdict(list)
    for sample in samples:
        sender = sample["data_sender"]
        groups[(sender["address"], sender["port"])].append(Decimal(str(sample["seconds"])))

    def stats(values):
        values = sorted(values)
        return {
            "sample_count": len(values),
            "min_seconds": float(values[0]) if values else None,
            "median_seconds": float(median(values)) if values else None,
            "p95_seconds": float(values[math.ceil(len(values) * 0.95) - 1]) if values else None,
            "max_seconds": float(values[-1]) if values else None,
        }

    return {
        **stats([Decimal(str(s["seconds"])) for s in samples]),
        "samples": samples,
        "directions": [
            {"data_sender": {"address": addr, "port": port}, **stats(v)}
            for (addr, port), v in sorted(groups.items())
        ],
        "rejected_ack_frames": rejected,
        "calculation": "Eligible TShark ACK RTT with a prior reverse segment in the same stream, ACK flag and nonnegative timestamps; omit segments marked retransmitted. Median midpoint; p95 nearest-rank ceil(0.95*n).",
        "limitations": [
            "ACK RTT is capture-point segment-to-ACK timing, includes delayed ACKs and may include SYN samples; not one-way path latency.",
            "TShark 4.2.2 does not expose newer ambiguous_ack classification; these samples do not independently implement Karn's algorithm.",
        ],
    }


def windows(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["src"], r["src_port"])].append(r)
    directions = []
    for (address, port), packets_ in sorted(groups.items()):
        samples = [
            (r, first(r, "tcp.window_size"))
            for r in packets_
            if first(r, "tcp.window_size") is not None
        ]
        scales = sorted(
            {
                first(r, "tcp.window_size_scalefactor")
                for r, _ in samples
                if first(r, "tcp.window_size_scalefactor") is not None
            }
        )
        shifts = [
            {"frame": r["frame"], "shift": v}
            for r in packets_
            for v in r["fields"].get("tcp.options.wscale.shift", [])
        ]
        spans = []
        start = None
        reliable = not any(b["time"] < a["time"] for a, b in pairwise(packets_))
        for r, value in samples:
            if (
                value == 0
                and not r["syn"]
                and not flag(r, "tcp.flags.reset")
                and not flag(r, "tcp.flags.fin")
                and start is None
            ):
                start = r
            elif value > 0 and start:
                spans.append(
                    {
                        "start_frame": start["frame"],
                        "reopen_frame": r["frame"],
                        "observed_seconds": interval(start, r, reliable),
                        "state": "reopened",
                    }
                )
                start = None
        if start:
            spans.append(
                {
                    "start_frame": start["frame"],
                    "reopen_frame": None,
                    "observed_seconds": None,
                    "state": "open_at_capture_end",
                }
            )
        minimum = min((v for _, v in samples), default=None)
        maximum = max((v for _, v in samples), default=None)
        directions.append(
            {
                "advertiser": {"address": address, "port": port},
                "sample_count": len(samples),
                "minimum_window_bytes": minimum,
                "maximum_window_bytes": maximum,
                "extreme_frame_refs": sorted(
                    {next(r["frame"] for r, v in samples if v == n) for n in (minimum, maximum)}
                )
                if samples
                else [],
                "scaling_factors": scales,
                "scale_options": shifts,
                "zero_window_intervals": spans,
            }
        )
    signals = {
        name: [r["frame"] for r in rows if flag(r, f"tcp.analysis.{name}")]
        for name in ("zero_window", "zero_window_probe", "window_full")
    }
    return {
        "directions": directions,
        "indicators": signals,
        "calculation": "Observe advertised/scaled windows by sender. Zero-window interval begins at first zero advertisement and ends at next positive advertisement from that endpoint; duration is only that observed interval.",
        "limitations": [
            "A zero window constrains the peer sender, but does not prove an application cause or all idle time is window-limited.",
            "Scale factor -1 means unknown; -2 means no scaling. Window-full is a Wireshark expert indication, not measured receiver buffer occupancy.",
        ],
    }


def resets(rows, setup, index):
    events = []
    syn = index.frames.get(setup["syn_frame"])
    final = index.frames.get(setup["final_ack_frame"])
    for r in rows:
        if not flag(r, "tcp.flags.reset"):
            continue
        events.append(
            {
                "frame": r["frame"],
                **direction(r),
                "rst": True,
                "ack": r["ack"],
                "phase": "after_establishment"
                if final and r["frame"] > final["frame"]
                else "during_establishment"
                if syn
                else "unknown_midstream",
                "seconds_since_syn": interval(syn, r, setup["timing_reliable"]),
                "seconds_since_established": interval(final, r, setup["timing_reliable"])
                if final and r["frame"] > final["frame"]
                else None,
            }
        )
    return {
        "resets": events,
        "count": len(events),
        "observed_reconnect_attempts": index.reconnects.get(rows[0]["stream"], []),
        "establishment_state": setup["state"],
        "calculation": "RST and ACK flags are observed; lifecycle intervals subtract matching establishment timestamps.",
        "limitations": [
            "Reset sender is from capture perspective; process intent, spoofing and application cause are unknown."
        ],
    }


def union_length(intervals):
    """Sort once and merge disjoint sequence intervals: O(N log N), never per-packet rescans."""
    total = 0
    end = None
    for start, stop in sorted(intervals):
        total += max(0, stop - max(start, end if end is not None else start))
        end = max(stop, end if end is not None else stop)
    return total


def throughput(rows, setup):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["src"], r["src_port"])].append(r)
    result = []
    for (address, port), packets_ in sorted(groups.items()):
        payload = sum(first(r, "tcp.len") or 0 for r in packets_)
        marked_payload = sum(
            first(r, "tcp.len") or 0
            for r in packets_
            if any(
                flag(r, f"tcp.analysis.{n}")
                for n in ("retransmission", "fast_retransmission", "spurious_retransmission")
            )
        )
        seqs = []
        reliable = setup["timing_reliable"]
        ambiguous = False
        previous = None
        anchor = None
        for r in packets_:
            size = first(r, "tcp.len")
            if not size:
                continue
            raw = first(r, "tcp.seq_raw")
            if raw is None or r["captured_bytes"] < r["wire_bytes"]:
                ambiguous = True
                continue
            if previous is None:
                unwrapped = raw
                anchor = raw
            else:
                delta = (raw - previous[0] + 2**31) % 2**32 - 2**31
                unwrapped = previous[1] + delta
                if abs(delta) >= 2**30 or abs(unwrapped - anchor) >= 2**31:
                    ambiguous = True
            previous = raw, unwrapped
            # SYN consumes a sequence number before any TCP Fast Open payload.
            begin = unwrapped + int(r["syn"])
            seqs.append((begin, begin + size))
        unique = None if ambiguous else union_length(seqs)
        cutoffs = []
        if anchor is not None and not ambiguous:
            for reverse in rows:
                if reverse["src"] == address and reverse["src_port"] == port:
                    continue
                acknowledgment = first(reverse, "tcp.ack_raw")
                if (
                    reverse["ack"]
                    and not flag(reverse, "tcp.flags.reset")
                    and acknowledgment is not None
                ):
                    cutoffs.append(anchor + (acknowledgment - anchor + 2**31) % 2**32 - 2**31)
        cutoff = max(cutoffs) if cutoffs else None
        acknowledged = (
            union_length((start, min(stop, cutoff)) for start, stop in seqs if start < cutoff)
            if cutoffs
            else None
        )
        duration = interval(rows[0], rows[-1], reliable)
        wire = sum(r["wire_bytes"] for r in packets_)
        captured = sum(r["captured_bytes"] for r in packets_)
        result.append(
            {
                "sender": {"address": address, "port": port},
                "packets": len(packets_),
                "wire_bytes": wire,
                "captured_bytes": captured,
                "tcp_payload_bytes": payload,
                "expert_marked_retransmitted_payload_bytes": marked_payload,
                "unique_observed_payload_bytes": unique,
                "unique_acknowledged_payload_bytes": acknowledged,
                "tcp_goodput_approx_bits_per_second": acknowledged * 8 / duration
                if duration and acknowledged is not None
                else None,
                "overlapping_payload_bytes": payload - unique if unique is not None else None,
                "duration_seconds": duration,
                "duration_frame_refs": [rows[0]["frame"], rows[-1]["frame"]],
                "wire_bits_per_second": wire * 8 / duration if duration else None,
                "captured_bits_per_second": captured * 8 / duration if duration else None,
                "tcp_payload_bits_per_second": payload * 8 / duration if duration else None,
                "observed_unique_payload_bits_per_second": unique * 8 / duration
                if duration and unique is not None
                else None,
                "application_goodput_bits_per_second": None,
            }
        )
    return {
        "directions": result,
        "calculation": "Rates=8*bytes/(last stream frame time-first stream frame time), common bidirectional interval. Unique observed payload=union of per-direction TCP sequence ranges, excluding SYN/FIN sequence occupancy; unwrap 32-bit sequence changes within half-space, reject ambiguous large spans. Overlap=payload total-union; tool-marked retransmission bytes are a separate measure. ACK-confirmed approximation clips observed sequence intervals to highest reverse cumulative ACK; TCP goodput approximation=8*ACK-confirmed bytes/duration, not application goodput.",
        "limitations": [
            "Unique observed payload is a delivered-payload approximation only; ACK delivery and application consumption are not proven, so application goodput is unknown.",
            "Header frame lengths omit physical preamble/FCS/IFG where not captured; partial/midstream/truncated traces limit rates. Zero duration or timestamp regression yields null rates.",
        ],
    }


def tls(rows, setup, index):
    messages = [
        {
            "frame": r["frame"],
            "types": r["fields"].get("tls.handshake.type", []),
            **direction(r),
            "reassembly_frame_refs": sorted(
                set(r["fields"].get("tcp.segment", []) + r["fields"].get("tls.segment", []))
            ),
        }
        for r in rows
        if r["fields"].get("tls.handshake.type")
    ]
    attempts = []
    pending = None
    ch_rows = []
    alerts = []
    established = index.frames.get(setup["final_ack_frame"])
    for r in rows:
        types = r["fields"].get("tls.handshake.type", [])
        if 1 in types:
            ch_rows.append(r)
            pending = {
                "client_hello_frame": r["frame"],
                "server_hello_frame": None,
                "client_hello_to_server_hello_seconds": None,
                "tcp_established_to_client_hello_seconds": interval(
                    established, r, setup["timing_reliable"]
                )
                if established and established["frame"] <= r["frame"]
                else None,
                "visible_finished_frame": None,
                "visible_handshake_interval_seconds": None,
            }
            attempts.append(pending)
        if 2 in types and pending and pending["server_hello_frame"] is None:
            ch = index.frames[pending["client_hello_frame"]]
            if endpoint(r) == endpoint(ch, False):
                pending["server_hello_frame"] = r["frame"]
                pending["client_hello_to_server_hello_seconds"] = interval(
                    ch, r, setup["timing_reliable"]
                )
        if 20 in types and pending and pending["server_hello_frame"]:
            pending["visible_finished_frame"] = r["frame"]
            pending["visible_handshake_interval_seconds"] = interval(
                index.frames[pending["client_hello_frame"]], r, setup["timing_reliable"]
            )
        if 21 in r["fields"].get("tls.record.content_type", []):
            alerts.append(
                {
                    "frame": r["frame"],
                    **direction(r),
                    "levels": r["fields"].get("tls.alert_message.level", []),
                    "descriptions": r["fields"].get("tls.alert_message.desc", []),
                    "state": "decoded"
                    if r["fields"].get("tls.alert_message.desc")
                    else "encrypted_or_unavailable",
                }
            )
    return {
        "visible_messages": messages,
        "attempts": attempts,
        "repeated_client_hello_frames": [r["frame"] for r in ch_rows[1:]],
        "alerts": alerts,
        "supported_version_fields": [
            {
                "frame": r["frame"],
                "versions": r["fields"].get("tls.handshake.extensions.supported_version", []),
            }
            for r in rows
            if r["fields"].get("tls.handshake.extensions.supported_version")
        ],
        "state": "visible_metadata" if messages or alerts else "not_observable",
        "session_completion": "unknown",
        "calculation": "Pair each visible ClientHello with next reverse ServerHello before another ClientHello. Measure message-completion-frame intervals; a visible Finished interval is separate, not proof of session usability.",
        "limitations": [
            "TLS 1.3 hides handshake content after ServerHello; TLS 1.2 Finished is normally encrypted. No decryption keys are used.",
            "Repeated ClientHello may be HelloRetryRequest, renegotiation or transport retransmission, not proven TLS failure.",
            "Reassembled handshakes are timestamped at their completion frame; frame references retain contributing segments where supplied by TShark.",
        ],
    }


def dns_sequences(transactions, index, limits):
    """One transaction pass, indexed by client address and normalized name identity."""
    groups = {}
    for tx in transactions:
        identity = tx["query_name_id"]
        if identity is None:
            continue
        key = (tx["client"]["address"], identity)
        groups.setdefault(key, []).append(tx)
    sequences = []
    for (client, identity), attempts in groups.items():
        refs = sorted({f for tx in attempts for f in tx["frame_refs"]})
        queries = [tx["query_frame"] for tx in attempts]
        repeated = []
        previous = {}
        changes = []
        last = None
        for tx in attempts:
            resolver = tx["resolver"]
            key = (tuple(tx["query_types"]), resolver["address"], resolver["port"], tx["transport"])
            if key in previous:
                repeated.append(
                    {"query_frame": tx["query_frame"], "previous_query_frame": previous[key]}
                )
            previous[key] = tx["query_frame"]
            if last and (last["resolver"] != resolver or last["transport"] != tx["transport"]):
                changes.append(
                    {
                        "from_query_frame": last["query_frame"],
                        "to_query_frame": tx["query_frame"],
                        "resolver_changed": last["resolver"] != resolver,
                        "transport_changed": last["transport"] != tx["transport"],
                        "previous_state": last["state"],
                        "previous_response_code": last["response_code"],
                        "previous_truncated_response": last["truncated_response"],
                    }
                )
            last = tx
        reliable = index.clock_regressions[refs[-1]] == index.clock_regressions[refs[0]]
        sequences.append(
            {
                "sequence_id": f"dns_{identity}_client_{client}",
                "query_name_id": identity,
                "client_address": client,
                "transaction_query_frames": queries
                if len(queries) <= limits.max_frame_refs
                else [],
                "transaction_count": len(attempts),
                "query_types": sorted({q for tx in attempts for q in tx["query_types"]}),
                "resolvers": [
                    dict(address=a, port=p)
                    for a, p in sorted(
                        {(tx["resolver"]["address"], tx["resolver"]["port"]) for tx in attempts}
                    )
                ],
                "repeated_same_type_resolver_attempts": repeated,
                "resolver_or_transport_changes": changes,
                "cname_target_ids": sorted(
                    {target for tx in attempts for target in tx["cname_target_ids"]}
                ),
                "observed_span_seconds": interval(
                    index.frames[refs[0]], index.frames[refs[-1]], reliable
                ),
                "timing_reliable": reliable,
                "frame_refs": refs if len(refs) <= limits.max_frame_refs else [],
                "supporting_frame_range": {"start": refs[0], "end": refs[-1]}
                if len(refs) > limits.max_frame_refs
                else None,
                "display_filter": " || ".join(f"frame.number == {f}" for f in refs)
                if len(refs) <= limits.max_frame_refs
                else f"dns && !(icmp || icmpv6) && frame.number >= {refs[0]} && frame.number <= {refs[-1]}",
                "limitations": [
                    "Same-name grouping is correlation across this capture, not a proven application resolution episode or fallback policy. Range filters may include unrelated DNS; transaction references identify exact contributions.",
                    "CNAME target identities are observed from linked responses; parallel answer fields cannot establish owner-to-target edges or a complete alias chain.",
                ],
            }
        )
    return sequences


def dns(index, limits=None):
    limits = limits or DiagnosticLimits()
    transactions = []
    ambiguous = []
    orphan = []
    for r in index.dns:
        if r["dns_ambiguous"] or first(r, "dns.flags.response") is None:
            ambiguous.append(r["frame"])
            continue
        if first(r, "dns.flags.response"):
            if first(r, "dns.response_to") is None:
                orphan.append(r["frame"])
            continue
        original_frame = first(r, "dns.retransmit_request_in")
        linked_query = r
        original = index.frames.get(original_frame)
        if (
            original
            and flag(r, "dns.retransmit_request")
            and not original["dns_ambiguous"]
            and not first(original, "dns.flags.response")
            and first(original, "dns.qry.name") == first(r, "dns.qry.name")
            and original["fields"].get("dns.qry.type") == r["fields"].get("dns.qry.type")
            and first(original, "dns.id") == first(r, "dns.id")
            and endpoint(original) == endpoint(r)
            and endpoint(original, False) == endpoint(r, False)
            and original["transport"] == r["transport"]
            and original["stream"] == r["stream"]
            and original["frame"] < r["frame"]
        ):
            linked_query = original
        response_frame = first(linked_query, "dns.response_in")
        response = index.frames.get(response_frame)
        matches = (
            response is not None
            and not response["dns_ambiguous"]
            and first(response, "dns.flags.response")
            and first(response, "dns.qry.name") == first(r, "dns.qry.name")
            and response["fields"].get("dns.qry.type") == r["fields"].get("dns.qry.type")
            and first(response, "dns.id") == first(r, "dns.id")
            and endpoint(response) == endpoint(r, False)
            and endpoint(response, False) == endpoint(r)
            and response["transport"] == r["transport"]
            and response["stream"] == r["stream"]
            and first(response, "dns.response_to") == linked_query["frame"]
            and response["frame"] > r["frame"]
        )
        direct = linked_query is r
        reliable = (
            matches
            and index.clock_regressions[r["frame"]] == index.clock_regressions[response["frame"]]
        )
        state = (
            ("matched" if direct else "response_linked_to_original_query")
            if matches
            else "ambiguous_link"
            if response_frame
            else "unanswered_in_capture"
        )
        refs = sorted({r["frame"], *([response_frame, linked_query["frame"]] if matches else [])})
        transactions.append(
            {
                "transaction_id": first(r, "dns.id"),
                "query_name_id": first(r, "dns.qry.name"),
                "cname_target_ids": response["fields"].get("dns.cname", []) if matches else [],
                "query_frame": r["frame"],
                "response_frame": response_frame if matches else None,
                "transport": r["transport"],
                "stream": r["stream"],
                "client": endpoint(r),
                "resolver": endpoint(r, False),
                "query_types": r["fields"].get("dns.qry.type", []),
                "state": state,
                "elapsed_seconds": interval(r, response, reliable) if matches and direct else None,
                "timing_state": "measured"
                if matches and direct and interval(r, response, reliable) is not None
                else "unavailable_or_ambiguous",
                "tool_dns_time_seconds": float(first(response, "dns.time"))
                if matches
                and direct
                and reliable
                and first(response, "dns.time") is not None
                and first(response, "dns.time") >= 0
                else None,
                "response_code": first(response, "dns.flags.rcode") if matches else None,
                "truncated_response": flag(response, "dns.flags.truncated") if matches else None,
                "repeated_query_indicator": flag(r, "dns.retransmit_request"),
                "original_query_frame": first(r, "dns.retransmit_request_in"),
                "frame_refs": refs,
                "display_filter": " || ".join(f"frame.number == {f}" for f in refs),
            }
        )
    return {
        "transactions": transactions,
        "name_resolution_sequences": dns_sequences(transactions, index, limits),
        "query_identity_design": "HMAC-SHA256(normalized ASCII name; key=SHA256(domain separator+capture SHA256 bytes)); lower case, remove one root dot. Per-capture pseudonym; no network meaning or secrecy guarantee.",
        "ambiguous_message_frames": ambiguous,
        "orphan_response_frames": orphan,
        "names_retained": False,
        "calculation": "Use reciprocal TShark DNS response_in/response_to frame links and matching ID, reverse endpoints and stream; elapsed=response timestamp-query timestamp. Rcode is observed; unanswered means no linked response in the capture.",
        "limitations": [
            "Unanswered queries do not prove timeout or resolver failure; encrypted DNS is unavailable.",
            "Raw names are never retained; unsupported DNS presentation characters fail safely. Missing query identity withholds sequence correlation. IDs and timing alone never establish name relationships.",
            "A retry linked to an original query response has no independently attributable response interval. Multiple DNS messages in one frame are explicitly ambiguous; message boundaries are not reconstructed from parallel field arrays.",
        ],
    }


def network(index, capability):
    records = []
    if capability is Capability.MSS:
        for rows in index.tcp.values():
            for r in rows:
                for size in r["fields"].get("tcp.options.mss_val", []):
                    records.append(
                        {
                            "frame": r["frame"],
                            "tcp_stream": r["stream"],
                            **direction(r),
                            "mss_bytes": size,
                            "syn": r["syn"],
                        }
                    )
    elif capability is Capability.FRAGMENTATION:
        for r in index.network:
            if "icmp" in r["protocols"] or "icmpv6" in r["protocols"]:
                continue  # Quoted inner fragment fields cannot be assigned to the outer packet.
            offset = first(r, "ip.frag_offset")
            if flag(r, "ip.flags.mf") or offset:
                records.append(
                    {
                        "frame": r["frame"],
                        "family": "ipv4",
                        "source": r["src"],
                        "destination": r["dst"],
                        "offset_units_8_bytes": offset,
                        "more": flag(r, "ip.flags.mf"),
                    }
                )
            if first(r, "ipv6.fraghdr.ident") is not None:
                records.append(
                    {
                        "frame": r["frame"],
                        "family": "ipv6",
                        "source": r["src"],
                        "destination": r["dst"],
                        "identification": first(r, "ipv6.fraghdr.ident"),
                        "offset_units_8_bytes": first(r, "ipv6.fraghdr.offset"),
                        "more": flag(r, "ipv6.fraghdr.more"),
                    }
                )
    else:
        for r in index.network:
            ipv4 = first(r, "icmp.type") == 3 and first(r, "icmp.code") == 4
            ipv6 = first(r, "icmpv6.type") == 2
            if ipv4 or ipv6:
                records.append(
                    {
                        "frame": r["frame"],
                        "kind": "fragmentation_needed" if ipv4 else "packet_too_big",
                        "source": r["src"],
                        "destination": r["dst"],
                        "mtu_bytes": first(r, "icmp.mtu" if ipv4 else "icmpv6.mtu"),
                    }
                )
    sizes = defaultdict(list)
    if capability is Capability.PMTUD:
        for r in index.network:
            family = "ipv4" if ":" not in r["src"] else "ipv6"
            length = first(r, "ip.len") if family == "ipv4" else first(r, "ipv6.plen")
            if length is not None:
                sizes[(family, r["src"], r["dst"])].append(
                    (
                        r["frame"],
                        length if family == "ipv4" else length + 40,
                        flag(r, "ip.flags.df"),
                    )
                )
    patterns = []
    for (family, src, dst), values in sorted(sizes.items()):
        minimum = min(x[1] for x in values)
        maximum = max(x[1] for x in values)
        patterns.append(
            {
                "family": family,
                "source": src,
                "destination": dst,
                "packet_count": len(values),
                "minimum_ip_bytes": minimum,
                "maximum_ip_bytes": maximum,
                "maximum_size_frame": next(f for f, n, _ in values if n == maximum),
                "df_packet_count": sum(df for _, _, df in values),
            }
        )
    return {
        "records": sorted(records, key=lambda r: r["frame"]),
        "packet_size_patterns": patterns,
        "calculation": "MSS and fragmentation/ICMP fields are directly observed. Size range=min/max outer IPv4 total length or 40+IPv6 payload length by directional endpoint pair. Fragment offsets are encoded in 8-byte units; atomic IPv6 fragments are retained.",
        "limitations": [
            "MSS is advertised receive capability, not measured path MTU.",
            "ICMP errors describe the quoted traffic; this gate does not assign them to a TCP stream from quoted inner fields. Fragment signals inside ICMP errors are not inventoried.",
            "No ICMP signal does not rule out PMTUD issues; large packets/retransmissions alone do not prove an MTU black hole.",
        ],
    }


def ensure_bytes(value, limits):
    size = 1  # persisted trailing newline
    for chunk in json.JSONEncoder(allow_nan=False, sort_keys=True, indent=2).iterencode(value):
        size += len(chunk.encode("utf-8"))
        if size > limits.max_evidence_bytes:
            raise AnalyzerError("diagnostic_evidence_byte_limit")


def build(capture_id, rows, version, quality, limits, validator, request=None):
    index = Index(rows)
    evidence = []
    records = 0
    wanted = [request.capability] if request else list(Capability)
    # Conservative shared quality limitations remain attached to all diagnostic results.
    common = [
        "Capture quality must be considered before interpreting these facts; no root-cause conclusion is produced.",
        *quality.get("limitations", []),
    ]

    def emit(cap, value, stream_rows=None, stream=None):
        nonlocal records

        frame_arrays = {
            "frame_refs",
            "transaction_query_frames",
            "reassembly_frame_refs",
            "retransmission_union_frames",
            "syn_repeated_frames",
            "repeated_client_hello_frames",
            "rejected_ack_frames",
            "orphan_response_frames",
            "ambiguous_message_frames",
            "zero_window",
            "zero_window_probe",
            "window_full",
        }

        def count_lists(obj):
            if isinstance(obj, list):
                return len(obj) + sum(count_lists(v) for v in obj)
            if isinstance(obj, dict):
                for key, value_ in obj.items():
                    if (
                        key in frame_arrays
                        and isinstance(value_, list)
                        and len(value_) > limits.max_frame_refs
                    ):
                        raise AnalyzerError("diagnostic_frame_reference_limit")
                return sum(count_lists(v) for v in obj.values())
            return 0

        records += count_lists(value)
        if records > limits.max_records or len(evidence) >= limits.max_evidence_items:
            raise AnalyzerError("diagnostic_evidence_record_limit")
        if stream_rows:
            refs = [r["frame"] for r in stream_rows]
            scope = {
                "tcp_stream": stream,
                "src_ip": stream_rows[0]["src"],
                "dst_ip": stream_rows[0]["dst"],
                "src_port": stream_rows[0]["src_port"],
                "dst_port": stream_rows[0]["dst_port"],
                "protocol": "tcp",
                "start_frame": refs[0],
                "end_frame": refs[-1],
            }
            display_filter = f"tcp.stream == {stream}"
        else:
            refs = (
                [r["frame"] for r in index.dns] if cap is Capability.DNS else sorted(index.frames)
            )
            scope = {"capture": True}
            display_filter = {
                Capability.DNS: "dns && !(icmp || icmpv6)",
                Capability.MSS: "tcp.options.mss_val",
                Capability.FRAGMENTATION: "ip.flags.mf || ip.frag_offset || ipv6.fraghdr",
                Capability.PMTUD: "ip || ipv6",
            }.get(cap, "tcp")
        suffix = f"_stream{stream}" if stream is not None else ""
        limitations = common + value.get("limitations", [])
        item = normalize.evidence_item(
            capture_id,
            cap.value,
            "tshark",
            version,
            value,
            derived=True,
            scope=scope,
            scope_key=suffix.lstrip("_") or None,
            limitations=limitations,
            display_filter=display_filter,
            frame_refs=refs if len(refs) <= limits.max_frame_refs else [],
        )
        if len(refs) > limits.max_frame_refs:
            item["value"]["supporting_frame_range"] = {
                "start": refs[0],
                "end": refs[-1],
                "selection": display_filter,
            }
        validator.validate(item)
        evidence.append(item)

    for cap in wanted:
        if cap is Capability.DNS:
            emit(cap, dns(index, limits))
        elif cap in (Capability.MSS, Capability.FRAGMENTATION, Capability.PMTUD) and not (
            request and request.tcp_stream is not None
        ):
            emit(cap, network(index, cap))
        else:
            streams = (
                sorted(index.tcp)
                if not request or request.tcp_stream is None
                else [request.tcp_stream]
            )
            if request and request.tcp_stream is not None and request.tcp_stream not in index.tcp:
                raise AnalyzerError("tcp_stream_unavailable")
            if not streams:
                emit(
                    cap,
                    {
                        "state": "not_observable",
                        "calculation": "No TCP stream rows observed.",
                        "limitations": [
                            "Absent traffic is not proof of absence outside this capture."
                        ],
                    },
                )
            for stream in streams:
                packets_ = index.tcp[stream]
                setup = establishment(packets_)
                if cap is Capability.ESTABLISHMENT:
                    value = setup
                elif cap is Capability.HEALTH:
                    value = health(packets_)
                elif cap is Capability.RTT:
                    value = rtt(packets_, index)
                elif cap is Capability.WINDOW:
                    value = windows(packets_)
                elif cap is Capability.RESETS:
                    value = resets(packets_, setup, index)
                elif cap is Capability.THROUGHPUT:
                    value = throughput(packets_, setup)
                elif cap is Capability.TLS:
                    value = tls(packets_, setup, index)
                else:
                    # MSS request scoped to a stream uses the same predefined observation.
                    local = Index(packets_)
                    value = network(local, cap)
                emit(cap, value, packets_, stream)
    ensure_bytes(evidence, limits)
    return evidence
