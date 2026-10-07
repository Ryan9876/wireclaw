"""Pure, bounded transformations of deterministic tool output."""

import ipaddress
import re
from collections import Counter
from decimal import Decimal, InvalidOperation
from itertools import pairwise

from .errors import AnalyzerError
from .runner import FIELDS


def metadata(text: str) -> dict:
    values = {}
    for line in text.split("Interface #", 1)[0].splitlines():
        if ":" in line:
            key, value = line.strip().split(":", 1)
            values[key.strip()] = value.strip()
    try:
        capture_format = values["File type"]
        if "pcap" not in capture_format.lower():
            raise AnalyzerError("unsupported_capture_format")

        def number(key):
            return int(values[key].split()[0])

        duration = values["Capture duration"].split()[0]
        if duration == "n/a" and number("Number of packets") == 0:
            duration = "0"
        result = {
            "format": "pcapng" if "pcapng" in capture_format.lower() else "pcap",
            "packet_count": number("Number of packets"),
            "wire_bytes": number("Data size"),
            "file_bytes": number("File size"),
            "duration_seconds": float(Decimal(duration)),
            "encapsulation": values["File encapsulation"],
            "snaplen": None,
            "capture_drops": None,
        }
        snaplen = values.get("Packet size limit", "")
        match = re.search(r"file hdr: (\d+)", snaplen)
        if match:
            result["snaplen"] = int(match.group(1))
        if any(result[key] < 0 for key in ("packet_count", "wire_bytes", "file_bytes")):
            raise ValueError
        if not Decimal(duration).is_finite() or result["duration_seconds"] < 0:
            raise ValueError
        return result
    except (KeyError, ValueError, InvalidOperation, IndexError):
        raise AnalyzerError("invalid_metadata_output") from None


def packets(text: str, maximum: int) -> list[dict]:
    rows = []
    for line in text.splitlines():
        if len(rows) >= maximum:
            raise AnalyzerError("packet_result_limit")
        columns = line.split("\t")
        if len(columns) != len(FIELDS):
            raise AnalyzerError("invalid_packet_output")
        raw = dict(zip(FIELDS, columns, strict=True))
        try:

            def integer(key, default=None, raw=raw):
                return int(raw[key]) if raw[key] else default

            source = raw["ip.src"] or raw["ipv6.src"]
            destination = raw["ip.dst"] or raw["ipv6.dst"]
            for address in (source, destination):
                if address:
                    ipaddress.ip_address(address)
            protocol_stack = raw["frame.protocols"].split(":")
            if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", p) for p in protocol_stack):
                raise ValueError
            tcp = raw["tcp.stream"] != ""
            udp = raw["udp.stream"] != ""
            transport = "tcp" if tcp else "udp" if udp else "other"
            row = {
                "frame": integer("frame.number"),
                "time": Decimal(raw["frame.time_epoch"]),
                "wire_bytes": integer("frame.len"),
                "captured_bytes": integer("frame.cap_len"),
                "protocols": protocol_stack,
                "src": source or None,
                "dst": destination or None,
                "transport": transport,
                "src_port": integer(f"{transport}.srcport") if tcp or udp else None,
                "dst_port": integer(f"{transport}.dstport") if tcp or udp else None,
                "stream": integer(f"{transport}.stream") if tcp or udp else None,
                "syn": raw["tcp.flags.syn"] in ("1", "True"),
                "ack": raw["tcp.flags.ack"] in ("1", "True"),
                "bad_checksum": any(
                    raw[key] == "0"
                    for key in ("tcp.checksum.status", "udp.checksum.status", "ip.checksum.status")
                ),
                "malformed": bool(raw["_ws.malformed"]),
            }
            if row["frame"] != len(rows) + 1 or not row["time"].is_finite():
                raise ValueError
            if not 0 <= row["captured_bytes"] <= row["wire_bytes"]:
                raise ValueError
            for key in ("src_port", "dst_port"):
                if row[key] is not None and not 0 <= row[key] <= 65535:
                    raise ValueError
            if row["stream"] is not None and row["stream"] < 0:
                raise ValueError
            rows.append(row)
        except (ValueError, InvalidOperation, TypeError):
            raise AnalyzerError("invalid_packet_output") from None
    return rows


def protocols(rows: list[dict]) -> dict:
    counts = Counter(p for row in rows for p in set(row["protocols"]))
    return {
        "protocols": [{"protocol": p, "packets": count} for p, count in sorted(counts.items())],
        "calculation": "Count each protocol at most once per frame; layers overlap.",
    }


def endpoints(rows: list[dict]) -> dict:
    result = {}
    for row in rows:
        for direction, key in (("sent", "src"), ("received", "dst")):
            address = row[key]
            if address is None:
                continue
            item = result.setdefault(
                address,
                {
                    "address": address,
                    "address_family": f"ipv{ipaddress.ip_address(address).version}",
                    "sent_packets": 0,
                    "received_packets": 0,
                    "sent_wire_bytes": 0,
                    "received_wire_bytes": 0,
                    "ports": set(),
                },
            )
            item[f"{direction}_packets"] += 1
            item[f"{direction}_wire_bytes"] += row["wire_bytes"]
            port = row[f"{key}_port"]
            if port is not None:
                item["ports"].add((row["transport"], port))
    for item in result.values():
        item["ports"] = [{"transport": t, "port": p} for t, p in sorted(item["ports"])]
    return {
        "endpoints": sorted(result.values(), key=lambda x: (x["address_family"], x["address"])),
        "calculation": "Sum frame wire lengths per observed IP endpoint and direction.",
        "excluded_non_ip_packets": sum(row["src"] is None for row in rows),
    }


def conversations(rows: list[dict]) -> dict:
    result = {}
    for row in rows:
        if row["src"] is None or row["dst"] is None:
            continue
        pair = sorted(
            ((row["src"], row["src_port"]), (row["dst"], row["dst_port"])),
            key=lambda x: (x[0], -1 if x[1] is None else x[1]),
        )
        key = (row["transport"], tuple(pair), row["stream"])
        item = result.setdefault(
            key,
            {
                "transport": row["transport"],
                "a": {"address": pair[0][0], "port": pair[0][1]},
                "b": {"address": pair[1][0], "port": pair[1][1]},
                "stream": row["stream"],
                "a_to_b_packets": 0,
                "b_to_a_packets": 0,
                "wire_bytes": 0,
                "frame_refs": [],
                "_times": [],
            },
        )
        direction = "a_to_b" if (row["src"], row["src_port"]) == pair[0] else "b_to_a"
        item[f"{direction}_packets"] += 1
        item["wire_bytes"] += row["wire_bytes"]
        item["frame_refs"].append(row["frame"])
        item["_times"].append(row["time"])
    items = []
    for item in result.values():
        times = item.pop("_times")
        item["duration_seconds"] = float(max(times) - min(times))
        item["display_filter"] = (
            f"{item['transport']}.stream == {item['stream']}"
            if item["stream"] is not None
            else None
        )
        items.append(item)
    return {
        "conversations": sorted(
            items,
            key=lambda x: (
                x["transport"],
                x["a"]["address"],
                x["a"]["port"] or 0,
                x["b"]["address"],
                x["b"]["port"] or 0,
                x["stream"] if x["stream"] is not None else -1,
            ),
        ),
        "calculation": "Group bidirectional endpoint pairs by transport and tool stream ID; sum wire lengths; duration=max(time)-min(time).",
    }


def quality(meta: dict, rows: list[dict], inventory: dict) -> dict:
    checks = {}

    def add(name, state, frames=None, **values):
        checks[name] = {"state": state, "frame_refs": frames or [], **values}

    add(
        "truncation",
        "observed" if any(r["captured_bytes"] < r["wire_bytes"] for r in rows) else "not_observed",
        [r["frame"] for r in rows if r["captured_bytes"] < r["wire_bytes"]],
    )
    add(
        "malformed_packets",
        "observed" if any(r["malformed"] for r in rows) else "not_observed",
        [r["frame"] for r in rows if r["malformed"]],
    )
    add(
        "checksum_anomalies",
        "observed" if any(r["bad_checksum"] for r in rows) else "not_observed",
        [r["frame"] for r in rows if r["bad_checksum"]],
        offload_cause="unknown",
        note="Checksum validation enabled. Offload, corruption and capture artifacts cannot be distinguished here.",
    )
    backwards = [b["frame"] for a, b in pairwise(rows) if b["time"] < a["time"]]
    add("timestamp_regressions", "observed" if backwards else "not_observed", backwards)
    drops = meta["capture_drops"]
    add(
        "capture_drops",
        "unknown" if drops is None else "observed" if drops else "not_observed",
        count=drops,
    )
    one_sided = [
        c for c in inventory["conversations"] if not c["a_to_b_packets"] or not c["b_to_a_packets"]
    ]
    add(
        "one_sided_conversations",
        "observed" if one_sided else "not_observed",
        sorted({f for c in one_sided for f in c["frame_refs"]}),
        count=len(one_sided),
        note="One observed direction may be normal; asymmetric capture is not proven.",
    )
    midstream, incomplete = [], []
    for c in inventory["conversations"]:
        if c["transport"] != "tcp":
            continue
        frames = set(c["frame_refs"])
        stream = [r for r in rows if r["frame"] in frames]
        first = stream[0]
        if not first["syn"] or first["ack"]:
            midstream.extend(c["frame_refs"])
            continue
        # Require SYN, reverse SYN-ACK, then original-direction ACK in capture order.
        synack = next(
            (
                i
                for i, r in enumerate(stream[1:], 1)
                if r["syn"]
                and r["ack"]
                and r["src"] == first["dst"]
                and r["src_port"] == first["dst_port"]
            ),
            None,
        )
        established = synack is not None and any(
            r["ack"]
            and not r["syn"]
            and r["src"] == first["src"]
            and r["src_port"] == first["src_port"]
            for r in stream[synack + 1 :]
        )
        if not established:
            incomplete.extend(c["frame_refs"])
    add(
        "midstream_indicators",
        "observed" if midstream else "not_observed",
        sorted(midstream),
        note="Initial SYN not visible; handshake cannot be assessed.",
    )
    add("incomplete_handshakes", "observed" if incomplete else "not_observed", sorted(incomplete))
    add(
        "duplicate_capture_artifacts",
        "unknown",
        note="Repeated transport packets alone do not prove duplicate capture.",
    )
    limitations = [
        name for name, value in checks.items() if value["state"] in ("observed", "unknown")
    ]
    material = [name for name, value in checks.items() if value["state"] == "observed"]
    state = "insufficient" if not rows else "limited" if material else "good"
    return {
        "state": state,
        "checks": checks,
        "limitations": limitations,
        "calculation": "Insufficient for empty capture; limited for observed quality indicators; good means no baseline indicator observed, not complete visibility.",
    }
