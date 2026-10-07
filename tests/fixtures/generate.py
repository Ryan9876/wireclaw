"""Synthetic, fixed bytes/timestamps only. No production data or random defaults."""

import ipaddress
import struct
from pathlib import Path

NAMES = (
    "healthy",
    "truncated",
    "midstream",
    "checksum_offload",
    "empty",
    "one_sided",
    "incomplete_handshake",
    "timestamp_regression",
    "pcapng",
    "drops",
)


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(src, dst, protocol, sport, dport, *, flags=0, seq=0, ack=0, payload=b"", bad=False):
    source, destination = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    ipv6 = len(source) == 16
    if protocol == 6:
        segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
        offset = 16
    else:
        segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        offset = 6
    segment += payload
    pseudo = (
        source
        + destination
        + (
            struct.pack("!I3xB", len(segment), protocol)
            if ipv6
            else struct.pack("!BBH", 0, protocol, len(segment))
        )
    )
    check = 0x1234 if bad else checksum(pseudo + segment) or 0xFFFF
    segment = segment[:offset] + struct.pack("!H", check) + segment[offset + 2 :]
    if ipv6:
        header = struct.pack("!IHBB", 6 << 28, len(segment), protocol, 64) + source + destination
        ethertype = 0x86DD
    else:
        header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, protocol, 0)
        header += source + destination
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        ethertype = 0x0800
    ethernet = bytes.fromhex("020000000002020000000001") + struct.pack("!H", ethertype)
    return ethernet + header + segment


def frames(*, bad=False):
    question = b"\x07example\x07invalid\x00" + struct.pack("!HH", 1, 1)
    query = struct.pack("!6H", 42, 0x0100, 1, 0, 0, 0) + question
    response = struct.pack("!6H", 42, 0x8180, 1, 1, 0, 0) + question
    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 2])
    return [
        packet("192.0.2.1", "192.0.2.2", 6, 50000, 443, flags=2, seq=100, bad=bad),
        packet("192.0.2.2", "192.0.2.1", 6, 443, 50000, flags=18, seq=200, ack=101, bad=bad),
        packet("192.0.2.1", "192.0.2.2", 6, 50000, 443, flags=16, seq=101, ack=201, bad=bad),
        packet("192.0.2.1", "192.0.2.53", 17, 53000, 53, payload=query),
        packet("192.0.2.53", "192.0.2.1", 17, 53, 53000, payload=response),
        packet("2001:db8::1", "2001:db8::2", 17, 40000, 40001, payload=b"synthetic"),
        packet("2001:db8::2", "2001:db8::1", 17, 40001, 40000, payload=b"response"),
    ]


def pcap(raws, *, truncated=False, backwards=False):
    output = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 40 if truncated else 65535, 1)
    for i, raw in enumerate(raws):
        captured = raw[:40] if truncated else raw
        micros = i * 100_000 if not backwards else (len(raws) - i) * 100_000
        output += struct.pack("<IIII", 1_700_000_000, micros, len(captured), len(raw)) + captured
    return output


def block(kind, body):
    size = len(body) + 12
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def pcapng(raws, *, drops=False):
    output = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    output += block(1, struct.pack("<HHI", 1, 0, 65535))
    for i, raw in enumerate(raws):
        ts = 1_700_000_000_000_000 + i * 100_000
        output += block(
            6,
            struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(raw), len(raw))
            + raw
            + b"\0" * (-len(raw) % 4),
        )
    if drops:
        ts = 1_700_000_000_600_000
        options = struct.pack("<HHQHH", 5, 8, 3, 0, 0)
        output += block(5, struct.pack("<III", 0, ts >> 32, ts & 0xFFFFFFFF) + options)
    return output


def generate(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    healthy = frames()
    bad = frames(bad=True)[:3]
    captures = {
        "healthy": pcap(healthy),
        "truncated": pcap(healthy, truncated=True),
        "midstream": pcap([healthy[2]]),
        "checksum_offload": pcap(bad),
        "empty": pcap([]),
        "one_sided": pcap([healthy[3], healthy[5]]),
        "incomplete_handshake": pcap(healthy[:2]),
        "timestamp_regression": pcap(healthy, backwards=True),
        "pcapng": pcapng(healthy),
        "drops": pcapng(healthy, drops=True),
        "malformed": b"not a capture\x00\xff",
        "damaged_record": pcap(healthy)[:-9],
        "unsupported": b"\xd4\xc3\xb2\xa1" + b"\x00" * 20,
    }
    for name, content in captures.items():
        (directory / f"{name}.capture").write_bytes(content)
    return captures


if __name__ == "__main__":
    import sys

    generate(Path(sys.argv[1]))
