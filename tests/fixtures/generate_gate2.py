"""Gate 2 captures: fixed clocks, documentation addresses, valid checksums, no secrets."""

import ipaddress
import struct
from pathlib import Path

from generate import checksum, network_packet, packet

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
NAMES = (
    "clean_tcp",
    "loss_tcp",
    "reordered_tcp",
    "window_tcp",
    "reset_tcp",
    "failed_tcp",
    "dns_delay",
    "dns_retry",
    "tls_delay",
    "tls_retry",
    "pmtud_signals",
    "fragments",
    "high_rtt",
    "server_wait",
    "syn_retry",
)


def tcp(
    src=CLIENT,
    dst=SERVER,
    *,
    seq=101,
    ack=201,
    flags=16,
    payload=b"",
    window=65535,
    options=b"",
    sport=None,
    dport=None,
):
    sport = sport if sport is not None else 50000 if src == CLIENT else 443
    dport = dport if dport is not None else 443 if src == CLIENT else 50000
    options += b"\0" * (-len(options) % 4)
    segment = (
        struct.pack(
            "!HHIIBBHHH", sport, dport, seq, ack, (5 + len(options) // 4) << 4, flags, window, 0, 0
        )
        + options
        + payload
    )
    a, b = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    pseudo = a + b + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return network_packet(src, dst, 6, segment)


def handshake(*, step=10_000, window=65535):
    options = bytes.fromhex("020405b401030302")  # MSS 1460, NOP, scale 2
    return [
        (0, tcp(seq=100, ack=0, flags=2, options=options)),
        (step, tcp(SERVER, CLIENT, seq=200, ack=101, flags=18, options=options, window=window)),
        (step * 2, tcp(window=window)),
    ]


def timed_pcap(frames):
    output = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for micros, raw in frames:
        seconds, fraction = divmod(micros, 1_000_000)
        output += struct.pack("<IIII", 1_700_000_000 + seconds, fraction, len(raw), len(raw)) + raw
    return output


def dns_message(ident=42, *, response=False, rcode=0):
    question = b"\x07example\x07invalid\x00" + struct.pack("!HH", 1, 1)
    return (
        struct.pack("!6H", ident, (0x8180 if response else 0x0100) | rcode, 1, 0, 0, 0) + question
    )


def dns_packet(*, response=False, ident=42, rcode=0):
    return packet(
        "192.0.2.53" if response else CLIENT,
        CLIENT if response else "192.0.2.53",
        17,
        53 if response else 53000,
        53000 if response else 53,
        payload=dns_message(ident, response=response, rcode=rcode),
    )


def tls_record(kind, content):
    return bytes([kind]) + bytes.fromhex("0303") + struct.pack("!H", len(content)) + content


def hello(kind):
    if kind == 1:
        body = (
            bytes.fromhex("0303")
            + bytes(32)
            + b"\0"
            + bytes.fromhex("0002130101000007002b0003020304")
        )
    else:
        body = bytes.fromhex("0303") + b"\x01" * 32 + bytes.fromhex("001301000006002b00020304")
    return tls_record(22, bytes([kind]) + len(body).to_bytes(3, "big") + body)


def fragment4(payload, offset, more):
    raw = bytearray(network_packet(CLIENT, SERVER, 17, payload))
    raw[20:22] = struct.pack("!H", offset | (0x2000 if more else 0))
    raw[24:26] = b"\0\0"
    raw[24:26] = struct.pack("!H", checksum(bytes(raw[14:34])))
    return bytes(raw)


def generate(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    clean = [
        *handshake(),
        (40000, tcp(payload=b"A" * 20, flags=24)),
        (50000, tcp(SERVER, CLIENT, seq=201, ack=121)),
        (70000, tcp(SERVER, CLIENT, seq=201, ack=121, flags=24, payload=b"B" * 30)),
        (80000, tcp(seq=121, ack=231)),
    ]
    loss = [
        *handshake(),
        (40000, tcp(payload=b"A" * 20, flags=24)),
        (400000, tcp(payload=b"A" * 20, flags=24)),
        (410000, tcp(SERVER, CLIENT, seq=201, ack=121)),
        (430000, tcp(seq=121, payload=b"C" * 20, flags=24)),
        (440000, tcp(SERVER, CLIENT, seq=201, ack=121)),
        (450000, tcp(SERVER, CLIENT, seq=201, ack=121)),
        (460000, tcp(SERVER, CLIENT, seq=201, ack=121)),
        (470000, tcp(seq=121, payload=b"C" * 20, flags=24)),
        (480000, tcp(SERVER, CLIENT, seq=201, ack=141)),
        (500000, tcp(payload=b"A" * 20, flags=24)),
    ]
    reorder = [
        *handshake(),
        (40000, tcp(seq=121, payload=b"C" * 20, flags=24)),
        (41000, tcp(seq=101, payload=b"A" * 20, flags=24)),
        (50000, tcp(SERVER, CLIENT, seq=201, ack=141)),
    ]
    window = [
        *handshake(window=25),
        (30_000, tcp(SERVER, CLIENT, seq=201, ack=101, window=25)),
        (40000, tcp(payload=b"A" * 100, flags=24)),
        (50000, tcp(SERVER, CLIENT, seq=201, ack=201, window=0)),
        (400000, tcp(seq=201, payload=b"P")),
        (410000, tcp(SERVER, CLIENT, seq=201, ack=201, window=0)),
        (1050000, tcp(SERVER, CLIENT, seq=201, ack=201, window=100)),
    ]
    ch, sh = hello(1), hello(2)
    tls = [
        *handshake(),
        (100000, tcp(payload=ch, flags=24)),
        (110000, tcp(SERVER, CLIENT, seq=201, ack=101 + len(ch))),
        (1100000, tcp(SERVER, CLIENT, seq=201, ack=101 + len(ch), payload=sh, flags=24)),
        (1110000, tcp(seq=101 + len(ch), ack=201 + len(sh))),
    ]
    retry = [
        *tls,
        (1200000, tcp(seq=101 + len(ch), ack=201 + len(sh), payload=ch, flags=24)),
        (
            1300000,
            tcp(
                SERVER,
                CLIENT,
                seq=201 + len(sh),
                ack=101 + 2 * len(ch),
                payload=tls_record(21, bytes([2, 40])),
                flags=24,
            ),
        ),
    ]
    quote4 = tcp(payload=b"A" * 100)[14:42]
    error4 = struct.pack("!BBHHH", 3, 4, 0, 0, 1200) + quote4
    error4 = error4[:2] + struct.pack("!H", checksum(error4)) + error4[4:]
    a6, b6 = "2001:db8::1", "2001:db8::2"
    quote6 = packet(a6, b6, 17, 40000, 40001, payload=b"synthetic")[14:]
    error6 = struct.pack("!BBHI", 2, 0, 0, 1280) + quote6
    pseudo = (
        ipaddress.ip_address(b6).packed
        + ipaddress.ip_address(a6).packed
        + struct.pack("!I3xB", len(error6), 58)
    )
    error6 = error6[:2] + struct.pack("!H", checksum(pseudo + error6)) + error6[4:]
    udp = packet(CLIENT, SERVER, 17, 40000, 40001, payload=b"A" * 24)[34:]
    udp6 = packet(a6, b6, 17, 40000, 40001, payload=b"A" * 24)[54:]
    fragments = [
        (0, fragment4(udp[:16], 0, True)),
        (10_000, fragment4(udp[16:], 2, False)),
        (20_000, network_packet(a6, b6, 44, struct.pack("!BBHI", 17, 0, 1, 42) + udp6[:16])),
        (30_000, network_packet(a6, b6, 44, struct.pack("!BBHI", 17, 0, 16, 42) + udp6[16:])),
    ]
    high = [
        *handshake(step=200000),
        (500000, tcp(payload=b"A" * 20)),
        (900000, tcp(SERVER, CLIENT, seq=201, ack=121)),
    ]
    wait = [
        *clean[:5],
        (2070000, tcp(SERVER, CLIENT, seq=201, ack=121, payload=b"B" * 30, flags=24)),
        (2080000, tcp(seq=121, ack=231)),
    ]
    cases = {
        "clean_tcp": clean,
        "loss_tcp": loss,
        "reordered_tcp": reorder,
        "window_tcp": window,
        "reset_tcp": [*clean[:5], (100000, tcp(SERVER, CLIENT, seq=201, ack=121, flags=20))],
        "failed_tcp": [*handshake()[:1], (100000, tcp(SERVER, CLIENT, seq=200, ack=101, flags=20))],
        "dns_delay": [(0, dns_packet()), (1_500_000, dns_packet(response=True))],
        "dns_retry": [
            (0, dns_packet()),
            (500_000, dns_packet()),
            (1_000_000, dns_packet(response=True, rcode=2)),
            (1_100_000, dns_packet(ident=43)),
        ],
        "tls_delay": tls,
        "tls_retry": retry,
        "pmtud_signals": [
            (0, tcp(payload=b"A" * 100)),
            (10_000, network_packet(SERVER, CLIENT, 1, error4)),
            (20_000, network_packet(b6, a6, 58, error6)),
        ],
        "fragments": fragments,
        "high_rtt": high,
        "server_wait": wait,
        "syn_retry": [
            (0, tcp(seq=100, ack=0, flags=2)),
            (100_000, tcp(seq=100, ack=0, flags=2)),
            (200_000, tcp(SERVER, CLIENT, seq=200, ack=101, flags=18)),
            (210_000, tcp()),
        ],
    }
    captures = {name: timed_pcap(raws) for name, raws in cases.items()}
    for name, content in captures.items():
        (directory / f"{name}.capture").write_bytes(content)
    return captures


if __name__ == "__main__":
    import sys

    generate(Path(sys.argv[1]))
