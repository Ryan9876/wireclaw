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
    "dns_sequences",
    "dns_quote4",
    "dns_quote6",
    "dns_cname",
    "reset_reconnect",
    "dns_tcp_fallback",
    "tls_clean",
    "tls12_clean",
    "isolation_dns",
    "isolation_nested",
    "outer_icmp_fragments",
    "quoted_fragments",
    "ptb_codes",
    "reset_independent",
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


def encoded_name(name):
    return (
        b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    )


def dns_message(
    ident=42,
    *,
    response=False,
    rcode=0,
    name="example.invalid",
    qtype=1,
    cname=None,
    truncated=False,
):
    question = encoded_name(name) + struct.pack("!HH", qtype, 1)
    answer = b""
    if cname:
        target = encoded_name(cname)
        answer = bytes.fromhex("c00c") + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
    return (
        struct.pack(
            "!6H",
            ident,
            (0x8180 if response else 0x0100) | rcode | (0x0200 if truncated else 0),
            1,
            int(bool(cname)),
            0,
            0,
        )
        + question
        + answer
    )


def dns_packet(
    *,
    response=False,
    ident=42,
    rcode=0,
    name="example.invalid",
    qtype=1,
    client=CLIENT,
    resolver="192.0.2.53",
    sport=53000,
    cname=None,
    truncated=False,
):
    return packet(
        resolver if response else client,
        client if response else resolver,
        17,
        53 if response else sport,
        sport if response else 53,
        payload=dns_message(
            ident,
            response=response,
            rcode=rcode,
            name=name,
            qtype=qtype,
            cname=cname,
            truncated=truncated,
        ),
    )


def quoted_dns(family, *, response=False):
    client, resolver = (CLIENT, "192.0.2.53") if family == 4 else ("2001:db8::1", "2001:db8::53")
    quote = dns_packet(client=client, resolver=resolver, response=response)[14:]
    # Full DNS question inside quote, rather than only the required first eight bytes.
    content = (
        struct.pack(
            "!BBHI",
            3 if family == 4 else 2,
            4 if family == 4 else 0,
            0,
            1200 if family == 4 else 1280,
        )
        + quote
    )
    pseudo = (
        b""
        if family == 4
        else ipaddress.ip_address(resolver).packed
        + ipaddress.ip_address(client).packed
        + struct.pack("!I3xB", len(content), 58)
    )
    content = content[:2] + struct.pack("!H", checksum(pseudo + content)) + content[4:]
    return network_packet(resolver, client, 1 if family == 4 else 58, content)


def tls_record(kind, content):
    return bytes([kind]) + bytes.fromhex("0303") + struct.pack("!H", len(content)) + content


def hello(kind, version=13):
    if version == 12:
        body = (
            bytes.fromhex("0303") + bytes(32) + bytes.fromhex("000002002f0100")
            if kind == 1
            else bytes.fromhex("0303") + bytes(32) + bytes.fromhex("00002f00")
        )
        return tls_record(22, bytes([kind]) + len(body).to_bytes(3, "big") + body)
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


def fragment4(payload, offset, more, protocol=17):
    raw = bytearray(network_packet(CLIENT, SERVER, protocol, payload))
    raw[20:22] = struct.pack("!H", offset | (0x2000 if more else 0))
    raw[24:26] = b"\0\0"
    raw[24:26] = struct.pack("!H", checksum(bytes(raw[14:34])))
    return bytes(raw)


def icmp6(payload, *, kind=128, code=0, mtu=0):
    a6, b6 = "2001:db8::1", "2001:db8::2"
    message = struct.pack("!BBHI", kind, code, 0, mtu) + payload
    pseudo = (
        ipaddress.ip_address(a6).packed
        + ipaddress.ip_address(b6).packed
        + struct.pack("!I3xB", len(message), 58)
    )
    return message[:2] + struct.pack("!H", checksum(pseudo + message)) + message[4:]


def icmp4_error(quote):
    message = struct.pack("!BBHHH", 3, 4, 0, 0, 1200) + quote
    return message[:2] + struct.pack("!H", checksum(message)) + message[4:]


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
    query_tcp = dns_message()
    answer_tcp = dns_message(response=True)
    qtcp = len(query_tcp).to_bytes(2, "big") + query_tcp
    rtcp = len(answer_tcp).to_bytes(2, "big") + answer_tcp
    fallback = [
        (0, dns_packet()),
        (10_000, dns_packet(response=True, truncated=True)),
        (20_000, tcp(seq=100, ack=0, flags=2, dport=53)),
        (30_000, tcp(SERVER, CLIENT, seq=200, ack=101, flags=18, sport=53)),
        (40_000, tcp(dport=53)),
        (50_000, tcp(dport=53, flags=24, payload=qtcp)),
        (
            60_000,
            tcp(SERVER, CLIENT, sport=53, flags=24, payload=rtcp, seq=201, ack=101 + len(qtcp)),
        ),
    ]
    clean_tls = [*tls[:5], (120_000, tls[5][1]), (130_000, tls[6][1])]
    ch12, sh12 = hello(1, 12), hello(2, 12)
    tls12 = [
        *handshake(),
        (100_000, tcp(payload=ch12, flags=24)),
        (110_000, tcp(SERVER, CLIENT, payload=sh12, flags=24, seq=201, ack=101 + len(ch12))),
    ]
    echo4 = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"E" * 24
    echo4 = echo4[:2] + struct.pack("!H", checksum(echo4)) + echo4[4:]
    echo6 = icmp6(b"E" * 24)
    outer_icmp = [
        (0, fragment4(echo4[:16], 0, True, 1)),
        (10_000, fragment4(echo4[16:], 2, False, 1)),
        (20_000, network_packet(a6, b6, 44, struct.pack("!BBHI", 58, 0, 1, 77) + echo6[:16])),
        (30_000, network_packet(a6, b6, 44, struct.pack("!BBHI", 58, 0, 16, 77) + echo6[16:])),
    ]
    inner4 = fragment4(udp[:16], 0, True)[14:]
    inner6 = network_packet(a6, b6, 44, struct.pack("!BBHI", 17, 0, 1, 99) + udp6[:16])[14:]
    quoted_fragments = [
        (0, network_packet(SERVER, CLIENT, 1, icmp4_error(inner4))),
        (10_000, network_packet(a6, b6, 58, icmp6(inner6, kind=2, mtu=1280))),
    ]
    nested_packet = network_packet(
        "198.51.100.1", "198.51.100.2", 4, tcp(seq=900, payload=b"nested")[14:]
    )
    cases = {
        "clean_tcp": clean,
        "isolation_dns": [
            *clean,
            (100_000, dns_packet(name="odd!name.invalid", ident=77)),
            (200_000, dns_packet(name="odd!name.invalid", ident=77, response=True, rcode=3)),
        ],
        "isolation_nested": [*clean, (100_000, nested_packet)],
        "outer_icmp_fragments": outer_icmp,
        "quoted_fragments": quoted_fragments,
        "ptb_codes": [
            (0, network_packet(a6, b6, 58, icmp6(quote6, kind=2, code=0, mtu=1280))),
            (10_000, network_packet(a6, b6, 58, icmp6(quote6, kind=2, code=1, mtu=1280))),
        ],
        # Packet evidence cannot determine whether this new process/session is related.
        "reset_independent": [
            *clean[:5],
            (100_000, tcp(SERVER, CLIENT, seq=201, ack=121, flags=20)),
            (200_000, tcp(seq=900, ack=0, flags=2, sport=50009)),
        ],
        "dns_tcp_fallback": fallback,
        "tls_clean": clean_tls,
        "tls12_clean": tls12,
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
        "dns_quote4": [(0, quoted_dns(4)), (10_000, quoted_dns(4, response=True))],
        "dns_quote6": [(0, quoted_dns(6)), (10_000, quoted_dns(6, response=True))],
        "dns_sequences": [
            (0, dns_packet(ident=10, name="Related.invalid", qtype=28)),
            (10_000, dns_packet(ident=10, name="unrelated.invalid", sport=53001)),
            (20_000, dns_packet(ident=11, name="related.invalid")),
            (30_000, dns_packet(ident=10, name="unrelated.invalid", sport=53001, response=True)),
            (40_000, dns_packet(ident=11, name="related.invalid", response=True)),
            (500_000, dns_packet(ident=10, name="related.invalid", qtype=28)),
            (
                600_000,
                dns_packet(ident=12, name="related.invalid", qtype=28, resolver="192.0.2.54"),
            ),
            (
                650_000,
                dns_packet(
                    ident=12, name="related.invalid", qtype=28, resolver="192.0.2.54", response=True
                ),
            ),
            (700_000, dns_packet(ident=13, name="missing.invalid")),
        ],
        "dns_cname": [
            (0, dns_packet()),
            (10_000, dns_packet(response=True, cname="alias.invalid")),
            (20_000, dns_packet(ident=43, name="alias.invalid")),
            (30_000, dns_packet(ident=43, name="alias.invalid", response=True)),
        ],
        "reset_reconnect": [
            *clean[:5],
            (100_000, tcp(SERVER, CLIENT, seq=201, ack=121, flags=20)),
            (200_000, tcp(seq=300, ack=0, flags=2, sport=50001)),
            (210_000, tcp(SERVER, CLIENT, seq=400, ack=301, flags=18, dport=50001)),
            (220_000, tcp(seq=301, ack=401, sport=50001)),
            (300_000, tcp(SERVER, CLIENT, seq=401, ack=301, flags=20, dport=50001)),
        ],
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
