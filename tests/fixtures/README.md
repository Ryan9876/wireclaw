# Gate 1 fixtures

`generate.py` uses only Python's standard library. It constructs Ethernet, IPv4,
IPv6, TCP, UDP and DNS bytes with independently calculated checksums, fixed addresses
from documentation ranges, and fixed timestamps. No sockets, production captures,
random IDs or external downloads are used. PCAP records and PCAPNG blocks are written
explicitly with fixed little-endian layouts.

Run `python tests/fixtures/generate.py data/incoming`. Tests generate captures in
pytest's temporary directory. Generated binary captures and runtime analysis outputs
are not committed.

| Fixture | Known construction / expected baseline |
| --- | --- |
| healthy | 7 frames, 469 wire bytes, 0.6 seconds; completed TCP flag handshake, DNS pair, IPv6 UDP pair; 5 IP endpoints and 3 conversations |
| pcapng | Same traffic in PCAPNG; interface snaplen 65535 |
| truncated | All 7 frames cut to 40 bytes with original lengths retained; quality limited |
| midstream | Initial client ACK only; original SYN absent |
| checksum_offload | TCP handshake with deliberately invalid TCP checksum words; flags checksum anomalies, cannot establish offload versus corruption |
| empty | Valid empty PCAP; quality insufficient |
| one_sided | DNS query and IPv6 UDP request only; direction indicator, no claimed path fault |
| incomplete_handshake | SYN/SYN-ACK only; final ACK absent |
| timestamp_regression | Healthy bytes with timestamps in descending order |
| drops | PCAPNG interface statistics block reporting three drops |
| mixed_protocols | IPv4 ICMP/IGMP and IPv6 ICMPv6/SCTP in opposite directions, including two hop-by-hop extension flows sharing base next-header 0; six distinct one-sided conversations |
| malformed | Invalid magic/text bytes; rejected |
| damaged_record | Valid PCAP cut inside final record; rejected |
| unsupported | PCAP-like magic with unsupported/corrupt header; rejected |

The checksum fixture deliberately represents a look-alike ambiguity, not proof of
real offload. Duplicate capture cause is likewise unknown in this baseline. Tests
also exercise partial/multiple-interface statistics and big-endian/multiple-section
PCAPNG metadata without adding payload-dissection logic.

## Gate 2 fixtures

`generate_gate2.py` adds fixed microsecond timestamps, valid TCP options/checksums,
synthetic TLS messages and direct ICMP signals. Run:

```sh
python tests/fixtures/generate_gate2.py data/incoming
```

| Fixture | Independent construction / expected evidence |
| --- | --- |
| clean_tcp | 20 ms complete handshake, 4 ACK RTT samples of 10 ms, 20/30 payload bytes acknowledged, MSS 1460, window scaling 2; no expert fault indicator |
| loss_tcp | 3 retransmission-union frames [5,11,13], fast retransmission [11], spurious retransmission [13], duplicate ACKs [8,9,10]; 100 payload bytes, 40 unique observed/ACK-covered bytes |
| reordered_tcp | Higher sequence arrives before missing lower segment within 1 ms; out-of-order [5], no retransmission union; 40 unique payload bytes |
| window_tcp | Server scaled window 100 before 100-byte segment; window-full [5], zero-window [6,8], probe [7], observed reopen interval frames 6–9 = 1 second |
| reset_tcp | Server RST/ACK frame 6, 80 ms after observed establishment |
| failed_tcp | SYN then server RST/ACK; no successful establishment interval |
| syn_retry | Initial/repeated SYN frames 1/2, SYN-ACK 3, final ACK 4; initial SYN to final ACK 210 ms |
| dns_delay | UDP query/response frames 1/2 separated by 1.5 seconds |
| dns_retry | Repeated query shares original transaction response; rcode 2; separate ID 43 unanswered in capture |
| tls_delay | TCP established at 20 ms; ClientHello 100 ms, ServerHello 1.1 seconds; 80 ms TCP-to-TLS and 1 second hello interval; supported-version field 0x0304 |
| tls_retry | Additional ClientHello and explicit fatal-alert record; observed metadata only, not a validated usable TLS session |
| pmtud_signals | IPv4 type 3/code 4 advertises 1200, IPv6 Packet Too Big advertises 1280; quoted inner transport is not a new stream |
| fragments | Two IPv4 and two IPv6 fragments; offsets 0 and 2 encoded in 8-byte units; fixed fragment ID |
| high_rtt | 400 ms TCP establishment; 200 ms ACK RTT median |
| server_wait | Same 10 ms transport ACK timings as clean, but synthetic response begins after 2 seconds; no zero window; no application/root-cause attribution |

Real integration tests additionally generate split TLS records with contributing
frames and TCP DNS with single/coalesced messages. Gate 1 incomplete, midstream,
truncation, checksum ambiguity, empty and backward-clock fixtures exercise explicit
limitations. All binary captures remain generated locally; no production data is committed.


Additional Gate 2 completion fixtures (all reproducible with the same generator):

| Fixture | Independent expected behavior |
| --- | --- |
| dns_sequences | Same-name AAAA/A queries and retry; unrelated simultaneous name with colliding ID; resolver change from unanswered attempt to response; separate unanswered name |
| dns_quote4 / dns_quote6 | Full DNS query and response inside IPv4 ICMP / IPv6 ICMPv6 errors, actually decoded by TShark; zero live DNS transactions; outer PMTUD signals retained |
| dns_cname | Linked response reports alias target; its pseudonymous ID matches later query identity without inventing answer-chain edges |
| dns_tcp_fallback | UDP truncated response followed by TCP query for the same name; observed transport/resolver change, no policy assertion |
| reset_reconnect | Server reset, different client ephemeral port on next stream, second reset; exact prior-reset/SYN frame references |
| tls_clean / tls12_clean | Real TLS 1.3 / 1.2 hellos with 20 / 10 ms intervals; encrypted handshake completion remains unknown |
