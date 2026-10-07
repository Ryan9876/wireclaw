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
| malformed | Invalid magic/text bytes; rejected |
| damaged_record | Valid PCAP cut inside final record; rejected |
| unsupported | PCAP-like magic with unsupported/corrupt header; rejected |

The checksum fixture deliberately represents a look-alike ambiguity, not proof of
real offload. Duplicate capture cause is likewise unknown in this baseline. Tests
also exercise partial/multiple-interface statistics and big-endian/multiple-section
PCAPNG metadata without adding payload-dissection logic.
