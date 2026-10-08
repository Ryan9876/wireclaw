# Deterministic analyzer — Gates 1 and 2

The Python package is in `src/wireclaw_analyzer`. It runs without the future API,
UI, model provider, Docker image, or host bridge. It does not diagnose root cause.

## Developer setup

From the repository root, use Python 3.11 or newer and install TShark and
capinfos through your OS's Wireshark distribution. Ensure both are on PATH.
Zeek is optional in Gate 1; its availability/version is recorded, but no Zeek
packet capability is required or executed yet.

```sh
python -m venv .venv
```

Activate `.venv` using your platform's normal activation command, then:

```sh
python -m pip install -e '.[test]'
python -m pytest -q
python -m ruff check services/analyzer/src tests/unit tests/integration tests/fixtures
python -m ruff format --check services/analyzer/src tests/unit tests/integration tests/fixtures
```

Real-tool integration tests explicitly skip if TShark or capinfos is missing.
A skipped integration suite is **not** validation of Gate 1. The unit suite can
still verify parsing, safety boundaries, failures and process bounds.

## Run a synthetic capture

```sh
python tests/fixtures/generate.py data/incoming
python -m wireclaw_analyzer.cli --data-root data incoming/healthy.capture
```

Or invoke `wireclaw-analyze` with the same arguments after installation. For a
non-editable install, provide `--schema /path/to/contracts/evidence.schema.json`.
The default schema path is for source checkouts; contracts remain repository-owned.

Stage a real capture under your private data root first. The CLI accepts only a
path beneath that root, never an external path, executable, filter, or flags.
Supported PCAP/PCAPNG content is checked by capinfos and TShark regardless of
filename extension. Compressed and non-PCAP wrappers are rejected before tool execution. Invalid input fails without publishing an original capture.

## Python capabilities

```python
from pathlib import Path
from wireclaw_analyzer import Analyzer, Limits

analyzer = Analyzer(Path("data"), limits=Limits())
capture_id = analyzer.ingest_capture(Path("incoming/healthy.capture"))
result = analyzer.analyze(capture_id)
metadata = analyzer.get_capture_metadata(capture_id)
quality = analyzer.assess_capture_quality(capture_id)
protocols = analyzer.list_protocols(capture_id)
endpoints = analyzer.list_endpoints(capture_id)
conversations = analyzer.list_conversations(capture_id)
```

Inventory calls currently perform the entire bounded baseline, including quality,
so callers cannot accidentally omit capture quality. Repeated calls are correct
but not optimized; API orchestration/caching remains Gate 3.

## Output and storage

- `cases/<sha256>/original/capture`: immutable byte copy, published without overwrite,
  read-only mode; hash verified before/after baseline execution. A failed ingest
  removes only originals created by that invocation; existing originals are preserved.
- `cases/<sha256>/normalized/capture-identity.json`: persisted identity and file size.
- `cases/<sha256>/normalized/capture-summary.json`: normalized evidence, analyzer and
  tool versions, configuration. Writes are atomic.

Every evidence item validates against the unchanged shared
`contracts/evidence.schema.json`. IDs include the full capture SHA-256 and
capability. Values include calculations, limitations and nested frame/stream/filter
references where applicable. Endpoints/conversations describe observed IP traffic;
non-IP packets remain in protocol inventory and are explicitly counted as excluded
from the IP endpoint inventory. The first IPv4 fields are preferred when present;
otherwise first IPv6 fields are used. Nested/tunneled endpoint inventory is not
implemented in Gate 1. Protocol-layer counts overlap and must not be summed as a
packet total. Byte totals are wire-frame lengths, not application goodput.
Non-TCP/UDP conversations include the observed IP protocol/base IPv6 next-header
number. Extension or unavailable headers also retain the first terminal dissector
to distinguish carried protocols; payload layers do not change ordinary protocol
identity. TCP/UDP conversation behavior is unchanged.

capinfos supplies metadata; TShark supplies selected fields with name resolution
**disabled** and checksum validation **enabled**. A narrow, bounded PCAPNG header
reader records IDB snaplen and last reported ISB ifdrop values with its own
provenance because capinfos 4.2.2 does not print those counters. Totals are unknown
unless every interface reports a count. No packet payload or interface text is
retained by that reader.

## Quality and limits

Quality is `insufficient` for an empty capture, `limited` for observed baseline
quality indicators, and `good` when none is observed. `good` does not certify
complete visibility or fitness for every future diagnostic question.

Checks cover truncation, malformed packets, checksum anomalies, backward timestamps,
reported capture drops, observed one-direction conversations, absent initial SYNs,
and incomplete SYN/SYN-ACK/ACK flag sequences. These are indicators only: direction
asymmetry and offload causes are not proven. Duplicate-capture artifacts remain
`unknown` because repeated transport packets cannot establish the capture cause.
Unavailable drop counters remain `unknown`, never zero. A malformed/unreadable file
returns an analyzer error rather than an apparently valid quality result. TCP
frames are indexed once for handshake checks, avoiding per-conversation rescans.

Defaults: 64 MiB capture, 100,000 frames, 16 MiB combined stdout/stderr per process,
30 seconds per process. Limits are configurable positive, finite values; exceeding
one fails explicitly without partial inventory or hidden sampling. Work is bounded
by capture bytes, frame count, process output and time. Large-capture indexing,
worker isolation and release packaging remain later-gate work.

## Safety boundary

The runner accepts only an `Operation` enum and, for packet operations, a confined
capture path. Executables are discovered once from administrator-controlled PATH;
request data cannot select an executable or add flags. Each plan uses direct
argument arrays with `shell=False`, a minimal environment, private tool configuration
and no inherited user Wireshark preferences. Output is drained in bounded chunks;
overflow and timeout kill and reap the child. Stderr is discarded, never logged or
included in errors. `AnalyzerError.as_dict()` gives safe code/capability/tool fields.

Traversal, backslash-based foreign paths, NULs and internal symlinks are rejected.
Managed data directories must be private to Wireclaw: this is not protection against
a privileged local process racing filesystem changes. Read-only mode is advisory
on some filesystems/platforms; integrity checks detect later changes. Atomic original
publication uses same-filesystem hard links; unsupported filesystems must fail rather
than fall back to overwriting. Post-publication failures roll back owned originals
and staging/identity artifacts. Persistent filesystem denial during rollback is
reported explicitly as `capture_cleanup_failure`, never as successful intake. Windows/macOS native execution has not been smoke-tested
in this Linux development environment. Docker packaging is intentionally deferred.

## Gate 2 deterministic diagnostics

Version 0.2.0 adds directly callable diagnostics; `analyze()` remains the Gate 1
baseline and its eleven semantic goldens are unchanged. `diagnose()` runs/persists
that baseline first, then one additional fixed, bounded two-pass TShark operation.
Its fixed bounded fields are isolated in `diagnostic_fields.py`; pure indexed calculations
are in `diagnostics.py`. No API, RCA/report, UI, host bridge, model or packaging is added.

```python
from wireclaw_analyzer import Capability, DiagnosticLimits, DiagnosticRequest

result = analyzer.diagnose(capture_id)
rtt = analyzer.run_diagnostic(
    DiagnosticRequest(capture_id, Capability.RTT, tcp_stream=0)
)
```

`DiagnosticRequest` accepts only a validated capture hash, `Capability` enum and
optional nonnegative integer TCP stream. DNS, fragmentation and PMTUD requests are
capture-scoped; other capabilities can select a TCP stream. Unknown streams fail
explicitly. It accepts no command, executable, flags, expression or display filter.
All extraction is capture-bounded; selecting a stream bounds normalization scope,
not the underlying full-capture dissector pass. No caching/orchestrator is added.

| Capability enum / source name | Evidence |
| --- | --- |
| DNS / `analyze_dns` | Reciprocal query/response frame links, transaction ID, resolver/client, query types, elapsed time, rcode, repeated queries, unanswered-in-capture and ambiguous state |
| ESTABLISHMENT / `analyze_tcp_establishment` | Sequence-validated SYN/SYN-ACK/final ACK, initial attempt interval, repeated SYNs, incomplete/reset/midstream state |
| HEALTH / `analyze_tcp_health` | Each TShark expert class, exact frames, retransmission-class union, packet/data counts, bytes-in-flight samples and frame fractions |
| RTT / `analyze_rtt` | Eligible ACK RTT samples with ACK/segment frames, direction, min/median/nearest-rank p95/max; rejected ACK frames |
| WINDOW / `analyze_window_behavior` | Advertiser, scaled-window observations, extrema with frames, scaling options, zero-window/probe/window-full labels, observed zero-window intervals |
| RESETS / `analyze_tcp_resets` | Sender/receiver and RST/ACK flags from capture perspective, exact frame, lifecycle timing/phase and subsequent same-service connection attempts (continuity/causality unknown) |
| THROUGHPUT / `analyze_throughput` | Wire/captured/payload bytes, expert-marked retransmitted bytes, sequence-union/ACK-covered payload approximations and explicit rate formulas |
| MSS / `analyze_mss` | Advertised MSS per packet/stream/direction |
| FRAGMENTATION / `analyze_fragmentation` | Outer IPv4 ID/MF/offset and IPv6 fragment-header ID/offset/M flag, including atomic headers |
| PMTUD / `analyze_pmtud_signals` | ICMP type 3/code 4 and ICMPv6 type 2/code 0 with advertised MTU, directional IP-size ranges/DF counts |
| TLS / `analyze_tls_handshakes` | Visible messages and contributing reassembly frames, TCP-to-ClientHello and ClientHello-to-ServerHello timing, repeated ClientHello and observed alerts |

Run the developer CLI using a predefined switch:

```sh
python tests/fixtures/generate_gate2.py data/incoming
wireclaw-analyze --data-root data --diagnostics incoming/tls_delay.capture
```

The result is persisted atomically as `normalized/diagnostics.json` after integrity
and unchanged shared evidence-schema validation. On diagnostic failure, the original
and baseline remain available; the failed run does not overwrite prior diagnostics.
A previous successful artifact is historical, not evidence of success for a failed
rerun. The caller receives a safe `AnalyzerError`; failure records/lifecycle are Gate 3.
Each item includes capture identity, capability/TShark version, calculation,
limitations, scope and generated verification filter. Exact event/sample frames
remain inside values. Broad supporting stream/capture frame lists above their bound
use a start/end range plus fixed selection filter, without hidden sample selection.

Default additional limits: 5,000 evidence items, 20,000 cumulative list slots in
normalized values, 16 MiB **serialized, indented** result, 64 occurrences per extracted
field and 256 references per explicit event/reference array. Oversize event arrays
fail with `diagnostic_frame_reference_limit`; record/byte/occurrence overflow fails
explicitly. Limits are positive integers and independently configurable through
`DiagnosticLimits`. All Gate 1 capture/packet/time/pipe limits still apply. A rejected
large diagnostic result can be rerun with a scoped capability or deliberately raised
limits. No partial output is labeled complete.

Work indexes frames/streams once, performs a fixed number of passes within each
stream and sorts sequence intervals once per direction. Two-endpoint stream identity
is checked before calculations. This bounds work to O(N log N), plus bounded schema
validation/serialization; no per-stream full-capture rescans. Tests count full-list
visits across 600 streams and consume 10,000 shuffled overlapping sequence intervals
once. A private managed data root and trusted packet-tool installation remain required.

### Measurement semantics and limits

- TShark 4.2.2 is the validated reference. Its live `-G fields` registry and real
  fixture observations verify the used fields; tool versions are recorded on every run.
  Expert labels remain **suspected indicators**, not independently proven loss.
- ACK RTT uses a prior reverse-direction segment in the same stream, valid ACK flag,
  nonnegative interval and nonnegative tool timing; segments marked retransmitted are
  excluded. Delayed ACKs and SYN samples remain possible. This is not one-way latency
  or a full independent Karn implementation.
- Rates use the common stream first-to-last frame interval. Sequence ranges deduplicate
  payload overlaps; SYN/FIN sequence occupancy is excluded. Conservative half-space
  checks withhold ambiguous wraps/large jumps or truncated payload approximations.
  Reverse cumulative ACK coverage adds a **TCP goodput approximation**; application
  goodput and application consumption remain unknown. Rates are null for zero duration
  or timestamp regression. Wire lengths do not imply physical Ethernet line rate.
- Zero-window duration measures first zero advertisement to next positive advertisement
  from that receiver. An unclosed span is open at capture end, not an inferred timeout.
  Receiver constraints do not identify why the application stopped consuming data.
- DNS query and CNAME target names are extracted locally via fixed `dns.qry.name` and
  `dns.cname` fields, then immediately converted to per-capture identities. Names use
  ASCII letters/digits/underscore/hyphen, labels of 1–63 characters, total 1–253
  characters, optional final root dot (254 input characters); root `.` is supported.
  Case and one trailing root dot are normalized. Controls, escaped/binary/non-ASCII
  presentation, empty labels and overlong labels/names withhold the affected transaction
  name identities and sequence correlation, with a specific limitation. Trustworthy
  numeric DNS fields, reciprocal frame links, timing and endpoints remain available.
  Excess occurrences still fail as a resource violation; no rejected text is echoed.
  Each field allows at most 64 occurrences by default. No raw
  name enters evidence, logs, filters or commands. TLS certificate/SNI/payload text is
  never extracted. Encrypted DNS is unavailable.
- Query-name ID is HMAC-SHA256 of the normalized name using
  `SHA256(b"wireclaw-dns-name-v1\0" + bytes.fromhex(capture_sha256))` as key. It is
  stable within the same capture, different across captures and independent of DNS
  transaction ID. This is data minimization, not a secrecy guarantee against guessing
  with the public capture hash; the identity has no network meaning. A future provider
  should receive normalized IDs, not raw names, unless a separate explicit policy allows it.
- DNS uses reciprocal TShark frame links, matching ID/type, compatible available
  query identities, reverse endpoint tuple and stream/transport. ICMP/ICMPv6 quoted DNS fields are suppressed;
  they never create transactions, orphan/ambiguous messages or sequences. Direct DNS,
  including TCP, remains supported. A retry linked to an original response has no
  independently attributable elapsed interval. Parallel multi-message/question arrays
  cannot establish message boundaries and are withheld as ambiguous.
- Name-resolution sequences group transactions by client address and query-name ID
  in one indexed pass. Transactions remain intact with exact query/response frames,
  timing, types, resolver, rcode and unanswered state. Group records retain frame order,
  repeated same-type/resolver attempts, resolver/transport changes and prior truncation
  facts; none proves client fallback policy, timeout or application impact. Observed
  CNAME target IDs support correlation with subsequent query IDs; owner-to-target answer
  edges and complete alias chains are not reconstructed from parallel fields.
  Clock regression withholds affected intervals. Exact references above their bound
  use a frame range and generated DNS filter, plus exact transaction query references;
  such a range may include unrelated DNS. Missing name fields withhold sequence grouping.
- TLS timing is based on the frame completing dissection/reassembly. TLS 1.3 content
  after ServerHello and normally encrypted TLS 1.2 Finished are unavailable without keys.
  Keylog loading is disabled; no TLS decryption is required or performed. Session
  completion remains unknown even if a Finished message is visible. Repeated hellos
  can reflect retry requests, renegotiation or transport behavior.
- ICMP quoted headers are never assigned as current TCP streams or live DNS. Only
  fragmentation on the outer IP header/extension chain is reported, including outer
  ICMP/ICMPv6 fragments. Inner quoted fragments are withheld. IPv4 identification
  uses `ip.id`; IPv6 uses `ipv6.fraghdr.ident`. PMTUD requires ICMPv4 type 3/code 4
  or ICMPv6 type 2/code 0. Signals do not establish an MTU black hole; absence does
  not rule one out.
- Nested/tunneled packets without safe layer attribution are excluded from diagnostic
  indexes with a bounded frame/count limitation. Unrelated supported streams remain
  analyzable. Structurally malformed numeric fields, frame/stream inconsistencies,
  compromised capture integrity and resource exhaustion still fail analysis.
- Capture-level MSS and fragmentation references select only observed record frames.
  PMTUD selects valid control-signal frames plus the first directional minimum/maximum
  outer-size frames, retained explicitly in each pattern. Pattern counts describe the
  directional outer-IP population, not only those extrema. Exact internally generated
  frame filters apply below the frame-reference bound; larger sets retain range/filter
  fallback. Empty packet evidence uses no references and `frame.number == 0`.
- `observed_reconnect_attempts` records only later SYNs to the same client-address,
  server-address and service-port tuple. Application/session continuity and causality
  to the previous reset are unknown, including when the client ephemeral port changes.

See [`../../docs/gate2-verification.md`](../../docs/gate2-verification.md) for task
mapping, real-tool validation, authoritative field references and reproducible examples.
