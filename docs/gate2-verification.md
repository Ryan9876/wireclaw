# Gate 2 verification — deterministic TCP/DNS/TLS diagnostics

Date: 2026-10-08 UTC. Branch: `gate2-tcp-dns-tls-diagnostics`.
Requirements: R-F006–R-F010, R-F017; safety/reproducibility R-S003–R-S007,
R-S010, R-N001–R-N006. No model provider or network service is required.

## Gate 1 closeout and authority

PR #1 was independently re-reviewed and approved, then merged into main as
`3eb988f84bb2ccdf1f193e4be6464d4d0d9c50e5`, preserving the reviewed head
`e4b05738b3e33a9d4276aa8896332aa6b39e8ba5` as an ancestor. All three threads
were resolved. All twelve Gate 1 tasks were checked; no Gate 2 implementation
was present on that main. The new branch starts from this merge commit; the old
Gate 1 branch was not used for Gate 2 changes.

Before implementation the constitution, requirements, solution, both accepted
ADRs, architecture/investigation/security/testing/deployment/Wireshark/roadmap
docs, task list, AGENTS, PROJECT_INSTRUCTIONS, Gate 1 record and analyzer README
were reread. The working tree was clean. The authoritative product specification
and shared schemas remain unchanged; this implements the existing Gate 2 scope.

## Task mapping

| Task / requirement | Implementation / validation |
| --- | --- |
| G2.1 / R-F006 | `diagnostics.dns`: reciprocal tool frame links plus ID/reverse endpoints/stream, numeric transaction data, timing/rcode/retries/unanswered/ambiguous states; UDP and TCP DNS integration, collision and multi-message unit tests |
| G2.2 / R-F007 | `establishment`: sequence-validated handshake, initial-attempt durations, repeated SYNs, incomplete/reset/midstream state; clean, failed, repeated-SYN and partial/clock tests |
| G2.3 / R-F008 | `health`: retransmission, fast/spurious retransmission, duplicate ACK, out-of-order and union counts; real expected event frames and reordering contrast |
| G2.4 / R-F008 | `rtt`: eligible ACK/segment samples, per-direction min/median/nearest-rank p95/max, rejected frames; independent 10/200 ms fixtures and missing/invalid sample tests |
| G2.5 / R-F008 | `windows`: scaled window ranges and extreme frames, scale provenance/options, zero/probe/full expert fields, observed zero-window intervals; 1-second window fixture and open/missing/regressing intervals |
| G2.6 / R-F007/R-F008 | `resets`: sender/receiver, RST/ACK flags, lifecycle phase/timing; resets before and after establishment, missing-handshake case |
| G2.7 / R-F008 | `throughput`, `union_length`: directional wire/captured/payload totals, expert-marked retransmission bytes, observed and ACK-covered sequence unions and explicit rate formulas; independently asserted byte/rate totals, overlap/wrap/ambiguity/partial tests |
| G2.8 / R-F009 | `network`: MSS options, IPv4 and IPv6 fragments, direct ICMP PMTUD signals and outer IP size/DF patterns; real 1200/1280 MTU signals, offsets and MSS 1460, negative/error-code/quoted-header checks |
| G2.9 / R-F010 | `tls`: visible hello/Finished metadata, TCP-to-TLS and hello intervals, repeated ClientHello/alerts, encryption and reassembly limits; real delayed/repeated/split TLS tests |
| G2.10 / R-F017 | `build`, `Analyzer._diagnose`: capture SHA, stable IDs, capability/version, stream/endpoints/transaction, exact events/samples or bounded supporting range and fixed filter, formula, limitations; shared-schema and reproducibility tests |
| G2.11 | `tests/fixtures/generate_gate2.py`: fifteen deterministic synthetic fixtures plus additional split-TLS/TCP-DNS constructions; fifteen complete diagnostic goldens with independently asserted semantic expectations |

Every row has pure unit, real-tool, healthy/negative, missing/malformed and schema
coverage. The baseline runs/persists before diagnostics. Direct Python requests use
`Capability`, `DiagnosticRequest` and `DiagnosticLimits`; there is no general filter
or command API. All eleven named capabilities are documented in the analyzer README.

## Representative normalized evidence

Complete schema-valid items with hashes, scopes, frames, formulas, limitations and
actual tool versions: [`gate2-evidence-examples.json`](gate2-evidence-examples.json).
These are packet facts and reproducible calculations, not a final finding/report.

| Evidence / fixture | Independently verified normalized values |
| --- | --- |
| DNS delay / dns_delay | Transaction 42, UDP resolver 192.0.2.53:53; query/response frames 1/2, elapsed 1.5 s, rcode 0; numeric ID plus tool links, not ID alone |
| TCP establishment / clean_tcp | Stream 0; SYN 1, SYN/ACK 2, final ACK 3; SYN→SYN/ACK 0.01 s, establishment 0.02 s |
| TCP health / loss_tcp | Retransmission union [5,11,13], fast [11], spurious [13], duplicate ACK [8,9,10]; union count 3, not the sum of overlapping expert classes |
| RTT / clean_tcp | ACK/segment pairs (2,1), (3,2), (5,4), (7,6); 4 samples; min/median/p95/max 0.01 s with directional groups |
| Window / window_tcp | Server advertises zero at frames 6/8; probe 7, window-full 5; frames 6→9 observed zero-window span 1.0 s |
| Reset / reset_tcp | Frame 6, stream 0, server 192.0.2.2:443 sends RST/ACK; 0.08 s after observed establishment |
| Throughput / clean_tcp | Client 244 wire/captured bytes, 20 payload bytes, 20 observed unique and ACK-covered bytes over 0.08 s; wire 24,400 bps; TCP goodput approximation 2,000 bps; application goodput null |
| MSS/fragments/PMTUD | MSS 1460 frames 1/2; IPv4/IPv6 fragment offsets 0/2 in 8-byte units; direct IPv4 fragmentation-needed frame 2 MTU 1200, IPv6 PTB frame 3 MTU 1280 |
| TLS timing / tls_delay | TCP final ACK 3; ClientHello 4 at 0.1 s, ServerHello 6 at 1.1 s; TCP→ClientHello 0.08 s, hello interval 1.0 s; usable session/Finished interval unknown |

Contrast assertions distinguish reordering from retransmission, short RTT plus
synthetic sender/server wait from long ACK RTT, zero window from idle sender,
DNS delay from TCP setup, and direct PMTUD signals from generic retransmissions.
They do not infer physical loss location, server process state or root cause.

## Tool semantics verification

Reference toolchain: actual Wireshark/TShark and capinfos 4.2.2 on Linux, Python
3.12.14, pytest 9.1.1, Ruff 0.16.10. `tshark -G fields` was executed and the actual
registry checked for numeric type/description/availability of each diagnostic
field. The fixed plan uses two-pass dissection, explicit TCP sequence analysis,
absolute sequence fields, reassembly, checksum checking and disabled keylog loading.
Real captures establish the behavior independently of prose documentation.

Primary upstream references consulted:

- [TCP analysis guide](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)
- [TCP field registry](https://www.wireshark.org/docs/dfref/t/tcp.html)
- [DNS field registry](https://www.wireshark.org/docs/dfref/d/dns.html)
- [TLS field registry](https://www.wireshark.org/docs/dfref/t/tls.html)
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)

Upstream online references cover newer releases too; the installed 4.2.2 registry
and fixture observations are the version-specific oracle. No unsupported newer
`tcp.analysis.ambiguous_ack` or `dns.response_missing` field is assumed. Requests
for unavailable fields fail explicitly; compatibility with other versions requires
rerunning this corpus, not silently promoting results from untested semantics.

RTT is tool segment-to-ACK elapsed time, not one-way latency. A prior reverse
segment in the same stream, ACK flag and nonnegative timestamps/tool timing are
required; marked retransmitted segments are excluded. Median and nearest-rank p95
are reproducible, retaining all eligible sample/frame pairs. This does not claim a
complete independent Karn algorithm. Timestamp regression can produce negative
tool times; they are excluded from RTT and invalid derived intervals are null.

Window-full/retransmission/reordering are Wireshark expert indications. Scaling
factor -1 is unknown, -2 is no scaling. Window intervals measure visible
advertisements, not hidden receiver behavior. A first-to-last stream interval is
used consistently for rates. Observed sequence unions remove overlap without
assuming physical delivery; reverse cumulative ACK coverage yields a separate TCP
goodput approximation. Application consumption remains unknown. Conservative
sequence half-space checks withhold ambiguous jumps/wraps/truncation.

DNS retries linked to an original response have no separately attributable timing.
Multi-message parallel field arrays are ambiguous. TLS timestamps use the completed
message dissection frame and retain contributing segment frames where supplied.
TLS 1.3 after ServerHello and normal encrypted Finished messages remain unavailable.
Even visible Finished is not proof of application readiness. No universal "slow"
threshold and no MTU-black-hole/loss-location/application-cause rule exists.

## Validation

The scratch-only real packet binaries/libraries from Gate 1 remain on PATH:

```sh
export PATH=/workspace/scratch/59e16347406d/packet-tools/usr/bin:$PATH
export LD_LIBRARY_PATH=/workspace/scratch/59e16347406d/packet-tools/usr/lib/x86_64-linux-gnu
```

| Command / check | Result |
| --- | --- |
| `.venv/bin/pytest -q` | 183 passed; 124 unit + 59 real integration; zero skipped |
| `.venv/bin/pytest tests/integration -q` | 59 passed; actual TShark/capinfos 4.2.2 |
| All semantic golden tests (included above) | 26 pass: eleven unchanged Gate 1 + fifteen new Gate 2 |
| `.venv/bin/ruff check services/analyzer/src tests` | Passed |
| `.venv/bin/ruff format --check services/analyzer/src tests` | Passed; 24 Python files |
| `.venv/bin/python -m compileall -q services/analyzer/src tests` | Passed |
| Installed `wireclaw-analyze` baseline and `--diagnostics` TLS smoke | Passed; recorded analyzer 0.2.0 and packet-tool versions |
| Shared schema and actual persisted/example record validation | Passed; 354 actual persisted/example records and shared schema |
| `git diff --check`, staged-tree inspection, original golden diff | Passed; existing golden JSON bytes unchanged |
| Editable package build/install | Passed offline with existing pinned dependencies; online install retry hit PyPI 502, then cached offline build installed 0.2.0 |

The initial complete run passed 182 tests. Final fixture review corrected an IPv6
fragment checksum that reused the IPv4 pseudo-header result, added a direct
checksum assertion and changed only that fixture's capture identity/quality golden.
The final run above supersedes it. Earlier targeted runs exposed negative tool RTT
on backward timestamps; eligibility now handles it rather than failing all
capabilities. Intermediate module-name collision and lint findings were corrected.
No final failing/skipped integration is represented as passing. Zeek is absent,
recorded optional/unavailable; no native Windows/macOS execution is claimed.

## Security and resource review

- Runner remains the only subprocess boundary: fixed enum plans, direct argv,
  `shell=False`, confined paths, isolated tool configuration, minimal environment,
  disabled name resolution, bounded combined pipes and finite execution timeout.
  No user/model executable, flags, filter or secret is accepted.
- Ingest rollback/no-overwrite/protection/integrity semantics are unchanged.
  Diagnostic persistence adds exactly one allowlisted filename. The original is
  rehashed before and after each analysis; failures preserve completed baseline.
- Frame and stream indexes are built in one packet pass. Per-stream calculations
  see only that stream; two-endpoint stream identity is validated. Sequence unions
  sort once per direction. Overall work is O(N log N) within configured packet
  bounds, with no O(N×streams) rescan. Counted-iteration tests cover 600 streams and
  10,000 unsorted overlapping sequence ranges; Gate 1's 3,000-stream test remains.
- New positive-integer bounds: 5,000 evidence items, 20,000 cumulative normalized-value list
  slots, 16 MiB serialized/indented JSON, 64 numeric occurrences per field, 256 per
  explicit event/reference array. Oversize supporting scope uses range+filter;
  oversize explicit event arrays fail. Underlying RTT/event samples are never
  silently sampled. Excess tool output, records, bytes or occurrences fail clearly.
- Gate 1 defaults remain 64 MiB capture, 100,000 frames, 16 MiB combined process
  output and 30 s per process. A two-pass diagnostic run is still subject to the
  same process deadline. Python work is packet/output-bounded, not an OS worker sandbox.
- DNS names, certificate/SNI text, secrets and raw payload are omitted. No logging
  of capture-derived strings, no outbound provider and no TLS decryption exists.

## Known limitations and gate boundary

Only TShark/capinfos 4.2.2 semantics were validated here. Release tool pinning,
container/OS isolation and native platform validation remain future gate work.
Concurrent case scheduling, lifecycle/failure manifests and caching are Gate 3.
This analyzer does not reconstruct simultaneous TCP open or multiple epochs in a
single tool stream. Goodput is an approximation from observed sequence/ACK coverage,
not application delivery; ambiguous sequence spans/truncation withhold it.

DNS names and name-resolution chains are not retained; encrypted DNS is unavailable.
Coalesced DNS messages are explicitly ambiguous. Visible TLS metadata does not
prove a usable session; alerts/repeated hellos do not identify a root cause.
Quoted ICMP transport never becomes a current diagnostic stream. Quoted fragment
fields are withheld; other nested/tunneled diagnostic headers fail explicitly.
Capture quality, missing directions, offload, timestamp anomalies and drops remain
material caveats, not proof of network failure. Prior successful diagnostic files
remain historical if a later run fails; callers must respect the returned failure.

Gate 1 tasks remain complete, Gate 2 tasks are marked complete only after validation,
and Gate 3 onward remain unchecked. No FastAPI, SQLite/case lifecycle, RCA/report
assembly, UI, host bridge, LLM or Docker implementation is included. Gate 2 is to be
published in a new PR into main and left open for independent review, without merge.
