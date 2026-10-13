# Wireclaw V1 — Gate 9 Acceptance Specification

Status: **Subordinate acceptance specification**

This document defines the V1 release-acceptance contract for Gate 9. It does not replace the constitution, requirements, solution, accepted ADRs, or gate execution specs. Gate 9 is primarily acceptance and hardening: a failed criterion is fixed at the lowest responsible layer, and any material behavior change must follow C14 before implementation.

## 1. Gate objective

Gate 9 proves that one immutable **macOS V1 release candidate**:

- produces correct deterministic evidence for representative troubleshooting cases;
- preserves uncertainty when the capture cannot establish a conclusion;
- keeps model reasoning inside typed evidence boundaries;
- protects raw-capture privacy by default;
- respects resource and malformed-input limits;
- preserves the host-bridge security boundary;
- runs the complete packaged workflow on the supported V1 host, macOS.

Windows and Linux are post-V1 roadmap targets. Existing CI/build coverage on those platforms does not block V1 and does not constitute release support.

Gate 9 must not become a catch-all feature-development phase. If acceptance exposes a missing required capability, return to the responsible gate/spec, implement it with tests, then restart the affected acceptance evidence against a new immutable release-candidate SHA.

## 2. Gate tasks

- G9.1 clean/healthy traffic corpus
- G9.2 DNS-delay case
- G9.3 TCP-loss/retransmission case
- G9.4 high-RTT case
- G9.5 receiver-window constrained case
- G9.6 TCP reset/reconnect case
- G9.7 TLS-delay case
- G9.8 server/application-wait case
- G9.9 MTU/PMTUD evidence case
- G9.10 one-sided/incomplete capture uncertainty case
- G9.11 large-capture/resource-limit case
- G9.12 malformed/adversarial capture case
- G9.13 cloud-provider privacy inspection
- G9.14 host-bridge security review
- G9.15 end-to-end macOS acceptance

Legacy task IDs G9.16 (Windows end-to-end) and G9.17 (Linux end-to-end) are deferred to future release qualification and are not V1 tasks.

## 3. Immutable release-candidate identity

Before running Gate 9, freeze one release candidate and record:

```text
git commit SHA
release version/tag if assigned
compose.yaml hash/revision
wireclaw-core image digest
base image digest
analyzer version lock
Python version
web build revision
macOS host-bridge binary SHA-256
configuration defaults
```

All acceptance results must name this identity.

If source code, Dockerfile, dependency lock, analyzer version, generated contract, or packaged bridge binary changes, the release-candidate identity changes and affected acceptance must be rerun.

Documentation-only corrections that do not alter the tested artifact may cite the original tested identity explicitly, but the final repository must not misleadingly claim untested code was accepted.

## 4. Acceptance result vocabulary

Every Gate 9 case records exactly one result:

```text
PASS
FAIL
BLOCKED
NOT_RUN
```

Only `PASS` satisfies a required release criterion.

`BLOCKED` is appropriate when a required macOS desktop/release environment is unavailable; it is not equivalent to pass.

`NOT_RUN` is never release-acceptable for a required G9 task.

## 5. Per-case assertion structure

Each acceptance case must specify:

### Must observe

Deterministic facts that must be present and numerically/frame-wise correct.

### Must conclude

The strongest user-visible conclusion Wireclaw is required to support from those facts.

### Must not conclude

Claims that would exceed the evidence.

### Operational acceptance

Requirements involving report traceability, Wireshark actions, persistence, privacy, failure behavior, or release packaging.

This structure prevents a test from passing merely because a string/category happened to appear.

## 6. G9.1 — Healthy/clean traffic

Use the existing deterministic `healthy` and/or `clean_tcp` fixtures.

Known fixture facts include:

- `healthy`: 7 frames, 469 wire bytes, 0.6 seconds, completed TCP handshake, DNS pair, IPv6 UDP pair;
- `clean_tcp`: 20 ms complete handshake, four 10 ms ACK RTT samples, 20/30 payload bytes acknowledged, MSS 1460, window scaling 2, no expert fault indicator.

### Must observe

- capture metadata matches generated ground truth;
- capture quality is not falsely degraded by construction;
- no retransmission/reset/zero-window/PMTUD fault signal is fabricated;
- deterministic evidence IDs and tool versions exist.

### Must conclude

A healthy/clean capture with no supported fault must not be forced into a root-cause diagnosis. `insufficient_evidence` or an explicitly healthy/no-supported-fault result consistent with the accepted report contract is acceptable.

### Must not conclude

- packet loss;
- high RTT;
- receive-window constraint;
- DNS failure;
- TLS failure;
- server/application root cause;
- MTU black hole.

## 7. G9.2 — DNS delay

Use `dns_delay` or its Gate 9 successor with the same deterministic construction.

Known fact:

```text
UDP DNS query/response frames 1/2 separated by 1.5 seconds
```

### Must observe

- exact query/response relationship;
- approximately 1.5 second measured DNS interval;
- supporting frame references;
- finding-specific Wireshark filter selecting the relevant transaction.

### Must conclude

A DNS timing finding is supported when symptom/context warrants it.

### Must not conclude

- that DNS necessarily delayed the complete user-visible transaction unless linkage evidence exists;
- a specific resolver/path root cause from timing alone.

### Operational acceptance

Evidence Capture must focus on the relevant DNS transaction set, not unrelated DNS.

## 8. G9.3 — TCP loss/retransmission

Use `loss_tcp`.

Known construction:

```text
retransmission-union frames: [5, 11, 13]
fast retransmission: [11]
spurious retransmission: [13]
duplicate ACKs: [8, 9, 10]
100 payload bytes
40 unique observed/ACK-covered bytes
```

### Must observe

All applicable counts/frame references without conflating categories.

### Must conclude

A supported retransmission/loss-indicator finding may identify transport/network-path contribution with appropriately bounded confidence.

### Must not conclude

- exact physical loss location;
- a specific switch/router/link as root cause;
- that every retransmission indicator proves packet loss at the capture point.

## 9. G9.4 — High RTT

Use `high_rtt`.

Known construction:

```text
TCP establishment: 400 ms
median ACK RTT: 200 ms
```

### Must observe

Expected establishment and RTT values within fixture precision.

### Must conclude

A supported high-RTT finding when symptom/context warrants it.

### Must not conclude

A specific path segment or device is responsible without discriminating evidence.

## 10. G9.5 — Receiver-window constrained

Use `window_tcp`.

Known construction:

```text
server scaled window: 100
window-full frame: [5]
zero-window frames: [6, 8]
probe frame: [7]
reopen interval frames 6–9: 1 second
```

### Must observe

The exact window/probe/reopen evidence and responsible advertised direction where deterministically known.

### Must conclude

A receive-window constraint finding is supported.

### Must not conclude

- network packet loss merely because throughput is poor;
- an endpoint process/root cause not visible in the capture;
- an endpoint role the evidence cannot establish.

## 11. G9.6 — TCP reset/reconnect

Use `reset_tcp` and `reset_reconnect` as applicable.

Known construction includes:

- `reset_tcp`: server RST/ACK frame 6, 80 ms after observed establishment;
- `reset_reconnect`: reset followed by a new stream with a different client ephemeral port and deterministic prior-reset/SYN references.

### Must observe

Exact reset and reconnect frame/stream relationships.

### Must conclude

A reset/reconnect transport condition is supported.

### Must not conclude

The application cause of the reset unless separate evidence supports it.

## 12. G9.7 — TLS delay

Use `tls_delay`.

Known construction:

```text
TCP established: 20 ms
ClientHello: 100 ms
ServerHello: 1.1 s
TCP-to-TLS: 80 ms
ClientHello-to-ServerHello: 1.0 s
supported-version field: 0x0304
```

### Must observe

- deterministic visible TLS milestones;
- approximately 80 ms TCP-to-ClientHello interval;
- approximately 1 second ClientHello-to-ServerHello interval;
- supporting frame references.

### Must conclude

A TLS-handshake-delay finding may be supported.

### Must not conclude

- decrypted application semantics;
- usable encrypted-session completion solely from visible ServerHello;
- endpoint-processing versus path cause without further evidence.

## 13. G9.8 — Server/application wait

Gate 9 must test both a positive decodable case and a negative opaque case.

### Positive case: `http_server_wait`

Gate 7 must provide a valid plaintext HTTP/1.x fixture with a complete request and delayed first response.

Expected construction includes:

- complete decodable request;
- normal prompt transport ACK behavior;
- no zero-window explanation;
- first application response approximately two seconds after request completion;
- deterministic request/response frame references.

#### Must observe

- request completion time;
- first response time;
- measured request-to-first-response interval;
- response transfer interval where determinable;
- TCP stream/endpoints;
- supporting frame references and display filter.

#### Must conclude

Wireclaw can identify a supported server/application-wait contribution/boundary for this decodable transaction with confidence consistent with evidence.

The wording must distinguish observed delay after request completion at the server/application boundary from an unsupported internal root cause.

#### Must not conclude

- database, CPU, thread pool, backend service, load balancer, or other internal cause without evidence;
- that the visible endpoint itself rather than a downstream dependency necessarily consumed the time.

### Negative case: existing opaque `server_wait`

The existing synthetic transport fixture has prompt transport behavior and a two-second gap but no deterministically decodable application transaction.

It must remain an uncertainty regression.

#### Must not conclude

A server/application semantic finding solely because generic TCP payload appeared after a two-second silence interval.

This pair proves R-F011/R-F012 and C3/C10 simultaneously.

## 14. G9.9 — MTU/PMTUD evidence

Use `pmtud_signals`.

Known construction:

```text
IPv4 fragmentation-needed advertises MTU 1200
IPv6 Packet Too Big advertises MTU 1280
```

### Must observe

Both explicit control signals with correct advertised MTUs and frame references.

### Must conclude

A PMTUD/path-MTU evidence finding may be supported.

### Must not conclude

- MTU black hole solely from these messages;
- that large-transfer slowness is caused by MTU without progress/failure evidence;
- quoted inner transport as a separate live stream.

## 15. G9.10 — One-sided/incomplete capture uncertainty

Use `one_sided`, `midstream`, `incomplete_handshake`, and/or `truncated`.

### Must observe

The relevant visibility limitation:

- one-sided/asymmetric traffic;
- capture beginning midstream;
- incomplete handshake;
- snap/truncation limits.

### Must conclude

Capture-quality limitations are visible and materially constrain confidence.

When packets cannot discriminate fault domains, the primary result must be `insufficient_evidence` with meaningful next evidence.

### Must not conclude

A forced client/network/server root cause from missing packets.

## 16. G9.11 — Large capture/resource limits

Create deterministic resource-bound cases that exercise configured limits without exhausting the acceptance host.

Cover at least:

- upload/capture-size limit;
- analyzer subprocess timeout where safely injectable;
- query/result-row limit;
- evidence-capture artifact-size limit;
- evidence-capture count/reuse behavior;
- model request size limit;
- model response size limit;
- max reasoning steps;
- duplicate capability request prevention;
- generated report/JSON bounds where configured.

### Must observe

- bounded/static error codes;
- case/original remains intact;
- prior deterministic evidence remains available where applicable;
- no unbounded memory/disk/process growth;
- no retry loop that defeats configured bounds.

### Must conclude

A limit was reached, not a fabricated diagnostic cause.

## 17. G9.12 — Malformed/adversarial capture

Use existing malformed/damaged/unsupported fixtures plus adversarial normalized-string fixtures.

Cover:

- invalid magic/header;
- damaged/truncated record structure;
- unsupported capture type;
- pathological but bounded analyzer output;
- capture-derived prompt-injection strings;
- control characters/unsafe filter material where applicable.

### Must observe

Safe rejection or explicit limitation without corrupting other cases.

### Must not conclude

A diagnostic finding from parser failure alone.

No crash, shell interpolation, arbitrary path access, or unsafe provider capability execution is acceptable.

## 18. G9.13 — Cloud-provider privacy inspection

Use the Gate 7 controlled fake cloud endpoint to inspect exact provider HTTP requests produced by the release candidate.

Seed sentinels representing:

- raw packet payload bytes;
- original capture bytes/fragments;
- absolute filesystem paths;
- credential/token/cookie-like values;
- host-bridge token-like values;
- analyzer raw output that should not be sent.

### Must observe

Provider request contains only approved normalized context.

### Must not observe

Any forbidden sentinel or raw capture/payload transmission.

### Scope of claim

This acceptance is about Wireclaw's provider request path. Do not claim that Docker, macOS, DNS, package managers, or unrelated software generated zero network traffic.

The test must control/mock the provider destination and inspect exact Wireclaw request body/headers while ensuring secrets are not logged/persisted.

## 19. G9.14 — Host-bridge security review

Repeat the Gate 6 trust-boundary review against the packaged macOS release.

Required checks:

- numeric loopback listener only;
- strict Origin allowlist for configured app port;
- bounded strict JSON;
- unknown fields rejected;
- high-entropy one-time grant token;
- only token hash persisted;
- constant-time token comparison;
- expiration boundary enforced;
- replay rejected;
- concurrent use of one grant causes at most one native launch;
- logical case/artifact IDs only;
- path traversal rejected;
- symlink escape rejected;
- cross-case substitution rejected;
- artifact SHA tampering rejected;
- artifact kind allowlist enforced;
- display filter bounded/control characters rejected;
- Wireshark executable selected only by trusted config/discovery;
- exact direct argv;
- no shell;
- no generic command/exec endpoint;
- paths containing spaces work without argument injection.

Any arbitrary process-execution path is an automatic release blocker.

## 20. Model-boundary acceptance

Gate 9 must rerun deterministic fake-provider scenarios against the packaged release.

Required:

1. rules-only/no-model mode;
2. one valid iterative capability request;
3. valid finalize action;
4. fabricated evidence ID;
5. unknown capability;
6. invalid capability parameters;
7. duplicate identical request;
8. malformed response;
9. oversized response;
10. timeout/unavailable provider;
11. prompt-injection normalized string;
12. unsupported packet-fact prose;
13. request for shell/path/native application action.

### Must observe

Only typed validated capability execution and deterministic evidence creation.

### Must not observe

- provider-created evidence records;
- arbitrary command/process execution;
- fabricated evidence entering final findings;
- deterministic findings disappearing because the provider disagreed;
- optional-provider failure erasing deterministic report usefulness.

## 21. Rules-only acceptance

Run the acceptance corpus with provider mode `none`.

Rules-only must remain capable of:

- capture intake/quality;
- deterministic evidence generation;
- deterministic findings where rules support them;
- uncertainty/insufficient-evidence outcomes;
- report/evidence display;
- evidence capture generation;
- Full/Evidence native Wireshark actions.

V1 must not require an LLM to be useful.

## 22. Model-assisted acceptance

Use a deterministic scripted/fake provider for release-gate correctness.

A real external model may be an optional smoke test but must not determine pass/fail truth for the acceptance corpus.

Model-assisted mode must not suppress or contradict deterministic ground truth.

## 23. Reproducibility acceptance

For a representative subset covering healthy, DNS, TCP loss, high RTT, HTTP server wait, PMTUD, and incomplete capture:

Run the same fixture twice using the same release candidate, analyzer versions, and configuration.

Verify deterministic evidence equivalence for:

- categories;
- normalized values;
- frame references;
- affected scope;
- display filters;
- parent/artifact hashes where deterministically derived;
- analyzer version metadata.

Intentional unique timestamps/IDs may differ, but deterministic packet facts must not.

## 24. Persistence and immutability acceptance

For representative cases:

1. record original capture SHA-256 after ingest;
2. investigate;
3. run model-assisted iteration where configured;
4. generate evidence capture;
5. open full/evidence capture;
6. restart container/release;
7. reload case/report;
8. verify original SHA-256 remains identical;
9. verify persisted deterministic evidence remains valid;
10. verify case deletion behavior is explicit and confined.

No derived operation may modify the uploaded original.

## 25. Logging/secrets acceptance

Inspect application/API/provider/bridge logs produced by acceptance scenarios.

Assert they do not contain:

- raw packet payloads;
- provider API keys;
- Authorization headers;
- host-bridge raw tokens;
- credentials/cookies extracted from captures;
- raw model chain-of-thought;
- unbounded raw provider prompts/responses.

Logs should retain useful bounded audit fields such as case ID, capability, duration, status, and normalized failure code.

## 26. Epistemic UX acceptance

Review representative rendered reports for:

- observed/derived evidence separated from inferred findings;
- confidence visible;
- material capture limitations visible;
- `insufficient_evidence` shown as a valid completed result;
- remaining hypotheses labeled as possibilities rather than findings;
- next evidence clearly stated;
- no “AI detected” wording used as evidence;
- measured versus inferred time attribution distinguished;
- encrypted/unsupported protocol limitations visible.

This is a product acceptance, not only a schema test.

## 27. Wireshark acceptance

For representative packet-level findings, verify both actions remain visible together:

```text
Open Full Capture in Wireshark
Open Evidence Capture in Wireshark
```

Also verify Copy Wireshark Display Filter and Show Packet Evidence.

### Full Capture

- native macOS Wireshark opens the immutable original;
- backend-approved relevant filter is applied;
- original hash remains unchanged.

### Evidence Capture

- separate derived PCAPNG opens;
- capture is bounded/focused to the finding;
- provenance identifies parent/finding/evidence/filter/tool versions;
- exact repeated generation reuses a valid matching artifact where specified;
- original remains unchanged.

## 28. G9.15 — macOS end-to-end acceptance

Run the actual Gate 8 release on a native macOS desktop with Docker-compatible runtime and native Wireshark.

Must include:

- macOS launcher start/stop;
- localhost-only core;
- case intake/investigation/report;
- rules-only mode;
- provider fake/local smoke path where available;
- persistence across restart;
- Full Capture native Wireshark;
- Evidence Capture native Wireshark;
- path containing spaces;
- bridge-down degradation;
- case deletion behavior.

Record:

```text
macOS version
architecture
Docker/runtime version
Compose version
Wireshark version
release source SHA
core image digest
bridge binary SHA-256
```

## 29. Deferred platform qualification

Windows and Linux end-to-end acceptance are not V1 Gate 9 criteria.

Before either platform is promoted to supported in a post-V1 release, perform Gate 9-equivalent acceptance on that actual host OS, including packaged launcher/install behavior, native Wireshark Full/Evidence actions, paths with spaces, persistence, provider/privacy behavior, bridge security, and release identity recording.

Cross-compilation or CI build success alone must never be treated as platform release qualification.

## 30. Acceptance report

Create `docs/v1-acceptance.md`.

Required header:

```text
Date
release candidate version
source SHA
core image digest
analyzer lock revision
macOS bridge binary SHA-256
```

For every V1 G9 task include:

```text
Result: PASS / FAIL / BLOCKED / NOT_RUN
Fixtures/scenario
Must-observe result
Must-conclude result
Must-not-conclude result
Operational result
Evidence/test references
Known limitations
```

Include the macOS release environment matrix and explicitly state that Windows/Linux are post-V1 targets, not untested V1 support claims.

## 31. Automatic release blockers

The V1 release is blocked by any of the following:

1. deterministic golden evidence differs materially from fixture ground truth without accepted spec/golden update;
2. known analyzer or bridge arbitrary-command-execution path;
3. host app exposed to LAN/WAN by default;
4. raw capture/payload sent to cloud provider under default policy;
5. secret/API key/token logged or persisted insecurely;
6. provider can fabricate evidence accepted by the report;
7. ambiguous/incomplete capture forced into unsupported root cause;
8. provider outage destroys or hides deterministic findings;
9. original capture modified by analysis/evidence/Wireshark path;
10. evidence capture is not confined/bounded or provenance is invalid;
11. Full/Evidence Wireshark actions missing or not functional where applicable;
12. required macOS release workflow fails;
13. packaged release requires undeclared developer toolchain;
14. analyzer versions are not pinned/recorded;
15. required V1 Gate 9 case remains `FAIL`, `BLOCKED`, or `NOT_RUN` at signoff.

Windows/Linux not being release-qualified is not a V1 blocker because those platforms are explicitly out of V1 scope.

## 32. Full regression before signoff

Run all unit/integration/golden/security/web/browser/packaging suites from Gates 0–8 against the release candidate.

At minimum preserve:

- real TShark/capinfos analyzer tests;
- API/state/security tests;
- Gate 4/7 deterministic goldens;
- Gate 6 bridge/evidence tests;
- web unit + production browser tests;
- provider privacy/fallback/injection tests;
- Docker image/Compose tests;
- macOS host-bridge test/vet/build.

Existing Ubuntu/Windows portability CI may continue but is non-blocking for V1 platform support.

Do not hide required tests behind silent skips.

## 33. Release signoff checklist

V1 may be declared accepted only when all are true:

1. all Gates 0–8 requirements needed by V1 are implemented and documented;
2. deterministic evidence is correct against the acceptance/golden corpus;
3. healthy traffic does not create false diagnoses;
4. DNS delay behavior passes;
5. TCP retransmission behavior passes;
6. high RTT behavior passes;
7. receive-window constraint behavior passes;
8. reset/reconnect behavior passes;
9. TLS delay behavior passes;
10. positive decodable HTTP server/application wait passes;
11. opaque transport-only server-wait remains appropriately uncertain;
12. PMTUD behavior passes without black-hole overclaim;
13. incomplete/one-sided capture behavior preserves uncertainty;
14. resource limits fail safely;
15. malformed/adversarial captures fail safely;
16. cloud-provider privacy inspection passes;
17. model typed-capability/evidence validation passes;
18. host-bridge security review passes;
19. original immutability/persistence passes;
20. both Wireshark actions pass in packaged macOS release;
21. macOS end-to-end acceptance passes;
22. analyzer/release identities are pinned and recorded;
23. no automatic release blocker remains;
24. `docs/v1-acceptance.md` contains exact evidence and release-candidate identity.

Windows/Linux qualification is intentionally deferred and is not part of this checklist.

## 34. V1 release gate

The existing `tasks.md` release gate remains primary:

- deterministic evidence correct against golden fixtures;
- no known path to arbitrary command execution through analyzer or bridge;
- ambiguous cases do not produce forced root-cause claims;
- raw captures are not transmitted to cloud model under default policy;
- both Wireshark actions work and remain visible together;
- macOS Docker/release workflow passes.

This acceptance specification makes those criteria testable; it does not weaken them.
