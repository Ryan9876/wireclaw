# Wireclaw V1 Requirements

Status: **Authoritative V1 requirements**

Requirement IDs are stable. Tests and tasks should reference them.

## 1. Product objective

Wireclaw shall let an operator provide a PCAP/PCAPNG plus a plain-language symptom and receive an evidence-backed investigation that helps determine whether the problem is primarily client-side, server/application-side, network-path-related, capture-related, or unresolved.

## 2. Functional requirements

### R-F001 — Capture intake

The user shall be able to submit PCAP and PCAPNG files through the localhost web UI.

Acceptance:
- supported capture types are validated by content/tool inspection, not filename alone
- the original file is stored read-only within the case data area
- unsupported/malformed files fail safely with a clear message

### R-F002 — Symptom statement

The user shall be able to provide a free-text problem statement such as "the app is slow" or "connections reset intermittently."

Acceptance:
- symptom text is preserved as case context
- symptom text cannot directly alter command execution

### R-F003 — Capture-quality assessment

Every investigation shall perform capture-quality assessment before diagnostic conclusions.

Acceptance:
- result contains a capture-quality state: `good`, `limited`, or `insufficient`
- limitations affecting diagnostic confidence are listed
- checksum-offload indicators are handled explicitly

### R-F004 — Capture inventory

Wireclaw shall inventory endpoints, address families, protocols, ports, conversations, capture duration, packet count, and byte count where available.

### R-F005 — Conversation ranking

Wireclaw shall identify and rank relevant conversations using symptom context, timing, volume, protocol, errors, and anomalies without excluding lower-volume conversations solely because they are small.

### R-F006 — DNS analysis

Where DNS traffic is visible, Wireclaw shall analyze query/response timing, failures, retries, response codes, resolver behavior, and relevant name resolution sequences.

### R-F007 — TCP establishment analysis

Where TCP is visible, Wireclaw shall analyze connection-establishment timing, SYN/SYN-ACK behavior, failed attempts, retransmitted SYNs, and resets.

### R-F008 — TCP health analysis

Where TCP is visible, Wireclaw shall analyze, as applicable:
- retransmission indicators
- duplicate ACKs
- fast retransmissions
- out-of-order behavior
- spurious retransmission indicators
- receive-window constraints
- zero-window/window-full conditions
- ACK RTT
- connection resets
- bytes in flight
- throughput/goodput indicators

### R-F009 — MTU/MSS indicators

Wireclaw shall inspect observable MSS, fragmentation, ICMP Packet Too Big / fragmentation-needed evidence, and packet-size patterns that may support or contradict an MTU/PMTUD hypothesis.

It shall not claim an MTU black hole solely because large transfers are slow.

### R-F010 — TLS timing

Where handshake metadata is visible, Wireclaw shall measure and report TCP-to-TLS timing and relevant TLS handshake failure/retry indicators.

### R-F011 — Application timing

For decodable request/response protocols, Wireclaw shall calculate request-to-first-response and transfer timing where possible.

For encrypted protocols, Wireclaw may use observable transport/TLS timing but must state payload visibility limitations.

### R-F012 — Time attribution

For suitable transactions, Wireclaw shall present elapsed-time attribution across available stages such as DNS, TCP, TLS, network/transport, server/application wait, and transfer.

Time attribution must identify which values are measured versus inferred.

### R-F013 — Fault-domain assessment

Wireclaw shall assess evidence for at least these domains when applicable:
- client
- local network
- network path
- server/application
- name resolution
- capture/observability limitation
- unknown

### R-F014 — Hypothesis ranking

Wireclaw shall rank plausible hypotheses with evidence and confidence.

Acceptance:
- confidence is qualitative at minimum (`high`, `medium`, `low`)
- each hypothesis cites evidence IDs
- unsupported hypotheses are not presented as findings

### R-F015 — Insufficient-evidence outcome

Wireclaw shall explicitly support an `insufficient_evidence` conclusion.

Acceptance:
- remaining plausible hypotheses are listed
- the next evidence needed to discriminate them is provided

### R-F016 — Iterative investigation

The reasoning layer shall be able to request additional predefined analyzer capabilities based on prior evidence.

Acceptance:
- requests use structured tool contracts
- number of investigation steps is bounded
- repeated identical requests are detected/prevented
- no arbitrary shell execution is possible

### R-F017 — Evidence traceability

Each finding shall reference the packet(s), frame range, stream, transaction, normalized evidence item, or deterministic tool output used to support it.

### R-F018 — Full-capture Wireshark action

Each applicable packet-level finding shall always show **Open Full Capture in Wireshark**.

Acceptance:
- native Wireshark opens the immutable original capture
- the relevant display filter is applied when supported

### R-F019 — Evidence-capture Wireshark action

Each applicable packet-level finding shall always show **Open Evidence Capture in Wireshark**.

Acceptance:
- a separate derived capture is created
- original capture remains unchanged
- evidence capture contains the relevant bounded packet set/stream/time slice
- native Wireshark opens the derived capture

### R-F020 — Copy filter / show evidence

Each applicable packet-level finding shall expose:
- Copy Wireshark Display Filter
- Show Packet Evidence

### R-F021 — Report

Wireclaw shall provide a concise investigation report containing:
- symptom
- capture-quality assessment
- primary conclusion
- confidence
- time attribution where applicable
- prioritized findings
- evidence
- limitations
- recommended next validation

### R-F022 — Case persistence

Wireclaw shall persist local case metadata and derived artifacts across application restarts unless explicitly deleted.

### R-F023 — Case deletion

The user shall be able to delete a case and its derived artifacts from the UI.

Deletion behavior must be explicit about the original capture and generated evidence files.

### R-F024 — Model-provider abstraction

Wireclaw shall support a provider interface that can accommodate:
- OpenAI-compatible cloud endpoints
- OpenAI-compatible local endpoints
- no-model/rules-only operation

The analyzer must not depend on one provider.

### R-F025 — Analyzer-version recording

Each case shall record the versions of deterministic tools used to generate its evidence.

### R-F026 — Failure isolation

Failure of one optional analyzer or model provider shall not corrupt the case or erase deterministic findings from other analyzers.

## 3. Security and privacy requirements

### R-S001 — Loopback default

The web/API services shall bind to loopback by default.

### R-S002 — No general remote exposure

V1 shall not expose a general unauthenticated network service to the LAN/WAN by default.

### R-S003 — No shell interpolation

Untrusted values shall never be interpolated into shell command strings.

### R-S004 — Bounded analyzer capabilities

TShark, Zeek, editcap, capinfos, and other tools shall be invoked through predefined wrappers with validated parameters and execution/resource limits.

### R-S005 — Untrusted-capture handling

Captures and analyzer output shall be treated as untrusted input.

### R-S006 — Raw-capture locality

Raw PCAP/PCAPNG data shall remain local under default settings.

### R-S007 — Cloud-model data minimization

Cloud-model requests shall contain normalized evidence by default and shall exclude raw packet payload bytes unless a future explicit policy enables them.

### R-S008 — Secret handling

Model credentials and host-bridge secrets shall not be stored in source control or emitted in logs.

### R-S009 — Host-bridge restriction

The host bridge shall not expose arbitrary process execution.

It may launch only configured approved applications/capabilities, initially Wireshark.

### R-S010 — Path confinement

The host bridge and analyzer shall reject path traversal and constrain artifact access to configured Wireclaw case/data roots.

## 4. Deployment requirements

### R-D001 — Dockerized core

The web UI, API/orchestrator, and analyzer shall run via Docker-compatible packaging.

### R-D002 — Cross-platform hosts

Supported host platforms are macOS, Windows, and Linux.

### R-D003 — Native Wireshark

Wireshark GUI remains a native host dependency for the Open-in-Wireshark actions.

### R-D004 — Native host bridge

Wireclaw shall provide equivalent host-bridge behavior for macOS, Windows, and Linux.

### R-D005 — Simple startup

A user who has Docker and Wireshark installed should be able to start Wireclaw through a documented launcher without understanding the internal service topology.

### R-D006 — Reproducible analyzer image

Analyzer tool versions shall be pinned in built releases.

## 5. UX requirements

### R-U001 — Single primary workflow

The default workflow shall be:

1. select/drop capture
2. describe symptom
3. investigate
4. review findings
5. open evidence in Wireshark as needed

### R-U002 — Findings before raw statistics

The UI shall prioritize conclusions and evidence over packet-count dashboards.

### R-U003 — Always-visible dual Wireshark actions

Both Wireshark actions required by R-F018 and R-F019 shall be visible together on applicable findings.

### R-U004 — Confidence and limitation visibility

Confidence and material limitations shall be visible without requiring the user to inspect logs.

### R-U005 — Progressive detail

The UI shall support concise default findings with expandable packet/tool details for expert validation.

### R-U006 — No unexplained AI certainty

The UI shall not use wording such as "AI detected" as evidence. Findings must identify measurable support.

## 6. Non-functional requirements

### R-N001 — Original capture immutability

Wireclaw shall not modify the uploaded original capture.

### R-N002 — Resource bounds

Analysis shall have configurable limits for capture size, execution time, extraction size, packet-query result count, and investigation steps.

### R-N003 — Graceful large-capture behavior

For captures exceeding configured thresholds, Wireclaw shall use bounded summaries/indexing/targeted extraction or clearly tell the user what limit was reached rather than exhausting host resources.

### R-N004 — Reproducible deterministic evidence

Normalized evidence shall be reproducible for the same capture, analyzer versions, and configuration.

### R-N005 — Auditability

A case shall retain enough local metadata to reconstruct which analysis capabilities ran, their versions, parameters at a safe level, and the evidence items produced.

### R-N006 — Maintainability

Tool/provider/platform-specific code shall be isolated behind interfaces rather than scattered through UI or business logic.

## 7. Explicit V1 non-goals

The following are not V1 requirements:

- centralized multi-user server deployment
- continuous packet capture appliance
- full NPM/APM replacement
- automatic switch/router configuration changes
- arbitrary remote command execution
- IDS/IPS replacement
- malware detonation
- decrypting TLS without user-provided keys/secrets
- autonomous remediation
- cloud storage of raw captures
- training a custom PCAP LLM

These may be reconsidered only through a future specification.
