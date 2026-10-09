# Wireclaw V1 Delivery Plan

Status: **Authoritative implementation sequence**

Implementation should proceed through gates. Do not skip forward merely because a later feature is easier to demonstrate.

## Gate 0 — Repository and specification baseline

Goal: establish product contract before implementation.

- [x] G0.1 Create product README.
- [x] G0.2 Create V1 constitution.
- [x] G0.3 Create V1 requirements.
- [x] G0.4 Create V1 solution design.
- [x] G0.5 Add project-level agent instructions.
- [x] G0.6 Add architecture/security/deployment/testing reference docs.
- [x] G0.7 Add initial shared JSON schema contracts.
- [x] G0.8 Add ADRs for local Docker architecture and deterministic-analysis-first design.

Exit criteria:
- product behavior and non-goals are explicit
- architecture boundaries are explicit
- implementation agents have repository instructions

## Gate 1 — Deterministic analyzer foundation

Goal: prove that Wireclaw can ingest a capture and produce reproducible facts without an LLM.

Requirements: R-F001, R-F003, R-F004, R-F025, R-N001, R-N004.

Tasks:

- [x] G1.1 Create Python analyzer package structure.
- [x] G1.2 Implement safe subprocess runner with no shell and enforced timeouts.
- [x] G1.3 Detect and record TShark/capinfos/Zeek versions.
- [x] G1.4 Implement immutable capture ingest and SHA-256 hashing.
- [x] G1.5 Implement `get_capture_metadata`.
- [x] G1.6 Implement `assess_capture_quality` baseline.
- [x] G1.7 Implement protocol inventory.
- [x] G1.8 Implement endpoint inventory.
- [x] G1.9 Implement conversation inventory.
- [x] G1.10 Normalize outputs into shared evidence contracts.
- [x] G1.11 Add malformed capture, truncation, midstream, and checksum-offload fixtures.
- [x] G1.12 Add golden normalization tests.

Exit criteria:
- same capture produces stable normalized evidence with recorded tool versions
- malformed inputs fail safely
- no model provider is required

## Gate 2 — TCP/DNS/TLS diagnostic engine

Goal: provide deterministic troubleshooting facts for the highest-value traffic issues.

Requirements: R-F006 through R-F010, R-F017.

Tasks:

- [x] G2.1 DNS timing/failure analyzer.
- [x] G2.2 TCP connection-establishment analyzer.
- [x] G2.3 TCP retransmission/duplicate-ACK/out-of-order analyzer.
- [x] G2.4 RTT derivation.
- [x] G2.5 window/zero-window/window-full analyzer.
- [x] G2.6 reset/failure analyzer.
- [x] G2.7 throughput/goodput analyzer.
- [x] G2.8 MSS/fragmentation/PMTUD-signal analyzer.
- [x] G2.9 TLS handshake timing analyzer.
- [x] G2.10 evidence-to-frame/stream traceability.
- [x] G2.11 fixture captures for clean, lossy, window-limited, reset, DNS-delay, and TLS-delay cases.

Exit criteria:
- analyzers distinguish common TCP/DNS/TLS symptoms using reproducible evidence
- each evidence item can identify its supporting packet/stream scope

## Gate 3 — Local API and case model

Goal: expose analyzer functions through a safe local application boundary.

Requirements: R-F002, R-F022 through R-F026, R-S001 through R-S010.

Tasks:

- [x] G3.1 Create FastAPI service.
- [x] G3.2 Implement case state machine.
- [x] G3.3 Implement SQLite schema/migrations.
- [x] G3.4 Implement artifact registry and path confinement.
- [x] G3.5 Implement capture upload/intake API.
- [x] G3.6 Implement baseline analysis orchestration.
- [x] G3.7 Implement analyzer capability API.
- [x] G3.8 Implement bounded execution/resource policy.
- [x] G3.9 Implement case retrieval/deletion.
- [x] G3.10 Add structured safe logging.
- [x] G3.11 Add API contract/integration tests.

Exit criteria:
- localhost API can create, analyze, retrieve, and delete a case safely
- API does not expose arbitrary analyzer commands or filesystem paths

## Gate 4 — Rules-only investigation and report

Goal: deliver useful troubleshooting without any LLM.

Requirements: R-F012 through R-F015, R-F021, R-U002, R-U004, R-U006.

Tasks:

- [x] G4.1 Implement deterministic candidate-conversation ranking.
- [x] G4.2 Implement basic time-attribution engine.
- [x] G4.3 Implement evidence-based fault-domain rules.
- [x] G4.4 Implement evidence sufficiency checks.
- [x] G4.5 Implement `insufficient_evidence` result.
- [x] G4.6 Implement finding/report assembler.
- [x] G4.7 Implement confidence policy based on evidence conditions.
- [x] G4.8 Create golden RCA cases with expected findings/unknown outcomes.

Exit criteria:
- Wireclaw can explain representative cases without model access
- ambiguous fixtures produce explicit uncertainty rather than forced diagnoses

## Gate 5 — Web UI

Goal: provide the simple capture + symptom + investigation workflow.

Requirements: R-U001 through R-U006.

Tasks:

- [ ] G5.1 Create React/TypeScript app.
- [ ] G5.2 Implement capture drop/select intake.
- [ ] G5.3 Implement symptom input.
- [ ] G5.4 Implement investigation progress stages.
- [ ] G5.5 Implement result summary with conclusion/confidence/fault domain/capture quality.
- [ ] G5.6 Implement time-attribution view.
- [ ] G5.7 Implement finding cards with evidence/limitations/next validation.
- [ ] G5.8 Implement expert evidence drawer.
- [ ] G5.9 Implement case deletion UI.
- [ ] G5.10 Accessibility and responsive layout review.

Exit criteria:
- a user can complete the primary workflow without CLI knowledge
- evidence and uncertainty remain visible and understandable

## Gate 6 — Evidence capture and Wireshark integration

Goal: make native Wireshark validation a first-class path.

Requirements: R-F018 through R-F020, R-D003, R-D004, R-U003.

Tasks:

- [ ] G6.1 Implement evidence-capture extraction service.
- [ ] G6.2 Record parent hash/extraction rule/display filter for derived captures.
- [ ] G6.3 Implement Go host bridge protocol.
- [ ] G6.4 Enforce loopback/authentication/origin restrictions.
- [ ] G6.5 Implement logical-artifact resolution/path confinement.
- [ ] G6.6 Implement configured Wireshark executable discovery/selection.
- [ ] G6.7 Implement macOS launcher behavior.
- [ ] G6.8 Implement Windows launcher behavior.
- [ ] G6.9 Implement Linux launcher behavior.
- [ ] G6.10 Add **Open Full Capture in Wireshark** to every applicable finding.
- [ ] G6.11 Add **Open Evidence Capture in Wireshark** beside it on every applicable finding.
- [ ] G6.12 Add Copy Display Filter and Show Packet Evidence.
- [ ] G6.13 Host-bridge security tests including path traversal and malicious filters.

Exit criteria:
- both Wireshark actions are always visible together when applicable
- both work on macOS, Windows, and Linux
- the bridge cannot be used for arbitrary command execution

## Gate 7 — Reasoning provider and iterative investigation

Goal: add LLM-assisted hypothesis planning/correlation without weakening evidence boundaries.

Requirements: R-F014 through R-F016, R-F024, R-S006 through R-S008.

Tasks:

- [ ] G7.1 Define provider interface.
- [ ] G7.2 Implement OpenAI-compatible cloud adapter.
- [ ] G7.3 Implement OpenAI-compatible local adapter.
- [ ] G7.4 Implement prompt/context builder using normalized evidence.
- [ ] G7.5 Implement typed capability-request schema.
- [ ] G7.6 Implement investigation-step bounds/repetition detection.
- [ ] G7.7 Validate model-requested capabilities and parameters.
- [ ] G7.8 Implement hypothesis/finding proposal validation against evidence IDs.
- [ ] G7.9 Prevent unsupported model claims from entering final findings.
- [ ] G7.10 Add provider timeout/failure fallback to deterministic report.
- [ ] G7.11 Add prompt-injection/adversarial text fixtures sourced from capture fields.

Exit criteria:
- the model can deepen investigations only through typed capabilities
- disabling/removing the model preserves core analyzer functionality
- model prose cannot fabricate evidence records

## Gate 8 — Docker packaging and cross-platform release

Goal: make the product easy to run and share.

Requirements: R-D001 through R-D006.

Tasks:

- [ ] G8.1 Create pinned analyzer Docker image.
- [ ] G8.2 Create web/API Docker packaging.
- [ ] G8.3 Create `compose.yaml` with loopback-only published ports.
- [ ] G8.4 Define bind-mounted data root.
- [ ] G8.5 Create `.env.example` with safe defaults.
- [ ] G8.6 macOS start/stop launcher.
- [ ] G8.7 Windows start/stop launcher.
- [ ] G8.8 Linux start/stop launcher.
- [ ] G8.9 host-bridge install/uninstall scripts for each OS.
- [ ] G8.10 first-run prerequisite checks for Docker and Wireshark.
- [ ] G8.11 release smoke tests on all three host OS families.

Exit criteria:
- a user with Docker and Wireshark can start Wireclaw without a developer toolchain
- equivalent core workflow works on macOS, Windows, and Linux

## Gate 9 — V1 acceptance and hardening

Goal: demonstrate that Wireclaw solves representative troubleshooting problems safely and reproducibly.

Tasks:

- [ ] G9.1 Build an acceptance corpus covering clean/healthy traffic.
- [ ] G9.2 DNS-delay case.
- [ ] G9.3 TCP-loss/retransmission case.
- [ ] G9.4 high-RTT case.
- [ ] G9.5 receiver-window constrained case.
- [ ] G9.6 TCP reset/reconnect case.
- [ ] G9.7 TLS-delay case.
- [ ] G9.8 server/application-wait case.
- [ ] G9.9 MTU/PMTUD evidence case.
- [ ] G9.10 one-sided/incomplete capture case requiring uncertainty.
- [ ] G9.11 large-capture resource-limit case.
- [ ] G9.12 malformed/adversarial capture case.
- [ ] G9.13 cloud-provider privacy inspection.
- [ ] G9.14 host-bridge security review.
- [ ] G9.15 end-to-end macOS acceptance.
- [ ] G9.16 end-to-end Windows acceptance.
- [ ] G9.17 end-to-end Linux acceptance.

V1 release gate:

- deterministic evidence correct against golden fixtures
- no known path to arbitrary command execution through analyzer or bridge
- ambiguous cases do not produce forced root-cause claims
- raw captures are not transmitted to cloud model under default policy
- both Wireshark actions work and remain visible together
- cross-platform Docker workflow passes

## Deferred post-V1 candidates

Do not pull these into V1 without specification change:

- browser HAR correlation
- interface/SNMP counters
- traceroute/MTR/ping/HTTP active testing
- load-balancer/application log correlation
- simultaneous client/server capture correlation
- NetFlow/IPFIX ingestion
- ThousandEyes import/API integration
- centralized team server mode
- case sharing/redaction workflow
- continuous capture
- custom PCAP foundation model
