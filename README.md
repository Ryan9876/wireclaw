# Wireclaw

Wireclaw is a local-first AI network traffic investigator for PCAP/PCAPNG troubleshooting.

Its purpose is to turn ambiguous reports such as **"the application is slow"** into an evidence-backed investigation that identifies the most likely fault domain, explains the supporting packet evidence, reports uncertainty, and tells the operator what evidence would resolve remaining ambiguity.

## Product principles

1. **Facts before inference.** Wireshark/TShark, Zeek, capinfos, and other deterministic tools establish packet facts. The reasoning layer interprets those facts; it does not replace them.
2. **Local-first by default.** Packet captures remain on the user's workstation unless the user explicitly configures otherwise.
3. **Raw payloads are not sent to an LLM by default.** The reasoning layer receives normalized evidence and bounded excerpts only when policy permits.
4. **Evidence is traceable.** Every finding must link back to packet numbers, streams, tool output, or derived measurements.
5. **Uncertainty is explicit.** Wireclaw must say when a conclusion cannot be established from the available capture.
6. **Wireshark remains available.** Every packet-level finding always exposes both **Open Full Capture in Wireshark** and **Open Evidence Capture in Wireshark**.
7. **Cross-platform.** The analyzer runs in Docker on macOS, Windows, and Linux. Native host integration is limited to operations that must occur outside the container, such as launching Wireshark.
8. **Spec first.** Product behavior is defined under `specs/` before implementation changes are made.

## Intended V1 workflow

1. User opens `http://localhost:<configured-port>`.
2. User drops a PCAP/PCAPNG and describes the symptom in plain language.
3. Wireclaw validates capture quality and inventories endpoints, protocols, and conversations.
4. Deterministic analyzers produce normalized evidence.
5. The investigation engine selects additional bounded queries based on the symptom and evidence.
6. Findings are ranked by confidence and impact.
7. The report separates observed facts, derived measurements, hypotheses, and conclusions.
8. For each relevant finding, the UI always offers:
   - Open Full Capture in Wireshark
   - Open Evidence Capture in Wireshark
   - Copy Wireshark Display Filter
   - Show Packet Evidence
9. If evidence is insufficient, Wireclaw identifies the next measurement or capture needed.

## V1 analysis focus

Wireclaw should help distinguish among:

- DNS delay or failure
- TCP connection-establishment delay
- packet loss and retransmission
- packet reordering
- receiver/window constraints
- resets and connection failure
- MTU/MSS and fragmentation symptoms
- TLS handshake delay
- application/server think time
- throughput/goodput constraints
- traffic asymmetry and incomplete capture
- client-side versus server-side versus network-path fault domains

## Architecture

```text
Browser UI
   |
   v
Local API / Investigation Orchestrator
   |
   +--> Capture intake and safety controls
   +--> TShark / capinfos / editcap / mergecap
   +--> Zeek
   +--> Derived metrics
   +--> Investigation policy and state
   +--> LLM reasoning adapter
   |
   v
Evidence-backed investigation result
   |
   +--> Full capture -> native Wireshark host bridge
   +--> Evidence capture -> native Wireshark host bridge
```

The analyzer and web application are containerized. A small optional host bridge handles native Wireshark launch behavior on macOS, Windows, and Linux.

## Repository map

- `specs/v1/` — authoritative V1 product specification and delivery plan
- `docs/` — architecture and operational design references
- `contracts/` — machine-readable contracts shared across components
- `apps/web/` — browser UI
- `services/api/` — local API and orchestration boundary
- `services/analyzer/` — deterministic packet analysis and evidence extraction
- `services/host-bridge/` — native Wireshark launch integration
- `tests/` — fixtures, golden cases, integration tests, and acceptance tests
- `AGENTS.md` — project-level instructions for coding agents and contributors

## Current status

Gates 1 through 4 are merged. Gate 5 implements the local browser workflow and
is awaiting PR approval. See [web startup instructions](apps/web/README.md) and
[Gate 5 verification](docs/gate5-verification.md). Gates 6 and later remain
unimplemented. The product specification remains authoritative; start with
`specs/v1/constitution.md`.

## Gate 1 analyzer

The deterministic Python analyzer is implemented. See [developer instructions](services/analyzer/README.md), [Gate 1 verification](docs/gate1-verification.md), and [Gate 2 verification](docs/gate2-verification.md).

The [local API](services/api/README.md) provides bounded intake, persistence,
analysis, rules-only findings/reports and case deletion. The [web UI](apps/web/README.md)
presents that API. LLM adapters, host bridge and Docker packaging remain later gates.
