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
7. **macOS-first V1, portable architecture.** V1 is release-qualified on macOS. Windows and Linux remain post-V1 roadmap targets; existing portability code/CI does not imply release support.
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

The analyzer and web application are containerized. V1 uses a small native macOS host bridge for Wireshark launch behavior. Windows/Linux bridge implementations and CI coverage are retained as portability groundwork for future release qualification.

## Repository map

- `specs/v1/` — authoritative V1 product specification and delivery plan
- `specs/post-v1/` — approved post-V1 feature specifications that extend, but do not retroactively rewrite, V1
- `docs/` — architecture and operational design references
- `contracts/` — machine-readable contracts shared across components
- `apps/web/` — browser UI
- `services/api/` — local API and orchestration boundary
- `services/analyzer/` — deterministic packet analysis and evidence extraction
- `services/host-bridge/` — native Wireshark launch integration
- `tests/` — fixtures, golden cases, integration tests, and acceptance tests
- `AGENTS.md` — project-level instructions for coding agents and contributors

## Current status

Post-V1 embedded local AI implementation is on `post-v1-embedded-ai-impl`. The pinned model/runtime package and benchmark are recorded in [the post-V1 acceptance record](docs/post-v1-embedded-ai-acceptance.md); packaged native acceptance, exact-head CI, independent review, and draft PR remain pending. This feature does not change the V1 acceptance history.


Gates 1 through 9 are merged and complete for V1.

Gate 6 completed the evidence-capture and native Wireshark path and passed native GUI acceptance on the supported V1 host, macOS. Windows and Linux release qualification are deferred to the [product roadmap](docs/roadmap.md), while their existing build/discovery/argv CI coverage remains portability evidence.

Gate 7 added optional OpenAI-compatible cloud/local reasoning behind a typed capability boundary, normalized-only model context, deterministic fallback, adversarial/privacy coverage, persistent reasoning audit history, and deterministic HTTP request/response timing. The positive decodable HTTP server-wait case is distinguished from opaque TCP silence. Gate 7 merged through [PR #10](https://github.com/Ryan9876/wireclaw/pull/10); see [Gate 7 verification](docs/gate7-verification.md).

Gate 8 packaged the single-core Docker release, pinned the analyzer/runtime identities, added the macOS arm64 start/stop and bridge install/uninstall workflow, preserved loopback-only exposure and Gate 7 privacy behavior, and passed a real same-artifact archive-loaded macOS release smoke including both native Wireshark actions, persistence, and immutability checks. Gate 8 merged through [PR #11](https://github.com/Ryan9876/wireclaw/pull/11); see [Gate 8 verification](docs/gate8-verification.md).

Gate 9 completed V1 acceptance and hardening against one frozen macOS arm64 candidate. G9.1–G9.15 and all 24 release signoff criteria passed, including cloud-provider privacy inspection, bridge security, reproducibility, persistence/immutability, native Full Capture and Evidence Capture workflows, and exact-head CI. Gate 9 merged through [PR #12](https://github.com/Ryan9876/wireclaw/pull/12); see the [V1 acceptance record](docs/v1-acceptance.md).

Gate 6 merged through [PR #8](https://github.com/Ryan9876/wireclaw/pull/8); see [Gate 6 verification](docs/gate6-verification.md). The implementation-grade Gate 7–9 specifications and agent guidance merged through [PR #9](https://github.com/Ryan9876/wireclaw/pull/9).

Wireclaw V1 acceptance is complete on the supported macOS arm64 target. Windows and Linux remain post-V1 qualification targets under the [product roadmap](docs/roadmap.md).

The next proposed development stage is **embedded local AI**: package Qwen3-4B-Instruct-2507 Q4_K_M plus a pinned native macOS llama.cpp runtime so AI-assisted troubleshooting works without a separately installed/configured model stack. The review-candidate development contract is [`specs/post-v1/embedded-local-ai.md`](specs/post-v1/embedded-local-ai.md); architecture choice is recorded in [ADR-0007](docs/decisions/ADR-0007-embedded-local-ai-native-runtime.md). This does not change the accepted V1 record.

## Gate 1 analyzer

The deterministic Python analyzer is implemented. See [developer instructions](services/analyzer/README.md), [Gate 1 verification](docs/gate1-verification.md), and [Gate 2 verification](docs/gate2-verification.md).

The [local API](services/api/README.md) provides bounded intake, persistence, deterministic analysis, rules-only findings/reports, evidence-capture extraction, bridge grants, optional bounded model-assisted reasoning, and case deletion. The [web UI](apps/web/README.md) presents that API. V1 acceptance and hardening are complete for the supported macOS arm64 release target.
