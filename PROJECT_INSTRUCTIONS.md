# Wireclaw Project-Level Instructions

Use these instructions when working on Wireclaw in ChatGPT, Codex, Copilot, or another coding agent environment. `AGENTS.md` remains the repository-canonical version for implementation agents.

## Mission

Build Wireclaw as a local-first, cross-platform network traffic investigator that turns PCAP/PCAPNG plus an ambiguous symptom such as "the application is slow" into a defensible, evidence-backed troubleshooting result.

Optimize for diagnostic accuracy, explainability, safe execution, reproducibility, and ease of use—not for demo speed or AI novelty.

## Source-of-truth order

Before making changes, read:

1. `specs/v1/constitution.md`
2. `specs/v1/requirements.md`
3. `specs/v1/solution.md`
4. relevant ADRs and `docs/`
5. `specs/v1/tasks.md`
6. `AGENTS.md`

If code conflicts with the specification, do not preserve the code behavior merely because it already exists. If the intended product behavior is changing, update the specification and acceptance criteria first.

## Architecture

Preserve these boundaries:

- `apps/web`: React/TypeScript UI only
- `services/api`: FastAPI case lifecycle, orchestration, persistence, provider adapters, finding validation
- `services/analyzer`: Python deterministic analyzer capabilities using TShark/Wireshark CLI, capinfos, editcap, Zeek, and reproducible derivations
- `services/host-bridge`: Go native bridge for launching host applications, initially Wireshark only
- `contracts`: shared schemas

The Dockerized core must remain portable across macOS, Windows, and Linux. Native host code exists only where Docker cannot provide the required host integration cleanly.

## Diagnostic rules

Deterministic tools establish packet facts. LLMs may plan investigations and interpret evidence but must never be treated as a source of packet truth.

For each conclusion, distinguish:
- observed facts
- derived measurements
- inferred explanation
- unknown/unresolved information

Every finding must reference concrete evidence IDs, packet/frame ranges, streams, transactions, or deterministic measurements.

Never force a root-cause conclusion. `insufficient_evidence` is a valid and required outcome. When evidence is insufficient, identify exactly what additional evidence would discriminate among remaining hypotheses.

Always assess capture quality before diagnosis, including incomplete/midstream captures, one-sided visibility, checksum offload, truncation, and capture artifacts.

## Required troubleshooting coverage

Prioritize analysis that can distinguish:
- DNS delay/failure
- TCP establishment delay/failure
- retransmission/loss indicators
- reordering
- RTT/latency
- window/receiver constraints
- resets/reconnects
- MSS/MTU/fragmentation/PMTUD signals
- TLS handshake delay
- request-to-first-response/server wait
- throughput/goodput constraints
- client vs network vs server/application vs observability fault domains

For slow transactions, attempt time attribution across DNS, TCP, TLS, request, server/application wait, and transfer without double-counting overlapping intervals.

## Wireshark contract

For every applicable packet-level finding, always show both actions at the same time:

- **Open Full Capture in Wireshark**
- **Open Evidence Capture in Wireshark**

Also provide:
- Copy Wireshark Display Filter
- Show Packet Evidence

Never replace the two open actions with a preference or remembered default.

Original captures are immutable. Evidence captures are separate derived artifacts with provenance back to the original capture and finding.

## Security boundaries

Treat captures, capture-derived strings, tool output, symptom text, and model output as untrusted.

Never:
- execute arbitrary user/model commands
- use `shell=True`
- pass analyzer work through `sh -c`, `bash -c`, or `cmd /c`
- interpolate untrusted values into shell strings
- expose the Docker socket
- add a general-purpose local command endpoint
- let the host bridge launch arbitrary executables

Analyzer execution must use predefined typed capabilities, direct subprocess argument arrays, validation, timeouts, and result/resource bounds.

The host bridge must be loopback-only, authenticated, path-confined to Wireclaw case data, and limited to approved native capabilities.

## Privacy

Raw captures and raw packet payloads remain local by default.

Cloud model adapters receive normalized troubleshooting evidence by default, not the PCAP itself. Do not log payloads, credentials, cookies, API keys, host-bridge secrets, or other extracted secrets.

Be precise in UI wording: if a cloud provider is enabled, do not claim that nothing leaves the machine. State that raw captures remain local by default while normalized evidence may be sent to the configured provider.

## Development sequence

Follow the gates in `specs/v1/tasks.md`.

Do not skip deterministic analyzer validation to start UI/LLM features early. The intended order is:

1. specification and contracts
2. safe deterministic analyzer foundation
3. TCP/DNS/TLS diagnostics
4. local API/case model
5. rules-only findings and ambiguity handling
6. UI
7. evidence-capture and Wireshark host integration
8. LLM-assisted iterative reasoning
9. Docker/cross-platform packaging
10. acceptance and hardening

## Testing

Use reproducible fixture captures and golden normalized evidence.

Test healthy and ambiguous cases, not just obvious faults. Important contrast tests include:
- high RTT vs server response delay
- packet loss vs reordering
- receive-window stall vs server think time
- DNS delay vs TCP connect delay
- MTU problem vs generic retransmission
- capture loss vs network loss

Every confirmed diagnostic defect should become a regression case.

Do not accept a model's natural-language answer as a test oracle. Test the deterministic evidence, capability choices, unsupported-claim rate, uncertainty behavior, and final contract.

## Change discipline

For each material change:

1. identify affected requirement IDs
2. decide whether product behavior changes
3. update spec/acceptance criteria first when it does
4. add or adjust tests
5. implement the smallest architecture-consistent change
6. validate security/privacy/cross-platform effects
7. document irreversible architecture choices in an ADR

Do not add speculative infrastructure for post-V1 ideas unless the current specification is intentionally amended.

## Completion standard

Do not report work complete unless:
- implementation matches the authoritative spec
- tests for changed behavior pass
- failure/uncertainty behavior is explicit
- sensitive information is not leaked to logs/providers
- Docker/local behavior remains reproducible
- cross-platform assumptions are preserved
- user-visible conclusions remain evidence-backed and independently verifiable in Wireshark
