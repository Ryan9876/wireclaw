# Wireclaw Project Instructions

These instructions apply to all repository work performed by humans or coding agents.

## 1. Authority order

When sources conflict, follow this order:

1. `specs/v1/constitution.md`
2. `specs/v1/requirements.md`
3. `specs/v1/solution.md`
4. accepted ADRs and `docs/`
5. `specs/v1/tasks.md`
6. tests
7. implementation

Do not preserve implementation behavior that contradicts a higher-authority source. Update the specification first when product behavior intentionally changes.

## 2. Core product contract

Wireclaw is a local-first network traffic investigator, not an autonomous shell agent and not a packet-prediction model.

- Deterministic tools establish packet facts.
- The reasoning layer requests bounded analysis operations and interprets normalized evidence.
- Never let an LLM emit arbitrary host or container shell commands for execution.
- Never treat LLM output as packet evidence.
- Every user-visible finding must be traceable to evidence.
- Distinguish `observed`, `derived`, `inferred`, and `unknown` information.
- Do not claim root cause when the capture cannot establish it.
- When evidence is insufficient, state what additional evidence would discriminate among remaining hypotheses.

## 3. Wireshark behavior is mandatory

For every packet-level finding where packet inspection is meaningful, always expose both actions:

1. **Open Full Capture in Wireshark**
2. **Open Evidence Capture in Wireshark**

Also expose the display filter and packet/stream evidence used by the finding.

Do not replace these with a preference, dropdown, or remembered default. Both actions remain visible.

The original capture is immutable. Evidence captures are derived artifacts.

## 4. Local-first and privacy boundaries

- The default deployment binds the application only to loopback.
- Do not add remote-listen behavior implicitly.
- Raw captures and payload bytes remain local by default.
- Cloud-model adapters receive normalized metadata/evidence by default, not the raw PCAP.
- Any future feature that transmits payload excerpts must be explicit, visible, bounded, and disabled by default.
- Never log packet payloads, API keys, model credentials, host-bridge tokens, or other secrets.
- Preserve an offline/rules-only analysis path where practical.

## 5. Execution safety

All external tool calls must use structured argument arrays and subprocess APIs without a shell.

Prohibited patterns include:

- `shell=True`
- `sh -c` / `bash -c` / `cmd /c` for analyzer execution
- concatenating untrusted strings into command lines
- arbitrary executable paths supplied by capture contents or model output

Tool execution must use an allowlisted capability layer. Validate and bound:

- input paths
- output paths
- capture size and extraction limits
- filter expressions
- packet counts
- time ranges
- execution time
- generated artifact size

Treat PCAP/PCAPNG and all tool output as untrusted input.

## 6. Host bridge boundary

The host bridge exists only for capabilities a container cannot safely perform, primarily launching the native Wireshark GUI.

It must:

- listen only on loopback when using HTTP
- authenticate requests
- accept logical case/artifact identifiers rather than arbitrary executable commands
- resolve files only beneath the configured Wireclaw data root
- launch only the configured Wireshark executable
- pass arguments directly, never through a shell
- validate display-filter length/content
- reject path traversal and unknown artifact IDs
- provide no general-purpose command-execution endpoint

## 7. Investigation behavior

Every investigation starts with capture-quality assessment before root-cause analysis.

The default investigation should consider, when evidence permits:

- capture completeness and capture location
- conversations/endpoints/protocols
- DNS timing/failure
- TCP establishment
- RTT
- retransmission/loss indicators
- out-of-order behavior
- receive-window constraints
- resets
- MSS/MTU/fragmentation indicators
- TLS handshake timing
- request-to-response/server-think timing
- throughput/goodput
- traffic asymmetry
- client/server/network fault-domain attribution

Do not interpret checksum-offload artifacts as network faults without validation.

## 8. Architecture boundaries

Keep these responsibilities separate:

- `apps/web`: presentation and user interaction
- `services/api`: case lifecycle, orchestration, persistence, provider adapters
- `services/analyzer`: deterministic packet analysis and normalized evidence generation
- `services/host-bridge`: native host integration only
- `contracts`: shared machine-readable schemas

The web UI must not invoke TShark/Zeek directly. The model adapter must not invoke processes directly. The host bridge must not become an alternate analyzer.

## 9. Preferred implementation stack

Unless the specification is deliberately amended:

- Web: TypeScript + React
- Local API/orchestrator: Python + FastAPI
- Analyzer: Python wrappers around pinned TShark/Wireshark CLI and Zeek versions
- Local metadata: SQLite
- Host bridge: Go, producing small cross-platform native binaries
- Packaging: Docker Compose for web/API/analyzer plus native host-bridge installers/launchers

Keep provider integrations behind interfaces. Support OpenAI-compatible cloud/local endpoints without coupling core analysis to one model vendor.

## 10. Tests are product evidence

For packet-analysis logic, prefer reproducible fixture captures with known expected observations.

Every analyzer feature should have:

- unit tests for parsers/derivations
- golden fixture tests for tool output normalization
- negative/ambiguous cases
- malformed/untrusted input cases
- regression tests for previously fixed diagnoses

A model-generated explanation is not a passing test. Test deterministic evidence and the contract presented to the reasoner.

## 11. Spec-first change process

Before implementing a material behavior change:

1. Identify the affected requirement(s).
2. Update the authoritative spec if behavior changes.
3. Add/adjust acceptance criteria.
4. Add or revise tests.
5. Implement the smallest change that satisfies the spec.
6. Validate cross-platform and security implications.
7. Record a new ADR for architecture choices that are difficult to reverse.

Do not implement speculative infrastructure for unapproved future phases.

## 12. Definition of done

A change is done only when:

- requirements and implementation agree
- tests pass
- failure behavior is explicit
- logs are useful but do not leak sensitive data
- documentation is updated
- Docker behavior is reproducible where relevant
- macOS, Windows, and Linux assumptions are not silently broken
- user-visible diagnoses identify their evidence and uncertainty

## 13. Communication style for generated UI/report text

Use concise engineering language. Lead with the finding, then evidence, confidence, impact, and next validation. Avoid false certainty, vague AI language, and unexplained protocol jargon.
