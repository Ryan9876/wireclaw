# Wireclaw Project Instructions

These instructions apply to all repository work performed by humans or coding agents.

## 1. Authority order

When sources conflict, follow this order:

1. `specs/v1/constitution.md`
2. `specs/v1/requirements.md`
3. `specs/v1/solution.md`
4. accepted ADRs
5. accepted post-V1 feature specifications and gate-specific execution/acceptance specifications
6. accepted `docs/` guidance and implementation plans
7. `specs/v1/tasks.md` for V1 work
8. tests
9. implementation

Gate-specific execution/acceptance specifications are subordinate to the constitution, requirements, solution, and accepted ADRs. They make an already-approved gate concrete; they may not silently weaken or redefine higher-authority behavior.

Post-V1 specifications may extend V1-only exact sets or packaging behavior only for the post-V1 product. They must preserve the V1 constitution and applicable evidence, privacy, uncertainty, execution-safety, immutability, and native-Wireshark contracts unless a higher-authority source is deliberately revised first. Post-V1 work must not rewrite the frozen V1 acceptance record as though the new feature existed in V1.

Before implementing Gates 7–9, agents **must** read the corresponding specification in addition to all higher-authority sources:

- Gate 7: `specs/v1/gate7-execution.md`
- Gate 8: `specs/v1/gate8-execution.md`
- Gate 9: `specs/v1/gate9-acceptance.md`

For V1 platform scope also read:

- `docs/decisions/ADR-0006-macos-first-v1-platform-scope.md`
- `docs/roadmap.md`

Before implementing the post-V1 embedded-local-AI stage, agents **must** also read:

- `specs/post-v1/README.md`
- `specs/post-v1/embedded-local-ai.md`
- `docs/decisions/ADR-0007-embedded-local-ai-native-runtime.md`
- `specs/v1/gate7-execution.md` for the existing reasoning boundary
- `docs/v1-acceptance.md` so V1 evidence is not accidentally reinterpreted

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
- Embedded/local models do not get broader raw-data access merely because inference occurs on the same machine.
- Any future feature that transmits payload excerpts must be explicit, visible, bounded, and disabled by default.
- Never log packet payloads, API keys, model credentials, embedded-AI tokens, host-bridge tokens, or other secrets.
- Preserve an offline/rules-only analysis path where practical and where the governing spec requires it.

## 5. Execution safety

All external tool calls must use structured argument arrays and subprocess APIs without a shell when implemented in application code.

Prohibited patterns include:

- `shell=True`
- `sh -c` / `bash -c` / `cmd /c` for analyzer/runtime execution from application code
- concatenating untrusted strings into command lines
- arbitrary executable paths supplied by capture contents or model output

Existing platform launch scripts may invoke fixed packaged executables directly, but must not use `eval`, source untrusted configuration, or convert browser/capture/model input into executable names or free-form flags.

Tool execution must use an allowlisted capability layer. Validate and bound:

- input paths
- output paths
- capture size and extraction limits
- filter expressions
- packet counts
- time ranges
- execution time
- generated artifact size
- embedded-AI model/runtime paths and arguments when that feature is in scope

Treat PCAP/PCAPNG and all tool/model output as untrusted input.

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

The embedded-AI runtime is a separate trust boundary. Do not add model inference, model file access, or arbitrary proxy behavior to the host bridge.

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
- `services/host-bridge`: native Wireshark integration only
- `ai/` or equivalent release/runtime area defined by the post-V1 spec: packaged model/runtime manifests, assets, and platform-specific inference runtime only
- `contracts`: shared machine-readable schemas

The web UI must not invoke TShark/Zeek directly. The model adapter must not invoke analyzer or arbitrary host processes directly. The embedded-AI runtime must not become an alternate analyzer or general tool agent. The host bridge must not become an alternate analyzer or model proxy.

## 9. Preferred implementation stack

Unless the specification is deliberately amended:

- Web: TypeScript + React
- Local API/orchestrator: Python + FastAPI
- Analyzer: Python wrappers around pinned TShark/Wireshark CLI and Zeek versions
- Local metadata: SQLite
- Host bridge: Go, producing small native binaries
- V1 packaging: Docker Compose for web/API/analyzer plus a native host bridge/launcher for the supported release platform
- Post-V1 embedded AI on macOS arm64: pinned native llama.cpp runtime + pinned Q4_K_M model packaged with the release and reached through the existing provider boundary

Keep provider integrations behind interfaces. Support OpenAI-compatible cloud/local endpoints without coupling core deterministic analysis to one model vendor.

V1 is release-qualified on macOS. Windows/Linux code and CI may remain as portability groundwork, but they are not V1 release blockers or support claims unless the authoritative specification is changed. Post-V1 embedded-AI qualification is also macOS arm64 first unless its specification is changed.

## 10. Tests are product evidence

For packet-analysis logic, prefer reproducible fixture captures with known expected observations.

Every analyzer feature should have:

- unit tests for parsers/derivations
- golden fixture tests for tool output normalization
- negative/ambiguous cases
- malformed/untrusted input cases
- regression tests for previously fixed diagnoses

A model-generated explanation is not a passing test. Test deterministic evidence and the contract presented to the reasoner.

For embedded-AI work, additionally test model/runtime integrity, process isolation, provider authentication, prompt-injection resistance, invalid evidence/capability rejection, deterministic fallback, resource bounds, and rules-only versus AI-assisted behavior over a versioned corpus. Do not use fluent prose alone as acceptance evidence.

## 11. Spec-first change process

Before implementing a material behavior change:

1. Identify the affected requirement(s).
2. Update the authoritative spec if behavior changes.
3. Add/adjust acceptance criteria.
4. Add or revise tests.
5. Implement the smallest change that satisfies the spec.
6. Validate platform and security implications.
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
- macOS V1 behavior is not silently broken
- deferred Windows/Linux portability groundwork is not accidentally broken where tests already cover it
- user-visible diagnoses identify their evidence and uncertainty
- when embedded AI is in scope, model/runtime provenance, integrity, local-only exposure, deterministic fallback, and native package behavior satisfy the post-V1 acceptance spec

## 13. Communication style for generated UI/report text

Use concise engineering language. Lead with the finding, then evidence, confidence, impact, and next validation. Avoid false certainty, vague AI language, and unexplained protocol jargon.
