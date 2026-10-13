# Wireclaw V1 — Gate 7 Execution Specification

Status: **Subordinate execution specification**

This document defines the implementation contract for Gate 7. It is subordinate to, and must not contradict, `specs/v1/constitution.md`, `specs/v1/requirements.md`, `specs/v1/solution.md`, and accepted ADRs. When this document conflicts with a higher-authority source, the higher-authority source wins and this document must be corrected before implementation proceeds.

## 1. Gate objective

Gate 7 adds optional LLM-assisted hypothesis planning, evidence correlation, and bounded iterative investigation without weakening Wireclaw's deterministic evidence boundary.

The model is a reasoning component, never a packet analyzer and never a source of packet facts.

Gate 7 also closes the V1 planning gap for R-F011/R-F012 by implementing the deterministic `analyze_http_timing` capability named in the authoritative solution. This capability is required so Gate 9 can distinguish a genuinely decodable server/application-wait case from an opaque transport-only delay.

## 2. Requirements and tasks

Primary requirements:

- R-F011 Application timing
- R-F012 Time attribution
- R-F014 Hypothesis ranking
- R-F015 Insufficient-evidence outcome
- R-F016 Iterative investigation
- R-F024 Model-provider abstraction
- R-F026 Failure isolation
- R-S003 No shell interpolation
- R-S004 Bounded analyzer capabilities
- R-S005 Untrusted-capture handling
- R-S006 Raw-capture locality
- R-S007 Cloud-model data minimization
- R-S008 Secret handling
- R-N002 Resource bounds
- R-N004 Reproducible deterministic evidence
- R-N005 Auditability
- R-N006 Maintainability

Constitutional constraints include C2, C3, C5, C6, C9, C10, C11, C12, C13, and C14.

Gate tasks:

- G7.1 provider interface
- G7.2 OpenAI-compatible cloud adapter
- G7.3 OpenAI-compatible local adapter
- G7.4 prompt/context builder using normalized evidence
- G7.5 typed capability-request schema
- G7.6 investigation-step bounds/repetition detection
- G7.7 validate model-requested capabilities and parameters
- G7.8 hypothesis/finding proposal validation against evidence IDs
- G7.9 prevent unsupported model claims from entering final findings
- G7.10 provider timeout/failure fallback to deterministic report
- G7.11 prompt-injection/adversarial normalized-text fixtures
- G7.12 deterministic HTTP request/response timing capability for R-F011/R-F012

## 3. Non-negotiable architecture

The reasoner belongs in `services/api`, behind an interface.

It must not be implemented in:

- `apps/web`
- `services/analyzer`
- `services/host-bridge`

The model adapter may request named analyzer capabilities through the API/orchestrator. It must never invoke TShark, Zeek, Python subprocesses, Docker, the host bridge, or native applications directly.

Target logical structure:

```text
services/api/src/wireclaw_api/
├── providers/
│   ├── base.py
│   ├── models.py
│   └── openai_compatible.py
└── reasoning/
    ├── context.py
    ├── contracts.py
    ├── capabilities.py
    ├── loop.py
    ├── validation.py
    └── persistence.py
```

Equivalent organization is acceptable if responsibility boundaries remain equally clear.

## 4. Provider modes

V1 supports exactly these logical modes:

```text
none
openai_compatible_cloud
openai_compatible_local
```

`none` is the safe default.

Provider selection is startup/administrator configuration. A case investigation request must not be able to inject or switch provider base URLs, API keys, executable paths, or provider mode through arbitrary request fields.

The effective provider mode used by an investigation must be visible in case/report metadata and persisted sufficiently for auditability.

Gate 7 does not require a browser settings UI for provider configuration.

## 5. Provider configuration

The implementation may use environment/configuration names consistent with the existing project configuration style. The following logical fields are required:

```text
provider_mode
provider_base_url
provider_model
provider_timeout_seconds
provider_api_key
```

The API key is secret configuration. It must never be:

- written to SQLite
- written to case artifacts
- returned to the browser
- included in exception text
- included in structured logs
- included in model prompts

For `openai_compatible_cloud`, V1 must require an HTTPS provider URL. Cleartext non-loopback cloud endpoints are not allowed.

For `openai_compatible_local`, HTTP or HTTPS is permitted because local OpenAI-compatible servers commonly expose HTTP. Gate 8 defines same-host Docker access through `host.docker.internal`.

In V1, cloud and local provider modes receive the same minimized normalized-evidence context. Gate 7 does not introduce a broader raw-data policy for local models.

## 6. Provider interface

Define a narrow provider protocol. Conceptually:

```python
class ReasoningProvider(Protocol):
    def propose(self, request: ReasoningRequest) -> ProviderResult: ...
```

The provider returns one validated model response payload or a normalized provider failure. It must not expose an HTTP client, SDK object, arbitrary model messages, or vendor response objects to the investigation loop.

Provider-specific exceptions must be mapped to bounded internal failure codes such as:

```text
provider_unavailable
provider_timeout
provider_auth_failed
provider_response_too_large
provider_invalid_response
provider_protocol_error
```

Do not persist raw provider exception bodies.

## 7. OpenAI-compatible wire contract

Use the minimal OpenAI-compatible chat-completions subset for V1 so both cloud and common local servers can implement the same adapter.

Logical request:

```http
POST <provider-base>/chat/completions
Authorization: Bearer <secret>   # only when configured
Content-Type: application/json
```

Minimum body shape:

```json
{
  "model": "<configured-model>",
  "messages": [
    {"role": "system", "content": "<fixed Wireclaw reasoning contract>"},
    {"role": "user", "content": "<canonical normalized context JSON>"}
  ],
  "temperature": 0
}
```

Do not depend on vendor-specific tool execution, remote code execution, hosted file upload, assistants, or provider-side storage.

Do not require provider-side structured-output extensions for correctness. The returned assistant content must be parsed locally as strict JSON against Wireclaw's own schema.

HTTP redirects must not silently move a request to an unvalidated destination. Disable redirects by default or validate the destination under the same provider policy before following one.

## 8. Resource defaults

Unless a higher-authority configuration changes them, use these Gate 7 defaults:

```text
max_reasoning_steps = 8
provider_timeout_seconds = 60
max_provider_request_bytes = 131072
max_provider_response_bytes = 65536
max_reasoning_evidence_items = 200
max_identical_capability_request_count = 1
```

These are implementation defaults, not permission to exceed R-N002 bounds elsewhere.

Provider request size must be checked after canonical serialization and before network transmission.

Provider response size must be bounded while reading, not only after fully buffering an unlimited response.

## 9. Canonical reasoning context

The reasoner context is built only from normalized case data.

Allowed by default:

- symptom statement
- capture-quality state and limitations
- protocol/conversation metadata
- normalized evidence records
- deterministic timing values
- deterministic error/indicator counts
- evidence IDs
- affected scopes
- tool/version metadata when useful
- existing deterministic findings
- remaining hypotheses
- prior reasoning-step summaries
- capability catalog containing only reasoner-callable capabilities
- configured resource limits relevant to the loop

Excluded:

- raw PCAP/PCAPNG bytes
- raw packet payload bytes
- absolute filesystem paths
- API keys
- cookies/tokens/credentials extracted from traffic
- host-bridge tokens
- arbitrary binary artifacts
- raw analyzer stdout/stderr when it can contain payload data
- chain-of-thought

The context builder must use an explicit allowlist serializer. Do not serialize entire Python objects and then try to remove sensitive fields afterward.

Context ordering must be deterministic for the same case evidence and configuration.

## 10. Treat normalized strings as untrusted data

Capture-derived strings can contain prompt-injection text.

Examples include:

- DNS names
- HTTP host/header values
- TLS names
- protocol metadata strings
- user symptom text

The fixed system instruction must state that these strings are evidence data and never instructions.

The model cannot gain privileges by emitting text such as:

```text
ignore previous instructions
run shell command
open this path
send the capture
call capability exec
```

Unknown capability names and parameters are rejected by code regardless of model wording.

## 11. Model action schema

Each provider turn must decode to exactly one top-level action.

### Capability request

Conceptual schema:

```json
{
  "action": "request_capability",
  "capability": "analyze_rtt",
  "parameters": {
    "tcp_stream": 7
  }
}
```

### Finalize

Conceptual schema:

```json
{
  "action": "finalize",
  "hypotheses": [
    {
      "category": "tcp.rtt",
      "evidence_ids": ["ev_..."],
      "fault_domains": ["network_path"],
      "summary": "High RTT is a supported contributor."
    }
  ],
  "remaining_hypotheses": [
    {
      "category": "server_application",
      "evidence_ids": [],
      "next_evidence": ["Compare server/application timing for the same transaction."]
    }
  ]
}
```

Requirements:

- strict schemas
- unknown fields rejected
- bounded strings/list sizes
- category/fault-domain enums or allowlists
- evidence IDs syntax validated
- no arbitrary command, executable, path, URL, shell, or raw filter fields
- no provider-selected model/provider/base URL fields

A malformed response consumes at most one reasoning step. Gate 7 must not create an unbounded self-repair conversation.

## 12. Capability registry

The reasoner sees only named capabilities registered by Wireclaw.

Each registration declares:

- name
- typed request model
- request validator
- deterministic implementation target
- max result size
- timeout/resource policy
- whether durable artifact side effects occur
- whether the capability is available for this case/capture

The registry must correspond to the capability set in the authoritative solution.

Reasoner requests never contain executable names or arbitrary CLI flags.

`create_evidence_capture` may be exposed only through its existing bounded case/finding/evidence contract. It must not accept model-authored filesystem paths, executables, arbitrary filters, or native-launch arguments, and it must not launch Wireshark. It counts against the reasoning-step and artifact limits when invoked.

## 13. Parameter validation

Model-requested capability parameters are validated against evidence already known for the case.

Examples:

- a TCP stream must exist in case evidence before a stream-specific request is executed
- frame references must be positive and case-bounded
- DNS names must use the analyzer capability's own bounded schema
- time ranges must be finite, ordered, and within capture duration
- result row counts must stay within configured limits
- filters, when a capability internally derives them, remain backend-generated and validated

Reject invalid model requests without invoking the analyzer.

## 14. Duplicate-request detection

After validation, build a canonical request fingerprint:

```text
SHA-256(
  capability name
  + canonical JSON(validated parameters)
)
```

The default maximum execution count for an identical fingerprint is one.

A repeated identical request must not re-run the analyzer merely because the model asks again. Return the already persisted evidence/result reference to the loop or stop with a bounded repetition reason.

Materially different validated parameters produce a different fingerprint.

## 15. Investigation loop

The loop is deterministic around the provider.

Conceptual state flow:

```text
BASELINE_AVAILABLE
  -> BUILD_CONTEXT
  -> PROVIDER_REQUEST
  -> PARSE_ACTION
  -> VALIDATE_ACTION

request_capability:
  -> DUPLICATE_CHECK
  -> EXECUTE_TYPED_CAPABILITY
  -> NORMALIZE/PERSIST EVIDENCE
  -> PERSIST STEP
  -> BUILD_CONTEXT

finalize:
  -> VALIDATE PROPOSALS
  -> ASSEMBLE REPORT
  -> PERSIST STEP
  -> COMPLETE

failure/bound:
  -> RECORD LIMITATION
  -> FALL BACK TO DETERMINISTIC REPORT
```

No transition allows provider text to mutate evidence directly.

## 16. Step accounting and stop conditions

One accepted provider action equals one reasoning step.

Stop reasoning when any of these occurs:

- provider returns `finalize`
- `max_reasoning_steps` reached
- provider timeout/unavailability/auth failure
- provider response exceeds bound
- malformed response
- unsupported/invalid capability request that cannot safely continue
- identical-request repetition would exceed the limit
- analyzer failure leaves no meaningful next reasoning step

Stopping the reasoner must never delete or suppress existing deterministic findings.

## 17. Proposal validation

Provider proposals are not findings until validated.

For every proposed hypothesis/finding:

- category must be recognized
- every cited evidence ID must exist in the same case
- cited evidence must be `observed` or `derived`, never provider-generated
- affected scope must be consistent with cited evidence
- fault domains must use the existing contract values
- capture-quality limitations must remain visible
- unsupported material claims must not be copied into the final report

Preferred V1 pattern:

```text
provider chooses/ranks category + cites evidence IDs
        ↓
category-specific deterministic validator checks support
        ↓
report assembler creates/updates the authoritative finding
```

A provider's free-form `summary` is explanatory text only. It must not introduce packet facts that are absent from cited normalized evidence.

Confidence remains a Wireclaw policy decision based on evidence sufficiency and ambiguity, not model self-reported certainty.

## 18. Deterministic finding preservation

Model assistance is additive.

The reasoning layer must not:

- remove a deterministic supported finding because the model omitted it
- lower a deterministic capture-quality limitation because the model disagrees
- convert `unknown` into observed fact
- replace evidence IDs with invented IDs
- rewrite deterministic values into materially different numbers

The final report may include additional validated inferred findings, reordered hypotheses, or better next-evidence recommendations, but deterministic evidence remains authoritative.

## 19. Insufficient evidence

If no validated model-assisted finding reaches the minimum confidence threshold, use the existing `insufficient_evidence` contract.

Provider activity must not force a root cause.

Remaining hypotheses and next evidence must still be presented.

## 20. Provider failure behavior

Provider failure is optional-component failure under R-F026/C12.

When the provider fails:

- preserve all deterministic evidence
- preserve deterministic findings/report capability
- record a bounded provider failure/limitation
- mark reasoning mode/status accurately
- do not mark the whole case corrupt solely because optional reasoning failed

The user must still receive the deterministic rules-only result.

## 21. Reasoning metadata

Reports/cases should expose enough metadata to distinguish:

```text
rules_only
model_assisted
model_fallback
```

Exact contract naming may differ, but the UI/report must not imply model assistance occurred when it did not.

The browser may display provider mode/model identifier where useful, but must never receive credentials.

## 22. Investigation-step persistence

Persist enough metadata to audit each reasoning action without persisting chain-of-thought or raw sensitive prompts.

Each step should include:

- step ID
- case ID
- sequence number
- timestamp
- provider mode
- model identifier
- endpoint classification (`cloud`/`local`/`none`), not credentials
- canonical context digest
- action type
- capability name when applicable
- validated safe parameters or their bounded normalized representation
- request fingerprint
- resulting evidence IDs
- status
- bounded failure code
- duration

Do not persist:

- API key
- Authorization header
- chain-of-thought
- raw PCAP/payload
- unbounded raw provider request/response bodies

## 23. Deterministic application timing capability

Gate 7 must implement the solution's named `analyze_http_timing` capability to satisfy the V1 planning gap for R-F011/R-F012.

### Minimum V1 scope

Support decodable HTTP/1.x request/response transactions when TShark can deterministically correlate them.

For each supported transaction, normalize where observable:

- request frame range
- request completion time
- first response frame/time
- request-to-first-response interval
- response transfer start/end interval when determinable
- TCP stream / endpoints
- frame references
- display filter
- limitations

The capability must not label a generic TCP silence interval as application wait without decodable request/response semantics.

Encrypted HTTPS without decryption remains transport/TLS-only unless application semantics are deterministically visible through another approved capability.

### Positive fixture

Add a valid plaintext HTTP fixture, e.g. `http_server_wait`, with a complete request and delayed response. The deterministic expected value must include an approximately two-second request-to-first-response interval constructed by the fixture generator.

### Negative fixture

Keep the existing opaque `server_wait` transport fixture as an epistemic-boundary regression. A two-second gap in generic TCP traffic without decodable request/response semantics must not be promoted to a server/application finding solely from silence.

### Finding/time-attribution integration

For the positive HTTP fixture, Wireclaw must be able to produce a measured application/server-wait timing segment and a supported inferred finding when the evidence warrants it.

The finding may identify the server/application boundary while still stating that the capture cannot distinguish the observed server endpoint from a downstream dependency behind it.

## 24. Privacy verification

Create a controlled fake cloud provider that captures the exact HTTP request body generated by Wireclaw.

Use sentinel values in fixture/case data representing:

- raw packet payload bytes
- credential/token-like strings
- absolute case path
- host-bridge token-like data

Assert the cloud request contains only allowed normalized context and excludes forbidden sentinels.

Do not claim that the entire operating system or Docker engine made zero network traffic. Gate 7 privacy acceptance is specifically about Wireclaw provider request content and destinations under test control.

## 25. Adversarial model tests

Use a deterministic fake provider, not a real model, for contract/security tests.

Required scripted scenarios:

1. valid capability request
2. valid finalize action
3. unsupported capability
4. invalid parameters
5. duplicate identical capability request
6. fabricated evidence ID
7. malformed JSON
8. unknown fields
9. oversized response
10. provider timeout
11. provider connection failure
12. prompt-injection text inside normalized capture fields
13. provider prose containing an unsupported packet fact
14. request to execute shell/host command
15. request to access an arbitrary path or launch Wireshark

The implementation must reject unsafe actions in code, not rely on the model to follow instructions.

## 26. Test mapping

### G7.1 provider interface

- provider protocol unit tests
- normalized error mapping
- no provider implementation imported by analyzer/bridge

### G7.2 cloud adapter

- exact bounded HTTP request
- HTTPS requirement
- auth header handling without logging/persistence
- redirect policy
- request/response size limits

### G7.3 local adapter

- same provider interface
- HTTP localhost-compatible endpoint
- no broadened raw-data policy

### G7.4 context builder

- deterministic ordering
- allowlist serialization
- raw payload/path/secret sentinels excluded
- prompt-injection strings retained as data, not instructions

### G7.5 contracts

- strict union action schema
- unknown fields rejected
- bounded strings/lists

### G7.6 bounds/repetition

- max steps
- canonical duplicate fingerprint
- duplicate does not rerun analyzer

### G7.7 capability validation

- unknown capability
- invalid stream/frame/time/name
- capability unavailable for current case

### G7.8/G7.9 proposal safety

- fabricated evidence rejected
- cross-case evidence rejected
- unsupported claim never becomes final finding
- deterministic finding survives model omission/disagreement

### G7.10 fallback

- timeout
- auth failure
- malformed/oversized response
- provider offline
- deterministic report remains available

### G7.11 injection

- adversarial normalized strings cannot select arbitrary capability, shell, path, executable, URL, or host action

### G7.12 HTTP timing

- positive valid HTTP delayed-response fixture
- opaque TCP delay negative fixture
- encrypted/unsupported visibility limitation
- measured timing and frame references reproducible

## 27. Integration acceptance scenarios

Gate 7 integration tests must include:

### Rules-only

`provider_mode=none` produces the existing deterministic result with no provider request.

### Useful iterative reasoning

Scripted provider requests one valid capability, receives new deterministic evidence, then finalizes with existing evidence IDs.

### Duplicate request

Provider asks for the exact same validated capability twice. Analyzer runs once.

### Fabricated evidence

Provider finalizes with a nonexistent evidence ID. Proposal is rejected; no fabricated finding appears.

### Provider outage

Provider fails after deterministic baseline. Case/report remains useful in deterministic fallback mode.

### Privacy

Fake cloud endpoint confirms raw payload/capture/path/credential sentinels were not transmitted.

### Prompt injection

Capture-derived normalized text attempts to override system instructions. Only typed allowlisted actions can execute.

### HTTP server wait

A decodable HTTP delayed-response fixture produces measured request-to-first-response timing, while the opaque transport-only `server_wait` case does not acquire false application semantics.

## 28. Validation commands

Run the complete repository suite plus Gate 7-specific tests.

At minimum:

```bash
python -m pytest -q
ruff check .
ruff format --check services scripts tests
python -m compileall -q services scripts tests
python scripts/validate_gate3.py
```

Also run the existing Go and web suites so Gate 7 does not regress Gates 0–6.

No Gate 7 test may require a paid/real cloud model for deterministic CI correctness. Real-provider smoke testing may be optional and separately configured.

## 29. Verification record

Create `docs/gate7-verification.md` containing:

- validated commit SHA
- requirements/task matrix G7.1–G7.12
- provider modes tested
- fake-provider scenarios
- privacy inspection result
- deterministic fallback result
- HTTP timing positive/negative results
- full regression counts
- known limitations

Do not mark a task complete without implementation and test evidence.

## 30. Gate 7 exit criteria

Gate 7 is complete only when all are true:

1. provider abstraction supports `none`, OpenAI-compatible cloud, and OpenAI-compatible local modes;
2. provider configuration is administrator/startup-controlled, not arbitrary investigation input;
3. cloud requests contain normalized allowlisted context only;
4. raw capture/payload/credentials are excluded by default;
5. the reasoner can deepen investigation only through typed registered capabilities;
6. capability parameters are validated before analyzer execution;
7. identical repeated requests do not rerun the analyzer;
8. reasoning steps and provider request/response sizes are bounded;
9. provider failures preserve deterministic results;
10. provider output cannot create or mutate evidence records;
11. fabricated/unsupported claims cannot enter authoritative findings;
12. deterministic findings cannot be suppressed by model disagreement;
13. capture-derived prompt-injection text cannot escape the typed action boundary;
14. reasoning audit metadata is persisted without secrets or chain-of-thought;
15. `analyze_http_timing` deterministically handles the supported plaintext HTTP scope;
16. a decodable HTTP server-wait case is distinguished from an opaque TCP-silence case;
17. rules-only operation remains fully usable;
18. all prior Gate regressions remain green;
19. Gate 7 verification documents the exact validated SHA and evidence;
20. Gate 8 implementation has not been started before Gate 7 is accepted.
