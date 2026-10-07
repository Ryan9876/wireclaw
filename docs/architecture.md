# Architecture Reference

This document is a contributor-oriented map of the V1 architecture. The authoritative behavior remains in `specs/v1/`.

## Components

### `apps/web`

Responsibilities:
- capture selection/drop UI
- symptom input
- investigation progress
- result/finding presentation
- Wireshark actions
- local configuration UI

Must not:
- execute analyzers
- construct shell commands
- read arbitrary host files
- call model providers directly

### `services/api`

Responsibilities:
- case lifecycle/state
- upload intake
- artifact registry
- persistence
- investigation orchestration
- capability authorization
- model-provider abstraction
- report assembly
- host-bridge launch-plan generation

This service is the primary trust boundary for the local application.

### `services/analyzer`

Responsibilities:
- deterministic tool invocation
- output parsing
- normalized evidence generation
- derived timing/transport calculations
- evidence-capture extraction

The analyzer exposes named typed capabilities, not general command execution.

### `services/host-bridge`

Responsibilities:
- run natively on host
- authenticate local launch requests
- resolve logical case artifacts beneath configured data root
- launch configured native Wireshark executable with approved capture/filter arguments

The bridge does not perform packet analysis and does not expose a generic process launcher.

### `contracts`

Responsibilities:
- shared schemas for evidence, findings, investigation state, artifacts, and bridge requests
- machine-readable boundary definitions used by tests

## Trust boundaries

```text
Untrusted
  capture file
  capture field strings
  symptom text
  analyzer stdout/stderr
  model output
      |
      v
Validation / normalization boundary
      |
      v
Trusted application state
      |
      +--> approved analyzer capabilities
      +--> approved persisted metadata
      +--> validated host-bridge launch plans
```

No untrusted string crosses directly into a shell command.

## Data classes

### Class A — Raw capture data

Includes original PCAP/PCAPNG and payload bytes.

Default: local only.

### Class B — Sensitive extracted values

Potential credentials, cookies, tokens, hostnames, URLs, query values, user data, or payload excerpts.

Default: local only; do not log.

### Class C — Normalized troubleshooting evidence

Examples:
- RTT
- retransmission counts/rates
- DNS response timing
- stream IDs
- packet/frame IDs
- TLS timing
- response wait timing
- endpoint metadata

May be sent to a configured model according to provider policy.

### Class D — Product metadata

Case IDs, timestamps, analyzer versions, statuses, configuration identifiers.

Persisted locally.

## Core invariant

A final finding can reference only evidence that exists in normalized application state. A language model may suggest a finding, but the report assembler must reject or downgrade claims whose evidence IDs do not exist or whose cited values contradict the evidence records.

## Cross-platform boundary

Containerized:
- web
- API/orchestrator
- analyzer
- SQLite/runtime application dependencies

Native host:
- Docker runtime
- Wireshark GUI
- Wireclaw host bridge
- launcher/install integration

This split preserves a consistent analyzer environment while retaining native Wireshark behavior.
