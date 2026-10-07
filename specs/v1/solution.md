# Wireclaw V1 Solution Design

Status: **Authoritative V1 solution design**

This document translates the constitution and requirements into an implementable architecture.

## 1. System goal

Wireclaw is a localhost troubleshooting application that accepts a PCAP/PCAPNG and a symptom statement, performs deterministic packet analysis, iteratively requests additional bounded evidence, and produces an explainable investigation result.

The design intentionally separates:

- packet fact extraction
- investigation orchestration
- model reasoning
- presentation
- native host integration

## 2. V1 technology choices

### Web UI

- React
- TypeScript
- browser served from the local application

### Local API / orchestrator

- Python
- FastAPI
- Pydantic models for contracts
- SQLite for local case metadata

### Analyzer

- Python capability wrappers around pinned versions of:
  - TShark
  - capinfos
  - editcap
  - mergecap when needed
  - Zeek
- no shell invocation
- structured subprocess arguments only

### Host bridge

- Go
- native small binary per supported OS
- loopback-only authenticated interface
- initial responsibility: launch native Wireshark with an approved case artifact and display filter

### Packaging

- Docker Compose for web/API/analyzer
- bind-mounted local data directory for captures, evidence, and reports
- platform-specific launcher/installer for the host bridge

### Model abstraction

Provider-neutral reasoning interface supporting:

1. OpenAI-compatible cloud endpoint
2. OpenAI-compatible local endpoint
3. rules-only/no-model mode

Core analysis shall not require a particular model vendor.

## 3. Logical architecture

```text
+---------------------------+
| Browser                   |
| React / TypeScript        |
+-------------+-------------+
              |
              | localhost HTTP
              v
+---------------------------+
| API / Orchestrator        |
| FastAPI                   |
|                           |
| - case lifecycle          |
| - investigation state     |
| - analyzer capability API |
| - evidence normalization  |
| - model adapter           |
| - report assembly         |
| - SQLite metadata         |
+------+-------------+------+
       |             |
       |             +-----------------------+
       |                                     |
       v                                     v
+----------------------+          +----------------------+
| Analyzer             |          | Reasoning provider   |
|                      |          |                      |
| TShark               |          | Cloud/local/none     |
| capinfos             |          | normalized evidence  |
| editcap              |          | only by default      |
| Zeek                 |          +----------------------+
| Python derivations   |
+----------+-----------+
           |
           v
+---------------------------+
| Local case artifacts      |
| original/ evidence/ logs/ |
+-------------+-------------+
              |
              | logical artifact ID
              v
+---------------------------+
| Host bridge               |
| Go / loopback / auth      |
+-------------+-------------+
              |
              v
+---------------------------+
| Native Wireshark GUI      |
+---------------------------+
```

## 4. Repository architecture

```text
wireclaw/
├── AGENTS.md
├── README.md
├── .github/
│   └── copilot-instructions.md
├── apps/
│   └── web/
├── services/
│   ├── api/
│   ├── analyzer/
│   └── host-bridge/
├── contracts/
├── specs/
│   └── v1/
├── docs/
│   └── decisions/
├── tests/
│   ├── fixtures/
│   ├── golden/
│   ├── integration/
│   └── acceptance/
├── scripts/
└── data/                 # runtime only; gitignored
```

## 5. Case lifecycle

A case is the unit of investigation.

State machine:

```text
NEW
 -> INGESTING
 -> VALIDATING_CAPTURE
 -> BASELINE_ANALYSIS
 -> INVESTIGATING
 -> ASSEMBLING_REPORT
 -> COMPLETE

Any active state may transition to FAILED while preserving prior evidence.
A COMPLETE or FAILED case may be re-run using preserved immutable input.
```

A case contains:

- case ID
- creation/update timestamps
- symptom statement
- original capture artifact ID
- original capture hash
- capture metadata
- analyzer versions
- capture-quality assessment
- normalized evidence items
- investigation steps
- hypotheses/findings
- report
- derived evidence-capture artifacts
- failures/limitations

## 6. Runtime data layout

Example host-side data root:

```text
data/
└── cases/
    └── <case-id>/
        ├── original/
        │   └── capture.pcapng
        ├── evidence/
        │   ├── finding-001.pcapng
        │   └── stream-37.pcapng
        ├── normalized/
        │   ├── capture-summary.json
        │   ├── conversations.json
        │   └── evidence.jsonl
        ├── reports/
        │   └── report.json
        └── work/
```

The original capture is never modified after ingest.

## 7. Evidence model

Every normalized evidence item has:

- stable evidence ID
- category
- epistemic class: `observed` or `derived`
- source capability
- source tool and version
- scope: capture / endpoint / conversation / stream / transaction / packet range
- machine-readable value(s)
- human-readable summary
- packet/frame references when applicable
- optional Wireshark display filter
- limitations

Example:

```json
{
  "id": "ev_tcp_retx_stream37",
  "category": "tcp.retransmission_rate",
  "epistemic_class": "derived",
  "source": {
    "capability": "inspect_tcp_stream",
    "tool": "tshark",
    "version": "<recorded-at-runtime>"
  },
  "scope": {"tcp_stream": 37},
  "value": {"retransmissions": 31, "data_packets": 642, "rate": 0.0483},
  "display_filter": "tcp.stream == 37 && tcp.analysis.retransmission",
  "frame_refs": [1201, 1238, 1244],
  "limitations": []
}
```

Findings reference evidence IDs; they do not duplicate unverifiable facts.

## 8. Analyzer capability layer

The reasoner cannot call executables. It may request only named capabilities with typed parameters.

Initial capability set:

### Capture-level

- `get_capture_metadata`
- `assess_capture_quality`
- `list_endpoints`
- `list_protocols`
- `list_conversations`
- `get_io_profile`

### DNS

- `analyze_dns`
- `inspect_dns_name`

### TCP

- `inspect_tcp_stream`
- `analyze_tcp_establishment`
- `analyze_tcp_health`
- `analyze_tcp_resets`
- `analyze_window_behavior`
- `analyze_rtt`
- `analyze_throughput`

### MTU / packet sizing

- `analyze_mss`
- `analyze_fragmentation`
- `analyze_pmtud_signals`

### TLS

- `analyze_tls_handshakes`
- `inspect_tls_conversation`

### Application timing

- `analyze_http_timing`
- future protocol-specific timing adapters as supported by available dissectors

### Evidence extraction

- `get_packet_evidence`
- `create_evidence_capture`

Each capability defines:

- typed request schema
- validation rules
- maximum result size
- timeout
- deterministic normalized response schema
- supported display-filter generation

## 9. TShark execution pattern

The analyzer builds argument arrays internally. Example conceptual invocation:

```python
[
    "tshark",
    "-r", approved_capture_path,
    "-Y", validated_filter,
    "-T", "fields",
    "-e", "frame.number",
    "-e", "frame.time_relative",
    "-e", "tcp.stream"
]
```

No shell parses this command. Model output never supplies executable names or arbitrary CLI flags.

## 10. Baseline investigation sequence

Every case runs a deterministic baseline before optional reasoning:

1. capture metadata/hash
2. capture-quality assessment
3. protocol inventory
4. endpoint inventory
5. conversation inventory
6. TCP expert-signal summary
7. DNS summary when present
8. TLS summary when present
9. obvious resets/failures
10. candidate conversation ranking

This makes Wireclaw useful even without an LLM.

## 11. Reasoning loop

After baseline evidence is available:

```text
symptom + normalized baseline evidence
             |
             v
      hypothesis planner
             |
      structured capability request
             |
             v
      deterministic analyzer
             |
             v
       normalized evidence
             |
             +----> repeat within bounds
             |
             v
     conclusion/report builder
```

Boundaries:

- max investigation steps configurable
- max identical request repetition = 1 unless parameters differ materially
- max returned evidence per step bounded
- analyzer timeout enforced
- provider timeout enforced
- reasoner cannot mutate files or launch applications

## 12. "Slow" investigation strategy

For a symptom containing slowness/latency/performance semantics, the investigation should attempt to answer:

1. Is DNS contributing material delay?
2. Is TCP establishment delayed or failing?
3. Is TLS establishment delayed or retrying?
4. Is RTT high relative to observed path behavior?
5. Is packet loss/retransmission materially affecting transfer time?
6. Is the receiver constraining throughput?
7. Are resets/reconnects increasing perceived delay?
8. Do MTU/MSS/fragmentation signals support a path-MTU problem?
9. For decodable transactions, how long from request completion to first response byte?
10. How much time is transfer versus pre-transfer waiting?
11. Does the evidence support client, network, server/application, DNS, or unknown fault domain?

### Time attribution model

When measurable:

```text
Total user-visible transaction interval
├── DNS
├── TCP establish
├── TLS establish
├── request transmit
├── server/application wait
├── response transfer
└── retransmission/transport penalty (reported as contributing evidence)
```

Do not double-count overlapping intervals. If categories cannot be separated from the capture, report them as unknown/combined.

## 13. Finding contract

A finding contains:

- ID
- title
- category
- severity/impact
- confidence: high / medium / low
- epistemic class: inferred
- statement
- affected scope
- evidence IDs
- display filter when applicable
- alternate explanations
- limitations
- recommended validation
- Wireshark action availability

Example:

```json
{
  "id": "finding_001",
  "title": "Server-side response delay dominates transaction time",
  "confidence": "high",
  "statement": "The server acknowledges client traffic promptly but application response data begins 2.56 seconds later.",
  "evidence_ids": ["ev_req_end", "ev_first_response", "ev_rtt"],
  "alternate_explanations": ["Delay may occur in a downstream dependency behind the observed server."],
  "recommended_validation": ["Compare application/load-balancer/backend timing for the same transaction."],
  "wireshark": {
    "full_capture": true,
    "evidence_capture": true,
    "display_filter": "tcp.stream == 37"
  }
}
```

## 14. Confidence policy

Confidence is based on evidence sufficiency, agreement, and diagnostic specificity—not model self-reported certainty.

### High

- direct/derived evidence strongly supports the finding
- material alternate explanations are either contradicted or require a fault behind the same identified boundary

### Medium

- evidence supports the finding but one or more plausible alternatives remain

### Low

- suggestive evidence exists but the capture cannot establish the boundary/root cause

If no supported finding reaches the product's minimum threshold, use `insufficient_evidence`.

## 15. Wireshark integration

### Full capture action

The UI sends a logical request containing:

- case ID
- original artifact ID
- approved display filter

The host bridge resolves the logical artifact to a path under its configured host data root and launches:

```text
Wireshark -r <resolved-original-capture> -Y <validated-display-filter>
```

### Evidence capture action

If not already materialized, the analyzer creates a derived PCAPNG using a bounded selected packet set/stream/time range. The UI then requests the host bridge to open that artifact.

### Host bridge security

- loopback only
- authenticated request
- strict origin/CORS policy if HTTP is used
- logical artifact identifiers preferred over caller-supplied paths
- path confinement to Wireclaw data root
- executable allowlist containing only configured Wireshark path in V1
- no shell
- no generic command arguments

## 16. Evidence-capture policy

Evidence captures should be minimal enough for focused review but complete enough to preserve necessary protocol context.

Extraction modes may include:

- complete TCP stream
- conversation 5-tuple
- DNS transaction set
- bounded time window around anomaly
- explicit frame set plus required context

The generated artifact records:

- parent capture hash
- extraction rule
- display filter
- creation timestamp
- related finding/evidence IDs

## 17. Model data policy

Default cloud-provider payload:

- symptom statement
- protocol/conversation metadata
- normalized timing/error evidence
- bounded tool summaries
- evidence IDs and limitations

Excluded by default:

- raw PCAP file
- raw packet payload bytes
- extracted credentials/tokens/cookies
- arbitrary binary objects

Local model providers may be configured under a future broader local-data policy, but analyzers still remain deterministic.

## 18. API boundary

Initial logical API resources:

- `POST /api/cases`
- `POST /api/cases/{id}/capture`
- `POST /api/cases/{id}/investigate`
- `GET /api/cases/{id}`
- `GET /api/cases/{id}/findings`
- `GET /api/cases/{id}/evidence/{evidence_id}`
- `POST /api/cases/{id}/artifacts/evidence-capture`
- `DELETE /api/cases/{id}`
- `GET /api/health`
- `GET /api/config/capabilities`

Exact OpenAPI definitions are implementation tasks; these paths define intended resource boundaries, not final wire compatibility.

## 19. Persistence

SQLite stores metadata, not packet blobs.

Capture/evidence files remain on disk in the case data root. Database rows reference logical artifact IDs and relative paths.

Database should store:

- cases
- artifacts
- analyzer runs
- evidence records/index
- findings
- investigation steps
- configuration metadata needed for reproducibility

## 20. Logging and observability

Structured application logs should include:

- case ID
- component
- capability name
- duration
- status
- bounded error detail

Logs must not contain:

- packet payloads
- credentials
- model API keys
- host-bridge auth secret
- raw model prompts if they may contain sensitive evidence unless explicit debug policy is enabled

## 21. Resource controls

Configurable limits include:

- max uploaded capture size
- max concurrent cases
- max analyzer subprocess duration
- max query result rows
- max evidence-capture size
- max investigation steps
- max model prompt/evidence size
- max generated report size

Large captures should first be summarized/indexed and then queried selectively.

## 22. Failure behavior

### Analyzer capability failure

- preserve prior evidence
- record failed capability and reason
- continue if remaining analysis is meaningful
- lower confidence when material

### Model provider unavailable

- deterministic baseline remains available
- rules-only findings/report are shown
- user may retry reasoning later

### Host bridge unavailable

- report remains usable
- Wireshark buttons visibly indicate bridge unavailable
- display filter remains copyable
- evidence capture may still be generated/downloadable locally

### Unsupported/encrypted protocol

- report observable metadata/timing
- state payload visibility limitation
- do not imply application semantics that cannot be observed

## 23. V1 UI structure

### Intake

- drag/drop or choose capture
- symptom text area
- Investigate action
- local/privacy indicator

### Investigation progress

Show meaningful stages, not model chain-of-thought:

- validating capture
- inventorying conversations
- analyzing transport health
- analyzing DNS/TLS/application timing
- testing hypotheses
- assembling report

### Results

Top section:

- primary conclusion
- confidence
- fault-domain assessment
- capture-quality state
- time-attribution summary when available

Finding cards:

- finding
- evidence summary
- confidence
- affected flow
- limitations/alternate explanations
- next validation
- Open Full Capture in Wireshark
- Open Evidence Capture in Wireshark
- Copy Display Filter
- Show Packet Evidence

### Expert evidence drawer

- evidence IDs
- frame numbers
- stream IDs
- tool/version
- normalized values
- bounded raw tool excerpt where safe/useful

## 24. Release architecture

Target V1 distribution:

```text
wireclaw-release/
├── compose.yaml
├── .env.example
├── launch/
│   ├── macos/
│   ├── windows/
│   └── linux/
├── host-bridge/
│   ├── macos/
│   ├── windows/
│   └── linux/
└── README.md
```

The user experience should be:

1. install Docker/Desktop-compatible runtime
2. install Wireshark
3. run platform launcher/installer
4. open Wireclaw localhost UI
5. investigate captures

## 25. Architectural decisions intentionally deferred

These should not block V1 scaffolding but require ADRs before implementation becomes dependent on them:

- final React component framework/design system
- exact model-provider SDK implementation
- whether web/API are one container or separate release containers
- evidence index strategy for very large captures
- optional active tests such as ping/MTR/HTTP from the host
- import of HAR/log/interface-counter evidence
- centralized/team mode

## 26. V1 success criteria

V1 is successful when a technically capable user can take representative captures for common performance/failure scenarios and:

- start the app locally without custom development setup
- submit the capture and symptom
- receive deterministic capture-quality and protocol evidence
- receive a defensible prioritized diagnosis or explicit insufficient-evidence result
- understand why the system reached that conclusion
- open either the full capture or a focused evidence capture in native Wireshark directly from every relevant finding
- reproduce/validate findings independently
- run the same workflow on macOS, Windows, and Linux
