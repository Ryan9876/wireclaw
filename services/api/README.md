# Local API — Gates 3, 4, 6, and 7

FastAPI owns case lifecycle, SQLite metadata, artifact registration, bounded analyzer orchestration, deterministic reports, optional Gate 7 reasoning, and Gate 6 evidence-capture/bridge-grant orchestration. The analyzer remains the packet-fact authority. Model reasoning runs only in the API boundary through typed capabilities. Release packaging is deferred to Gate 8.

## Developer startup

Install Python 3.11+ and real TShark/capinfos. From the repository root:

```sh
python -m pip install -e '.[api,test]'
wireclaw-api --data-root data
```

The launcher binds `127.0.0.1:8765`, runs one worker, disables request/access and exception logs, and caps active HTTP connections at 32. Only numeric loopback addresses are accepted for `--host`; `--port` is administrator configuration. One lifetime OS lock permits one service process per data root. Host/Origin checks reject nonlocal browser requests and DNS rebinding; no wildcard CORS is enabled.

## Routes and contracts

OpenAPI is served at `/openapi.json`, documentation at `/docs`, and the checked-in snapshot is `contracts/api.openapi.json`.

| Route | Purpose |
| --- | --- |
| `GET /api/health` | Service health, Gate 7, configured provider mode |
| `GET /api/config/capabilities` | Existing deterministic analyzer capabilities and public bounds |
| `POST /api/cases` | Create a case from a bounded symptom string |
| `POST /api/cases/{case_id}/capture` | Stream PCAP/PCAPNG bytes into immutable intake |
| `POST /api/cases/{case_id}/investigate` | Run deterministic baseline/diagnostics, optional bounded reasoning, assemble report, reach `COMPLETE` |
| `POST /api/cases/{case_id}/capabilities` | Re-run a typed deterministic capability against the registered original |
| `GET /api/cases/{case_id}` | Case state/history, capture quality, artifacts, runs and metadata |
| `GET /api/cases/{case_id}/findings` | Prioritized deterministic findings from the persisted report |
| `GET /api/cases/{case_id}/report` | Schema-valid persisted report with rules-only/model-assisted/fallback status |
| `GET /api/cases/{case_id}/evidence` | Bounded evidence page |
| `GET /api/cases/{case_id}/evidence/{evidence_id}` | Exact normalized evidence record |
| `GET /api/cases/{case_id}/artifacts/{artifact_id}` | Integrity-checked artifact metadata; never a caller filesystem path |
| `DELETE /api/cases/{case_id}` | Delete metadata, original and generated case files |

Capability requests remain typed and cannot contain executable names, arbitrary flags, paths, commands, or caller display filters. Unknown resources return 404; invalid input 422; bounded-resource overflow 413/429; persistence/storage availability failures 503. Public errors use static codes rather than packet-tool stderr, request values, or exception text.

## Investigation behavior

Every investigation starts with capture quality and deterministic Gate 1/2 evidence. The deterministic report is assembled from normalized evidence. If configured, the optional reasoner receives a canonical allowlisted context and may request only a registered analyzer capability or finalize a proposal. Provider failure leaves the deterministic report usable. `none` is the default.

Configure a provider at process startup only:

```text
WIRECLAW_PROVIDER_MODE=none|openai_compatible_cloud|openai_compatible_local
WIRECLAW_PROVIDER_BASE_URL=https://provider.example/v1
WIRECLAW_PROVIDER_MODEL=model-name
WIRECLAW_PROVIDER_TIMEOUT_SECONDS=60
WIRECLAW_PROVIDER_API_KEY=<secret>
```

The API key is read from the environment, excluded from reports and audit records, and never accepted from investigation requests. Cloud endpoints require HTTPS; local endpoints may use HTTP or HTTPS. Redirects and ambient HTTP proxies are disabled. Both modes receive the same minimized normalized evidence; neither receives PCAP bytes or payloads. Requests, responses, evidence count, and reasoning steps are bounded.

The rules engine:

- classifies symptom text only to rank relevance; symptom text is never evidence
- ranks all normalized inventoried conversations, including non-TCP/UDP records without a tool stream ID, using explicit endpoint/port context, protocol relevance, anomalies where available, timing, and weak volume signals without excluding small flows solely for low byte count
- evaluates DNS delay/failure, TCP setup, retransmission/reordering, RTT, receive-window constraints, resets, TLS visibility, PMTUD signals, and capture limitations
- cites normalized evidence IDs for every finding
- derives confidence from evidence sufficiency and capture quality
- limits supported primary conclusions to medium/high-confidence findings
- returns `insufficient_evidence` when available evidence cannot discriminate adequately
- provides remaining hypotheses and concrete next evidence for unresolved cases

Important conservative boundaries are intentional: a reset proves termination but not cause; a retransmission indicator does not localize the physical loss point; reordering alone is not promoted to a root-cause finding; a zero window identifies a constrained receiver but not automatically client/server ownership; PMTUD control signals support a path hypothesis but do not by themselves prove an MTU black hole.

## Post-V1 embedded provider

`embedded_local` reuses the same Gate 7 request context, JSON action schema, evidence-ID validation, capability allowlist, step/byte limits, audit persistence, and deterministic fallback as other providers. The macOS launcher supplies the local authenticated endpoint and ephemeral token at container start; the API does not own or launch llama.cpp and the host bridge is not an inference proxy. If the runtime is unavailable, deterministic analysis remains healthy and reports safe availability/fallback metadata. See [post-V1 operations](../../docs/embedded-ai-operations.md).

## Time attribution

The deterministic attribution can include DNS, TCP establishment, the visible TLS establishment milestone, and decodable HTTP request-to-first-response timing. Measurement class and evidence IDs accompany each segment.

The result is a measured subtotal, not necessarily complete user-visible elapsed time. Plaintext HTTP/1.x timing uses TShark-correlated request/response frames and includes contributing TCP frames when reassembly references are available. Response transfer intervals are included when those frame boundaries are determinable. Opaque TCP silence remains unresolved and is not labeled server delay.

## Findings and uncertainty

Findings are concise, prioritized, and include:

- category, statement and confidence
- affected scope
- supporting evidence IDs
- alternate explanations and limitations
- recommended validation
- packet-level applicability and display filter where available

The investigation-result contract is `contracts/investigation-result.schema.json`. Applicable packet-level findings expose both native Wireshark actions and approved display-filter metadata. Reasoning can rank only existing deterministic findings with same-case evidence references; provider prose is not copied into authoritative findings.

## Gate 6 evidence and bridge grants

The API extracts a focused evidence capture from the immutable original, subject
to the configured evidence-capture byte bound. A derived artifact is registered
only after it parses successfully. Failure leaves the original capture and
previous findings intact. Provenance records the parent SHA-256, extraction mode
and rule, display filter, creation time, related finding IDs, and evidence IDs.
Repeated requests for the same finding reuse a capture only after both the
registered derived bytes and paired provenance verify against the current
parent, finding, evidence IDs, extraction mode, and approved filter.

The evidence-capture and bridge-grant routes accept logical case, finding and
artifact IDs. They do not accept filesystem paths, caller-authored display
filters, executable names, or argument vectors. Before granting a native open,
the API verifies the case-scoped registered artifact and writes a short-lived
one-time grant manifest containing only the token hash. Case deletion removes
its grants. See [the host bridge instructions](../host-bridge/README.md) for the
native trust boundary and [Gate 6 verification](../../docs/gate6-verification.md)
for validated behavior.

## Lifecycle and persistence

The normal successful lifecycle is:

```text
NEW
 -> INGESTING
 -> VALIDATING_CAPTURE
 -> BASELINE_ANALYSIS
 -> INVESTIGATING
 -> ASSEMBLING_REPORT
 -> COMPLETE
```

Failures preserve prior deterministic evidence and immutable input. A report-assembly failure transitions the case to `FAILED` without deleting analyzer results. A completed case can be re-run from its preserved original.

SQLite stores case metadata, analyzer runs, evidence indexes, and bounded reasoning-step audit metadata while packet/report bytes remain as confined case artifacts. Reasoning records omit raw prompts/responses, credentials, and chain-of-thought. A completed report is serialized deterministically, validated against the investigation-result schema, stored under `reports/<sha256>.json`, registered as a logical artifact, and made read-only. Restart recovery preserves registered reports and removes unregistered report debris.

Reports include the deterministic analyzer, TShark and capinfos versions recovered from completed run metadata. The report endpoint re-validates the report schema, case identity and registered artifact integrity before returning it.

A later optional capability failure does not invalidate or erase the completed deterministic report. A successful capability request against a completed case immediately rebuilds the report from the current persisted evidence before the case returns to `COMPLETE`, preventing evidence/report divergence. Gate 7 iterative model reasoning is not implemented here.

## Storage and deletion

Case paths remain confined below the configured data root. Original captures are immutable and independently stored per application case. Callers use logical IDs rather than filesystem paths. Existing Gate 3 transactional intake/deletion/recovery behavior remains in force, including cleanup journals and cross-case deletion isolation.

Representative layout:

```text
data/
  cases.sqlite3
  service.lock
  cases/<case-id>/
    analyzer/...                         # immutable original + analyzer state
    normalized/<run-id>.json            # reproducibility snapshots
    reports/<report-sha256>.json        # read-only Gate 4 report
  trash/<deleted-case-id>/
```

## Resource and privacy policy

Existing Gate 1–3 execution, capture, pipe, evidence, request, run and case bounds remain unchanged. Gate 4 caps candidate and finding counts. Gate 7 bounds provider context/response sizes, reasoning turns, and repeated capability requests.

Raw captures and payload bytes remain local. Structured logs contain case/component/capability/duration/status/static error code only. Symptoms, packet payload, DNS raw names, credentials, arbitrary exceptions and request bodies are not emitted to logs. Provider requests use an explicit context allowlist; API keys are neither stored nor returned.

## Validation

Gate validation uses deterministic fake-provider tests; a paid or live model is not required. Real TShark/capinfos are required to validate packet-tool semantics, including the positive HTTP server-wait fixture and opaque negative fixture. See `docs/gate7-verification.md` for the exact Gate 7 evidence and environment limitations.

See `docs/gate4-verification.md` for the exact validated environment, counts, task mapping, RCA cases, and known limitations.
