# Local API — Gate 4

FastAPI owns case lifecycle, SQLite metadata, artifact registration, bounded analyzer orchestration, and deterministic rules-only investigation/report assembly. The analyzer remains the packet-fact authority. Gate 4 does not add a UI, model reasoning, host bridge, Wireshark launch integration, or release packaging.

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
| `GET /api/health` | Service health, Gate 4, provider mode `none` |
| `GET /api/config/capabilities` | Existing deterministic analyzer capabilities and public bounds |
| `POST /api/cases` | Create a case from a bounded symptom string |
| `POST /api/cases/{case_id}/capture` | Stream PCAP/PCAPNG bytes into immutable intake |
| `POST /api/cases/{case_id}/investigate` | Run deterministic baseline/diagnostics, assemble report, reach `COMPLETE` |
| `POST /api/cases/{case_id}/capabilities` | Re-run a typed deterministic capability against the registered original |
| `GET /api/cases/{case_id}` | Case state/history, capture quality, artifacts, runs and metadata |
| `GET /api/cases/{case_id}/findings` | Prioritized deterministic findings from the persisted report |
| `GET /api/cases/{case_id}/report` | Schema-valid persisted Gate 4 investigation report |
| `GET /api/cases/{case_id}/evidence` | Bounded evidence page |
| `GET /api/cases/{case_id}/evidence/{evidence_id}` | Exact normalized evidence record |
| `GET /api/cases/{case_id}/artifacts/{artifact_id}` | Integrity-checked artifact metadata; never a caller filesystem path |
| `DELETE /api/cases/{case_id}` | Delete metadata, original and generated case files |

Capability requests remain typed and cannot contain executable names, arbitrary flags, paths, commands, or caller display filters. Unknown resources return 404; invalid input 422; bounded-resource overflow 413/429; persistence/storage availability failures 503. Public errors use static codes rather than packet-tool stderr, request values, or exception text.

## Investigation behavior

Every investigation starts with capture quality and deterministic Gate 1/2 evidence. Gate 4 then runs a rules-only investigation over normalized evidence; it does not parse packet bytes itself and does not call any model provider.

The rules engine:

- classifies symptom text only to rank relevance; symptom text is never evidence
- ranks TCP candidates using explicit endpoint/port context, protocol relevance, anomalies, timing, and weak volume signals without excluding small flows solely for low byte count
- evaluates DNS delay/failure, TCP setup, retransmission/reordering, RTT, receive-window constraints, resets, TLS visibility, PMTUD signals, and capture limitations
- cites normalized evidence IDs for every finding
- derives confidence from evidence sufficiency and capture quality
- limits supported primary conclusions to medium/high-confidence findings
- returns `insufficient_evidence` when available evidence cannot discriminate adequately
- provides remaining hypotheses and concrete next evidence for unresolved cases

Important conservative boundaries are intentional: a reset proves termination but not cause; a retransmission indicator does not localize the physical loss point; reordering alone is not promoted to a root-cause finding; a zero window identifies a constrained receiver but not automatically client/server ownership; PMTUD control signals support a path hypothesis but do not by themselves prove an MTU black hole.

## Time attribution

Gate 4 emits only stages the deterministic evidence can measure without overlap. Current attribution may include DNS, TCP establishment and the visible TLS establishment milestone. Measurement class and evidence IDs accompany each segment.

The result is a measured subtotal, not necessarily complete user-visible elapsed time. Application/server wait and request/response transfer attribution require deterministic application timing evidence that is not implemented yet. A capture with an idle interval but no decodable request/response timing therefore remains unresolved rather than being labeled server delay.

## Findings and uncertainty

Findings are concise, prioritized, and include:

- category, statement and confidence
- affected scope
- supporting evidence IDs
- alternate explanations and limitations
- recommended validation
- packet-level applicability and display filter where available

The investigation-result contract is `contracts/investigation-result.schema.json`. Packet-level findings expose the future Wireshark-action availability fields required by the shared result model, but Gate 6 host-bridge/evidence-capture launch behavior is not implemented in Gate 4.

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

SQLite continues to store metadata, runs and evidence indexes while packet/report bytes remain as confined case artifacts. A completed report is serialized deterministically, validated against the investigation-result schema, stored under `reports/<sha256>.json`, registered as a logical artifact, and made read-only. Re-running an unchanged case produces the same report content and reuses the report artifact identity. Restart recovery preserves registered reports and removes unregistered report debris.

Reports include the deterministic analyzer, TShark and capinfos versions recovered from completed run metadata. The report endpoint re-validates the report schema, case identity and registered artifact integrity before returning it.

A later optional capability failure does not invalidate or erase the completed deterministic report. Gate 7 iterative model reasoning is not implemented here.

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

Existing Gate 1–3 execution, capture, pipe, evidence, request, run and case bounds remain unchanged. Gate 4 additionally caps candidate and finding counts and validates report size before persistence.

Raw captures and payload bytes remain local. Structured logs contain case/component/capability/duration/status/static error code only. Symptoms, packet payload, DNS raw names, credentials, arbitrary exceptions and request bodies are not emitted to logs. Active provider mode remains `none`; Gate 4 has no model transport or model credentials.

## Validation

Gate 4 validation requires real TShark/capinfos with zero relevant skips, the full Gate 1–4 regression suite, schema/OpenAPI checks, Ruff lint/format, compileall, and `git diff --check`. Real-capture Gate 4 RCA goldens live in `tests/golden/gate4/rules_cases.json` and intentionally include healthy and ambiguous outcomes that must return `insufficient_evidence`.

See `docs/gate4-verification.md` for the exact validated environment, counts, task mapping, RCA cases, and known limitations.
