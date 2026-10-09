# Gate 4 Verification — Rules-only Investigation and Report

Date: 2026-10-09

Status: **Gate 4 implementation complete; ready for independent review**

This record covers Gate 4 only. It does not authorize or include Gate 5 UI work, Gate 6 host/Wireshark integration, Gate 7 model reasoning, or Gate 8 packaging.

## 1. Scope and authority

Gate 4 implements the tasks assigned by `specs/v1/tasks.md` for R-F012 through R-F015, R-F021, R-U002, R-U004 and R-U006. Higher-authority constitution/requirements/solution behavior remains unchanged.

The implementation begins from merged Gate 3 main commit:

`da324413fc7a24845ce4add93a30d2ab3cf1be86`

Validated Gate 4 implementation/documentation head before this verification-record commit:

`bd7b03bb03ad9563e590116e71d16f196a96468d`

Validation workflow run: `37918133130`, job `113779231550`.

No analyzer implementation or Gate 1/Gate 2 golden packet evidence was changed by Gate 4.

## 2. Task mapping

### G4.1 — deterministic candidate-conversation ranking

Implemented in `services/api/src/wireclaw_api/investigation.py`.

Candidate TCP conversations are ranked deterministically using bounded combinations of:
- explicit symptom endpoint/address references
- explicit symptom port references
- symptom-family/protocol relevance
- connection/anomaly evidence
- observed duration
- traffic volume as a weak signal rather than a sole selector

Lower-volume flows remain eligible. Symptom text affects relevance ranking only; it cannot create packet facts or alter command execution.

### G4.2 — basic time-attribution engine

Implemented as non-overlapping measured attribution over available deterministic evidence.

Current measurable stages:
- DNS, when a single complete DNS transaction is the applicable visible stage
- TCP establishment
- visible TLS establishment milestone

Each segment includes measurement class and evidence IDs. The total is explicitly a measured subtotal rather than a claim of complete user-visible transaction time. Overlapping stages are not double-counted.

### G4.3 — evidence-based fault-domain rules

Rules consume normalized Gate 1/2 evidence only. Current finding families include:
- DNS timing/failure
- TCP establishment failure/delay
- retransmission/loss indicators
- high RTT
- receive-window/zero-window constraint
- reset/termination
- TLS delay/retry/alert visibility
- PMTUD control signals
- capture/observability limitations

Fault-domain statements remain deliberately bounded. Examples:
- retransmissions do not localize the physical loss point
- resets prove termination, not causal source
- zero-window evidence does not invent client/server role when endpoint role is unavailable
- PMTUD signals support a path hypothesis but do not prove an MTU black hole

### G4.4 — evidence sufficiency checks

Primary findings require evidence IDs and minimum supported confidence. Capture quality can cap confidence. Material ambiguity remains visible rather than being converted into a diagnosis.

Pure reordering is intentionally not elevated to a packet-loss root cause. A server-wait-looking idle interval without deterministic request/response timing is intentionally not labeled server/application delay.

### G4.5 — `insufficient_evidence`

The investigation-result contract explicitly supports `insufficient_evidence`. These results include remaining plausible hypotheses and concrete next evidence needed to discriminate them.

Healthy or non-discriminating captures therefore do not receive a forced finding.

### G4.6 — finding/report assembler

`services/api/src/wireclaw_api/gate4_service.py` assembles a deterministic report after baseline/diagnostic evidence is persisted.

Successful lifecycle:

`NEW -> INGESTING -> VALIDATING_CAPTURE -> BASELINE_ANALYSIS -> INVESTIGATING -> ASSEMBLING_REPORT -> COMPLETE`

Reports are:
- validated against `contracts/investigation-result.schema.json`
- deterministically serialized
- content-addressed by SHA-256
- stored as confined read-only case artifacts
- revalidated on retrieval
- stable across restart and unchanged reruns
- isolated from later optional capability failures

Report-assembly failure preserves the original capture and previously generated deterministic evidence and transitions the case to `FAILED` with a static error code.

API endpoints added for Gate 4:
- `GET /api/cases/{case_id}/findings`
- `GET /api/cases/{case_id}/report`

### G4.7 — confidence policy

Confidence is derived from evidence conditions and capture quality, never a model self-rating.

Rules use qualitative `high`, `medium`, and `low` confidence. Unsupported or merely suggestive conditions do not become the primary conclusion. A supported primary conclusion requires at least medium confidence; otherwise the report uses `insufficient_evidence`.

### G4.8 — golden RCA cases

`tests/integration/test_gate4_golden.py` runs the real analyzer over deterministic Gate 1/2 packet captures using real TShark/capinfos, validates the generated investigation-result schema, repeats report assembly for determinism, verifies original capture immutability, and compares semantic RCA outcomes with `tests/golden/gate4/rules_cases.json`.

Twelve Gate 4 RCA cases are covered:

| Case | Expected Gate 4 outcome |
| --- | --- |
| `clean_tcp` | `insufficient_evidence` |
| `loss_tcp` | supported `tcp.retransmission`, medium confidence, network-path/local-network boundary |
| `reordered_tcp` | `insufficient_evidence`; reordering is not promoted to loss root cause |
| `high_rtt` | supported `tcp.rtt`, medium confidence |
| `server_wait` | `insufficient_evidence`; application wait is not observable with current deterministic capabilities |
| `window_tcp` | supported `tcp.receive_window`, high confidence, endpoint role remains unknown |
| `reset_tcp` | supported `tcp.reset`, medium confidence, causal domain remains unknown |
| `dns_delay` | supported `dns.timing`, medium confidence |
| `tls_delay` | supported `tls.handshake`, medium confidence with bounded possible domains |
| `failed_tcp` | supported `tcp.establishment_failure`, medium confidence; capture quality limited |
| `pmtud_signals` | supported `network.pmtud`, medium confidence; does not claim black hole |
| `midstream` | `insufficient_evidence`; capture quality limited |

## 3. Report contract and persistence regressions

`tests/integration/test_gate4_report.py` verifies:
- report unavailable before completion
- successful lifecycle reaches `COMPLETE`
- report schema validation
- findings endpoint equality with the persisted report
- SHA-256 integrity and read-only report artifact
- actual analyzer, TShark and capinfos versions recorded in the report
- restart persistence
- deterministic rerun and report-artifact reuse
- later optional capability failure leaves the completed report intact
- report-assembly failure preserves deterministic evidence and immutable original input

The existing Gate 3 API integration suite was updated only where the intended Gate 4 lifecycle changes from stopping at `INVESTIGATING` to reaching `COMPLETE` through `ASSEMBLING_REPORT`.

## 4. Validation results

Validated on GitHub Actions Ubuntu 24.04.5 LTS with:
- Python 3.11.17
- analyzer package 0.2.0
- TShark 4.2.2
- capinfos 4.2.2
- pytest 9.1.1
- Ruff 0.16.10

Results at validated head `bd7b03bb03ad9563e590116e71d16f196a96468d`:
- full suite: **384 passed, zero skipped**
- unit suite: **244 passed, zero skipped**
- real integration suite: **140 passed, zero skipped**
- Ruff `check`: passed
- Ruff format check: passed
- `compileall`: passed
- `git diff --check`: passed
- OpenAPI snapshot regeneration/equality path: passed
- investigation-result schema validation: passed in unit/integration and real RCA golden paths

One existing warning remains: Starlette/FastAPI TestClient reports the upstream `httpx` transport deprecation. It does not skip or fail a test.

All real integration tests ran with TShark/capinfos installed. No skipped/mocked packet-tool result is represented as real validation.

## 5. Safety, privacy and failure behavior

Gate 4 preserves Gate 1–3 boundaries:
- no shell execution or caller-controlled process arguments
- no new analyzer executable capability
- no raw PCAP upload to any model/provider
- provider mode remains `none`
- no packet payload logging
- no raw DNS-name restoration
- original capture remains immutable
- case/artifact path confinement remains in force
- report failures preserve prior evidence rather than rewriting them as findings
- bounded candidate/finding/report output

Rules operate only on normalized persisted evidence. User symptom text is untrusted context, not evidence.

## 6. Known limitations

Validated execution is Linux/Ubuntu with TShark/capinfos 4.2.2 only. Native macOS/Windows packet-tool execution, other packet-tool versions, Docker/release packaging, optional Zeek operation, UI behavior and host bridge behavior remain unvalidated/deferred to their assigned gates.

Time attribution is intentionally incomplete where deterministic stage evidence is absent. In particular, R-F011 application timing is an authoritative V1 requirement, but the current delivery-plan task mapping does not assign a deterministic application-timing implementation to Gate 4. The existing analyzer has no `analyze_http_timing` implementation. Gate 4 therefore does not fabricate `server_application_wait`; the `server_wait` real-capture golden remains `insufficient_evidence`. This V1 planning gap must be assigned through the spec/task process before V1 acceptance rather than silently pulled into Gate 4.

Other boundaries:
- encrypted TLS session completion remains unknown beyond visible handshake milestones
- single-ended captures often cannot distinguish local-network from wider network-path loss
- reset evidence identifies termination, not why it occurred
- receiver role is not invented when endpoint ownership is unavailable
- PMTUD control signals do not independently prove an MTU black hole
- the Gate 4 time total is a measured subtotal, not guaranteed end-to-end user-visible time

## 7. Gate boundary

Gate 4 exit criteria are satisfied:
- representative real-capture cases produce useful deterministic explanations without model access
- ambiguous/healthy cases produce explicit uncertainty instead of forced diagnoses
- findings are evidence-linked and confidence-limited
- persisted reports survive restart and failures safely

Gate 5 and later tasks remain unchecked. Do not begin Gate 5 until Gate 4 receives independent review and merge authorization.
