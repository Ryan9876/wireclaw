# Gate 4 Verification — Rules-only Investigation and Report

Date: 2026-10-09

Status: **Gate 4 implementation complete; independent review blockers remediated; ready for approval/merge decision**

This record covers Gate 4 only. It does not authorize or include Gate 5 UI work, Gate 6 host/Wireshark integration, Gate 7 model reasoning, or Gate 8 packaging.

## 1. Scope and authority

Gate 4 implements the tasks assigned by `specs/v1/tasks.md` for R-F012 through R-F015, R-F021, R-U002, R-U004 and R-U006. Higher-authority constitution/requirements/solution behavior remains unchanged.

The implementation begins from merged Gate 3 main commit:

`da324413fc7a24845ce4add93a30d2ab3cf1be86`

Final validated Gate 4 product/documentation head before closeout-only cleanup:

`3a86abc26d4f8457cfd4cf7daf7a6ccdbd371bf7`

Final validation workflow run: `37922084624`, job `113792166756`.

The commits after that validated head remove temporary Gate 4 validation/remediation workflow and helper-script scaffolding and update this verification record. They do not change product/analyzer/rules behavior.

Gate 4 did not modify Gate 1/Gate 2 golden packet captures or their analyzer implementations except where explicitly required by the independently reviewed Gate 4 rules/report integration surface.

## 2. Task mapping

### G4.1 — deterministic candidate-conversation ranking

Implemented in `services/api/src/wireclaw_api/investigation.py`.

All normalized inventoried conversations, including transport records without a tool stream ID, are ranked deterministically using bounded combinations of:
- explicit symptom endpoint/address references
- explicit symptom port references
- symptom-family/protocol relevance
- connection/anomaly evidence where the underlying analyzer exposes it
- observed duration
- traffic volume as a weak signal rather than a sole selector

Lower-volume flows remain eligible. Non-TCP/UDP inventoried conversations with no stream ID remain eligible and can rank first when explicit symptom context matches. Symptom text affects relevance ranking only; it cannot create packet facts or alter command execution.

### G4.2 — basic time-attribution engine

Implemented as non-overlapping measured attribution over available deterministic evidence.

Current measurable stages:
- DNS, when a single complete DNS transaction is the applicable visible stage
- TCP establishment
- visible TLS establishment milestone

Each segment includes measurement class and evidence IDs. The total is explicitly a measured subtotal rather than a claim of complete user-visible transaction time. Overlapping stages are not double-counted. TLS retry/repeated-ClientHello conditions do not report a misleading minimum-attempt duration as the representative handshake time; where a deterministic single-stage attribution cannot be supported, that stage is omitted with a limitation.

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

Pure reordering is intentionally not elevated to a packet-loss root cause. A server-wait-looking idle interval without deterministic request/response timing is intentionally not labeled server/application delay. DNS evidence remains visible but does not become the primary diagnosis for a generic symptom solely by crossing a timing threshold without relevant symptom/evidence linkage.

### G4.5 — `insufficient_evidence`

The investigation-result contract explicitly supports `insufficient_evidence`. These results include remaining plausible hypotheses and concrete next evidence needed to discriminate them.

Healthy, unrelated, or non-discriminating captures therefore do not receive a forced finding.

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
- invalidated/rebuilt when a later successful analyzer capability changes the deterministic evidence set, preventing stale `/report` and `/findings` views

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
| `dns_delay` | supported `dns.timing`, medium confidence when symptom/evidence linkage is sufficient |
| `tls_delay` | supported `tls.handshake`, medium confidence with bounded possible domains |
| `failed_tcp` | supported `tcp.establishment_failure`, medium confidence; capture quality limited |
| `pmtud_signals` | supported `network.pmtud`, medium confidence; does not claim black hole |
| `midstream` | `insufficient_evidence`; capture quality limited |

## 3. Independent review and remediation

PR #5 received an independent Gate 4 contract/correctness review after the initial 384-test implementation checkpoint. The review identified five blocking themes plus one follow-up ranking-scope issue. All were remediated before the final validation run:

1. **Completed-report freshness:** a later successful analyzer capability could add evidence after `COMPLETE` while leaving the persisted Gate 4 report stale. Successful evidence-changing runs now invalidate/rebuild the report path so report/findings remain consistent with persisted evidence.
2. **Protocol-general candidate ranking:** ranking was generalized beyond TCP-only assumptions so UDP and other normalized inventoried conversations participate deterministically.
3. **Relevance/evidence sufficiency:** unrelated DNS delay cannot become the primary diagnosis for a generic symptom solely because a threshold is crossed; unsupported cases remain low confidence/insufficient evidence.
4. **Explicit bounded-output truncation:** candidate/finding caps no longer silently discard relevant scope without recording the limitation/truncation condition.
5. **TLS retry attribution:** repeated/slow TLS attempts no longer pair a retry-related finding with a misleading minimum visible handshake duration; ambiguous stage attribution is omitted with a limitation when necessary.
6. **Non-stream inventoried conversations:** non-TCP/UDP records represented with `stream: null` are now eligible for deterministic candidate ranking and can win on explicit endpoint relevance.

Targeted regressions were added for these reviewed boundaries. The final full-suite count increased from 384 to 390 tests.

## 4. Report contract and persistence regressions

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
- later successful evidence-changing capability execution refreshes the report rather than leaving stale findings
- report-assembly failure preserves deterministic evidence and immutable original input

The existing Gate 3 API integration suite was updated only where the intended Gate 4 lifecycle changes from stopping at `INVESTIGATING` to reaching `COMPLETE` through `ASSEMBLING_REPORT`, plus the reviewed report-freshness behavior above.

## 5. Final validation results

Validated on GitHub Actions Ubuntu 24.04.5 LTS with:
- Python 3.11.17
- analyzer package 0.2.0
- TShark 4.2.2
- capinfos 4.2.2
- pytest 9.1.1
- Ruff 0.16.10

Final results for product/documentation head `3a86abc26d4f8457cfd4cf7daf7a6ccdbd371bf7` from workflow run `37922084624`, job `113792166756`:
- full suite: **390 passed, zero skipped**
- unit suite: **249 passed, zero skipped**
- real integration suite: **141 passed, zero skipped**
- Ruff `check`: passed
- Ruff format check: passed
- `compileall`: passed
- `git diff --check`: passed
- OpenAPI snapshot regeneration path: passed
- investigation-result schema validation: passed in unit/integration and real RCA golden paths

The run used real TShark/capinfos 4.2.2. No skipped or mocked packet-tool result is represented as real validation.

One non-failing warning remains: Starlette/FastAPI TestClient reports the upstream `httpx` transport deprecation. It does not skip or fail a test.

An earlier pre-review checkpoint at `bd7b03bb03ad9563e590116e71d16f196a96468d` passed 384/244/140 tests. That result is superseded by the final independent-review remediation validation above.

## 6. Safety, privacy and failure behavior

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
- bounded candidate/finding/report output with explicit truncation/limitations where applicable

Rules operate only on normalized persisted evidence. User symptom text is untrusted context, not evidence.

## 7. Known limitations

Validated execution is Linux/Ubuntu with TShark/capinfos 4.2.2 only. Native macOS/Windows packet-tool execution, other packet-tool versions, Docker/release packaging, optional Zeek operation, UI behavior and host bridge behavior remain unvalidated/deferred to their assigned gates.

Time attribution is intentionally incomplete where deterministic stage evidence is absent. In particular, R-F011 application timing is an authoritative V1 requirement, but the current delivery-plan task mapping does not assign a deterministic application-timing implementation to Gate 4. The existing analyzer has no `analyze_http_timing` implementation. Gate 4 therefore does not fabricate `server_application_wait`; the `server_wait` real-capture golden remains `insufficient_evidence`. This V1 planning gap must be assigned through the spec/task process before V1 acceptance rather than silently pulled into Gate 4.

Other boundaries:
- encrypted TLS session completion remains unknown beyond visible handshake milestones
- single-ended captures often cannot distinguish local-network from wider network-path loss
- reset evidence identifies termination, not why it occurred
- receiver role is not invented when endpoint ownership is unavailable
- PMTUD control signals do not independently prove an MTU black hole
- the Gate 4 time total is a measured subtotal, not guaranteed end-to-end user-visible time

## 8. Gate boundary

Gate 4 exit criteria are satisfied after independent review remediation:
- representative real-capture cases produce useful deterministic explanations without model access
- ambiguous/healthy/unrelated cases produce explicit uncertainty instead of forced diagnoses
- all inventoried conversations remain eligible for deterministic relevance ranking, including records without stream IDs
- findings are evidence-linked and confidence-limited
- persisted reports survive restart and failures safely and remain consistent with later successful deterministic evidence changes
- bounded output behavior is explicit rather than silently truncating diagnostic scope

Gate 5 and later tasks remain unchecked. PR #5 should remain open until the Gate 4 merge decision is made. Do not begin Gate 5 before Gate 4 is approved and merged.