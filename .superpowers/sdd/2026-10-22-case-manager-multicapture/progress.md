# SDD ledger — plan: docs/superpowers/plans/2026-10-22-case-manager-multicapture.md

Starting branch: `eai14-qualification-tooling`
Starting HEAD: `88e9741061d4454b43ae8470b49c57bb597a9f2e`
Task in scope: Task 1 only.

## Plan pre-flight scan

| Task(s) | Shared file/interface | Producer → consumer | Scan result |
|---|---|---|---|
| 1 ↔ 2 | `storage.py`, `models.py`, API models | Task 1 creates capture persistence/contracts; Task 2 consumes them for lifecycle routes. | Consistent. Keep Task 1 free of routes/service lifecycle. |
| 1 ↔ 3 | `storage.py`, capture provenance | Task 1 adds nullable provenance columns; Task 3 tags new analysis records. | Consistent. Existing data only gets backfilled where ownership is provable. |
| 2 ↔ 3 | service/storage, capture IDs | Task 2 creates/uploads captures; Task 3 scopes records to those IDs. | Consistent. |
| 3 ↔ 4 | evidence records, `investigation.py` | Task 3 supplies per-capture evidence; Task 4 consumes evidence/capture lists. | Consistent. |
| 4 ↔ 5 | correlation record contract, `investigation.py` | Task 4 emits provenance-rich correlation; Task 5 localizes from it. | Consistent; no implementation until later tasks. |
| 5 ↔ 6 | report/capture summary contract | Task 5 adds deterministic report findings; Task 6 presents capture management and report. | Consistent. |
| 6 ↔ 7 | plural capture API/UI | Task 6 provides UI/API lifecycle; Task 7 qualifies it in production browser. | Consistent. |
| 7 ↔ 8 | production behavior and release verification | Task 7 qualifies workflows; Task 8 runs full suite/package/hands-on checks. | Consistent. |
| 1 | Task self-consistency | Migration test, model tests, schema/provenance migration, strict models all target listed files. | Consistent. Preserve schema-v3 fields and avoid API/UI scope. |
| 2 | Task self-consistency | API tests and routes/service/model changes align. | Consistent. |
| 3 | Task self-consistency | Provenance tags and reasoning context changes align. | Consistent. |
| 4 | Task self-consistency | Pure correlation and clock tests align with new module/investigation integration. | Consistent. |
| 5 | Task self-consistency | Report tests and deterministic localization implementation align. | Consistent. |
| 6 | Task self-consistency | API client, hook, app, component, styles, unit tests align. | Consistent. |
| 7 | Task self-consistency | E2E lifecycle behaviors consume Tasks 1–6. | Consistent. |
| 8 | Task self-consistency | Full verification/package/hands-on scope follows prior tasks. | Consistent. |

## Task 1 execution

Task 1: complete (commits `459a84e` and `443b627`, task review clean after fix round 1).

- RED: schema/model regression tests failed before production edits for schema v3, absent capture models/table/provenance columns. Fix RED: failed ingest migration regression failed because the failed attempt received the new capture ID.
- GREEN: final `PATH=/Applications/Wireshark.app/Contents/MacOS:$PATH .venv/bin/python -m pytest -q tests/integration/test_gate7.py tests/integration/test_api.py` — 108 passed, 1 Starlette deprecation warning.
- Ruff check passed; Ruff format check passed; `git diff HEAD --check` passed.
- Task reviewer found failed legacy ingest runs were incorrectly scoped to the retained capture. Fix round leaves failed ingests/evidence NULL, scopes successful ingest and matching capture-derived artifacts; scoped re-review passed with no new breakage.
- Legacy capture ID: first 32 hex characters of SHA-256 over UTF-8 `capture:{case_id}:{original_artifact_id}`. A case without `original_id` gets no capture row.
- Legacy single-capture case columns remain unchanged. Source/normalized/evidence capture/evidence provenance artifacts and known successful per-capture runs/evidence are scoped; failed ingestion and report artifacts/runs/evidence remain NULL. Vantage defaults to `unknown`.
- Commits: `459a84e feat: add capture entities and provenance`; `443b627 fix: scope migrated capture provenance safely`.
- Push succeeded; `git ls-remote` and local HEAD both report `443b6279a4b82d1531fcce939337faad6f3e3966` on `origin/eai14-qualification-tooling`. Working tree clean.

## Task 2 execution

Starting HEAD: `443b6279a4b82d1531fcce939337faad6f3e3966`; branch and remote verified, working tree clean, schema v4 and Task 1 contracts/provenance present.

Ruling: legacy upload endpoint is `POST /api/cases/{case_id}/capture`; preserve octet-stream and `CaseResponse` behavior. The request boundary currently exempts only that POST path from body buffering, so the plural `PUT .../data` endpoint must receive the same streaming exemption and configured size/time enforcement.

Ruling: the singular upload wrapper resolves to the sole unregistered capture; a registered source is not a candidate, and multiple unregistered candidates are ambiguous — this preserves deterministic legacy behavior while enabling a failed/waiting explicit capture to be retried — cost if wrong: an old client may expect rejection when any second capture exists.

Task 2: complete (commit `4dc6757`; focused API/Gate 7/boundary rerun: 221 passed, 1 warning; Ruff and diff checks passed). Task 2's original branch verification is in `task-2-implementer-report.md`. The checkout also contained uncommitted regressions after that commit; they were red first and are included with the Task 3 persistence change below rather than split into an unrelated service-only commit.

Task 2 follow-up Rulings: recovery cleanup uses missing `original_artifact_id`, not `status`, as the criterion for unregistered intake — persisted failure may precede a crash before cleanup — cost if wrong: an unregistered file could be retained or a registered source removed. Successful legacy primary investigation marks only the primary capture analyzed in the same completion transaction — secondary captures have not participated in that report — cost if wrong: capture status could misstate which source was analyzed.

## Task 3 execution

Task brief: plan Task 3 (no persisted brief existed; read its plan section and design interfaces). Starting HEAD: `4dc6757112f8eba379cb93c6c08dc5ce9ea47091`.

- RED: `test_each_capture_analysis_persists_runs_artifacts_and_evidence_with_its_capture_id` first failed because explicit capture analysis was absent, then exposed the v4 evidence table's `(case_id,id)` key collapsing identical evidence across captures. `test_reasoning_context_projects_bounded_capture_identity_and_vantage` failed because provider projection omitted capture labels. `test_v4_evidence_migration_allows_same_evidence_id_per_capture` failed because the database remained schema v4.
- Ruling: bump schema v4 to v5 and make evidence identity capture-scoped, with a separate unique index for unscoped case-level evidence — one case-wide evidence ID cannot truthfully refer to the same deterministic fact from two captures — cost if wrong: additive migration/testing and downstream clients must treat IDs as capture-specific.
- Implemented scoped run deduplication/insertion, deriving normalized artifact and evidence provenance from the run, deterministic secondary evidence IDs, capture-scoped legacy baseline/diagnostic/capability execution, and bounded provider context capture labels/vantage. Primary evidence IDs remain byte-for-byte compatible.
- v4→v5 migration preserves existing evidence, creates composite `(case_id,id,capture_id)` identity, retains case-level uniqueness, and restores ownership triggers/indexes.
- GREEN: `tests/integration/test_api.py tests/integration/test_gate7.py tests/unit/test_reasoning.py` — 190 passed, 1 existing Starlette warning (80.80s). Ruff check, Ruff format check, and `git diff --check` passed.
- Task 3: complete (commit `68fce25`; tests above).

## Task 4 execution (in progress)

- RED: `tests/unit/test_correlation.py` failed collection because the planned module did not exist.
Ruling: Task 4 correlation will consume a bounded internal TCP packet-observation projection derived from Wireclaw's existing validated diagnostic packet rows, not from human/report summary evidence. The projection is internal deterministic data, not provider context or user-facing evidence. This preserves the spec's packet-level matching requirement without adding a second PCAP parser or inventing packet facts.

- RED: new diagnostic projection tests failed with missing `tcp_correlation_observations`; a real capture integration test exercises upload → analyzer baseline/diagnostic extraction → internal observation projection → exact correlator. It proves capture ID, frame, endpoint tuple, SYN/SYN-ACK state, raw sequence/ack, payload length, timestamps, JSON-safe provenance, and rejection of an unrelated mixed-protocol capture.
- The projection uses the analyzer's existing diagnostic `Runner` invocation, `diagnostics.packets` validation, record/field bounds, and quoted/nested/malformed safeguards. It contains no packet payload, paths, commands, or arbitrary fields and is absent from API evidence and provider projection.
- Correlation is strict on direction-normalized exact tuple, flags, raw sequence/ack, and payload length. It ignores capture-local `tcp.stream` and all timestamps for identity, withholds duplicated signatures within a capture, keeps separate SYN epochs as separate match records, and records source artifact IDs plus original frame/time descriptors. Offset estimates use only these matches; minimum three samples, maximum residual uncertainty, and timing-regression checks gate usability.
- Summary-only correlation was rejected. The internal observation contract is the only Task 3→4 bridge; normal evidence remains summary evidence.
- GREEN: `tests/unit/test_diagnostics.py tests/unit/test_correlation.py` — 97 passed. API + Gate 7: 140 passed, 1 existing warning. Real multi-capture observation/correlation integration: 1 passed. Gate 2: 71 passed, 3 known local TShark 4.6.9 golden mismatches (`reordered_tcp`, `pmtud_signals`, `test_loss_reordering_expert_classes_and_sequence_union`); these match failures already demonstrated against the pristine Task 2 base in the prior verification record. Ruff check/format and `git diff --check` passed.
- Limitation: correlation is deterministic packet matching/alignment only; it does not perform localization, merge captures, or persist packet-observation rows. Task 5 owns localization and recomputation.

Task 4: complete (commit `b9b08ac`; analyzer/API/Gate 7 tests and integration results recorded below).
- Task 4 commit: `b9b08ac feat: correlate tcp across capture vantage points`.
- Observation-contract ruling: bounded internal packet observations come from validated diagnostic rows; summary-only correlation was rejected. See the ruling above for the full interface correction.
- Verification: 97 diagnostic/correlation unit tests passed; 140 API/Gate 7 tests passed; actual two-capture extraction/correlation integration passed. Gate 2: 71 passed, 3 local TShark 4.6.9 golden mismatches matched the failures reproduced at the pristine Task 2 base. Ruff, format, and diff checks passed at Task 4 completion.

## Task 5 execution

Ruling: localization requires exact matched TCP handshake observations, usable multi-sample clock alignment, capture-specific evidence provenance, and explicit client/server vantage labels. Unknown placement remains correlated but cannot produce a fault-domain finding — cost if wrong: conservative reports may defer a useful localization until the user labels the capture.

Ruling: Task 5 recomputes a completed report after metadata relabel or source removal without packet re-extraction. If primary removal already reset the case to `BASELINE_ANALYSIS`, reuse that state and advance once to report assembly; the report is immediately recomputed, so the former Task 2 test now expects `COMPLETE` for removal from an already completed case — cost if wrong: clients expecting an intermediate baseline state will instead see the current recomputed report.

- RED: unit localization tests failed before localizer/report interface existed; report integration first proved unknown vantage does not localize and then failed to recompute after relabel; removal regression exposed a duplicate `COMPLETE→BASELINE_ANALYSIS` transition.
- Implemented exact SYN/SYN-ACK cross-vantage timing findings, return-path delay, evidence/capture/frame provenance, limitations, and support indicator (`stronger` only when deterministic localization exists; otherwise `unchanged`). Added schema contract and bounded finding statements in provider context without packet descriptor dumps.
- Bounded validated packet observation projections are cached as per-capture internal artifacts to support relabel/removal recompute without parser re-execution. They are not normal evidence records or provider/API finding context. Capture-owned cleanup removes them with their source.
- RED/GREEN lifecycle regression proves relabel uses cached observations, recalculates the report, removal drops correlation while preserving the case, and completed-primary removal no longer errors.
- GREEN: `PATH=/Applications/Wireshark.app/Contents/MacOS:$PATH .venv/bin/pytest -q tests/unit/test_localization.py tests/unit/test_reasoning.py tests/integration/test_gate4_report.py tests/integration/test_gate7.py tests/integration/test_api.py` — 202 passed, 1 existing Starlette deprecation warning (91.61s).
- Ruff check passed; Ruff format check passed (12 changed Python files); `git diff --check` passed.
- Limitation: no physical packet loss or specific middlebox localization is inferred; this task localizes only the supported SYN/SYN-ACK timing patterns. Unknown vantage and unusable alignment remain unlocalized.

Task 5: complete (commit `b0b63d8 feat: localize issues with cross-vantage evidence`; 202 passed in report/reasoning/API/Gate 7 suites; Ruff/format/diff passed).

## Task 6 execution

- RED: new API-client test failed because `api.createCapture` was absent; malformed response test proved arbitrary capture response fields were accepted. New component test failed module resolution because CaseManager did not exist. Updated composer attachment regression failed because the old flow staged a replacement case instead of adding to the active case.
- Implemented typed plural capture create/upload/update/remove API methods with safe path IDs, bounded metadata validation, and strict response fields. Case parsing already validates `captures` against generated strict `CaseResponse` contract.
- Added persistent lower-left Case Manager with 1–4 capture rows, size/status, Unknown/Client/Network/Server/Other vantage, network subtype, add/drop, max-4 UI boundary, remove confirmation, and in-session collapse. Mounted it outside the report feed. Composer attachments now upload into the active case. Metadata changes call only PATCH and refresh; they never upload the file.
- Task 6 verification: `cd apps/web && npm test` — 129 passed (then a focused 5-test CaseManager rerun after adding the four-capture limit check). `npm run format:check`, `npm run lint`, and `npm run typecheck` all passed.
- Limitation: adding a capture uses the existing investigate endpoint after intake to run deterministic analysis and refresh the report; the API remains authoritative for concurrent max-capture admission.
