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

Task 6: complete (commit `371491e feat: add persistent multi-capture case manager`; 130 frontend unit tests passed at final Task 7 verification; web lint/format/typecheck passed).

## Task 7 execution

- RED: production-browser workflow initially exposed stale generated report validation, incorrect mobile report reachability, report recompute timing, and secondary capture admission races; a new API integration regression showed secondary captures stayed `analyzing` after investigation.
- Implemented Gate 7 analysis of pending uploaded secondary sources. Initial multi-capture investigations analyze primary and pending secondary sources before one report; adding a source to a completed case preserves primary runs and analyzes only the new source. Failed secondary analysis is marked `needs_attention` with safe error code.
- Updated generated report contract for the existing `cross_vantage` report result. E2E fixtures use physically resolved temporary roots to satisfy root confinement on macOS. Mobile workflow collapses Case Manager before report interactions.
- Ruling: Initial multi-capture investigations analyze primary and every uploaded secondary before one report; after COMPLETE, added sources are analyzed while completed primary runs are reused. This avoids unnecessary extraction and preserves the existing single-capture Gate 4 flow; a failed secondary remains `needs_attention` and primary evidence can still report.
- Ruling: At 390px, users can collapse the Case Manager bottom sheet to reach report content; the browser workflow exercises this layout behavior.
- Ruling: E2E fixture prep resolves the temporary data root physically because macOS `/var` symlinks are rejected by the strict root confinement check; this is limited to test fixture location.
- GREEN: production browser suite — `21 passed`; frontend unit — `130 passed`; `npm run lint`, `npm run format:check`, `npm run typecheck` passed.
- GREEN: `PATH=/Applications/Wireshark.app/Contents/MacOS:$PATH .venv/bin/pytest -q tests/integration/test_gate4_report.py tests/integration/test_gate7.py tests/integration/test_api.py` — 145 passed, 1 existing Starlette deprecation warning.
- Ruff check, Ruff format check, and `git diff --check` passed.
- Limitation: synthetic client/server fixture captures carry the same deterministic handshake and do not model independent clock skew, NAT, or middlebox ambiguity; those remain unqualified by this workflow.

Task 7: complete after commit (production browser 21 passed; integration 145 passed; frontend 130 passed; lint/format/typecheck/Ruff/diff checks passed).

## Task 8 execution — verification in progress; release gates blocked

- RED/GREEN packaging-image fix: `docker build --target core-test -t wireclaw-core:task8-test .` initially failed because its test stage omitted `apps/web/public/brand/wireclaw-logo.jpeg`, required by the existing packaged-logo route test. Added that asset to the core-test stage. Rebuild passed: 595 unit/integration tests, 1 existing Starlette deprecation warning.
- GREEN: packaging suite with local-only loopback access — `PYTHONPATH=.:services/api/src:services/analyzer/src .venv/bin/pytest -q tests/packaging` — 295 passed.
- GREEN: provider privacy tests with local-only loopback access — 31 passed. Isolated slow subprocess bound test — 1 passed. Gate 3 validator with local-only loopback — 448 schema checks and all CLI/live API/evidence/bridge/deletion checks passed.
- GREEN: production core-runtime image built; pinned analyzer versions verified as Python 3.12.3 and TShark/capinfos/editcap/mergecap 4.2.2. `scripts/validate_container_release.py` passed automated G9.1–G9.13 corpus, health/web, policy, rules-only investigation, evidence, restart persistence, immutable original, provider route, and privacy checks.
- GREEN: full web build, lint, formatting, typecheck, and 130 frontend tests. Task 7 production browser suite passed 21 tests. Full Ruff check/format and compileall passed. Host bridge `go test ./...`, `go vet ./...`, `go build ./...` passed.
- Host full pytest run: 882 passed, 8 failed. Three failures were local TShark 4.6.9 golden differences; pinned Docker core-test at locked TShark 4.2.2 passed all tests. The subprocess timeout/pipe test passed in isolation. Three provider privacy fixture tests passed when allowed to bind their intended 127.0.0.1 mock server. All tests are therefore covered by the passing pinned core suite plus the passing packaging suite; host-wide command itself remains recorded as non-green.
- Blocker: exact-head GitHub Gate 6 jobs cannot be started/verified because `gh auth status` reports the configured token is invalid. The workflow also requires a push or PR to a configured branch; no push/PR was performed.
- Blocker: no staged embedded-AI release assets are present, so the fresh macOS candidate package and hands-on frozen-candidate qualification cannot run. No candidate was created or frozen.
- Task 8 remains incomplete until exact-head CI and candidate-bound qualification prerequisites are available. No final whole-branch review yet; run once after the branch reaches the final verification point.

### Task 8 whole-branch review fix pass

- Fix-pass commit: `afb9797` (`fix: address multi-capture qualification review`).
- Review range: `443b6279a4b82d1531fcce939337faad6f3e3966` through `5b7fe6945107b44fab63528f904b1ab0cb449f44`. The first whole-branch review identified eight Important findings and two Minor findings; see the retained review diff under `.superpowers/sdd/2026-10-22-case-manager-multicapture/`.
- Fixed false cross-flow localization by grouping SYN/SYN-ACK observations by a canonical initiating tuple and sequence epoch and validating packet identity across sources. Added regression for packets from different TCP flows.
- Fixed secondary capture coverage by running baseline and diagnostics for each uploaded source. Evidence serialization now includes capture ownership consistently in first and cached capability responses; capture-local stream IDs remain scoped in candidate ranking.
- Fixed source-specific Wireshark paths: full capture grants accept only contributing case-owned originals; focused extraction and grants use the selected capture, matched frames, and capture-bound artifact provenance. The UI displays source labels and per-source matched-frame filters and correlation descriptors. Existing single-capture filter behavior remains covered.
- Fixed batch intake to continue after one upload fails, analyze successful uploads, and retain the last verified report while the case is confirmed updating. Status connectivity loss still hides the report and forces a fresh revision check. Added retry upload for `needs_attention` captures and capture rename UI/API naming consistency.
- Fixed clock calibration to estimate from repeated matched-packet inliers while retaining uncertainty bounds; corrected report limitation copy so matched packets without valid localization are not described as unmatched.
- Rulings: preserve the previous report only during a confirmed in-progress case update; hide it on status-fetch failure and require a new verified revision before redisplay — cost if wrong: users may briefly see stale results during a known update or lose report visibility during API outages. Source-specific Wireshark actions use matched frame descriptors when a finding spans captures, while the legacy per-capture filter remains for single-source findings — cost if wrong: source-specific review could omit unrelated context, which remains available via the full-capture action.
- Verification: pinned Docker `core-test` — 600 passed, one existing Starlette deprecation warning; `tests/packaging` — 295 passed; Gate 3 validator — 448 schema checks plus CLI/live loopback, repeated request, evidence capture, bridge grant, and deletion passed; web lint/Prettier/typecheck/build and 132 frontend tests passed; production browser suite — 21 passed, including mobile flow, source-specific filter selection, relabel/removal, and max-four behavior; Ruff check/format and `git diff --check` passed.
- Focused backend regression group (`test_localization`, `test_correlation`, `test_investigation`, API, Gate 4, Gate 7) had 178 passes before the wording-only regression was corrected; the corrected test passed separately. The pinned core suite subsequently passed all 600 unit/integration tests.
- Confirmed limitations: exact-head GitHub CI remains unavailable because the configured `gh` token is invalid; candidate-bound hands-on qualification remains unavailable because embedded-AI release assets are not staged. No candidate has been packaged or frozen.
- Final whole-branch re-review of the corrected commit range remains required before declaring the implementation review-ready. Task 8 remains incomplete until external qualification gates are satisfied.

### Correlation provenance follow-up

- Fix commit: `a001ebb` (`fix: bind correlation evidence to matched frames`).
- The final re-review found that a packet match inherited the first eight evidence IDs per capture, which could cite unrelated evidence in larger cases.
- RED: a new unit regression put the actual SYN evidence after twelve unrelated records; it failed because correlation provenance did not include the matched-frame records.
- Ruling: correlation evidence IDs must come from existing evidence records whose `capture_id` matches the source and whose `frame_refs` contain the exact matched frame. Report assembly rejects cross-capture provenance or frame references that do not support the matched descriptor — cost if wrong: some otherwise exact packet correlations may remain unlocalized when analyzer evidence does not cite that frame.
- Implemented a bounded frame-to-evidence index, frame-specific `capture_evidence_ids`, and report validation of source ownership plus frame-reference coverage. The synthetic client/server integration now proves each emitted correlation citation covers its corresponding matched frame.
- GREEN: correlation/localization unit and actual multi-capture integration checks — 19 passed before the added wrong-frame negative case; both new provenance regressions then passed. Pinned Docker `core-test` after the correction — 603 passed, one existing Starlette deprecation warning. Ruff check/format and `git diff --check` passed.
- One final whole-branch re-review after this provenance correction is pending. Exact-head CI and candidate-bound hands-on qualification remain blocked by the previously recorded external prerequisites; no package candidate was made or frozen.
- Final whole-branch re-review: base `443b6279a4b82d1531fcce939337faad6f3e3966` through `dc63ffd1e08cf30e636196bac60cec8132fb3671`; no Critical, Important, or Minor findings. It verified exact capture/frame evidence ownership and closure of the prior review findings.
- Task 8 implementation and local verification are ready; Task 8 itself remains incomplete because exact-head GitHub CI requires valid GitHub credentials and candidate-bound macOS hands-on qualification requires the unstaged embedded-AI release assets. Do not package or freeze until those gates are available and pass.
