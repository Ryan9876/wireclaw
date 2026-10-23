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

### Task 8 resumed native qualification (2026-10-23)

- Exact-head Gate 6 had passed for reviewed source `57bd1e145cea2e26baec3538f188352c528b9264` (manually dispatched by the user). The reusable embedded-AI stage at `/Users/smithr/Documents/Wireclaw Qualification/c300949f/ai-stage/ai` validated against pinned release metadata: Qwen `wireclaw-qwen3-4b-instruct-2507-q4_k_m`, revision `cdbee75f17c01a7cc42f958dc650907174af0554`, SHA256 `4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc`; llama.cpp runtime revision `8345f333951c661d166b00e6f9362e553768f292`; macOS arm64 and 26 runtime files validated.
- Built fresh candidate for `57bd1e1` at `/Users/smithr/Documents/Wireclaw Qualification/57bd1e1/wireclaw-release`, with provider timeout 120 seconds. Its embedded model reported ready; packaged logo returned HTTP 200 and visibly rendered in current UI. Candidate package included logo, host bridge, and current web bundle.
- Single-capture synthetic SYN-delay qualification passed on that candidate: client `10.20.30.50:52000`, server `203.0.113.25:443`, TCP setup 3.21 seconds, two retransmission indicators. Embedded Qwen answered the required client/path/server question in 812 characters, said source attribution was unsupported from one client-side capture, cited evidence through the UI support control, and recommended simultaneous endpoint captures/server logs. No raw evidence IDs appeared in prose.
- Multi-capture case used client/server captures plus two unrelated captures. Four captures were analyzed; exact packet-signature matching ignored capture-local stream numbering, matched frames belonged to both original sources, and alignment was usable with 3 matched packets, +10 ms offset and 0 ms residual uncertainty. Deterministic report localized the observed ~3.2-second wait to server SYN-ACK response, with high support and source-capture/frame provenance. Unrelated captures did not join that flow. Relabeling changed the conclusion without upload; removing the server capture preserved the case/client source and removed localization/support. Technical Evidence exposed source-specific frame filters. Fifth-capture behavior was not accepted on the first attempt because the request raced re-analysis and returned 429; it remains to be verified after stable COMPLETE state on the final candidate.
- Required multi-capture AI follow-up failed on the initial candidate: API returned `503 provider_unavailable`; filtered container logs showed repeated llama-server HTTP 400 responses. The report correctly retained deterministic findings and marked optional reasoning unavailable. The original candidate was stopped cleanly and ports 8765–8767 verified free. No freeze.
- RED: added `test_followup_context_contains_report_cited_evidence_only`, which inserted 12 large uncited evidence records and observed them leaking into follow-up provider context. GREEN fix filters follow-up evidence to deterministic report citations, including per-capture correlation citations, preserving every cited record while excluding unrelated evidence. This limits context size for the embedded model without changing deterministic findings or evidence storage.
- Verification: focused Gate 7 follow-up tests — 27 passed, one existing Starlette deprecation warning. Affected API/Gate 7/reasoning suites initially had two tool-unavailable failures because this host run omitted the Wireshark PATH; rerun with `PATH=/Applications/Wireshark.app/Contents/MacOS:$PATH` passed 193 tests, one existing warning. Ruff check, Ruff format check, and `git diff --check` passed.
- Fix commit `771d1b95a3ff9a247720cca31a9681a737e9005c` (`fix: bound follow-up context to cited evidence`) was pushed. Remote branch verified at the same SHA under GitHub account `Ryan9876`.
- Exact-head Gate 6 rerun `39991422981` targets `771d1b95a3ff9a247720cca31a9681a737e9005c`. Windows, macOS bridge, Ubuntu bridge, and macOS AI sandbox jobs passed; Linux full and Docker release were still running at this ledger update. Do not package until all jobs finish green. Then build a new candidate rooted at `771d1b9` and repeat required candidate-bound checks, including stable-state fifth-capture rejection and multi-capture AI follow-up.
- Limitation/status: Task 8 remains incomplete. Old candidate is superseded by the fix. No freeze or merge has occurred.

### Task 8 attribution-limit follow-up

- Fresh `771d1b9` package proved the cited-evidence context filter lets a real embedded Qwen request complete. One valid answer nevertheless promoted the report's “makes the client-to-server path less likely” to “not attributable to network path,” and a later UI request returned the safe incompatible-response error. Treat the first as an attribution-strength regression and the second as observed model response variability; do not accept the first candidate for freeze.
- RED: `tests/unit/test_reasoning.py::test_followup_instruction_preserves_deterministic_attribution_strength` failed because follow-up instructions did not explicitly state that the deterministic report is authoritative or that “less likely” does not mean ruled out.
- Fix: clarified follow-up system instructions to prohibit strengthening report certainty/specificity, to distinguish server-side timing from application processing, and to state that retransmission indicators do not prove physical packet loss.
- GREEN: `tests/unit/test_reasoning.py tests/integration/test_gate7.py -k followup` — 29 passed, 1 existing Starlette deprecation warning. Ruff check/format and `git diff --check` passed.
- Commit `b3cd1512cb4f7516154ed312b80cc490aff9a353` (`fix: preserve follow-up attribution limits`) pushed; remote SHA verified equal. Exact-head Gate 6 run `39994009410` is underway. The `771d1b9` candidate was stopped cleanly. Do not package or freeze until the new exact-head CI is green and a new candidate passes the real-model checks.
- Exact-head Gate 6 run `39994009410` completed successfully on `b3cd1512cb4f7516154ed312b80cc490aff9a353`; all six jobs passed: `linux-full`, `docker-release`, `bridge-platform (windows-2025)`, `bridge-platform (macos-14)`, `bridge-platform (ubuntu-24.04)`, and `macos-ai-sandbox-qualification`.
- Remote `eai14-qualification-tooling` SHA equals this exact local/CI SHA. A new `b3cd151` candidate must now be built and pass embedded-AI qualification before freeze.

### Task 8 final candidate qualification result — FAILED; no freeze

- Fresh exact-head candidate `/Users/smithr/Documents/Wireclaw Qualification/b3cd151/wireclaw-release` packaged source `b3cd1512cb4f7516154ed312b80cc490aff9a353`, pinned Qwen model/runtime hashes, ad-hoc signature, and 120-second timeout. Candidate health reported embedded Qwen ready; logo route returned HTTP 200 (1,929,767 bytes). Headless Chrome loaded the packaged UI title and logo at natural width 2048 with no page errors.
- Single-capture case on this candidate used the existing synthetic SYN-delay PCAP. Deterministic report: client `10.20.30.50:52000` to server `203.0.113.25:443`, TCP establishment 3210 ms, two retransmission indicators. The exact required Qwen prompt returned HTTP 200 in 16.2 seconds; answer was 1,096 characters, said the available evidence cannot distinguish client/path/server cause, noted the 3.21 s delay and two retransmission indicators, contained no evidence IDs in prose, cited three structured evidence IDs, and recommended endpoint captures or server listener timing.
- Multi-capture case retained four analyzed sources in the packaged UI; exact correlation used direction-normalized packet signature, client/server vantages, three matched observations for alignment, +0.00999999 s offset, 0 s uncertainty, usable alignment, and exact source-owned matched frames. Two unrelated captures did not correlate. A stable-state fifth capture was rejected with HTTP 409 `capture_count_limit`; count remained four. Technical correlation records retained each capture's evidence IDs and frame descriptors; source-specific Technical Evidence inspection was previously verified on the same deterministic case/workflow.
- Multi-capture Qwen response on final candidate returned HTTP 200 with four structured evidence citations and no raw IDs in prose, but still overclaimed: it said the delay was “not in the client path or network path” and named server application processing as the cause, while the deterministic report only says server/listener-side delay is supported and the client-to-server path is less likely. The model ignored the strengthened prompt instruction to preserve that uncertainty. This fails the epistemic qualification criterion.
- Final candidate stopped cleanly, case data preserved, and no freeze performed. Task 8 remains incomplete. Outstanding on a future attempt: correct the model/report boundary with a testable deterministic solution or accept the release blocker; rerun final candidate multi-capture AI and supporting-evidence UI validation; complete relabel/removal lifecycle checks on the final candidate if needed. Do not freeze this HEAD/candidate based on the failed AI answer.
- Follow-up context hardening: RED `tests/integration/test_gate7.py::test_followup_context_uses_conclusion_without_internal_fault_domain_labels` failed because `fault_domains` were forwarded unchanged. Removed those internal classification labels from the provider's conclusion, finding, and remaining-hypothesis projection while preserving the deterministic conclusion text, confidence, citations, limitations, and referenced normalized evidence.
- GREEN: affected API/Gate 7/reasoning suites with the required Wireshark PATH — 194 passed, one existing Starlette deprecation warning; focused follow-up/reasoning tests — 29 passed. Ruff check, Ruff format, and `git diff --check` passed.
- Commit `c4e9bdd1ea73ad126a35c692c0e88972a2b354c8` (`fix: limit follow-up fault-domain context`) is ready to push and exact-head Gate 6. Candidate `b3cd151` was stopped after its Qwen response still made categorical path/application attribution.
- Exact-head Gate 6 run `39996194115` completed successfully on `c4e9bdd1ea73ad126a35c692c0e88972a2b354c8`; all six jobs passed (`linux-full`, `docker-release`, Windows/macOS/Ubuntu bridge, macOS AI sandbox). Remote branch SHA was verified equal before dispatch.
- Final `c4e9bdd` candidate failed the same multi-capture epistemic criterion after the `fault_domains` projection change. Real Qwen follow-up returned HTTP 200, but stated that the delay was not due to network path loss and was due to server processing. The deterministic report remains the narrower statement: server/listener-side delay is supported; client-to-server path is less likely. The model did not preserve this distinction despite explicit system instruction and omission of internal domain labels. Candidate was stopped cleanly with case data preserved; no freeze. Exact local/remote HEAD remains `c4e9bdd1ea73ad126a35c692c0e88972a2b354c8` and its Gate 6 run `39996194115` was green.


### Task 8 follow-up grounding investigation — root cause confirmed

- Reproduced the exact production boundary on the `c4e9bdd` candidate and preserved the sanitized provider context at `/private/tmp/wireclaw-c4-multicapture-followup-context.json` (43,997 bytes; SHA-256 `ece17067c49ff5259ec732dc6e24a007e104a7ed24c80879a2587dc1a2d00a3e`). The system instruction hash was `d092536d9aff428e840dcbf9ade1f3583caeaeb0e0d938be12f16b6a1e6d6772`.
- Deterministic report/context statement: “Both client and server captures observed the SYN promptly; the server's SYN-ACK followed about 3.2 seconds later. This supports a server/listener-side delay and makes the client-to-server path less likely.” The same report explicitly limits timing to matched packet observations and usable clock alignment, with capture placement and unsampled devices remaining limitations; normalized evidence says retransmission indicators are not independent proof of physical loss/location.
- The actual Qwen response passed JSON schema, supplied-evidence citation membership, raw-ID exclusion, and nonempty-citation checks. Its prose changed “makes the client-to-server path less likely” into “not due to network path loss,” and changed “server/listener-side delay” into “server-side processing delay.” It also treated absence of retransmissions as support against path loss despite evidence limitations.
- Inspected `reasoning/followup.py`: after those structural checks, `answer_followup` returns the provider response unchanged. No post-generation certainty or attribution check exists. This proves the root-cause hypothesis: report and context are bounded correctly; free-form provider prose can semantically strengthen them; current validation does not enforce attribution strength.
- RED test work begins only after this reproduced dataflow finding. No production code has been changed for this fix yet.

### Task 8 deterministic follow-up grounding fix — implementation complete; requalification pending

- Root cause confirmed before production edits: the c4e9bdd deterministic report and sanitized follow-up context preserve “server/listener-side delay” and “client-to-server path less likely,” while evidence limits retransmission indicators to non-proof of physical loss/location. Qwen's valid cited JSON strengthened those points to “not due to network path loss” and “server processing delay.” `answer_followup` validated schema, case-local citation membership, raw-ID exclusion, and empty-citation behavior, then returned `answer` unchanged. The actual saved context and both hashes are recorded above.
- TDD: scripted-provider API regression first failed because the overclaim was returned unchanged (the intended RED). Implemented narrow report-derived attribution checks for less-likely path exclusions, server/listener timing promoted to application processing, and retransmission promoted to physical loss. Negated limitations are excluded from affirmative support. A rejected answer is replaced after one provider call with a concise fallback using the deterministic conclusion, its case-local citations, bounded report limitation text, explicit uncertainty, and no evidence IDs in prose. Safe model language remains unchanged.
- Added tests for the exact qualification overclaim, safe qualified path language, server/listener versus application attribution, physical-loss claims versus retransmission indicators, citation validity/case locality, evidence-ID exclusion from fallback prose, and unchanged inconclusive follow-up behavior.
- GREEN: `PATH=/Applications/Wireshark.app/Contents/MacOS:$PATH .venv/bin/pytest -q tests/unit/test_reasoning.py tests/integration/test_gate7.py tests/integration/test_gate4_report.py tests/integration/test_api.py` — 203 passed, one existing Starlette deprecation warning.
- GREEN: Ruff check, Ruff format check, and `git diff --check` passed.
- Limitation: grounding is intentionally a bounded deterministic phrase/structure check for the approved attribution distinctions, not general natural-language entailment. A fresh real-Qwen reproduction and full candidate requalification remain required before freeze.
- Runtime cleanup note: the prior candidate's managed AI stop initially hit the workspace sandbox's macOS signal restriction; its established stop script was rerun with elevated authorization, stopped the prior candidate cleanly, and confirmed no listener remained on 127.0.0.1:8767. No source or qualification data was reset.
- Status: production changes are ready to commit/push. Do not freeze; exact-head Gate 6, fresh candidate, real-model fallback verification, and remaining Task 8 checks are pending.
