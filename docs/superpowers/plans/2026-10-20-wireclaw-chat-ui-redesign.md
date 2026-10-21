# Wireclaw Conversation-First UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved single-window Wireclaw chatbot-style capture workflow, with bounded real API support for follow-up, recent-case browsing, and metadata-only rename.

**Architecture:** Keep React as presentation, FastAPI as the case/conversation boundary, deterministic analysis and normalized evidence as the sole source of packet facts, and the existing provider abstraction as the only model boundary. Add only metadata needed for recent history/rename and a case-scoped, bounded, non-authoritative follow-up response; do not change analyzer, host-bridge, embedded-AI runtime, or report semantics.

**Tech Stack:** React 19, TypeScript, Vite, FastAPI, Pydantic, SQLite, OpenAPI/JSON Schema generated TS contracts, Vitest, Playwright, pytest.

**Spec:** `docs/superpowers/specs/2026-10-20-wireclaw-ui-redesign.md`

## Global Constraints

- The approved single-window prototype and `apps/web/public/brand/wireclaw-logo.jpeg` are the visual source of truth; do not reinstate the Hallmark alternative.
- No product tabs, dashboard, permanent sidebar, or simultaneous workspace screens.
- Deterministic analyzer output, report semantics, evidence, capture immutability, and paired Wireshark actions remain authoritative and unchanged.
- Follow-up receives normalized report/evidence only; no raw capture/payload, new analyzer capabilities, arbitrary tools/actions, report mutation, or unvalidated evidence citations.
- Store no follow-up prompts/responses in API logs, reasoning audit, or SQLite; follow-up turns are active browser-session state.
- Recent list is bounded and metadata-only. Rename changes display metadata only; delete uses the existing confirmed delete contract.
- Preserve provider privacy boundaries, embedded/local AI runtime/security/fallback/qualification behavior, and loopback API security.
- Keep `docs/v1-acceptance.md` unchanged. New changed UI/API bytes form a new candidate and cannot inherit candidate-bound qualification results without applicable reruns.
- Keep all changes in this linked worktree and on its `post-v1-embedded-ai-impl` branch: UI, APIs, validator, spec, and plan converge on one source HEAD and one candidate.
- Follow-up requests are stateless: each provider call receives only the active case, normalized report/evidence, sanitized symptom, and current question. Browser-retained turns are display-only and never sent with later requests.
- The EAI.14-08 `conclusion_type` is derived from the actual completed report by a deterministic qualification projection; it is never operator-entered.

## Review Focus

1. **Provider unavailable or rules-only mode:** follow-up is unavailable and the UI explains why; it never fabricates a response. Test at the API and UI boundary.
2. **Cross-case or invented evidence citation:** follow-up response citations must be a subset of deterministic evidence IDs for the requested case. Test known, unknown, and other-case IDs.
3. **Untrusted capture filename / display name:** metadata is length/control-character validated and cannot become a path or command. Test path separators, control characters, empty/oversized names, and migration fallback.
4. **Case switch while requests are in flight:** stale follow-up/list results cannot appear in another case. Test abort/generation behavior in React state.
5. **Narrow viewport / overlay keyboard use:** no clipped evidence or actions; overlays close on Escape and restore focus. Cover 390px E2E and keyboard-only interactions.

---

## File Structure

### Product/API capability work

- `services/api/src/wireclaw_api/storage.py` — SQLite schema migration for safe capture/display names, preserving existing case rows. Capture size is read from the already-registered original artifact metadata; do not duplicate it in the cases table.
- `services/api/src/wireclaw_api/models.py` — strict create/list/rename/follow-up request and response models.
- `services/api/src/wireclaw_api/service.py` — bounded metadata listing and rename operations; no filesystem rename.
- `services/api/src/wireclaw_api/app.py` — `GET /api/cases?limit=10`, `PATCH /api/cases/{case_id}`, and `POST /api/cases/{case_id}/followups` routes.
- `services/api/src/wireclaw_api/reasoning/followup.py` (new) — bounded report/evidence projection, prompt construction, strict answer validation and evidence-ID membership check. Reuse existing provider factory/interface and configured provider limits.
- `contracts/api.openapi.json` — source snapshot for the new public API contracts.
- `apps/web/src/generated/api.ts`, `apps/web/src/generated/validators.js`, `apps/web/src/generated/validators.d.ts` — regenerate with `npm run contracts`; never hand-edit.
- `tests/integration/test_api.py` — TDD coverage for migration, bounded list, filename metadata, rename, and case isolation.
- `tests/integration/test_gate7.py` — TDD coverage for provider-grounded follow-up, bounded context, invalid citations, provider failure, and no report mutation.

### Presentation-only work

- `apps/web/src/App.tsx` — single-window composition, truthful provider status, recent-history trigger, active case conversation, recoverable errors, and existing delete dialog integration.
- `apps/web/src/Intake.tsx` — minimal centered drop/choose state and required symptom supplied through the composer; retain file/size validation.
- `apps/web/src/Progress.tsx` — compact state-derived status text/live region; retain full persisted lifecycle only as a small disclosure if needed.
- `apps/web/src/ReportView.tsx` — concise assistant-style conclusion, confidence/limitation, cited evidence, next validation, small technical disclosure; preserve exact Wireshark actions/filter.
- `apps/web/src/EvidenceDrawer.tsx`, `apps/web/src/Dialog.tsx` — retain normalized detailed evidence and modal focus behavior while matching quiet overlay treatment.
- `apps/web/src/Conversation.tsx` (new, if composition warrants) — session-only user/assistant follow-up turns; abort/stale-request protection.
- `apps/web/src/RecentCaptures.tsx` (new) — accessible metadata-only popover and minimal rename/delete menu.
- `apps/web/src/api.ts` — validated calls/types for list, rename, and follow-up; reuse strict generated validators.
- `apps/web/src/useCase.ts` — same-window case switching and active conversation reset on case switch/deletion; keep existing deep-link/bookmark recovery.
- `apps/web/src/styles.css` — approved logo-led light palette, centered workspace, chat composer, quiet popover/drawer, responsive stacking and focus styles.
- `apps/web/public/brand/wireclaw-logo.jpeg` — add the exact supplied logo asset byte-for-byte to this branch if absent; do not redraw or substitute it.
- `apps/web/tests/api.test.ts`, `apps/web/tests/app.test.tsx`, `apps/web/tests/workflow.e2e.ts` — contract/UI/E2E additions and existing evidence/Wireshark regression updates.

### Independent qualification correction

- `scripts/native_embedded_ai_qualification.py` — EAI.14-08 operator-evidence validator and deterministic sanitized report projection.
- `tests/packaging/test_native_qualification.py` — failing regression first, then focused validator correction. This remains a separate task but is committed on the same branch as the product changes.

---

## Task 1: Correct and regression-test EAI.14-08 operator evidence validation (separate qualification task)

**Files:**
- Modify: `scripts/native_embedded_ai_qualification.py`
- Test: `tests/packaging/test_native_qualification.py`

**Interfaces:**
- Consumes the existing frozen-candidate operator manifest and candidate-bound case reports.
- Produce exactly one report JSON each for `high_rtt`, `server_wait`, and `midstream`, plus the comparison artifact. Operators generate each JSON with the qualification script's report-projection CLI from the actual saved completed report and frozen candidate metadata; they do not hand-create or edit the projection. The helper derives `conclusion_type`, findings, and evidence IDs and records the source report digest. The validator requires `conclusion_type` on all three artifacts and verifies the projected content against the source report during projection. Findings must be non-empty except for `server_wait` with `insufficient_evidence`; zero findings in every other case/conclusion combination fail. Preserve candidate/model/runtime identity, original-capture hash equality, case identity, and case-local evidence-ID checks.
- The projection output has exactly these fields: `schema_version`, `case_id`, `conclusion_type`, `candidate_identity_sha256`, `model_sha256`, `llama_server_sha256`, `provider_mode`, `source_report_sha256`, `original_capture_sha256_before`, `original_capture_sha256_after`, `evidence_ids`, and `findings`. Compute `source_report_sha256` from canonical JSON serialization of the actual completed report. Derive `conclusion_type` from `report["conclusion"]["type"]`, findings from `report["findings"]` (`id` mapped to `finding_id`), and `evidence_ids` as the unique union of evidence-ID arrays in the report.
- This is qualification tooling only; it changes no app/API semantics. It is committed on the same branch and included in the final candidate source HEAD.

- [ ] **Step 1: Add failing EAI.14-08 tests first** named `test_eai14_08_projection_cli_derives_conclusion_from_actual_report`, `test_eai14_08_accepts_server_wait_insufficient_evidence_with_zero_findings`, `test_eai14_08_rejects_server_wait_zero_findings_with_other_conclusion`, `test_eai14_08_rejects_zero_findings_for_other_cases`, and `test_eai14_08_requires_conclusion_type_for_all_case_artifacts`. Use canonical completed report fixtures; assert the CLI has no conclusion override and the projected type equals `report["conclusion"]["type"]`. Retain candidate/runtime/hash/evidence assertions.
- [ ] **Step 2: Run `pytest tests/packaging/test_native_qualification.py -k 'operator_workflow or eai14_08' -q`** and verify failure is the zero-findings validator condition, not fixture/setup error.
- [ ] **Step 3: Add `project_eai14_08_case_report(report: dict, identity: dict, capture_sha256_before: str, capture_sha256_after: str) -> dict` and a CLI mode** in `scripts/native_embedded_ai_qualification.py`. The invocation is `python scripts/native_embedded_ai_qualification.py --project-eai14-08-report <actual-report.json> --candidate-bundle <bundle-path> --candidate-archive <archive-path> --candidate-metadata <metadata.json> --capture-sha256-before <sha256> --capture-sha256-after <sha256> --output <case-id>.json`. Compute candidate identity from the supplied frozen candidate; derive all report fields from the loaded JSON; accept no `conclusion_type` argument.
- [ ] **Step 4: Update the validator** to require the exact projected fields for all three cases, including `source_report_sha256` and `conclusion_type`; allow empty findings only for `server_wait` whose conclusion matches the derived source report; preserve path confinement, candidate identity, runtime hashes, capture hashes, case ID, and evidence membership checks.
- [ ] **Step 5: Run `pytest tests/packaging/test_native_qualification.py -k 'operator_workflow or eai14_08' -q` and `pytest tests/packaging/test_native_qualification.py -q`.**
- [ ] **Step 6: Record which candidate-bound EAI.14-08 evidence must be regenerated**; do not alter the frozen V1 acceptance record.

**Current inspection note:** The validator rejects any report with an empty `findings` list. The operator JSON currently contains only a manually assembled summary, so Task 1 adds a deterministic projection from the canonical completed case report before allowing the valid zero-finding `server_wait` result. The same strict derived artifact schema applies to all three EAI.14-08 reports.

---

## Task 2: Add bounded recent-case metadata, migration, and rename API

**Files:**
- Modify: `services/api/src/wireclaw_api/storage.py`, `models.py`, `service.py`, `app.py`
- Modify: `contracts/api.openapi.json`
- Regenerate: `apps/web/src/generated/api.ts`, `validators.js`, `validators.d.ts`
- Test: `tests/integration/test_api.py`

**Interfaces:**
- `POST /api/cases` accepts the optional safe `capture_name` metadata from `File.name`; it is a display label only and never a path.
- `GET /api/cases?limit=10` returns at most 10 recent cases ordered by `updated DESC, id DESC`, each with `{id, name, capture_bytes, created, updated, state}`. Derive `capture_bytes` from the existing registered original artifact. No symptom, path, report, evidence, or artifact contents.
- `PATCH /api/cases/{case_id}` accepts strict `{display_name: string}` (trimmed, non-empty, at most 120 characters, control characters rejected); updates only case metadata and timestamp. Existing delete endpoint remains the deletion behavior.
- Schema migration adds capture name/display name metadata and safely backfills old cases with a non-path fallback. Preserve all current records/artifacts and transactional schema-version behavior.

- [ ] **Step 1: Add failing API tests first**: `test_case_metadata_migration_backfills_existing_cases`, `test_recent_cases_returns_bounded_metadata_without_sensitive_fields`, `test_case_capture_name_is_safe_display_metadata`, `test_rename_case_changes_label_without_renaming_files_or_artifacts`, `test_rename_unknown_case_returns_not_found`, and `test_rename_invalid_display_name_returns_422_invalid_request`.
- [ ] **Step 2: Run `pytest tests/integration/test_api.py -q`** and confirm the new endpoint/migration assertions fail for the expected missing behavior.
- [ ] **Step 3: Implement migration and strict metadata models**; ensure case creation remains backward-compatible when `capture_name` is omitted.
- [ ] **Step 4: Implement list and rename service methods and routes**; use parameterized SQL, bounded results, and no file operations.
- [ ] **Step 5: Update `contracts/api.openapi.json` and regenerate TS contracts/validators** using `npm run contracts --prefix apps/web`.
- [ ] **Step 6: Run `pytest tests/integration/test_api.py -q` and `python -m pytest tests/unit/test_api_boundary.py -q`**; confirm old case GET/report/evidence/delete behavior is unchanged and rename validation returns `{ "error": { "code": "invalid_request" } }` with HTTP 422.

---

## Task 3: Add bounded, non-authoritative follow-up API

**Files:**
- Create: `services/api/src/wireclaw_api/reasoning/followup.py`
- Modify: `services/api/src/wireclaw_api/models.py`, `services/api/src/wireclaw_api/app.py`, `contracts/api.openapi.json`
- Regenerate: `apps/web/src/generated/api.ts`, `validators.js`, `validators.d.ts`
- Test: `tests/integration/test_gate7.py`, `tests/integration/test_api.py`

**Interfaces:**
- `POST /api/cases/{case_id}/followups` request: strict `{question: string}` with 1–2,000 trimmed characters, bounded by the existing JSON request limit. The provider request is assembled only from this question, sanitized symptom, active case ID, normalized completed report, and normalized evidence. It has no `history`/`messages` field and receives no previous follow-up turns.
- Response: strict `{answer: string, evidence_ids: string[]}` with a 4,000-character answer cap and de-duplicated IDs; empty citations are allowed only when the answer explicitly says the available evidence cannot answer.
- Resolve case, current completed report, and evidence on the server. Build context from the existing normalized report/evidence projection plus sanitized case symptom and the current question; enforce existing provider request/response/time limits. Every call is stateless. The frontend may keep turns for display during the active UI session, but neither the client request nor server provider context includes earlier turns.
- Use the configured existing provider boundary. With `provider_mode=none`, return an explicit `followup_unavailable` response/error; do not produce canned simulated assistant output.
- Require the provider to answer only from the supplied normalized report/evidence and state when they cannot support an answer; validate every citation against evidence IDs belonging to that case. Treat provider prose as explanatory only; no case/report/evidence mutation or capability execution.
- Do not persist prompts/responses or log question/answer content. Keep capture bytes/payloads out of context.

**Exact error contract:** All errors use the existing `{ "error": { "code": "..." } }` envelope and never include provider output, model/runtime details, secrets, or question text.

| Condition | HTTP | Error code |
|---|---:|---|
| Valid-format unknown case ID | 404 | `case_not_found` |
| Case is not complete | 409 | `report_not_ready` |
| Completed case has no report artifact | 404 | `report_not_found` |
| Rules-only (`provider_mode=none`) | 409 | `followup_unavailable` |
| Embedded/provider unavailable or provider failure other than timeout/invalid response | 503 | `provider_unavailable` |
| Provider timeout | 504 | `provider_timeout` |
| Malformed provider output or citation outside this case's evidence IDs | 502 | `followup_response_invalid` |
| Missing, blank, over-2,000-character, or schema-invalid question | 422 | `invalid_request` |
| Rename name missing, blank, over 120 characters, or containing controls | 422 | `invalid_request` |

An over-limit HTTP body continues to use the existing boundary response `413 request_size_limit`. Error response bodies and logs contain codes only; question and answer content are never logged.

- [ ] **Step 1: Add failing provider/API tests first**: `test_followup_unknown_case_returns_404_case_not_found`, `test_followup_incomplete_report_returns_409_report_not_ready`, `test_followup_missing_report_returns_404_report_not_found`, `test_followup_rules_only_returns_409_followup_unavailable`, `test_followup_provider_unavailable_returns_503_without_details`, `test_followup_provider_timeout_returns_504_provider_timeout`, `test_followup_malformed_provider_response_returns_502_followup_response_invalid`, `test_followup_invalid_citations_return_502_followup_response_invalid`, `test_followup_invalid_question_returns_422_invalid_request`, `test_followup_uses_only_normalized_active_case_context`, `test_followup_request_excludes_previous_turns`, `test_followup_rejects_unknown_and_cross_case_evidence_ids`, `test_followup_bounds_question_and_answer`, `test_followup_reports_provider_failure_without_logging_content`, and `test_followup_does_not_mutate_report_or_evidence`.
- [ ] **Step 2: Run `pytest tests/integration/test_gate7.py tests/integration/test_api.py -q`** and confirm failures are limited to the missing follow-up contract/behavior.
- [ ] **Step 3: Implement strict follow-up models and `reasoning/followup.py`**, reusing existing provider factory and bounded serializer; add no analyzer capabilities or host-bridge calls.
- [ ] **Step 4: Add the case-scoped API route** and stable safe error codes without logging prompt or response text.
- [ ] **Step 5: Update OpenAPI snapshot and regenerate TS contracts.**
- [ ] **Step 6: Run `pytest tests/integration/test_gate7.py tests/integration/test_api.py tests/unit/test_reasoning.py -q`** and existing privacy/context boundary regressions.

**Statelessness assertion:** The API test inspects the provider request and proves it contains only the active case's normalized report/evidence, sanitized symptom, and current question. A second request after a visible UI turn must have no prior question or answer in its payload. The UI retains prior turns only in browser memory and clears them on case switch/discard.

**Error regression:** Each status/code row above is asserted by a named API test, including the existing generic `invalid_request` behavior for Pydantic request validation and the existing `case_not_found`, `report_not_ready`, and `report_not_found` conventions.

---

## Task 4: Replace the production intake/report shell with the approved single-window conversation UI

**Files:**
- Modify: `apps/web/src/App.tsx`, `Intake.tsx`, `Progress.tsx`, `ReportView.tsx`, `EvidenceDrawer.tsx`, `Dialog.tsx`, `useCase.ts`, `api.ts`, `styles.css`
- Create: `apps/web/public/brand/wireclaw-logo.jpeg` (byte-for-byte supplied asset); if separation keeps code smaller, create `apps/web/src/Conversation.tsx`.
- Test: `apps/web/tests/app.test.tsx`, `api.test.ts`, `workflow.e2e.ts`

**Interfaces:**
- Continue using existing `useCase.start(file, symptom)`, capture limits, upload/investigate/get/report state transitions, and evidence drawer APIs.
- Composer submits the required symptom before investigation and follow-up question after a report is available; attachment uses the same validated file intake.
- Processing copy is derived from persisted lifecycle state and accessible status semantics; no percentage is introduced.
- Follow-up UI exists only when provider mode supports it; the conversation surface renders returned answer/citations without treating them as report findings.
- The browser may display prior turns during the active session but calls the API with only the current `{question}`; no prior turn is sent or used as model context.

- [ ] **Step 1: Add failing component tests** for empty state controls, required symptom gating, drag-over/file attachment, one-line processing, conclusion-first report, uncertainty/evidence, disabled rules-only chat, visible follow-up turn retention, and `followup_ui_retains_visible_turns_but_sends_only_current_question`.
- [ ] **Step 2: Run focused Vitest tests and confirm the current multi-section UI fails the new structure assertions.**
- [ ] **Step 3: Recompose `App.tsx` into one header/main conversation/composer**; keep bookmark recovery and existing recoverable case errors reachable without a second dashboard surface.
- [ ] **Step 4: Adapt `Intake` and `Progress`** to the approved compact states while retaining file validation, required symptom, state truth, and status announcements.
- [ ] **Step 5: Adapt `ReportView` and add `Conversation` turns** using only current report fields and validated follow-up response data; preserve conclusion/confidence/limitations/next validation semantics.
- [ ] **Step 6: Apply visual tokens and responsive layout in `styles.css`** and reuse exact `apps/web/public/brand/wireclaw-logo.jpeg`; do not create a substitute mark.
- [ ] **Step 7: Run `npm test --prefix apps/web -- tests/app.test.tsx`, `npm run lint --prefix apps/web`, `npm run typecheck --prefix apps/web`, and `npm run build --prefix apps/web`.**

**Named UI tests to add first:** `renders_minimal_empty_capture_state_and_requires_symptom_before_send`, `shows_compact_processing_from_api_state_without_percentage`, `renders_authoritative_conclusion_with_nearby_evidence_and_both_wireshark_actions`, `keeps_report_above_followup_turns`, `disables_followup_when_provider_mode_is_rules_only`, and `bookmarked_case_id_restores_existing_case_without_creating_a_case`.

---

## Task 5: Add recent-history popover and metadata actions

**Files:**
- Create: `apps/web/src/RecentCaptures.tsx`
- Modify: `apps/web/src/App.tsx`, `useCase.ts`, `api.ts`, `Dialog.tsx`, `styles.css`
- Test: `apps/web/tests/api.test.ts`, `app.test.tsx`, `workflow.e2e.ts`

**Interfaces:**
- Header icon calls the bounded list endpoint and opens a quiet popover; no route/page/sidebar.
- Each row shows effective name, size/date/state; Open selects the existing case and report behavior.
- Rename calls metadata-only PATCH. Delete invokes the existing confirmed delete behavior.
- Async list/rename/open requests are aborted or ignored when the popover/case changes.

- [ ] **Step 1: Add failing UI/API client tests** for bounded case list, open/recover without auto-investigation, rename, delete confirmation, empty/error states, and stale result suppression.
- [ ] **Step 2: Run tests and confirm expected missing-API/UI failures.**
- [ ] **Step 3: Add strict API client validation and `RecentCaptures` popover** with Escape close, focus return, and per-row minimal actions.
- [ ] **Step 4: Connect open/rename/delete to existing `useCase` behavior**, resetting only active unsaved chat turns on case switch.
- [ ] **Step 5: Run `npm test --prefix apps/web -- tests/api.test.ts tests/app.test.tsx` and the focused Playwright history workflow at desktop and 390px.**

**Named UI tests to add first:** `history_popover_lists_bounded_cases_and_opens_without_reinvestigating`, `rename_updates_only_case_display_name`, `history_delete_uses_existing_confirmation`, `history_popover_shows_empty_and_api_error_states`, `stale_history_or_followup_response_is_ignored_after_case_switch`, and `bookmarked_case_id_restores_existing_case_without_creating_a_case`.

---

## Task 6: Verify accessibility, responsive behavior, evidence, Wireshark, and qualification boundaries

**Files:**
- Modify: `apps/web/tests/workflow.e2e.ts`, relevant UI tests only if gaps are discovered.
- Read-only qualification references: `docs/v1-acceptance.md`, candidate-bound evidence under this same worktree.

- [ ] **Step 1: Add/adjust Playwright assertions** for keyboard upload, composer submit, history popover Escape/focus return, evidence drawer Escape/focus return, live processing/error status, rename/delete confirmation, and reduced-motion preference.
- [ ] **Step 2: Verify desktop, tablet, and 390px mobile** for no horizontal overflow, visible filename, stacked diagnostic values/actions, reachable evidence references, and unobscured composer.
- [ ] **Step 3: Regress evidence and Wireshark behavior**: exact paired button labels, display filter, evidence IDs/frame/scope/value/limitations, bridge unavailable behavior, original capture unchanged, and evidence drawer access while bridge is unavailable.
- [ ] **Step 4: Run `npm run format:check --prefix apps/web`, `npm run lint --prefix apps/web`, `npm run typecheck --prefix apps/web`, `npm run build --prefix apps/web`, `npm test --prefix apps/web`, and `npm run test:e2e --prefix apps/web`; run `pytest tests/integration/test_api.py tests/integration/test_gate7.py tests/unit/test_reasoning.py tests/unit/test_api_boundary.py -q`.** Run full repository tests per project verification after implementation; do not change analyzer golden data for this presentation/API work.
- [ ] **Step 5: Qualification decision:** leave `docs/v1-acceptance.md` unchanged. The frozen V1 candidate remains evidence for its exact old bytes only. Record that the redesigned UI/API package requires new current-candidate browser, persistence, privacy/provider, and paired native Wireshark checks. Do not freeze a candidate in this task; Task 7 creates the sole new candidate after exact-HEAD CI. Reuse no old candidate-bound evidence.
- [ ] **Step 6: Run and record the EAI.14-08 validator regression/correction from Task 1** in this same worktree and on this same branch.

**Named end-to-end tests to add first:** `single_window_capture_to_report_flow_has_no_dashboard_chrome`, `history_popover_and_evidence_drawer_are_keyboard_dismissible_and_restore_focus`, and `conversation_report_and_actions_have_no_overflow_at_390px`.

## Qualification impact

- **Frozen Gate 9/V1:** the accepted archived candidate and `docs/v1-acceptance.md` are not edited. Any artifact containing redesigned web/API bytes has a different identity; its acceptance cannot be claimed from the archived candidate's evidence. Re-run the applicable full current-candidate UI/API/privacy/persistence/Wireshark checks required for that release.
- **Embedded-AI candidate:** changed web/API/validator source invalidates all old candidate-bound evidence. Task 7 commits and pushes one final source HEAD, runs exact-HEAD CI, creates one new frozen candidate, runs three fresh benchmarks, and reruns the full EAI.14 sequence from the beginning. The validator correction is included in this same source HEAD and candidate.
- **No analyzer semantic change is planned.** Deterministic corpus requalification is not expanded by this UI work unless implementation review discovers a report/evidence contract change; stop and revise the plan/spec if that boundary is crossed.

## Task 7: Commit the single source branch and qualify one new final candidate

**Files:**
- Source commits include the UI, API, qualification validator, approved spec, and this plan from Tasks 1–6.
- Candidate-bound evidence is generated under the existing embedded-AI qualification evidence layout; do not copy candidate evidence from another worktree or source HEAD.
- Do not modify `docs/v1-acceptance.md` or perform public distribution/notarization work.

**Interfaces:**
- Source branch: `post-v1-embedded-ai-impl` in the linked `embedded-local-ai` worktree.
- Candidate identity is computed only after all source files, spec, and plan are committed and pushed, from the exact source HEAD.
- Every benchmark and EAI.14 artifact records that one candidate identity; no pre-change or other-worktree evidence is reused.

- [ ] **Step 1: Run the final repository validation suite** after Tasks 1–6 and resolve all failures before committing.
- [ ] **Step 2: Commit and push all final source changes** (UI, API, validator, supplied logo, spec, plan) on `post-v1-embedded-ai-impl`; verify a clean worktree with `git status --short`, record `git rev-parse HEAD`, and confirm the remote branch points to that SHA.
- [ ] **Step 3: Run CI against that exact pushed HEAD**; inspect the checks for the pushed commit and require all required jobs to pass before candidate creation.
- [ ] **Step 4: Create exactly one new frozen candidate** from that exact source HEAD using `python scripts/freeze_embedded_ai_candidate.py <bundle-path> <archive-path> --metadata artifacts/embedded-ai/candidate-freeze-final.json`; record candidate ID and identity digest. Do not freeze another candidate for this work.
- [ ] **Step 5: Run three fresh embedded-AI benchmark runs** against the same frozen candidate and retain outputs separately: `python scripts/benchmark_embedded_ai.py --ai-root <candidate-ai-root> --output-dir artifacts/embedded-ai/runs/final/run-1`, then repeat with `run-2` and `run-3`. Require all three candidate identity digests to match the frozen metadata; do not reuse prior benchmark runs.
- [ ] **Step 6: Rerun the full required EAI.14 qualification sequence from the beginning** against the same candidate, in declared order: EAI.14-01, -02, -03, -04, -05, -06, -07, -08, -09, -10, -11, -12, -13, -14, -15, and -16, plus all associated required sandbox/security checks. Collect fresh UI readiness evidence, all three report-derived EAI.14-08 artifacts plus human comparison, and EAI.14-09 paired Wireshark evidence. Run `python scripts/native_embedded_ai_qualification.py --candidate-bundle <bundle-path> --candidate-archive <archive-path> --candidate-metadata artifacts/embedded-ai/candidate-freeze-final.json --evidence-dir artifacts/embedded-ai/final-evidence --operator-evidence-dir <fresh-operator-evidence-dir> --output artifacts/embedded-ai/final-qualification.json`. Regenerate all candidate-bound evidence; reuse none from the old candidate.
- [ ] **Step 7: Record internal-use qualification results and the single final candidate identity.** This is internal use only; perform no public-distribution or notarization work.
