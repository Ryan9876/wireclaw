# Wireclaw Case Manager and Multi-Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one Wireclaw case contain 1-4 independently analyzed PCAPs from labeled vantage points, correlate matching TCP traffic deterministically, and manage those captures from a persistent lower-left Case Manager.

**Architecture:** Preserve each PCAP as its own immutable source artifact and add explicit capture rows/provenance instead of merging files. Run the existing analyzer independently per capture, then run a case-level deterministic TCP correlation stage that produces provenance-rich cross-vantage evidence; the existing report/reasoning layer consumes that evidence and the UI manages capture lifecycle/labels through plural capture APIs.

**Tech Stack:** Python 3.11+, FastAPI, SQLite, existing `wireclaw_analyzer`, Pydantic, React + TypeScript, Vitest/Testing Library, Playwright, existing packaging/CI gates.

**Spec:** `docs/superpowers/specs/2026-10-22-case-manager-multicapture-design.md`

## Global Constraints

- Support 1-4 captures per case in v1.
- Vantage types: `unknown|client|network|server|other`; optional network subtype: Firewall, Router, Switch, Load balancer, Proxy, Wireless, Other network device.
- Unknown is valid and must not block analysis.
- Never physically merge PCAPs or erase source provenance.
- Existing single-capture cases must migrate/recover and continue working.
- Every per-capture run/evidence/artifact must remain attributable to its capture; case-level correlation evidence must cite contributing capture/evidence IDs.
- Changing vantage metadata must not re-ingest or re-run packet extraction; it re-runs only correlation/report work that depends on placement.
- Removing a capture removes its active evidence/correlation contribution and recomputes the case without deleting the case.
- Deterministic correlation/localization is authoritative; AI only explains the deterministic report in plain language.
- Do not infer packet loss/location from retransmission indicators alone.
- TCP first; unsupported/NAT-ambiguous cases must remain inconclusive rather than forcing correlation.
- Preserve existing host/origin, upload size/time, path-confinement, safe-error, and immutable-source security boundaries.

## Review Focus

- Migrating an existing schema-v3 case with one stored capture must produce exactly one capture row without losing artifact/evidence references.
- Two PCAPs containing unrelated or ambiguous TCP traffic must not be force-correlated merely because timing/ports look similar.
- Clock offsets larger than the claimed delay, or too few matched packets, must suppress cross-vantage timing localization.
- Removing/relabeling a capture after a completed report must invalidate only dependent correlation/report data while preserving unaffected per-capture evidence.
- A fourth capture must be accepted and a fifth rejected with a stable safe error without partially ingesting data.

---

### Task 1: Add the capture entity and migrate legacy cases

**Files:**
- Modify: `services/api/src/wireclaw_api/storage.py`
- Modify: `services/api/src/wireclaw_api/models.py`
- Modify: `tests/integration/test_api.py`
- Modify: `tests/integration/test_gate7.py`

**Interfaces:**
- Produces `captures` rows scoped by case and nullable `capture_id` provenance columns on per-capture records.
- Produces Pydantic/enum contracts `CaptureVantage`, `CaptureStatus`, `CaptureResponse`, `CreateCapture`, `UpdateCapture` used by later tasks.

- [ ] **Step 1: Write a failing schema-migration test** that builds a schema-v3 database with one legacy case/source artifact, opens it with the new Database, and asserts schema version 4 plus exactly one migrated capture preserving name, SHA, bytes, original artifact, and case ownership.
- [ ] **Step 2: Write failing model tests** for accepted/rejected vantage values, bounded capture/display names, optional network subtype, and the four-capture policy boundary where represented.
- [ ] **Step 3: Run focused tests and verify RED.**
- [ ] **Step 4: Implement schema version 4** by adding `captures(id, case_id, capture_name, display_name, original_artifact_id, sha256, bytes, vantage_type, vantage_subtype, status, last_error, created, updated)` plus indexes; add nullable `capture_id` columns/indexes to `artifacts`, `runs`, and `evidence`. Keep legacy case capture columns for compatibility during this version.
- [ ] **Step 5: Migrate each legacy case with an `original_id` to one capture row** using deterministic IDs/metadata and backfill matching artifact/run/evidence `capture_id` where ownership can be established safely; leave case-level/reasoning records null.
- [ ] **Step 6: Add strict capture models/enums** in `models.py`, including `unknown|client|network|server|other` and bounded network subtype values.
- [ ] **Step 7: Re-run focused migration/model tests and verify GREEN.**
- [ ] **Step 8: Commit** as `feat: add capture entities and provenance`.

### Task 2: Add plural capture lifecycle APIs with legacy wrapper compatibility

**Files:**
- Modify: `services/api/src/wireclaw_api/app.py`
- Modify: `services/api/src/wireclaw_api/service.py` and/or `gate7_service.py` following the existing ownership boundary
- Modify: `services/api/src/wireclaw_api/storage.py`
- Modify: `services/api/src/wireclaw_api/models.py`
- Modify: `tests/integration/test_api.py`
- Modify: `tests/integration/test_gate7.py`

**Interfaces:**
- Produces `POST /api/cases/{case_id}/captures` -> `CaptureResponse`.
- Produces `PUT /api/cases/{case_id}/captures/{capture_id}/data` for bounded octet-stream ingestion.
- Produces `PATCH /api/cases/{case_id}/captures/{capture_id}` and `DELETE .../{capture_id}`.
- Extends `CaseResponse` with `captures: list[CaptureResponse]`.
- Keeps `POST /api/cases/{case_id}/capture` as a first-capture compatibility wrapper.

- [ ] **Step 1: Write failing API tests** for create/list-in-case, upload data, metadata patch, delete, unknown case/capture, invalid vantage, wrong content type, and fifth-capture rejection with no partial row/artifact.
- [ ] **Step 2: Add failing compatibility tests** proving the legacy singular upload creates/uses the first explicit capture and old single-capture workflows still complete.
- [ ] **Step 3: Run focused tests and verify RED.**
- [ ] **Step 4: Implement service signatures** `create_capture(case_id, capture_name, vantage_type='unknown', vantage_subtype=None)`, `begin_capture_ingest(case_id, capture_id)`, `ingest_capture(case_id, capture_id, run_id, path)`, `update_capture(case_id, capture_id, ...)`, and `remove_capture(case_id, capture_id)` using existing admission/confinement/upload limits.
- [ ] **Step 5: Implement FastAPI routes** and return only code-only safe errors; use the same raw stream/time/size protections as the existing capture endpoint.
- [ ] **Step 6: Make `CaseResponse.captures` authoritative for new UI code** while continuing to populate legacy top-level capture fields from the first/primary capture where required by existing consumers during migration.
- [ ] **Step 7: Re-run API/gate tests and verify GREEN.**
- [ ] **Step 8: Commit** as `feat: add multi-capture case APIs`.

### Task 3: Scope analyzer runs and evidence to each capture

**Files:**
- Modify: `services/api/src/wireclaw_api/service.py`
- Modify: `services/api/src/wireclaw_api/gate7_service.py`
- Modify: `services/api/src/wireclaw_api/investigation.py`
- Modify: `services/api/src/wireclaw_api/reasoning/context.py`
- Modify: `tests/integration/test_gate7.py`
- Modify: `tests/integration/test_baseline.py`

**Interfaces:**
- Consumes: explicit `capture_id` from Task 2.
- Produces: per-capture analyzer runs/evidence/artifacts tagged with `capture_id`; case-level evidence keeps `capture_id=None` and explicit contributing provenance in its record.

- [ ] **Step 1: Write failing tests** that ingest two captures into one case, analyze both, and assert each run/evidence/source artifact is scoped to the correct `capture_id` with no cross-contamination.
- [ ] **Step 2: Write a failing reasoning-context test** proving provider context contains capture/vantage labels for supplied evidence without exposing paths or additional unallowlisted fields.
- [ ] **Step 3: Run tests and verify RED.**
- [ ] **Step 4: Thread `capture_id` through existing per-capture analysis/run/evidence registration paths** without changing analyzer semantics.
- [ ] **Step 5: Update context projection** to include bounded capture identity/vantage metadata needed to explain cross-vantage findings while preserving the existing allowlist/redaction model.
- [ ] **Step 6: Re-run focused tests and verify GREEN.**
- [ ] **Step 7: Commit** as `feat: scope analysis evidence by capture`.

### Task 4: Implement deterministic TCP correlation and clock alignment

**Files:**
- Create: `services/api/src/wireclaw_api/correlation.py`
- Modify: `services/api/src/wireclaw_api/investigation.py`
- Modify: `tests/unit/test_correlation.py`
- Modify: `tests/integration/test_gate7.py`
- Add/extend: deterministic synthetic multi-vantage fixtures under `tests/fixtures/` using existing fixture-generation conventions.

**Interfaces:**
- Produces `correlate_tcp(captures: list[dict], evidence: list[dict]) -> list[dict]` case-level correlation records.
- Produces `estimate_clock_alignment(matches: list[dict]) -> dict` with offset, uncertainty, matched-count, and usable flag.
- Correlation records contain contributing capture IDs, evidence IDs, matched packet/flow descriptors, limitations, and support metadata; they never invent packet facts.

- [ ] **Step 1: Write failing pure-unit tests** for exact preserved-tuple matching, direction normalization, multiple connection epochs, unrelated same-port traffic, ambiguous candidates, and capture labels that remain Unknown.
- [ ] **Step 2: Write failing clock-alignment tests** using matched observations with known offsets/jitter; assert robust offset/uncertainty and `usable=False` when sample count/uncertainty is inadequate.
- [ ] **Step 3: Write failing synthetic integration tests** for client+server captures showing the same delayed TCP handshake and for a deliberately non-correlatable pair.
- [ ] **Step 4: Run focused tests and verify RED.**
- [ ] **Step 5: Implement direction-normalized TCP candidate extraction/matching** preferring exact tuple + flags/sequence/ack/payload/order; use timing only as supporting evidence, never as the sole identity key.
- [ ] **Step 6: Implement robust clock offset estimation** from confidently matched packets using a median/trimmed estimator and bounded uncertainty; do not localize timing when uncertainty is material relative to the delay.
- [ ] **Step 7: Emit provenance-rich correlation records** rather than merged/synthetic packets.
- [ ] **Step 8: Re-run unit/integration tests and verify GREEN.**
- [ ] **Step 9: Commit** as `feat: correlate tcp across capture vantage points`.

### Task 5: Turn correlation into deterministic localization findings and support changes

**Files:**
- Modify: `services/api/src/wireclaw_api/investigation.py`
- Modify: report/ranking code in `services/api/src/wireclaw_api/gate7_service.py` or the existing report assembly owner
- Modify: `services/api/src/wireclaw_api/reasoning/followup.py`
- Modify: `tests/integration/test_gate4_report.py`
- Modify: `tests/integration/test_gate7.py`
- Modify: `tests/unit/test_reasoning.py`

**Interfaces:**
- Consumes: Task 4 correlation records.
- Produces: deterministic case-level findings such as server/listener-side delay, bounded path-segment concern, return-path delay, or inconclusive correlation; exposes why support changed and cites all contributing capture/evidence IDs.

- [ ] **Step 1: Write failing report tests** for: client+server both see SYN promptly then server SYN-ACK ~3.2 s later -> server/listener-side delay with stronger support; server sees prompt SYN-ACK but client much later -> return-path delay; missing/ambiguous matches -> inconclusive.
- [ ] **Step 2: Add failing tests** proving retransmission indicators alone still cannot establish physical loss/location and additional captures do not automatically raise support.
- [ ] **Step 3: Run tests and verify RED.**
- [ ] **Step 4: Implement localization rules** only for observation patterns explicitly supported by the spec; every conclusion must carry contributing capture/evidence provenance and limitations.
- [ ] **Step 5: Recompute case-level correlation/report after capture add/remove/vantage change** without re-running unaffected packet extraction.
- [ ] **Step 6: Ensure follow-up context can explain the cross-vantage finding in the existing plain-language bounded style** and still validates case-local evidence membership.
- [ ] **Step 7: Re-run report/reasoning tests and verify GREEN.**
- [ ] **Step 8: Commit** as `feat: localize issues with cross-vantage evidence`.

### Task 6: Add web API client support and persistent Case Manager

**Files:**
- Create: `apps/web/src/CaseManager.tsx`
- Modify: `apps/web/src/api.ts`
- Modify: `apps/web/src/useCase.ts`
- Modify: `apps/web/src/App.tsx`
- Modify: `apps/web/src/Conversation.tsx`
- Modify: `apps/web/src/styles.css`
- Modify: `apps/web/tests/api.test.ts`
- Modify: `apps/web/tests/app.test.tsx`

**Interfaces:**
- Consumes: plural capture APIs and `Case.captures` from Tasks 1-2.
- Produces: persistent lower-left Case Manager, drag/drop/add, per-capture status, vantage selector, optional network subtype, remove action, and session-local collapsed/expanded preference.

- [ ] **Step 1: Write failing API-client tests** for create/upload/update/remove capture and parsing `Case.captures` with strict contract validation.
- [ ] **Step 2: Write failing component tests** asserting the active case name/count, 1-4 capture rows, filename/size/status, Unknown default, vantage selection, network subtype reveal, add/drop behavior, remove confirmation, and collapse preference.
- [ ] **Step 3: Write failing tests** proving vantage changes call only metadata/correlation refresh paths and do not upload the file again; removing one capture leaves the case and remaining rows intact.
- [ ] **Step 4: Run focused tests and verify RED.**
- [ ] **Step 5: Implement typed API methods** in `api.ts` and capture operations/state refresh in `useCase.ts`.
- [ ] **Step 6: Implement `CaseManager.tsx`** as a lower-left floating dock (320-360 px expanded) with compact drop target, accessible controls, session-local collapse state, and mobile bottom-sheet/full-width behavior.
- [ ] **Step 7: Mount Case Manager in `App.tsx` without converting the report into a dashboard**; preserve the main conversational feed and composer layout.
- [ ] **Step 8: Route the composer attach action through the active Case Manager/multi-capture flow** rather than replacing the case.
- [ ] **Step 9: Run unit tests and verify GREEN.**
- [ ] **Step 10: Commit** as `feat: add persistent multi-capture case manager`.

### Task 7: Production-browser multi-capture workflow

**Files:**
- Modify: `apps/web/tests/workflow.e2e.ts`
- Modify/add: production test fixtures/helper routes as required by the existing e2e harness.

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: browser-level proof of capture management and cross-vantage report updates.

- [ ] **Step 1: Add a failing production-browser workflow** that creates one case, adds client and server synthetic captures, labels them, observes per-capture analyzed/correlated status, and receives the stronger deterministic localization finding.
- [ ] **Step 2: Add failing browser steps** that relabel a capture, confirm correlation/report recompute without file re-upload, then remove it and confirm support drops while the case remains.
- [ ] **Step 3: Add a failing fifth-capture UI test** showing the bounded limit before/with stable server rejection.
- [ ] **Step 4: Run e2e and verify RED, then make only integration/UI fixes required for the planned behavior.**
- [ ] **Step 5: Re-run e2e and verify GREEN on desktop and narrow/mobile Case Manager layouts.**
- [ ] **Step 6: Commit** as `test: qualify multi-capture case workflow`.

### Task 8: Full regression, CI, packaging, and real hands-on qualification

**Files:**
- No production changes unless a real regression is found; any fix requires its own failing regression first.

**Interfaces:**
- Consumes: all prior tasks plus the UI-finishing plan.
- Produces: one clean branch candidate ready for packaging/freeze only after hands-on validation.

- [ ] **Step 1: Run full Python unit/integration/packaging suite.** Report all skips/warnings/failures accurately.
- [ ] **Step 2: Run Ruff, Python formatting check, web lint/typecheck/build, changed-file formatting, and `git diff --check`.**
- [ ] **Step 3: Run full frontend unit and production-browser suites.**
- [ ] **Step 4: Run exact-head Gate 6 validation and require all jobs green.**
- [ ] **Step 5: Package a fresh commit-derived candidate only after CI is green; verify provider timeout remains 120 seconds and `/brand/wireclaw-logo.jpeg` returns 200.**
- [ ] **Step 6: Hands-on single-capture regression:** run the original synthetic SYN-delay PCAP, confirm deterministic report, ask the client/path/server follow-up, and require a concise plain-language AI answer with no raw evidence IDs in prose.
- [ ] **Step 7: Hands-on multi-capture qualification:** add corresponding client/server (and optional network) synthetic captures, label vantage points, verify correlation status and stronger localization, inspect Technical Evidence provenance, then remove/relabel one capture and verify the report/support updates correctly.
- [ ] **Step 8: Stop the candidate cleanly. Do not freeze if any qualification criterion fails.**
- [ ] **Step 9: If all criteria pass, use the repository's established freeze workflow exactly; do not invent a new freeze command.**
