# Wireclaw UI Finishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the current Wireclaw conversational UI by fixing the packaged logo, replacing the wave with a quick playful snapping lobster claw, making Technical Evidence human-first, and keeping raw follow-up evidence IDs out of the visible answer while preserving access to the cited evidence.

**Architecture:** Keep the existing conversational app and deterministic/AI boundaries unchanged. Make this a presentation-only slice: React/CSS components consume the same API contracts, the evidence drawer progressively discloses raw metadata, and the packaged web server explicitly proves the brand asset is shipped and served.

**Tech Stack:** React + TypeScript, CSS, Vitest/Testing Library, Playwright production-browser tests, FastAPI static web serving, existing Vite build/release packaging.

**Spec:** `docs/superpowers/specs/2026-10-20-wireclaw-ui-redesign.md` plus the approved 2026-10-22 UI addendum decisions in the Case Manager design discussion.

## Global Constraints

- Do not change deterministic analyzer conclusions or evidence generation.
- Do not weaken follow-up evidence-ID validation or provider safety boundaries.
- Do not expose raw evidence IDs in the normal conversational answer; cited evidence must remain reachable through Technical Evidence.
- The thinking indicator is visual-only: no sound.
- The claw motion is quick and playful/cartoon-like, with `prefers-reduced-motion` support.
- Preserve stage-driven status copy and relative motion intensity.
- The packaged candidate must return `/brand/wireclaw-logo.jpeg` with HTTP 200 and render the logo in a production browser.
- Technical Evidence must lead with human meaning and place raw analyzer/schema metadata behind progressive disclosure.

## Review Focus

- Packaged web root where `/brand/wireclaw-logo.jpeg` is absent or copied to the wrong path must fail a packaging/browser test.
- Follow-up answers with multiple evidence IDs must expose a single human-readable evidence action without printing raw IDs.
- Sparse evidence records must still render a useful human-first summary without crashing or inventing fields.
- Reduced-motion users must get a static claw/status instead of repeated snapping animation.
- Long raw IDs/filter strings must not overflow or control drawer width on desktop or mobile.

---

### Task 1: Lock the packaged brand asset contract

**Files:**
- Modify: `services/api/src/wireclaw_api/web.py`
- Modify: `tests/packaging/test_release_bundle_contract.py`
- Modify: `tests/integration/test_api.py`
- Modify: `apps/web/tests/workflow.e2e.ts`
- Verify: `apps/web/public/brand/wireclaw-logo.jpeg`

**Interfaces:**
- Consumes: Vite public asset copied to `dist/brand/wireclaw-logo.jpeg`.
- Produces: packaged GET `/brand/wireclaw-logo.jpeg` -> `200 image/jpeg` with existing security headers.

- [ ] **Step 1: Write failing tests** that assert the release bundle contains `web/brand/wireclaw-logo.jpeg` (or the actual packaged web-dist location used by the release contract), the API returns it with 200/image/jpeg, and the production browser reports the header image loaded successfully (`naturalWidth > 0`).
- [ ] **Step 2: Run the focused packaging/integration/browser tests and verify RED** because the current deployed candidate can show a broken logo.
- [ ] **Step 3: Implement the smallest packaging/static-serving fix** so the existing approved logo asset is copied into the production web dist and served only through the dedicated safe route; do not add directory browsing or broaden the asset allowlist.
- [ ] **Step 4: Re-run the focused tests and verify GREEN.**
- [ ] **Step 5: Commit** with a focused message such as `fix: ship Wireclaw logo in packaged web build`.

### Task 2: Replace ProcessingWave with a snapping lobster claw

**Files:**
- Modify: `apps/web/src/Progress.tsx`
- Modify: `apps/web/src/styles.css`
- Modify: `apps/web/tests/app.test.tsx`
- Modify: `apps/web/tests/workflow.e2e.ts`

**Interfaces:**
- Consumes: existing `ProcessingWave({ label, motion, testId })` call sites and `motion` values `calm|moderate|reasoning|settling`.
- Produces: the same component API rendered as an accessible status plus a blue lobster-claw SVG whose movable jaw snaps open/closed.

- [ ] **Step 1: Write failing component/browser tests** asserting the status text remains live, the visual is aria-hidden, the claw element exists, motion classes vary by stage, and reduced-motion disables the repeated transform animation.
- [ ] **Step 2: Run the focused tests and verify RED** against the current wave paths.
- [ ] **Step 3: Implement a simple inline SVG claw** with a fixed palm/lower jaw and one transformable jaw. Use a fast-close/brief-recoil/open/pause keyframe; target roughly 0.6-0.8 s for `reasoning`, slower multipliers for calm/settling, and no sound.
- [ ] **Step 4: Add `prefers-reduced-motion: reduce` CSS** that leaves a static recognizable claw while preserving the textual status.
- [ ] **Step 5: Run component and production-browser tests and verify GREEN.**
- [ ] **Step 6: Commit** as `feat: use snapping claw progress indicator`.

### Task 3: Make Technical Evidence human-first

**Files:**
- Modify: `apps/web/src/EvidenceDrawer.tsx`
- Modify: `apps/web/src/styles.css`
- Modify: `apps/web/tests/app.test.tsx`
- Modify: `apps/web/tests/workflow.e2e.ts`

**Interfaces:**
- Consumes: existing `Evidence` contract (`id`, `category`, `summary`, `epistemic_class`, `source`, `scope`, `frame_refs`, `display_filter`, `value`, `limitations`).
- Produces: human-first drawer sections: title/evidence class, `What this shows`, connection/packet details when derivable, `Measurements`, `Inspect in Wireshark`, limitations, and collapsed `Raw record`.

- [ ] **Step 1: Write failing tests** for a TCP-establishment record asserting: `Technical evidence` title; human title `TCP connection setup`; `Derived evidence`; combined Client and Server endpoint values; packets shown as a compact range/list; `Measurements`; display filter visible under `Inspect in Wireshark`; raw evidence ID/capability/tool metadata hidden until `Raw record` is expanded.
- [ ] **Step 2: Add failing tests for sparse/capture-quality evidence** proving the drawer falls back to safe generic labels and never invents client/server roles when scope is insufficient.
- [ ] **Step 3: Run tests and verify RED.**
- [ ] **Step 4: Refactor rendering helpers inside `EvidenceDrawer.tsx`** to derive display title, evidence-class label, endpoint grouping, frame summary, and prioritized measurements from existing fields only. Keep the complete raw record available in a disclosure.
- [ ] **Step 5: Add a copy-filter action** using browser clipboard APIs only; keep the existing filter text visible and do not introduce arbitrary command execution.
- [ ] **Step 6: Update drawer CSS** to ~480-560 px desktop width, grouped sections, wrapped code/IDs, and full-width/mobile-sheet behavior.
- [ ] **Step 7: Run unit/browser tests and visually inspect TCP establishment, TCP health/retransmission, capture quality, and sparse evidence on desktop/mobile.**
- [ ] **Step 8: Commit** as `feat: simplify technical evidence presentation`.

### Task 4: Hide raw evidence IDs from conversational follow-up answers

**Files:**
- Modify: `apps/web/src/Conversation.tsx`
- Modify: `apps/web/src/styles.css`
- Modify: `apps/web/tests/app.test.tsx`
- Modify: `apps/web/tests/workflow.e2e.ts`

**Interfaces:**
- Consumes: `Followup.answer` and `Followup.evidence_ids` plus existing `onEvidence(ids)` callback.
- Produces: plain answer prose plus one compact human action such as `View supporting evidence (2)` that opens all cited records through the existing drawer.

- [ ] **Step 1: Write a failing test** that a follow-up with two evidence IDs renders the answer and `View supporting evidence (2)` but does not render either raw `ev_...` string in the conversation.
- [ ] **Step 2: Run test and verify RED.**
- [ ] **Step 3: Replace the per-ID button list** with one human-readable button calling `onEvidence(turn.response.evidence_ids)`; omit it when the array is empty.
- [ ] **Step 4: Run unit/browser tests and verify GREEN, including keyboard activation and evidence drawer opening.**
- [ ] **Step 5: Commit** as `fix: keep followup evidence ids out of prose`.

### Task 5: Full UI/release verification

**Files:**
- No production files unless verification exposes a regression.
- Test/fixture updates only as required by real behavior.

**Interfaces:**
- Consumes: Tasks 1-4.
- Produces: a clean UI-finishing commit range safe to layer the multi-capture work on top of.

- [ ] **Step 1: Run the full frontend unit suite.** Expected: all pass.
- [ ] **Step 2: Run production build, typecheck, lint, formatting check, and `git diff --check`.** Expected: all pass.
- [ ] **Step 3: Run the full production-browser suite.** Expected: all pass, including packaged logo and sticky composer clearance.
- [ ] **Step 4: Run applicable Python packaging/integration tests for static asset serving.** Expected: all pass.
- [ ] **Step 5: Visually inspect the production build** for logo, snapping-claw states, Technical Evidence, follow-up supporting-evidence action, desktop and narrow/mobile layouts.
- [ ] **Step 6: Commit any test-only final adjustments, then leave the tree clean.**
