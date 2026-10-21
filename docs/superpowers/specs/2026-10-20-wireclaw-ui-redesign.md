# Wireclaw conversation-first UI redesign

**Status:** Approved for implementation; Tasks 1–6 implemented and Task 7 qualification in progress.
**Audience:** Implementers of the existing Wireclaw application.
**Visual source of truth:** User-approved single-window prototype at `/private/tmp/wireclaw-chat-prototype/index.html`, together with the approved concept image and `apps/web/public/brand/wireclaw-logo.jpeg`. The disposable prototype is a reference, not production code.

## 1. Product direction

Wireclaw is a focused assistant for packet captures. Its main experience is a single, simple chatbot-style window that moves naturally from capture intake to processing, analysis, and evidence-grounded follow-up. The UI must not become a dashboard, multi-page workflow, tabbed workspace, or permanent technical sidebar. The prior Hallmark investigation-workspace alternative is not the approved direction.

The interface stays minimal while keeping packet facts, uncertainty, evidence references, and existing Wireshark actions authoritative and available. Conversation text explains the report; it never becomes packet evidence or changes analyzer conclusions.

## 2. Approved visual structure

### Window and header

- One primary Wireclaw window and one continuous conversation/workspace.
- No product navigation bar, prototype state tabs, dashboard tiles, permanent sidebar, settings clutter, or simultaneous screens.
- Compact header: exact supplied logo at upper left; truthful provider/local status and one lightweight recent-captures icon at upper right.
- Use a white or very light cool background, navy text and structure, red sparingly as the primary accent, and orange only for small secondary emphasis. Preserve semantic status colors and accessible contrast.
- Keep borders quiet, use whitespace and dividers, and reserve soft shadows for the composer and lightweight history/evidence overlays when useful.

### Empty state and composer

- Center a compact capture icon/drop area labeled “Drop PCAP or PCAPNG” with a clear “Choose file” action. Avoid a large technical form or long explanatory text.
- Keep the bottom composer in the same window, with attachment on the left and send on the right. It may guide or disable submission until the required symptom is supplied, matching actual product behavior.
- Treat the symptom as context, never as packet evidence. Show local-storage/privacy language only where it is accurate.

### Capture, processing, and analysis

- After selection, replace the large drop area with a compact filename/size row and a supported replace action.
- Keep processing to one short, state-derived status line such as “Reading capture · Finding relevant signals,” with a subtle activity indicator. Do not show estimated percentages or decorative progress panels. The underlying persisted API lifecycle remains authoritative; errors and validation remain recoverable.
- Present a concise assistant-style answer in the conversation: conclusion first; confidence/basis and limitations immediately below when useful; evidence reference beside its claim; one recommended next validation; then small disclosures for deeper technical detail.
- Keep follow-up questions and responses as ordinary conversation turns below the report, retaining the report above as context. Replies must be concise, bounded to the active report and normalized cited evidence, and explicit when evidence cannot answer the question.
- Do not add packet-layer attribution unless the active report provides it. Do not infer a layer from protocol labels or color.
- For packet-level findings where inspection applies, preserve both exact actions, **Open Full Capture in Wireshark** and **Open Evidence Capture in Wireshark**, and expose the associated display filter and packet/stream evidence.

### Evidence and history

- Keep concise evidence references near supported claims. Activating one opens the existing detailed evidence view/drawer with normalized values, epistemic class, tool/version, frame references, scope, display filter, and limitations.
- Deeper details remain available on demand and must not dominate the initial answer.
- Open a quiet recent-captures popover/sheet from the single header history icon. Show a bounded recent list with display/original filename, size, date, and status as available. Opening a case restores its existing report/case state; it does not start a new investigation automatically.
- Rename is a metadata-only case action. Delete uses the existing confirmed case-deletion behavior. Keep both inside a per-case overflow action, not as prominent primary controls.

### Responsive and accessible behavior

- Preserve a single reading column on desktop, tablet, and mobile; no horizontal overflow.
- On narrow screens, stack diagnostic values and Wireshark actions, retain reachable evidence references, and show history/evidence as compact overlays or sheets.
- All controls must be keyboard-operable with visible focus. Announce processing, validation, completion, and errors through appropriate status/live regions. Escape closes overlays and focus returns to the invoking control. Respect reduced-motion preferences and maintain usable touch targets.

## 3. Existing capability map and product/API gaps

Confirmed in the current React/Vite UI and loopback FastAPI service:

- `Intake` accepts one `.pcap`/`.pcapng` capture by file picker or drag/drop; it obtains the configured size limit, validates selection, requires a symptom, and submits through the existing case/create, capture/upload, and investigate sequence.
- `useCase` recovers a case using the `#case=<id>` bookmark or case ID, polls persisted lifecycle state, and only publishes reports from matching completed case snapshots.
- `Progress` renders persisted API lifecycle stages without estimated progress.
- `ReportView` renders the authoritative report, confidence, fault domain, capture quality, evidence references, next validation, filter, and applicable paired Wireshark actions.
- `EvidenceDrawer` loads the normalized evidence record, including epistemic class, provenance/tool version, frame references, scope, values, filter, and limitations.
- Confirmed case deletion exists and uses a confirmation dialog. The exact logo exists at `apps/web/public/brand/wireclaw-logo.jpeg`.
- The API and provider layer already support bounded optional reasoning during investigation. That flow is not a follow-up conversation endpoint and must not be repurposed to change report semantics.

Not currently supported and therefore requiring product/API work before being exposed as functional UI:

1. **Follow-up questions:** no case-scoped user-question endpoint or validated response contract exists. Add a bounded endpoint using the existing configured provider boundary, reusing the normalized report/evidence context projection. Provider responses are explanation only; accept only citations that match evidence IDs for that case. No packet payload/raw capture, new analyzer capability, evidence creation, or lifecycle action is available to chat. Do not persist raw prompts/responses in SQLite, reasoning audit, or logs. In rules-only mode, clearly disable or explain unavailable follow-up rather than fabricating a reply.
2. **Recent-case browsing:** there is no list endpoint, and the cases table does not retain the capture's display filename/size as list metadata. Extend case metadata with a safe client filename and optional display name, then add a bounded `GET /api/cases?limit=10` returning only case ID, effective display name, capture size, created/updated timestamps, and lifecycle state. Do not return paths, symptoms, report/evidence content, or raw artifacts in the list. Reopening uses existing case GET/report behavior.
3. **Rename/history actions:** no rename API or persistent display name exists. Add a strict `PATCH /api/cases/{case_id}` metadata-only rename that validates a bounded plain display name and never renames files or artifacts. Use existing `DELETE /api/cases/{case_id}` for removal after the existing confirmation flow. No conversation-history persistence is added; follow-up turns live in the active browser conversation only and reset when that conversation is discarded.

The recent list's `capture_name` is client-supplied display metadata only: validate length and controls, reduce to a basename, and never use it to construct a filesystem path or command. Persist case display metadata in a schema migration that preserves existing records; old rows receive a safe fallback display name. Generated API contracts must be regenerated from the checked-in OpenAPI snapshot.

## 4. Architecture and safety boundaries

- Keep `apps/web` presentation and interaction only; it calls the existing loopback API and never runs TShark/Zeek.
- Keep `services/api` responsible for case metadata, list/rename, follow-up validation, persistence boundaries, and provider calls.
- Keep `services/analyzer` as the only source of deterministic packet facts. This redesign does not change analyzer logic, finding categories, confidence, evidence, or recommendations.
- Follow-up uses the existing provider interface and privacy policy. It receives only normalized case/report/evidence context plus the user's question; raw capture and payload bytes remain local and are not sent to providers. Evidence remains deterministic and authoritative; response citation IDs must be validated against the active case. Provider output is not appended to the authoritative report or qualification record.
- Keep host bridge responsibilities limited to native Wireshark launch. Do not route chat or model traffic through it.
- Preserve embedded/local AI packaging, runtime, authentication, sandboxing, fallback, provider identity, and qualification architecture. Do not add UI redesign behavior to those subsystems.
- Preserve original capture immutability, bounded case/API behavior, evidence access, and the paired Wireshark contract.
- No packet-layer map is required. Render layer attribution only if the existing report explicitly supplies it.

## 5. Implementation acceptance

1. The production UI matches the approved prototype's single-window chatbot-style flow and exact supplied logo; no product tabs, dashboard, or permanent sidebar appear.
2. Empty, drag-over, file attached, processing, validation/error, completed report, expanded evidence/detail, follow-up, recent popover, rename/delete menu, and narrow-screen states remain in the same window.
3. Existing upload limits, persisted lifecycle/recovery, report content, evidence drawer, capture immutability, and paired Wireshark actions continue to work.
4. Follow-up is exposed only when the configured provider supports it; its API contract is bounded, case-scoped, prompt-injection-aware, and validates citations against deterministic evidence. It cannot request tools, change reports, or create packet claims without citations.
5. Recent-case listing is bounded and metadata-only. Rename changes display metadata only; delete uses the existing confirmation and deletion semantics.
6. No unsupported packet-layer attribution, confidence, status, or analysis is introduced. Existing report fields remain the sole source of analysis semantics.
7. Keyboard navigation, visible focus, live-region status, overlay dismissal/focus return, contrast, reduced motion, and desktop/mobile overflow are verified.
8. Existing evidence and Wireshark browser/API regression checks pass.
9. The frozen V1 acceptance record remains historical and unchanged. Any new release/package candidate containing changed UI/API code is a new identity and cannot inherit candidate-bound qualification claims without applicable reruns.
10. The separate EAI.14-08 qualification-validator correction is test-first and isolated from application UI/API changes. It must preserve candidate-bound evidence validation and receive its own affected qualification rerun; it must not be mixed into conversation or report logic.

## 6. Verification

- Use TDD for follow-up, list/rename metadata, and the independent EAI.14-08 validator correction.
- Run focused API and UI tests for each new behavior, then the existing web lint/typecheck/build/unit/E2E and relevant API regression suites.
- Exercise keyboard-only upload, history, rename/delete, evidence opening/closing, and composer submission; confirm focus restoration, live announcements, contrast, and reduced-motion handling.
- Exercise desktop, tablet, and approximately 390px viewport; confirm no clipped evidence, actions, filename, popover, or composer.
- Regress the existing exact paired Wireshark actions, display filter, evidence references/frames/scope, bridge unavailable behavior, and evidence drawer while the bridge is unavailable.
- Treat any new frozen UI/API/EAI release bundle as a separate qualification candidate. Do not rewrite `docs/v1-acceptance.md` or claim old candidate evidence applies to changed bytes.
