# Gate 5 verification — local web workflow

Date: 2026-10-09. PR: [#6](https://github.com/Ryan9876/wireclaw/pull/6).
Branch: `gate5-web-ui`. Status: implemented, validated and separately reviewed;
open and unmerged for owner merge approval.

Final validated product commit: `187ec13861fec504bb0ae37669f81d18d6cf35c3`.
Closeout changes after that commit only record verification and check Gate 5 tasks.

## Gate 4 prerequisite

Independently checked PR #5 head `b32980aa3beed3ef5009878be1d42c00888cdd4e`
against expected Gate 3 main `da324413fc7a24845ce4add93a30d2ab3cf1be86`.
The closeout-only delta after its validated product commit contained no unexpected
product changes or temporary CI/remediation helpers. G4.1–G4.8 were checked;
Gate 5+ tasks were unchecked. Reproduced 390 Python tests with real packet tools
and no skips, including regression coverage for all five prior blockers:
completed-report invalidation, protocol-general candidates without stream IDs,
DNS symptom linkage, explicit bounded truncation and TLS repeated-attempt timing.

Merged PR #5 using the repository's merge convention and expected-head check.
Resulting main: `41a3050085f96f038a955462d4656f4419a36d07`.
Gate 5 started from this merged main, preserving the Gate 4 verification record.

## Scope and mapping

| Task | Implementation / verification |
| --- | --- |
| G5.1 | React/TypeScript, pinned npm lockfile, generated contracts, production Vite build |
| G5.2 | Single-file drop/select, file size/empty/multiple selection checks, actual API size limit, backend format validation |
| G5.3 | Labeled bounded symptom input, visible context-is-not-evidence qualification |
| G5.4 | Persisted eight-state lifecycle/history and running records; no fabricated percentages |
| G5.5 | Backend conclusion, confidence, fault domain and capture quality; insufficient evidence is a completed result |
| G5.6 | Stage interval table, measured/estimated classification, stage subtotal and explicit unknown/unobserved time |
| G5.7 | Backend-ranked findings, deterministic support, evidence IDs, scope, domains, limitations, alternate explanations, next validation |
| G5.8 | Secondary modal evidence drawer with normalized values, source/version, scope, frames, filter, limitations and retry |
| G5.9 | Identified-case confirmation, stored-file deletion semantics, safe initial focus, failure retention and cleanup-pending notice |
| G5.10 | Semantic/keyboard review, axe A/AA checks, focus/escape/return tests, desktop and 390/768/1024 responsive review |

| Requirement | Evidence |
| --- | --- |
| R-U001 | One capture + symptom + Investigate action; create/upload/investigate order; recovery and delete flows |
| R-U002 | Conclusion and supporting findings lead; raw normalized values are secondary |
| R-U003 | Both required Wireshark actions visible together on applicable findings, disabled with an explicit Gate 6 explanation |
| R-U004 | Confidence, capture quality, material limitations, alternate explanations and validation visible in main results |
| R-U005 | Evidence drawer, expandable original hash/provenance/lifecycle; readable default summary |
| R-U006 | Measurable deterministic support and evidence links; inference and unknowns distinguished; no AI-as-evidence language |

## Architecture and workflow

[ADR-0004](decisions/ADR-0004-local-web-workflow.md) records same-origin compiled
assets, implicit case creation, polling/recovery, report freshness, additive
finding metadata, deferred Wireshark integration and deletion semantics.

The intake collects capture and symptom before creating the case. Submit creates,
uploads as `application/octet-stream`, then investigates. The browser polls
persisted state/history; quick transitions remain inspectable in history.
A logical case ID in the URL fragment supports reload/bookmark recovery without
storing capture bytes or reports in browser storage. Recovery reads state and
requires explicit continue/retry for idle/failed cases. The source file is unchanged.

Reports publish only between matching COMPLETE snapshots, including report hashes,
revision time, history sequence, evidence count and run statuses. Results clear on
case switches, mutations, running/non-COMPLETE state, changed revisions or lost
status connectivity. Completed cases continue polling. Abort/generation guards
prevent late responses from restoring obsolete reports; evidence drawers close
when their report ceases to be current.

The backend change only exposes existing per-finding domains and `inferred`
classification. Schema 1.0 accepts these optional additive fields and persisted
Gate 4 reports without them. Missing legacy domains display Unknown; no domain,
client/server role, diagnostic priority or confidence is invented in the UI.

## API contracts used

Types derive from `contracts/api.openapi.json`, `evidence.schema.json` and
`investigation-result.schema.json`. Standalone validators compile at build time;
the production CSP requires no runtime eval. Case/report/evidence/deletion responses
are checked before rendering; config limits are checked against rules-only mode.

| Method / resource | Purpose |
| --- | --- |
| GET `/api/config/capabilities` | Actual capture size limit and disabled provider mode |
| POST `/api/cases` | Symptom-bearing implicit case creation |
| POST `/api/cases/{id}/capture` | File octet stream; immutable capture intake |
| POST `/api/cases/{id}/investigate` | Explicit deterministic investigation / retry |
| GET `/api/cases/{id}` | Persisted lifecycle, artifacts, history and runs |
| GET `/api/cases/{id}/report` | Authoritative completed report |
| GET `/api/cases/{id}/evidence/{evidence_id}` | Cited normalized evidence |
| DELETE `/api/cases/{id}` | Deliberate deletion and accurate cleanup result |

Fixed same-origin URLs accept logical identifiers only. No configurable remote API,
CORS weakening, analyzer invocation, provider call, arbitrary URL/path, host bridge
or evidence extraction is added. Original API OpenAPI routes remain unchanged.
`/` and strict `/assets/{name}` serve only compiled HTML/JS/CSS, reject traversal and
symlinks, and do not expose source, repository directories or raw case artifacts.
CSP restricts scripts/styles/connections to self and forbids framing/objects/base
URLs; responses use no-store, nosniff and no-referrer. Untrusted strings render as
React text, not HTML. Browser verification observed no external requests or page
errors in the supported workflow.

## Validation

| Check | Result |
| --- | --- |
| Full Python suite | **401 passed, 0 failed, 0 skipped**: 260 unit + 141 integration/golden tests, real TShark/capinfos |
| Frontend API/component suite | **38 passed**: 14 API + 24 workflow/presentation/failure/race tests |
| Production browser suite | **9 passed**, retries 0, no skips; actual API and packet tools |
| TypeScript / production build | Pass; generated contracts and standalone validators included |
| ESLint / Prettier | Pass |
| Ruff lint / format | Pass across services, tests and scripts (47 Python files formatted) |
| Real loopback CLI smoke | Pass; 447 schema-record checks, CLI evidence counts 5/11, repeat request and deletion pass |
| Git whitespace | `git diff --check` passes |

Commands from the checkout (activate the Python environment and put real tools on PATH):

```bash
pytest -q --junitxml=artifacts/gate5-python.xml
ruff check services tests scripts
ruff format --check services tests scripts
python scripts/validate_gate3.py
npm run build --prefix apps/web
npm run typecheck --prefix apps/web
npm run lint --prefix apps/web
npm run format:check --prefix apps/web
npm test --prefix apps/web
python scripts/prepare_web_fixtures.py
npm run test:e2e --prefix apps/web
```

The smoke script's old Gate 3-only state expectation was updated to COMPLETE to
match Gate 4 behavior; no production orchestration behavior changed. Fixture
preparation uses the actual API and tools for committed normalized test data.
Browser runs use ignored generated PCAPs and an isolated ignored case root.
Build assets and test databases/captures are not committed.

## Browser, accessibility and visual evidence

Chromium exercises supported high RTT, healthy insufficient evidence, midstream
capture limitations, malformed-input FAILED/recovery/deletion, uploaded idle
case recovery without automatic mutation, and the main workflow at 390, 768 and
1024 pixels. Supported results are compared to the live API report. Reload keeps
the logical case; confirmed deletion is verified by API 404. Both Wireshark actions
remain disabled. Evidence drawer source/values, Escape/focus return and destructive
dialog cancellation, focus wrapping and safe initial focus are exercised.

Axe checks WCAG 2 A/AA and 2.1 A/AA tags in intake, supported/insufficient/limited/
failed results, evidence and deletion dialogs, and responsive views: zero detected
violations. Semantic labels, native controls, skip link, focus visibility,
keyboard access, heading/table structure, live status and horizontal overflow were
also checked. Visual review covered desktop and narrow layouts.

- [Desktop intake](gate5-visual/intake-desktop.png)
- [Supported report](gate5-visual/supported-desktop.png)
- [Expert evidence](gate5-visual/evidence-desktop.png)
- [Insufficient evidence](gate5-visual/insufficient-desktop.png)
- [Capture limited](gate5-visual/limited-desktop.png)
- [Malformed failure](gate5-visual/failed-desktop.png)
- [390px](gate5-visual/supported-390.png), [768px](gate5-visual/supported-768.png), [1024px](gate5-visual/supported-1024.png)

Real browser testing exposed standalone validator CommonJS helper interop under
production bundling and native dialog initial-focus/wrapping differences from
jsdom. Both were fixed; assertions were retained and the complete nine-test
production suite rerun successfully. Component tests additionally exercise upload
failure, config/network errors, size limits, dropped files, legacy report fields,
cleanup pending, deletion failure, late report responses, changed verification
snapshots, later completed revisions and connectivity recovery.

## Separate senior review

Opened PR #6 before the separate review pass. Reviewed product commit
`187ec13861fec504bb0ae37669f81d18d6cf35c3` against repository authority and the actual
contracts, specifically checking spec compliance, upload failure, destructive
semantics, freshness races, accessibility/responsiveness, evidence/uncertainty,
frontend security, raw data/path handling, diagnostic duplication, scope creep
and tests that could bypass the real workflow. No unresolved blocking findings.
The review is recorded as a COMMENT anchored to that product commit. This was a
separate review pass by the implementation agent, not a second human approval or
GitHub APPROVE. Owner merge approval remains outstanding.

## Environment and limits

Linux x86_64; Python 3.12.14; Node 24.19.0; npm 11.9.0; TShark/capinfos 4.2.2;
FastAPI 0.143.0; Starlette 1.7.0; Pydantic 2.13.5; uvicorn 0.54.0;
pytest 9.1.1; Ruff 0.16.10. Frontend: React 19.3.0, TypeScript 5.9.3,
Vite 8.3.4, Vitest 5.0.3, Playwright 1.64.0, axe 4.13.0.
Browser: Chromium 153.0.8010.0, selected through `WIRECLAW_BROWSER_PATH`.
Normal Playwright browser archives failed to download in this workspace; a full
Chromium executable from the separately installed @sparticuz/chromium package
was used with Playwright's standard launch defaults. It is not a repo dependency.
Packet-tool packages were extracted locally rather than installed system-wide.

Native Windows/macOS, Firefox/Safari and screen-reader certification were not
executed. Axe is useful evidence, not complete accessibility certification.
Polling can observe quick stages only after completion; history preserves them.
There is no case-list or symptom-update API, so recovery uses logical IDs and
persisted symptoms. Legacy reports cannot supply absent per-finding domains.
Both native Wireshark actions remain unavailable until Gate 6. Provider adapters,
Docker/release packaging, launchers and Gates 6+ remain untouched. A known
Starlette/httpx TestClient deprecation warning is informational; no test is skipped.
