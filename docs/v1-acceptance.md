# Wireclaw V1 Acceptance Record

Status: **Gate 9 OPEN — not release accepted**

This record reports acceptance against one frozen macOS arm64 candidate. A `PASS` on a task or criterion is limited to the evidence named here. Any `BLOCKED` or `NOT_RUN` criterion keeps Gate 9 open.

## Candidate identity

| Property | Frozen value |
|---|---|
| Source commit | `b403c4468b1cb4382a2b9bf7f9cdb74f85653ad4` |
| Platform / architecture | macOS 27.0.1 / arm64, Apple M3 Pro |
| Docker / Compose | 29.8.2 / 5.6.0 |
| Core image config ID | `sha256:5419a181888cf5b8809de2280156e55527fa929394169ce65a6e8bb088c11cf5` |
| Core image archive SHA-256 | `d996f9d592ffe6009c0fbc91c4ed078ea9734d1ace6f66877c26681062cc504b` |
| Candidate bundle SHA-256 | `7abcbe5274e34e7acdce6c361fce802604fb65c20f239cb1c90b65cc8fa4d10c` |
| Host bridge SHA-256 | `a96e4c7c191ac41b8f7892f6f5830b7745dc9f26a4a73b1068b033f7ddb0699b` |
| Compiled web SHA-256 | `53c041f45fdf89491697653e222b099beb3ab08c0c30946ed4a4209f56b07faa` |
| Dockerfile / Compose / analyzer-lock SHA-256 | `3a16200becfeb631e2e558e93c5f9ca57a83d314f5f50f77818f5339a2fd7389` / `c65098ab8f20500301aa3b4d27b844ae6fa58d4f658348acc1fcc899422c3030` / `5767fbd4243d1cc8f70b44cb17ff6cb8496f2261058aa260fd38704b73f9df8e` |
| Packaged tools | Python 3.12.3; TShark, capinfos, editcap, mergecap 4.2.2 |
| Native Wireshark | 4.6.9 |
| Provider default | `none` |

The candidate bundle used for the native run is preserved outside the repository at `/private/tmp/Wireclaw Gate9 Candidate b403c44/gate9-candidate.tar`. Its extracted directory includes `gate9-candidate-metadata.json`. The image ID was checked before and after the completed packaged validator run and across native candidate use/restart. The macOS bridge was independently rebuilt with Go 1.26.5 and matched the packaged bridge hash. The full environment metadata is in the extracted candidate's metadata JSON.

## Task results

| Task | Result | Record |
|---|---|---|
| A — immutable candidate | PASS | Candidate identity above; exact image and bundle digests recorded. |
| B — deterministic corpus, G9.1–G9.10 | PASS | 18 corpus scenarios pass. Healthy traffic has no diagnosis; DNS, retransmission, RTT, receive window, reset/reconnect, TLS, positive HTTP wait and PMTUD findings are bounded and traceable. Opaque silence stays `insufficient_evidence`. See `artifacts/gate9/corpus.json`. |
| C — resource and malformed input, G9.11–G9.12 | PASS | Packaged HTTP limits reject oversized declared capture and JSON body; malformed, damaged and unsupported captures are rejected without partial artifact and permit one healthy retry. Packaged adversarial JUnit: 167 passed. See `artifacts/gate9/resource-adversarial.json` and `.junit.xml`. |
| D — provider/model boundaries | PASS | 31 packaged tests pass. Provider actions are typed and bounded; invented/cross-case evidence, privileged actions and malformed/oversized responses are rejected or safely fall back. Local and cloud compatible routes were exercised. See `artifacts/gate9/model-boundary.json` and `.junit.xml`. |
| E — privacy/logging, G9.13 | PASS | The full packaged validator ran with `WIRECLAW_EXPECTED_IMAGE_ID=sha256:5419a181888cf5b8809de2280156e55527fa929394169ce65a6e8bb088c11cf5`. A generated test CA was appended to the frozen candidate's normal `certifi.where()` bundle and mounted read-only at that exact path; no child image was built. One HTTPS fake-provider request was inspected. The API key appeared only in `Authorization`; seeded payload/header, credential, cookie, symptom, bridge-token and absolute-path sentinels were absent from body, other headers and core logs. Raw and original capture bytes were absent. The candidate image ID was verified unchanged after the run. See `artifacts/gate9/privacy.json` and the G9.13 row in `corpus.json`. |
| F — reproducibility and persistence | PASS | Seven duplicate-ingest fixture pairs produced matching normalized semantics; evidence extraction reuse retained hashes and parent provenance. Fourteen cases survived restart with report/evidence and original hashes intact. Explicit deletion removed the selected case and preserved its control. See `artifacts/gate9/reproducibility.json`, `persistence.json`, and `macos/final-deletion-isolation.json`. |
| G — rendered UI | PASS | Compiled candidate UI was exercised for healthy, TLS delay, and opaque TCP wait. The positive HTTP wait screen was inspected during native candidate work: request completion frame 4 to response frame 5 measured 2.1 s, with an application/server boundary and downstream dependency limits. Both Wireshark actions and the exact filter were visible. Evidence drawer remains usable when the bridge is down. See `artifacts/gate9/ui/` and `macos/final-bridge-down-evidence.png`. |
| H — host bridge security, G9.14 | PASS | 23 Go tests, `go vet`, darwin/arm64 build, packaged hash comparison and source boundary review pass. Review covers loopback, Origin, one-use expiring grant, hash-only token storage, strict bounded JSON, filter validation, canonical data-root and symlink confinement, cross-case/artifact hashes, direct argv, configured executable and no shell/general execution endpoint. See `artifacts/gate9/host-bridge-review.json` and `host-bridge-tests.jsonl`. |
| I — native macOS workflow, G9.15 | PASS | Packaged start/install/stop, paths containing spaces, provider-none intake/report, localhost binding, native full/evidence Wireshark actions for DNS, high RTT, HTTP wait and incomplete handshake, exact argv/filter, original/evidence hashes, PCAPNG provenance, restart, bridge-down state, deletion isolation and stop/persistence were recorded. See `artifacts/gate9/macos/final-native-evidence.json`, `native-cases-final.json`, `final-deletion-isolation.json` and screenshots. |
| J — regression | PASS WITH ENVIRONMENT NOTE | Pinned Docker core-test: 450 passed, 0 failures under packaged TShark 4.2.2; packaging: 18 passed. Static Python checks, Gate 3 validator, web lint/format/build/unit (41)/browser E2E (9), Go test/vet/build passed. A separate host-wide pytest run with host TShark 4.6.9 had 464 pass and four fixture/golden mismatches (Gate 2 reordered TCP, PMTUD, loss expert classes; Gate 4 real-capture golden). The same complete core unit/integration suite passed in the pinned candidate environment. One Starlette/httpx TestClient deprecation warning was emitted. GitHub workflow file parses and formats, but its Actions run is NOT_RUN. Details: `artifacts/gate9/regression.json`. |
| K — independent signoff / draft PR | BLOCKED | The independent whole-diff reviewer has not signed off. The GitHub Actions workflow was not triggered because no push was authorized/performed. No draft PR was opened. Gate 9 remains open. |

### G9.10 interpretation

The incomplete handshake fixture returns a supported observation that TCP establishment did not complete normally. This is limited to the observed handshake state: client, network path and server/application causes remain open, with opposite-side capture requested. One-sided, midstream and truncated captures remain `insufficient_evidence`. This is not a root-cause claim.

### Privacy evidence qualification

`artifacts/gate9/privacy.json` retains only redacted assertions from the qualifying mounted-bundle rerun. The generated test CA was appended to the frozen image's normal certifi bundle and mounted read-only at the certifi path; the candidate image was not rebuilt. The exact HTTPS request, headers and core logs were checked. No secret body, key, payload, raw grant or sensitive screenshot is retained in this repository.

## Twenty-four signoff criteria

| # | Criterion | Result | Evidence / limitation |
|---:|---|---|---|
| 1 | Gates 0–8 implemented and documented | PASS | Pinned core and packaging regressions plus current authority review; independent whole-diff review remains separate at #23. |
| 2 | Deterministic corpus correct | PASS | Corpus facts, conclusions, references and extraction records in `artifacts/gate9/corpus.json`. |
| 3 | Healthy traffic has no false diagnosis | PASS | G9.1 healthy and clean TCP are `insufficient_evidence`, no finding categories. |
| 4 | DNS timing | PASS | G9.2 query/response transaction and focused extraction; native Wireshark evidence. |
| 5 | Retransmission scope | PASS | Gate 2 class/sequence suite and G9.3 corpus, with evidence extraction. |
| 6 | RTT | PASS | G9.4 measured RTT; rendered and native evidence. |
| 7 | Receive windows | PASS | G9.5 advertiser direction and window evidence. |
| 8 | Reset/reconnect | PASS | G9.6 exact reset and new stream relationship. |
| 9 | TLS | PASS | G9.7 handshake evidence and rendered encryption limitation. |
| 10 | Positive HTTP wait | PASS | G9.8 2.1 s measured request/response boundary, frames 4/5 and limited downstream attribution. |
| 11 | Opaque TCP uncertainty | PASS | G9.8 remains `insufficient_evidence`; no HTTP semantics inferred. |
| 12 | PMTUD without black-hole claim | PASS | G9.9 explicit ICMP MTU signals; no black-hole claim. |
| 13 | Incomplete capture uncertainty | PASS | G9.10 limits causes to observed handshake state or insufficient evidence, with next evidence. |
| 14 | Resource safety | PASS | G9.11 bounds and 167 adversarial/API tests. |
| 15 | Malformed/adversarial safety | PASS | G9.12 malformed/damaged/unsupported input and safety tests. |
| 16 | Cloud privacy | PASS | G9.13 rerun used the frozen image and read-only mounted `certifi` bundle; exact request, headers and core logs were checked for all seeded sentinels. |
| 17 | Typed model/evidence boundary | PASS | 31 tests and packaged provider routes in `model-boundary.json`. |
| 18 | Bridge security | PASS | Tests, source review, packaged binary hash and native launches. |
| 19 | Original immutability/persistence | PASS | Repeated ingestion, restart, provenance and deletion isolation records. |
| 20 | Both native Wireshark actions | PASS | Actual packaged macOS UI and process argv records for four representative cases. |
| 21 | macOS end-to-end | PASS | Native candidate workflow completed; environment and evidence listed above. |
| 22 | Pinned identities | PASS | Candidate image ID and bundle, bridge, web, Dockerfile, Compose and analyzer lock hashes recorded. |
| 23 | No blockers | BLOCKED | Independent whole-branch review and exact-head GitHub Actions run remain outstanding. |
| 24 | Exact report | PASS | This report cites candidate and exact evidence paths, with limitations and test counts. |

## Security review

The Codex Security diff-scan helper preflight was ready with a delegation availability warning, but the single scan attempt failed before creating a scan ID because its runtime could import neither `tomllib` nor `tomli`. There is no automated scan report and no automated “no findings” claim. The changed-file manual review covered provider context redaction, candidate freeze and validator subprocess arguments, bridge listener/authentication/confinement/launch boundaries, Docker test-stage changes and the regression tests. It found no confirmed exploitable issue in the reviewed changes. The bridge boundary map is recorded in `artifacts/gate9/host-bridge-review.json`; the scanner failure and host regression limitations are in `artifacts/gate9/regression.json`.

## Remaining work to close Gate 9

1. Obtain independent whole-branch signoff against the authority documents and Gate 9 criteria.
2. Run `.github/workflows/gate9-acceptance.yml` on GitHub Actions for the final branch head and retain the run URL/evidence. The workflow file was syntax/format checked locally only.
3. Reconcile any reviewer or CI findings, then update the criterion statuses. Gate 9 must remain open until every required criterion is PASS.

Windows and Linux remain portability groundwork and future targets under ADR-0006; they are not V1 release blockers.
