# Gate 9 V1 Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Qualify one immutable macOS arm64 candidate with exact deterministic, operational, security and native evidence; leave the PR draft and Gate 9 open until every required result is PASS.

**Architecture:** Preserve Gates 0–8 runtime behavior. Add acceptance-only scripts, tests and evidence records. Use the accepted Gate 8 Dockerfile, lock, compiled web and darwin-arm64 bridge packaging layout. Run cloud automation against an identified arm64 core image; never represent cloud automation as native desktop acceptance.

**Tech Stack:** Python/FastAPI, pinned Wireshark CLI 4.2.2, React/TypeScript, Go, Docker Compose, GitHub Actions, native macOS Wireshark.

**Spec:** `specs/v1/gate9-acceptance.md`, subordinate to constitution, requirements, solution and accepted ADRs 0001–0006.

## Global constraints

- Starting main: `51c598d7ceeb3b8c828734dfdebca04b08a0ffd7`; branch `gate9-v1-acceptance`.
- Gate 8 merge: `3b8f19a53612caac515be71ce347082cf5bb91d4`; accepted identities remain in `docs/gate8-verification.md` and are historical, not Gate 9 evidence.
- Only PASS satisfies a release criterion. FAIL/BLOCKED/NOT_RUN keep Gate 9 open.
- No merge, Windows/Linux qualification, redesign, new providers or speculative features.
- Freeze source SHA, Compose/Dockerfile/lock hashes, base digest, image ID, archive SHA, tool versions, web hash, bridge SHA and defaults before acceptance. A mutable image tag is only an alias; verify immutable ID before/after use.
- Runtime/artifact changes invalidate affected results and require a new candidate. Documentation-only changes may cite the tested source explicitly.
- Follow C14/spec-first and RED→GREEN regression tests for any discovered behavior defect. Do not weaken fixtures, goldens or conclusions to pass.
- Native Mac desktop APIs are unavailable here. G9.15 and native Full/Evidence launches remain BLOCKED until real desktop evidence for the Gate 9 candidate is supplied.

## Review focus

1. Privacy tests must seed forbidden data in actual context inputs and inspect exact body/headers/logs; checking absent strings that were never seeded proves nothing.
2. Positive HTTP and opaque TCP silence must receive different semantic conclusions; validate timing and traceability, not category appearance alone.
3. Retransmission subcategories, quoted ICMP inner packets and one-sided visibility must retain their exact scope and uncertainty.
4. Candidate image/binary identity must survive CI upload/download, restart, browser and local handoff; a rebuild is a new artifact.
5. Resource failures must preserve originals/prior evidence and bound retries; parser failure is not diagnostic cause.

## Files and evidence interfaces

- Create `tests/acceptance/test_gate9_corpus.py`: real-tool API corpus, facts, report conclusions, extraction, provenance, repeat-run equivalence.
- Create `scripts/gate9_freeze.py`: acceptance-only staging using Gate 8 packaging functions/INCLUDED layout; emit exact candidate metadata and archive. Cloud builder identity remains explicit.
- Create `scripts/validate_gate9.py`: packaged HTTP corpus and scripted provider acceptance, identity check, restart, log checks, static result evidence; no arbitrary provider execution.
- Create `.github/workflows/gate9-acceptance.yml`: arm64 candidate freeze, acceptance, packaged browser screenshots, regression evidence upload. Preserve existing CI.
- Create `docs/gate9-macos-handoff.md`: executable candidate verification and exact desktop procedure, fixture facts and cleanup.
- Create `docs/v1-acceptance.md`: result records, environment, 24 independent signoff criteria, blockers and links to exact runs/artifacts.
- Evidence output: `artifacts/gate9/` (CI artifact, not runtime secrets in Git). Include `release-metadata.json`, JUnit, corpus/provider summaries, redacted log inspection and screenshots. Never publish API keys/raw grants/provider bodies with credentials.
- Acceptance record interface: Result, candidate identity, scenario, must observe/observed result, must conclude/conclusion result, must not conclude/overclaim result, operational result, evidence references, limitations.

## Task A — Freeze candidate

- [ ] Recheck main and branch; read all authority sources, fixtures/goldens and existing workflows before edits.
- [ ] Stage arm64 image plus darwin-arm64 bridge with the accepted Gate 8 included files, locks and archive-loading layout. Record build-host OS separately from supported runtime host.
- [ ] Export source SHA, image config ID, archive SHA, base digest, analyzer lock revision/hash, Python/TShark/capinfos/editcap/mergecap, web tree hash, bridge SHA, Compose/Dockerfile/default configuration hashes.
- [ ] Verify image ID at every acceptance start and after restart. Upload the exact archive/bundle for Mac handoff; do not rebuild it for desktop testing.
- [ ] Commit plan before implementation/acceptance and commit acceptance harness separately.

## Task B — Deterministic corpus (G9.1–G9.10)

All rows use the frozen core image, provider none/no credential/no model server; automated evidence goes to `artifacts/gate9/corpus.json` and JUnit. Every applicable finding must cite existing evidence IDs, correct scope/frames/filter, display paired action metadata and create/reuse bounded derived PCAPNG with parent SHA. Native opening is Task I, never inferred here.

| Task | Fixture/scenario | Automated tests | Must observe | Must conclude | Must not conclude | Desktop evidence |
|---|---|---|---|---|---|---|
| G9.1 | healthy + clean_tcp | Gate 1/2 independent measurements + Gate 9 corpus | 7 frames/469 bytes/0.6 s; 20 ms handshake; four 10 ms RTT samples; 20/30 ACK-covered payload; MSS 1460; scale 2; good quality, no expert faults | no supported fault or insufficient_evidence | loss/reset/window/DNS/TLS/PMTUD/application fault | rendered healthy result, Task G |
| G9.2 | dns_delay, unrelated-DNS focus control | Gate 2 DNS + Gate 9 extraction | query 1/response 2; 1.5 s; exact transaction filter and focused extraction | DNS timing contribution for DNS symptom | complete user transaction causality/resolver root cause without linkage | relevant DNS packets/filter in native Wireshark, Task I |
| G9.3 | loss_tcp | Gate 2 class/sequence tests + corpus | union 5/11/13; fast 11; spurious 13; dup ACK 8/9/10; 100 payload/40 unique/40 ACK-covered | bounded transport contribution | physical loss device/location; conflated expert classes | native stream and evidence subset |
| G9.4 | high_rtt | Gate 2 + Gate 4/9 | establishment 400 ms; median ACK RTT 200 ms | supported RTT contribution | specific device/path segment | native RTT finding/filter |
| G9.5 | window_tcp | Gate 2 windows + corpus | server scaled window 100; full 5; zero 6/8; probe 7; reopen 6–9 1 s; advertiser direction | receive-window constraint | packet loss or internal process cause | native direction/frames |
| G9.6 | reset_tcp + reset_reconnect | Gate 2 exact reset/reconnect + corpus | reset 6 at 80 ms after establish; prior stream 0 reset 6; new SYN 7 at 100 ms/new ephemeral port; new reset 10 | transport reset/reconnect condition | application reset cause or session continuity | native two-stream references |
| G9.7 | tls_delay | Gate 2 TLS + corpus | establish 20 ms; CH 100 ms; SH 1.1 s; 80 ms/1 s intervals; 0x0304; frames | visible handshake delay | decrypted semantics/full session completion/internal cause | rendered encrypted limitation and native hellos |
| G9.8 | http_server_wait + opaque server_wait | Gate 7 HTTP + corpus | complete decoded request/end; first response; 2.1 s (fixture precision); stream/endpoints/frames/filter; opaque has no HTTP transaction | positive server/application boundary; opaque uncertainty | database/CPU/threadpool/backend/LB/visible server vs dependency; semantics from generic gap | rendered pair plus native request/response |
| G9.9 | pmtud_signals + quoted controls | Gate 2 PMTUD/quote tests + corpus | IPv4 frame 2 MTU1200, IPv6 frame3 MTU1280; no quoted live stream | explicit PMTUD signal | MTU black hole or inner packet as live flow | native quoted packets |
| G9.10 | one_sided/midstream/incomplete_handshake/truncated | Gate 1 quality + corpus | exact quality limitations affect confidence | insufficient_evidence when domains cannot discriminate; next evidence | forced client/server/network root cause | rendered limitations/next evidence |

- [ ] Assert independently known facts and complete semantic goldens without auto-regeneration.
- [ ] Inspect report wording, evidence links, scopes, frames and filters for every row.
- [ ] Generate/reuse evidence; inspect bounded selected contents with real packet tools; verify original unchanged.
- [ ] Save exact observations and PASS/FAIL for each assertion; do not check tasks merely because category exists.

## Task C — Resources/adversarial (G9.11/G9.12)

- [ ] Run `tests/unit/test_safety.py`, `test_diagnostics.py`, API resource tests, Gate 6 artifact limits, Gate 7 request/response/step/duplicate limits against candidate modules with real tools where required.
- [ ] Safely lower policy thresholds in test-controlled application instances using the unmodified candidate modules: upload size, analyzer timeout, rows, artifact size/count/reuse, provider request/response, max steps/duplicates, configured JSON/evidence/report bounds.
- [ ] Assert static bounded errors, reap subprocesses, intact originals/prior evidence, no retry bypass, bounded file/process growth; resource failure cannot become a fault diagnosis.
- [ ] Malformed/unsupported/damaged capture intake plus bounded pathological analyzer output, control/filter characters, prompt injection; reject/limit without crash, shell/path/provider escape or parser-failure diagnosis.
- [ ] Save scenario/error/original/evidence comparisons to `artifacts/gate9/resource-adversarial.json`; cross-reference exact test names and JUnit. No native desktop needed.

## Task D — Provider/model boundaries

- [ ] Script fake HTTP provider actions: none, valid capability/finalize, invented evidence, unknown capability, invalid parameters, duplicate, malformed/oversized/timeout/unavailable, injection, unsupported fact prose, shell/path/native launch.
- [ ] Inspect typed capability audit and real evidence. Assert fabricated/provider prose never enters findings, only allowed capabilities run, deterministic findings persist after disagreement/outage.
- [ ] Save action/result/bounded audit/evidence checks in `artifacts/gate9/model-boundary.json`; do not save raw credentials or unbounded response.

## Task E — Privacy/logging/security (G9.13)

- [ ] Controlled HTTPS fake-cloud request from frozen candidate with a test-only mounted trust bundle (no child image/code substitution); record override.
- [ ] Seed raw capture/payload/fragments, absolute paths, credentials/cookies, bridge token and raw analyzer output in fixture/context inputs. Include injection as untrusted data.
- [ ] Inspect exact body and all relevant headers; API key only intended Authorization transport. Persist only sanitized inspection assertions/digests, never Authorization/body with secret.
- [ ] Inspect API/app/provider/bridge/acceptance logs for payload/API key/Authorization/raw token/cookies/chain-of-thought/unbounded prompt-response; bounded audit must remain.
- [ ] Attempt Codex Security once if functional; if helper unavailable record exact limitation and do full manual trust-boundary/branch review. Save `artifacts/gate9/privacy.json` and `docs/v1-acceptance.md` security section. Claim only Wireclaw provider traffic.

## Task F — Reproducibility/persistence

- [ ] Run independent twice-ingested healthy/DNS/loss/RTT/HTTP/PMTUD/incomplete fixtures with identical candidate/config; compare category/values/frames/scope/filter/tool versions and deterministic parent/artifact hashes. Ignore only intentional IDs/timestamps.
- [ ] Ingest/hash → investigate → scripted iteration → evidence extraction → restart → reload/hash/evidence → explicit confined deletion, with a second unaffected case. Native actions deferred to I.
- [ ] Save `artifacts/gate9/reproducibility.json`, `persistence.json` with original SHA and artifact provenance/reuse checks.

## Task G — Epistemic rendered UI

- [ ] Run actual compiled candidate UI in production browser for healthy, RTT, HTTP/opaque, TLS and incomplete cases.
- [ ] Verify observed/derived vs inferred, visible confidence/quality, valid completed insufficient_evidence, possibility labels and next evidence, no AI-detected support, measured vs inferred time and encrypted limitations.
- [ ] Verify paired buttons, copy exact filter, evidence drawer, local evidence generation/reuse and bridge-down degradation. Native launches are not satisfied by browser tests.
- [ ] Save screenshots/browser assertions under `artifacts/gate9/ui/` and review images directly. No UI redesign.

## Task H — Host bridge (G9.14)

- [ ] Run macOS `go test ./...`, `go vet ./...`, build. Compare build inputs/binary hash with candidate; cross-build success is not GUI acceptance.
- [ ] Independently review `bridge.go`, `main.go`, grant generation, packaging/launchers; prove loopback/origin/strict bounded JSON/unknown fields/entropy/hash-only/constant-time/expiry/replay/concurrent-single-launch.
- [ ] Prove logical IDs/confinement/traversal/symlink/cross-case/SHA/kind/filter/executable/direct-argv/no-shell/no-generic-exec/spaces, using bridge tests plus source review. Save exact per-boundary mapping in report.
- [ ] Packaged binary native launch remains Task I; arbitrary process path is blocker.

## Task I — Native macOS (G9.15)

- [ ] Create exact handoff for the already frozen archive/binary; verify source/image/archive/bridge/web hashes before start.
- [ ] Record macOS/arm64/Docker/Compose/native Wireshark versions.
- [ ] Install/start launcher in a path with spaces, localhost-only intake/investigation/report with provider none, fake/local provider, persistence restart, both native Wireshark actions for representative findings, exact approved filters, PCAPNG provenance/reuse, unchanged original, bridge-down degradation, confined deletion, stop/cleanup.
- [ ] Record screenshots, process argv, SHA measurements and outputs in `artifacts/gate9/macos/`. Without actual desktop access/result mark G9.15 BLOCKED and Gate 9 open; no inherited Gate 8 PASS.

## Task J — Full regression

- [ ] Run complete Gates 0–8 pytest unit/integration/packaging (real packet tools mandatory), Gate 3 validator, semantic goldens, web lint/format/build/unit/production browser, Docker test/runtime/Compose/package and macOS Go test/vet/build.
- [ ] Record counts, warnings, failures/skips with reasons. A host skip is not a release pass. Keep existing portability coverage; do not start platform qualification.
- [ ] Upload JUnit/logs/screenshots and exact candidate metadata. Report exact validated SHA and Actions run URL.

## Task K — Independent signoff and draft PR

- [ ] Obtain independent full-diff reviewers for spec/deterministic/privacy/model/epistemic/artifact identity. Fix verified defects at responsible layer using TDD/systematic debugging; freeze/retest new candidate where needed.
- [ ] Create report with per-task full record, environment matrix, reproducibility, persistence, logging, model/UI/security/regression and blocker review.
- [ ] Check all 24 signoff criteria below independently; no unchecked criterion may be inferred from task labels.
- [ ] Push logical commits and open draft PR against main; include exact candidate, G9 matrix, runs, limitations/blockers and Mac handoff. Never merge.

## Independent signoff mapping

All rows require the frozen artifact and exact evidence, with expected conclusion PASS only if every named assertion passes; prohibited conclusion is release acceptance from unchecked/blocked evidence.

| # | Criterion | Group / fixture and automated evidence | Required manual evidence / output |
|---|---|---|---|
| 1 | Gates 0–8 implemented/documented | J full suites + authority review | K report/whole-diff review |
| 2 | deterministic corpus correct | B independent facts + goldens | corpus.json/JUnit |
| 3 | healthy no false diagnosis | B G9.1 | G rendered result |
| 4 | DNS | B G9.2 | I native focused DNS |
| 5 | retransmission | B G9.3 | corpus/packet scope |
| 6 | RTT | B G9.4 | G/I rendered/native |
| 7 | windows | B G9.5 | direction/frames |
| 8 | reset/reconnect | B G9.6 | stream/port relationships |
| 9 | TLS | B G9.7 | G encryption limitation |
| 10 | positive HTTP | B G9.8 positive | G rendered measured boundary |
| 11 | opaque uncertain | B G9.8 negative | G completed uncertainty |
| 12 | PMTUD no black hole | B G9.9 | quoted-inner review |
| 13 | incomplete uncertain | B G9.10 | G quality/next evidence |
| 14 | resource safety | C G9.11 | resource-adversarial.json |
| 15 | malformed/adversarial safety | C G9.12 | resource-adversarial.json |
| 16 | cloud privacy | E G9.13 | exact body/header/log inspection summary |
| 17 | typed model/evidence | D | model-boundary.json |
| 18 | bridge security | H G9.14 | whole-boundary review; packaged macOS binary |
| 19 | original/persistence | F + I | restart hashes/native action evidence |
| 20 | both native actions | I | actual macOS GUI/argv/provenance/hash |
| 21 | macOS E2E | I G9.15 | full executable handoff results |
| 22 | pinned identities | A | metadata verified before/after all runs |
| 23 | no blockers | K all 15 blocker review | FAIL/BLOCKED/NOT_RUN prevent signoff |
| 24 | exact report | K `docs/v1-acceptance.md` | per-task evidence + identities |

## Execution ledger

- Plan created before acceptance execution. User authorizes immediate execution without plan approval.
- Work environment: Linux x86_64, no native desktop APIs or Docker daemon. Connected GitHub and direct public read access work; GitHub writes use connector. Python development dependencies installed for harness checks, not represented as packaged acceptance.
- Gate 8 historical identities read in full. Runtime source remains unchanged at planning time.
