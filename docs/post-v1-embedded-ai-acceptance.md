# Post-V1 embedded local AI acceptance

**Current disposition: BLOCKED** — implementation source `bae67a0996afa7ca34c2890295e72de0acd02221` passes exact-head CI, three complete official benchmark runs, and all 16 native macOS EAI.14 checks. The final independent whole-branch/security reviews and exact-head CI for this acceptance update remain outstanding. PR #13 remains draft and unmerged. This record does not alter historical V1 acceptance.

## Task states

| Task | State | Evidence / note |
| --- | --- | --- |
| Preflight P0 | PASS | `artifacts/embedded-ai/preflight-loopback.json`; packaged core reached a host service bound only to loopback. |
| EAI.1–EAI.11 | PASS | Provider, provenance, packaging, launcher, Gate 7, UI, offline bundle, and privacy controls passed current-head tests and candidate checks. |
| EAI.12 | PASS | Three complete unchanged 22-scenario official runs passed individually against the frozen `bae67a0` candidate. Full scenario reports and summaries are in `artifacts/embedded-ai/runs/bae67a0/` and `benchmark-summary-bae67a0.json`. |
| EAI.13 | PASS | Full local regression and all five exact-head CI jobs passed on `bae67a0`. CI run [38829585198](https://github.com/Ryan9876/wireclaw/actions/runs/38829585198) exercised Linux, Docker release/packaging, and bridge builds on Ubuntu/macOS/Windows. |
| EAI.14 | PASS | All 16 native macOS checks passed against the same frozen `bae67a0` archive. See `macos-bae67a0.json` and `artifacts/embedded-ai/native/bae67a0/`. The async-probe warning did not recur during any packaged capture path. |
| EAI.15 | BLOCKED | Independent final whole-branch/security reviews and exact-head CI for this acceptance update remain. PR #13 remains draft and unmerged. |

Windows/Linux embedded-AI implementation and release qualification: **NOT_RUN**, outside this macOS arm64 stage. Bridge portability jobs do not make an embedded-AI support claim.

## Current frozen candidate

- Branch: `post-v1-embedded-ai-impl`
- Implementation source SHA: `bae67a0996afa7ca34c2890295e72de0acd02221`
- Archive SHA-256: `747f90fdb45828db59651780b0d6834d803a9db7c9d5da7c9880a7e4ffdd305d`
- Archive size: 2,671,237,120 bytes
- Bundle tree SHA-256: `41a8d6f063d36450eb0df7d696e64a80d2f163101f982638a86dbd2bd9d0ad3a`
- Core image ID: `sha256:708e7d806ef5a3bd794bec94c34e18ed6b3eb75c7f48f5bd3e48d9d2c728639d`
- Core image archive SHA-256: `fd2f9d6f93e39139a232eadc2b72685273d1711bb469c8b10791d74a8b69b983`
- Compiled web tree SHA-256: `752056be9b75616354a57ffd9e0f92e9b87a48ca390d7d0f245ade3c6350b706`
- macOS arm64 host bridge SHA-256: `f1a64583b0331129458f6f9c4ee56c43e012d725312d915e0482465d7b126964`
- Model SHA-256 / size: `4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc` / 2,497,279,040 bytes
- llama.cpp revision: `8345f333951c661d166b00e6f9362e553768f292`
- llama-server SHA-256: `84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034`
- Runtime manifest SHA-256: `5cafd2ecfa0d76a484ca1c5a9d039588c1832e7f26175d46417f1f361f40a93c`
- Model manifest SHA-256: `a40ec1543fc060a2fb5513fb3cedeea045fc048f06ce68acc3efafb9c5f1c285`
- Release metadata SHA-256: `e243c0232bede6350fc62ed0f3a418874ffa680f86feb5bf51ad7dae532f7c64`
- Runtime policy: Metal enabled; mmap enabled by the pinned runtime default; context 16,384; batch 128; micro-batch 32; one slot; generation cap 2,048; authenticated `127.0.0.1:8767`; no agent tools or web UI; `--cache-ram 0` (0 MiB prompt cache).
- Host/build environment recorded with freeze: macOS 27.0.1 arm64, Xcode 27.0 (27A266a), CMake 4.4.4, Apple clang 21.0.0; Docker 29.8.2 and Compose 5.6.0.
- Full runtime file names, hashes, sizes, policy, argv template, and manifests: `artifacts/embedded-ai/candidate-freeze-bae67a0.json`.

The archive was frozen from the clean exact source commit. After native qualification, the archive and untouched frozen staging tree still matched the freeze record, as did the core image and packaged runtime/model hashes. The fresh disposable native extraction differed from the frozen tree only by the launcher-generated `.env`; its resulting tree hash and this generated file are recorded in `artifacts/embedded-ai/native/bae67a0/candidate-integrity-final.json`. The official unchanged benchmark harness used the frozen bundle's AI assets and the exact same source SHA for every run. Native EAI.14 used the packaged candidate core image recorded above.

Candidates `799f87a635aa600f7efa808f36f04e98b86d760f`, `f38bac27cb893aec2530931c93cc2d1806a1b1d5`, and all earlier candidates are **historical/superseded for final qualification**. Their benchmark and native evidence is not combined with this candidate's evidence. In particular, `799f87a` is superseded because its async capture path invoked synchronous embedded status probing on the ASGI event loop; `asyncio.run()` failed inside that loop, the probe coroutine was not awaited, and Python emitted an unawaited-coroutine warning. Candidate `bae67a0` is the only source/archive identity used for the three benchmark runs and all 16 native checks recorded here.

## Review findings and remediation

- Security review at `d8dbcb71c2807b4ea0e374268e6d68933ae0ff17`: **SECURITY APPROVE WITH NOTES**; no blocking security issue was found.
- Whole-branch review at the same head: **REQUEST CHANGES** with P2. Model remaining-hypothesis proposals accepted same-case observed/derived evidence without proving that non-empty evidence IDs belonged to the deterministic remaining hypothesis authorizing the fixed recommendation. The implementation now binds every non-empty cited ID to that hypothesis's structured evidence IDs while preserving category/domain checks, empty-evidence behavior, deterministic hypotheses, and fixed allowlisted recommendation text. Arbitrary model prose remains excluded.
- The prior proposal-summary finding had no persisted or user-visible impact. The approved response schema remains unchanged; the summary value remains unused and unexposed.
- A separate source defect was then confirmed at `799f87a`: async capture called synchronous `begin_ingest()` and `cleanup_ingest()` directly on the ASGI event loop. Their `get()` path called the embedded runtime probe, whose `asyncio.run()` raised inside the active loop; the catch-all path returned unavailable and Python warned that the probe coroutine was never awaited. Commit `bae67a0996afa7ca34c2890295e72de0acd02221` moves both synchronous service operations through Starlette's existing threadpool boundary. API regressions cover both success and cleanup paths. The real packaged async capture completed without this warning; 13 packaged core/launcher logs were scanned with zero matching warnings.
- Runtime status remains authenticated, bounded, model-identity checked, redirect-disabled, proxy-independent, and limited to a 200 ms whole-operation probe. Process-loss qualification observed public `runtime-unhealthy` before the next investigation, safe deterministic fallback, and ready recovery after packaged restart.
- The PID verify-to-signal race remains a narrow residual. The launcher validates numeric PID, process start time, and executable identity before TERM and rechecks before KILL. The product does not claim atomic PID-reuse protection; this remains non-blocking P3.

## Memory diagnosis and approved policy

The historical source `1fbe6838a01fa7becb75ad73394223108efaaa07` recorded 6.913 GiB, but its exact frozen binary was unavailable. Same-toolchain source rebuilds of old and current source both exceeded 8 GiB; this did not recreate the historical candidate or establish a Wireclaw source regression. The `fed0ea7` candidate also failed host runs at 9.578, 10.521, and 11.988 GiB.

Attribution identified real physical-memory growth from llama.cpp's default prompt-state cache: 8,192 MiB cache limit, about 355 MiB per independent prompt, and about 7,463 MiB retained for 21 prompt states. The extended diagnostic reached 9.85 GiB RSS and 9.72 GiB physical footprint. `--cache-ram 0` measured about 4.71 GiB RSS and 2.40 GiB physical footprint in the small diagnostic, with similar mean provider latency. That diagnostic alone was not treated as acceptance.

The launcher explicitly supplies `--cache-ram 0`; lock, runtime manifest, release metadata, candidate freeze, and benchmark output record the effective policy. The flag is not user configurable. Package smoke checks verify the pinned runtime accepts it and startup fails closed if it does not. Wireclaw constructs bounded provider context from its own persisted case/reasoning state; correctness does not depend on hidden llama-server prompt state.

## Official benchmark results

All three complete unchanged 22-scenario official runs passed individually. RSS measurement semantics and the 8 GiB target were unchanged.

| Run | Peak AI RSS | Peak GiB | Cold readiness | Median provider step | Model size | Safety counters | Original PCAP hashes | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| 1 | 4,996,530,176 bytes | 4.653 | 1.884 s | 15,390 ms | 2,497,279,040 bytes | all zero | unchanged | PASS |
| 2 | 5,017,681,920 bytes | 4.673 | 2.064 s | 15,394 ms | 2,497,279,040 bytes | all zero | unchanged | PASS |
| 3 | 5,024,448,512 bytes | 4.679 | 1.644 s | 15,396 ms | 2,497,279,040 bytes | all zero | unchanged | PASS |

Each run had zero deterministic semantic regressions, unsupported authoritative claims, invalid/cross-case evidence references, unauthorized capabilities, privacy leaks, provider failures without safe fallback, and uncertainty failures. Each report covers all 22 unchanged scenarios and independently passes result validation. See `artifacts/embedded-ai/benchmark-summary-bae67a0.json` and the full reports in `artifacts/embedded-ai/runs/bae67a0/run-{1,2,3}/`.

## Native qualification and CI

All 16 exact Section 22 EAI.14 checks passed against the same frozen archive. The run used a fresh path-with-spaces extraction, core port 28795, bridge port 28796, and the approved AI port 8767. One foreground launcher shell context remained alive during each native run. Evidence covers authenticated `/v1/models`, Docker-core reachability, Metal/mmap runtime identity, UI readiness, model-assisted `tcp.rtt` with 17 evidence records, both Wireshark actions, process-loss fallback and recovery, stop/start persistence, the deliberate port-conflict fixture and its explicit cleanup, isolated model tampering, loopback-only listeners, privacy checks, and final immutable hash verification. See `artifacts/embedded-ai/macos-bae67a0.json`, `artifacts/embedded-ai/native/bae67a0/process-loss-recovery.json`, `artifacts/embedded-ai/native/bae67a0/port-conflict-cleanup.json`, and `artifacts/embedded-ai/native/bae67a0/candidate-integrity-final.json`.

The exact async-capture path was exercised in model-assisted and fallback cases. Thirteen core/launcher logs contained no `RuntimeWarning` and no `embedded_runtime_available.<locals>.probe was never awaited` warning. The async warning audit is `artifacts/embedded-ai/native/bae67a0/async-probe-warning-audit.json`.

The packaged launcher redirects host-bridge stdout/stderr to `/dev/null`; macOS unified-log access was denied during this run. No bridge log text was available. The bridge process identity, 127.0.0.1 listener, and successful `/v1/health` response are preserved. No full-host packet capture was made for no-download verification; the evidence is the offline packaged assets, fixed local paths, `network_downloads=false`, and loopback-only runtime sockets.

Exact-head CI run [#105 / 38829585198](https://github.com/Ryan9876/wireclaw/actions/runs/38829585198) passed all five jobs on implementation source `bae67a0996afa7ca34c2890295e72de0acd02221`: Linux full, Docker release, and Ubuntu/macOS/Windows bridge-platform jobs. Local full Python regression passed with 411 passed and 147 skipped; skips are primarily packet-tool-dependent tests because TShark/capinfos are unavailable on the host. One Starlette TestClient deprecation warning was recorded. Web tests (54), lint, typecheck, and build passed; bridge Go tests/vet, shell syntax, changed-file Ruff check/format, and `git diff --check` passed. The full-repository Ruff format check still reports the pre-existing unrelated formatting difference at `specs/v1/solution.md:318`; that V1 file was not changed. CI installed packet tools and passed its Docker-dependent validation.

## Remaining closeout

The next steps are read-only independent whole-branch and security reviews of this updated acceptance head, followed by exact-head CI for the final documentation/review head. Any new P0/P1/P2 finding blocks release. PR #13 must remain draft and unmerged.
