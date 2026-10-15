# Post-V1 embedded local AI acceptance

**Current disposition: BLOCKED** — the frozen `f38bac27` candidate passes exact-head CI, the three-run official benchmark, and all 16 native macOS EAI.14 checks. Independent whole-branch and security re-reviews of the current acceptance head and final exact-head CI remain outstanding. PR #13 remains draft and must not be merged. This record does not alter historical V1 acceptance.

## Task states

| Task | State | Evidence / note |
| --- | --- | --- |
| Preflight P0 | PASS | `artifacts/embedded-ai/preflight-loopback.json`; packaged core reached a host service bound only to loopback. |
| EAI.1–EAI.11 | PASS | Provider, provenance, packaging, launcher, Gate 7, UI, offline bundle, and privacy controls passed current-head tests and candidate checks. |
| EAI.12 | PASS | Three complete official 22-scenario runs on frozen `f38bac27`; all per-run targets and safety checks passed. See `benchmark.json`, `comparison.md`, and `runs/f38bac2/`. |
| EAI.13 | PASS | Full local pre-commit regression and all five exact-head CI jobs passed on remediation source `f38bac27`. CI exercised Docker release/packaging and the Linux full test suite, including locally skipped packet-tool tests. |
| EAI.14 | PASS | All 16 native macOS checks passed against the same frozen `f38bac27` archive; see `macos-f38bac2.json` and linked evidence. |
| EAI.15 | BLOCKED | Independent read-only whole-branch/security reviews and final documentation/review-head CI remain. PR #13 remains draft and unmerged. |

Windows/Linux embedded-AI implementation and release qualification: **NOT_RUN**, outside this macOS arm64 stage. Bridge portability jobs do not make an embedded-AI support claim.

## Current frozen candidate

- Branch: `post-v1-embedded-ai-impl`
- Implementation source SHA: `f38bac27cb893aec2530931c93cc2d1806a1b1d5`
- Archive SHA-256: `584f6ea27d08298b0920de244abe3cb03d9b2c729dd2905039ba3b1e60f973db`
- Archive size: 2,671,237,120 bytes
- Bundle tree SHA-256: `c6988ddd616996b208837d701ea246f86c40f35bbc68137e3f34205a38f2a1aa`
- Core image ID: `sha256:6ebc5ad2ee966d841e2e1013a1dcf1a11e86d76ccb229f48469ff3d0e3c085ff`
- Core image archive SHA-256: `18da566ede95197f4e760d704bc20117e2d29b9c5fc8f065058f45535c7bbc2d`
- Compiled web tree SHA-256: `752056be9b75616354a57ffd9e0f92e9b87a48ca390d7d0f245ade3c6350b706`
- macOS arm64 host bridge SHA-256: `f1a64583b0331129458f6f9c4ee56c43e012d725312d915e0482465d7b126964`
- Model SHA-256 / size: `4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc` / 2,497,279,040 bytes
- llama.cpp revision: `8345f333951c661d166b00e6f9362e553768f292`
- llama-server SHA-256: `84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034`
- Runtime manifest SHA-256: `5cafd2ecfa0d76a484ca1c5a9d039588c1832e7f26175d46417f1f361f40a93c`
- Model manifest SHA-256: `a40ec1543fc060a2fb5513fb3cedeea045fc048f06ce68acc3efafb9c5f1c285`
- Release metadata SHA-256: `ace963d8fd0560650ad392f5a6dbf46fb14b30511ce87174432a18315c3982de`
- Runtime policy: Metal and mmap enabled; context 16,384; batch 128; micro-batch 32; one slot; generation cap 2,048; authenticated loopback-only endpoint; no agent tools or web UI; `--cache-ram 0` (0 MiB prompt cache).
- Host/build environment recorded with freeze: macOS 27.0.1 arm64, Xcode 27.0 (27A266a), CMake 4.4.4, Apple clang 21.0.0; Docker 29.8.2 and Compose 5.6.0.
- Full runtime file names, hashes, sizes, policy, argv template, and manifests: `artifacts/embedded-ai/candidate-freeze-f38bac2.json`.

The archive was frozen from the clean exact source commit. Its extracted tree and archive hashes were independently rechecked. The official benchmark harness rebuilt the same core source/image for each run as in the approved procedure; native EAI.14 used the packaged candidate core image recorded above. The run-specific benchmark core image IDs are preserved per run and are not represented as the frozen package core ID.

Candidate `647c267cb90307454d949a8e10cdaade0eef2e20` is **superseded for final release qualification**. Its prior benchmark/native evidence remains historical and is not combined with `f38bac27` results. The new candidate was required because independent review remediation changed recommendation validation and live embedded-runtime status reporting after `647c267` was frozen.

## Review findings and remediation

- The security review's original P1 claim that arbitrary next-evidence prose altered deterministic hypotheses was overstated: prose was already filtered, and deterministic remaining hypotheses remained authoritative. A narrower correctness gap was reproduced: an unrelated allowlisted recommendation could be appended. The fix binds fixed recommendation codes to a deterministic remaining hypothesis with matching category/domain. Arbitrary model prose remains excluded. The regression runs against the frozen packaged core and is recorded in `native/f38bac2/recommendation-binding.json`.
- The `HypothesisProposal.summary` finding had no persisted or user-visible impact. The approved response schema remains unchanged; the summary value remains unused and unexposed.
- The stale embedded-AI ready status finding was confirmed as P2. Public status now performs bounded authenticated reachability/identity probing, normalizes failure to `runtime-unhealthy`, and recovers to ready when the runtime returns. Runtime loss was observed through health/capabilities before any new investigation; deterministic core health remained OK and a subsequent case completed by rules-only fallback.
- The PID verify-to-signal race remains a narrow residual. The launcher continues to validate numeric PID, process start time, and executable identity before TERM and rechecks before KILL. No practical macOS identity-bound signal primitive fits this design without a disproportionate supervision redesign. Documentation records the residual; it is non-blocking P3, and the product does not claim atomic PID-reuse protection.

## Memory diagnosis and approved policy

The historical source `1fbe6838a01fa7becb75ad73394223108efaaa07` recorded 6.913 GiB, but its exact frozen binary was unavailable. Same-toolchain source rebuilds of old and current source both exceeded 8 GiB; this did not recreate the historical candidate or establish a Wireclaw source regression. The `fed0ea7` candidate also failed host runs at 9.578, 10.521, and 11.988 GiB.

Attribution identified real physical-memory growth from llama.cpp's default prompt-state cache: 8,192 MiB cache limit, about 355 MiB per independent prompt, and about 7,463 MiB retained for 21 prompt states. The extended diagnostic reached 9.85 GiB RSS and 9.72 GiB physical footprint. `--cache-ram 0` measured about 4.71 GiB RSS and 2.40 GiB physical footprint in the small diagnostic, with similar mean provider latency. That diagnostic alone was not treated as acceptance.

The launcher explicitly supplies `--cache-ram 0`; lock, runtime manifest, release metadata, candidate freeze, and benchmark output record the effective policy. The flag is not user configurable. Package smoke checks verify the pinned runtime accepts it and startup fails closed if it does not. Wireclaw constructs bounded provider context from its own persisted case/reasoning state; correctness does not depend on hidden llama-server prompt state.

## Official benchmark results

All three complete unchanged 22-scenario official runs passed individually. RSS measurement semantics and the 8 GiB target were unchanged.

| Run | Peak AI RSS | Peak GiB | Cold readiness | Median provider step | Model size | Safety counters | Original PCAP hashes | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| 1 | 5,060,542,464 bytes | 4.713 | 1.448 s | 15,420 ms | 2,497,279,040 bytes | all zero | unchanged | PASS |
| 2 | 5,065,523,200 bytes | 4.718 | 1.039 s | 15,415 ms | 2,497,279,040 bytes | all zero | unchanged | PASS |
| 3 | 5,060,771,840 bytes | 4.713 | 0.831 s | 15,440 ms | 2,497,279,040 bytes | all zero | unchanged | PASS |

Each run had zero deterministic semantic regressions, unsupported authoritative claims, invalid/cross-case evidence references, unauthorized capabilities, privacy leaks, provider failures without safe fallback, and uncertainty failures. See the separate JSON reports in `artifacts/embedded-ai/runs/f38bac2/run-{1,2,3}/` and the human-readable `comparison.md`.

## Native qualification and CI

All 16 exact Section 22 EAI.14 checks passed against the same frozen archive. Evidence includes packaged startup/provenance, loopback identity, core connectivity, UI readiness, model-assisted `tcp.rtt` with 17 evidence records, both Wireshark actions, process-loss status and rules-only fallback, restart recovery and persistence, spaced paths, port-conflict/tamper fallback, and privacy checks. The full checklist is `artifacts/embedded-ai/macos-f38bac2.json`.

Exact-head CI run [`38802955931`](https://github.com/Ryan9876/wireclaw/actions/runs/38802955931) passed all five jobs on implementation source `f38bac27cb893aec2530931c93cc2d1806a1b1d5`: Linux full, Docker release, and Ubuntu/macOS/Windows bridge-platform jobs. The Docker release and Linux full jobs exercised Docker-dependent packaging and packet-tool integration coverage that skipped locally. See `artifacts/embedded-ai/regression-f38bac2.json` for the full local and exact-head regression record. Local full Python regression was 405 passed and 147 skipped because TShark/capinfos are unavailable on the host; skips are not reported as passes. Web, bridge, Ruff, shell syntax, and diff checks also passed. Repository-wide Ruff format check still reports one unrelated pre-existing formatting difference at `specs/v1/solution.md:318`; that V1 file was not changed.

## Remaining closeout

The next steps are read-only independent whole-branch review and security review of this updated acceptance head, followed by exact-head CI for the final documentation/review head. Any new P0/P1/P2 finding blocks release. PR #13 must remain draft and unmerged.
