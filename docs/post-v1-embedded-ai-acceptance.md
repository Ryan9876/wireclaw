# Post-V1 embedded local AI acceptance

**Current disposition: BLOCKED** — the frozen 647c267 candidate passes the three-run full benchmark, all 16 native EAI.14 checks, full regression, and exact-head CI. Independent whole-branch and security reviews remain outstanding. Draft PR #13 is open and must not be merged until EAI.15 closeout. This record does not change historical V1 acceptance.

## Task states

| Task | State | Evidence / note |
| --- | --- | --- |
| Preflight P0 | PASS | artifacts/embedded-ai/preflight-loopback.json; packaged core reached a host service bound only to loopback. |
| EAI.1–EAI.11 | PASS | Provider, provenance, packaging, launcher, Gate 7, UI, offline bundle, and privacy controls passed current-head tests and candidate checks. |
| EAI.12 | PASS | Three full unchanged 22-scenario official runs on 647c267; see artifacts/embedded-ai/benchmark.json, comparison.md, and runs/647c267/. Every hard target and safety check passed. |
| EAI.13 | PASS | Full Python, web, bridge, Docker release, and exact-head GitHub workflow validation passed; see artifacts/embedded-ai/regression-647c267.json. |
| EAI.14 | PASS | All 16 native macOS checks passed on the same frozen 647c267 archive; see artifacts/embedded-ai/macos-647c267.json. |
| EAI.15 | BLOCKED | Independent whole-branch/security review remains outstanding. Draft PR #13 is open, with no merge. |

Windows/Linux embedded-AI implementation and release qualification: **NOT_RUN**, outside this macOS arm64 stage. The bridge portability workflows pass but do not make an embedded-AI support claim.

## Current frozen candidate

- Branch: post-v1-embedded-ai-impl
- Implementation source: 647c267cb90307454d949a8e10cdaade0eef2e20
- Archive: /private/tmp/wireclaw-candidate-647c267/embedded-ai-candidate.tar
- Archive SHA-256: 9b6c2280cd92fcd15f9e0644818c989d981e3bbbb0953ee5d2713c622556d60b
- Tree SHA-256: cdf85a97e5507be4b5a3b1e54b346120f110b616861c633d2263d30c75663853
- Archive size: 2,671,247,360 bytes
- Core image: sha256:b9cfd2b7bb59700d264fcefcc690d03e15d7fcb07b179388421d0ab758c2219c
- Compiled web SHA-256: 752056be9b75616354a57ffd9e0f92e9b87a48ca390d7d0f245ade3c6350b706
- Host bridge SHA-256: f1a64583b0331129458f6f9c4ee56c43e012d725312d915e0482465d7b126964
- Model SHA-256 / size: 4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc / 2,497,279,040 bytes
- llama.cpp revision: 8345f333951c661d166b00e6f9362e553768f292
- llama-server SHA-256: 84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034
- Runtime manifest SHA-256: 5cafd2ecfa0d76a484ca1c5a9d039588c1832e7f26175d46417f1f361f40a93c
- Model manifest SHA-256: a40ec1543fc060a2fb5513fb3cedeea045fc048f06ce68acc3efafb9c5f1c285
- Runtime: macOS 27.0.1 arm64, Metal and mmap enabled; context 16,384; batch 128; micro-batch 32; one slot; generation cap 2,048; authenticated loopback-only; --cache-ram 0.
- Xcode 27.0 (27A266a), CMake 4.4.4.

The launcher uses fixed --cache-ram 0; the lock, runtime manifest, release metadata, and benchmark output record prompt_cache_ram_mib: 0. The setting is not user configurable. Startup and packaging smoke fail closed if the pinned runtime does not accept the flag.

## Superseded candidate history and memory diagnosis

The historical candidate at source 1fbe6838a01fa7becb75ad73394223108efaaa07 recorded 6.913 GiB, but its exact frozen binary could not be recovered. Same-toolchain old/new source rebuilds both exceeded 8 GiB, so they did not reproduce that historical binary or establish a Wireclaw source regression. The fed0ea7 candidate then failed three host runs at 9.578, 10.521, and 11.988 GiB RSS.

Memory attribution showed a real physical-memory miss from llama.cpp's default prompt-state cache: 8,192 MiB limit, approximately 355 MiB per independent prompt, and approximately 7,463 MiB retained for 21 prompt states. The extended diagnostic reached 9.85 GiB RSS and 9.72 GiB physical footprint. The small --cache-ram 0 diagnostic measured about 4.71 GiB RSS and 2.40 GiB physical footprint with similar mean provider latency, but was not accepted as qualification.

The first cache-zero frozen candidate b64a0fdaa80ef5a9c4115a757e677942cd685beb passed three benchmark runs and 16 native checks. It was superseded after exact-head CI found a separate recovery initialization-order defect. The fix initializes Gate 7's runtime-failure state before the parent constructor, which runs startup recovery through overridden Gate 7 methods. A regression test demonstrated the failure before the fix. Candidate 647c267 was rebuilt and requalified from scratch.

## Current benchmark and native acceptance

The replacement candidate passed three full official benchmark repetitions with peak RSS values 5,094,866,944; 5,084,643,328; and 5,059,117,056 bytes. Each run passed readiness, latency, model-size, safety, and original-PCAP integrity checks. Full results are preserved separately; no peak was averaged away.

All 16 Section 22 checks passed on the same immutable candidate: packaged startup and identity, offline model/runtime behavior, Metal and Docker connectivity, UI ready state, model-assisted investigation with evidence links, both native Wireshark actions, safe fallback, restart/persistence, paths containing spaces, port conflict and tamper degradation, loopback-only listeners, and privacy-token checks.

## Remaining closeout

Exact-head PR CI passed all five workflow jobs on source 647c267 (Linux full, Docker release, and macOS/Ubuntu/Windows bridge). The local full suite passed 397 tests with 147 platform/tool skips. The repository-wide Ruff formatter check still reports one unrelated pre-existing formatting difference in specs/v1/solution.md:318; the V1 spec was left unchanged.

Independent whole-branch and security reviews are still needed. PR #13 is a draft and has not been merged. Do not mark EAI.15 complete or release-qualified until those reviews and any resulting fixes are complete.
