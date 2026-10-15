# Post-V1 embedded local AI acceptance

**Current disposition: BLOCKED** — the new frozen candidate passes the three-run benchmark and all 16 native EAI.14 checks. Exact-head hosted CI, final whole-branch and security reviews, regression closeout, and draft PR creation remain in progress. This record does not alter the historical V1 acceptance record.

## Task states

| Task | State | Evidence / note |
| --- | --- | --- |
| Preflight P0 | PASS | `artifacts/embedded-ai/preflight-loopback.json`; Docker core reached a loopback host service. |
| EAI.1–EAI.11 | PASS | Provider, provenance, packaging, launcher, Gate 7, UI, offline bundle, and privacy controls remain covered by current-head tests and package evidence. |
| EAI.12 | PASS | Three complete official 22-scenario runs for the new frozen candidate; see `artifacts/embedded-ai/benchmark.json`, `comparison.md`, and `runs/b64a0fd/`. Every run met all hard targets and safety counters. |
| EAI.13 | IN_PROGRESS | Full current-head regression and review closeout are running; previous `fed0ea7` evidence is superseded for candidate acceptance. |
| EAI.14 | PASS | All 16 native macOS checks were run against the frozen `b64a0fd` candidate. See `artifacts/embedded-ai/macos-b64a0fd.json` and its linked evidence files. |
| EAI.15 | BLOCKED | Exact-head hosted CI, independent reviews, final documentation closeout, and draft PR are pending. No PR is merged. |

Windows/Linux embedded-AI implementation and release qualification: **NOT_RUN**, outside this macOS arm64 stage.

## Current frozen candidate

- Branch: `post-v1-embedded-ai-impl`
- Source: `b64a0fdaa80ef5a9c4115a757e677942cd685beb`
- Archive: `/private/tmp/wireclaw-candidate-b64a0fd/wireclaw-candidate.tar`
- Archive SHA-256: `fb804e0e2f35264464f9577f4dc68d05d312e99c825c621f48ebb799a5bcb281`
- Tree SHA-256: `6408e56d88fef6502fb80aab1bd70424cb1214f3bf5c9183feb3d39d0501d76d`
- Archive size: 2,671,237,120 bytes
- Core image: `sha256:aa43a91bf2113dd5c9db520e9a448d9137e1ecdbbe2e14672c459db5700244b1`
- Model SHA-256 / size: `4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc` / 2,497,279,040 bytes
- llama.cpp revision: `8345f333951c661d166b00e6f9362e553768f292`
- llama-server SHA-256: `84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034`
- Runtime manifest SHA-256: `5cafd2ecfa0d76a484ca1c5a9d039588c1832e7f26175d46417f1f361f40a93c`
- Model manifest SHA-256: `a40ec1543fc060a2fb5513fb3cedeea045fc048f06ce68acc3efafb9c5f1c285`
- Runtime: macOS arm64, Metal and mmap enabled; context 16,384; batch 128; micro-batch 32; one slot; generation cap 2,048; authenticated loopback-only; `--cache-ram 0`.
- Xcode 27.0 (27A266a), CMake 4.4.4.

The launcher uses the fixed runtime argument `--cache-ram 0`; runtime and release manifests record `prompt_cache_ram_mib: 0`. The setting is not user configurable. Launcher verification and the pinned-runtime smoke fail closed if the policy or flag is not accepted.

## Superseded candidate history and memory diagnosis

The historical frozen candidate at source `1fbe6838a01fa7becb75ad73394223108efaaa07` recorded 6.913 GiB, but that exact binary could not be recovered. Same-toolchain OLD-REBUILT and NEW-REBUILT source experiments both exceeded 8 GiB; they did not reproduce the historical frozen binary and did not establish a Wireclaw source regression. The `fed0ea7` candidate then failed three host benchmark runs at 9.578, 10.521, and 11.988 GiB RSS.

Memory attribution established a real physical-memory miss from llama.cpp's default prompt-state cache. Its default 8,192 MiB budget retained roughly 355 MiB per independent prompt; 21 retained prompt states accounted for roughly 7,463 MiB. The 22-prompt diagnostic peaked at 9.85 GiB RSS and 9.72 GiB physical footprint. With supported `--cache-ram 0`, the small diagnostic measured about 4.71 GiB RSS and 2.40 GiB physical footprint with approximately unchanged mean provider latency (8.46 s versus 8.49 s).

The small diagnostic was not treated as acceptance. The new frozen `b64a0fd` candidate completed the full unchanged corpus three times; peaks were 5,096,046,592, 5,096,472,576, and 5,083,529,216 bytes. Each complete run passed every hard target and all safety checks. The 8 GiB target and benchmark semantics are unchanged.

## Native EAI.14

The new candidate passed automatic packaged startup, manifest/hash checks, Metal/runtime identity, Docker-core connectivity, UI ready state, model-assisted investigation with evidence links, both native Wireshark actions, process-loss fallback, restart recovery, case persistence across stop/start, paths containing spaces, AI-port conflict, tamper rejection, loopback listener checks, and privacy-token checks. Full check details and per-case hashes are in `artifacts/embedded-ai/macos-b64a0fd.json`.

## Outstanding closeout

The final exact-head workflow run, independent whole-branch review, security-focused review, regression record update, and draft PR creation remain required. Do not merge the draft PR. EAI.12 and EAI.14 evidence applies only to the frozen `b64a0fd` candidate; the earlier `fed0ea7` candidate is superseded.
