# Post-V1 embedded local AI acceptance

**Current disposition: BLOCKED** — implementation and benchmark evidence are ready for review, but the complete native macOS packaged acceptance and final review pipeline are not yet recorded as complete. This document does not alter the historical V1 acceptance record.

## Task states

| Task | State | Evidence / note |
| --- | --- | --- |
| Preflight P0 | PASS | `artifacts/embedded-ai/preflight-loopback.json`; Docker core reached a host service bound only to `127.0.0.1:18767`. |
| EAI.1 | PASS | Embedded provider contract and Gate 7 tests. |
| EAI.2 | PASS | Pinned Qwen source/conversion/quantization manifests and actual GGUF provenance. |
| EAI.3 | PASS | Pinned llama.cpp v0.6.0 macOS arm64 Metal runtime; authenticated native protocol smoke. |
| EAI.4 | PASS | Model/runtime and release metadata manifests, hash validation, immutable candidate freeze. |
| EAI.5 | PASS | macOS lifecycle, PID/start-time/executable identity checks, hash/path validation, fallback; packaged readiness regression was fixed and retested. |
| EAI.6 | PASS | Docker Desktop host-route P0 and embedded core benchmark through the host loopback service. |
| EAI.7 | PASS | Embedded adapter uses the existing Gate 7 schema, typed actions, evidence validation, and fallback boundary. |
| EAI.8 | PASS | Safe effective AI status and audit metadata. |
| EAI.9 | PASS | Minimal provider status labels; automated browser check rendered “Local embedded AI ready.” |
| EAI.10 | PASS | Offline release bundle includes core archive, host bridge, model/runtime, licenses, and identity metadata; no launch-time downloads. |
| EAI.11 | PASS | `artifacts/embedded-ai/security-privacy.json`; sentinel and adversarial acceptance passed. |
| EAI.12 | PASS | Exact-head 22-scenario benchmark: `artifacts/embedded-ai/benchmark.json` and `comparison.md`; all safety counters zero and all release targets met. |
| EAI.13 | PASS | `artifacts/embedded-ai/regression.json`; Gate 9, core, Python, packaging, web, bridge, fallback, and native Wireshark checks recorded. |
| EAI.14 | BLOCKED | Candidate is frozen and packaged startup/UI/loopback checks passed, but the full 16-check native acceptance has not been completed against the frozen final archive. Do not treat unit tests or the earlier equivalent staging run as a substitute. |
| EAI.15 | BLOCKED | Documentation is prepared here and in the operations guide; exact-head hosted CI, independent whole-branch review, and draft PR still need completion. |

Windows/Linux embedded-AI implementation and release qualification: **NOT_RUN**, explicitly outside this macOS arm64 stage.

## Frozen candidate identities

- Branch: `post-v1-embedded-ai-impl`
- Candidate source: `1fbe6838a01fa7becb75ad73394223108efaaa07`
- Bundle archive: `/private/tmp/wireclaw-eai-candidate-1fbe683.tar`
- Bundle SHA-256: `d2253bccbb3e6178f94f88018f440a4b0da645c35fc29f261978c4d02240603a`
- Bundle tree SHA-256: `5370ff37013118a083ddc0b22cf413a0c671d4ea6fc1f6a82564bf3bccf02203`
- Archive size: 2,642,309,120 bytes
- Qwen: `Qwen/Qwen3-4B-Instruct-2507`, revision `cdbee75f17c01a7cc42f958dc650907174af0554`, Apache-2.0, Q4_K_M; SHA-256 `4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc`, size 2,497,279,040 bytes.
- llama.cpp: `ggml-org/llama.cpp` v0.6.0, commit `8345f333951c661d166b00e6f9362e553768f292`; `llama-server` SHA-256 `2f2d9ebad23c9d6f28122715292f27e98f51fdfadd120c3f63152007469b7b32`.
- Runtime policy: loopback `127.0.0.1:8767`, context 16,384, batch 128, micro-batch 32, generation cap 2,048, one slot, ephemeral per-launch authentication, no agent/UI/file features.
- Model manifest SHA-256: `18e39b41e58c4b9f4328dca5c88d86d87021c8b4a1c5e96ab96d58b21a498f49`.
- Runtime manifest SHA-256: `617058f8945fc16d5029ecf379422e73e10d66d5670bf4e40200d3e9ee4e29aa`.

## Benchmark

The exact candidate source benchmark completed 22 paired scenarios. Verdict: **PASS**.

- Deterministic semantic regressions: 0
- Unsupported authoritative claims: 0
- Invalid/cross-case evidence references: 0
- Unauthorized capabilities: 0
- Uncertainty failures: 0
- Provider failures without safe fallback: 0
- Privacy leaks: 0
- Original capture hashes changed: no
- Cold readiness: 1.25 s (target <=30 s)
- Peak AI RSS: 7,422,312,448 bytes / 6.91 GiB (target <=8 GiB)
- Median provider step: 18,609 ms (target <=20,000 ms)
- Model size: 2,497,279,040 bytes / 2.33 GiB (target <=3.5 GiB)
- Estimated release payload: 2,642,212,536 bytes

The comparison found no material improvement in hypothesis ordering or next-evidence guidance. Explanation and packet facts remain deterministic. Embedded reasoning passed without weakening evidence traceability, uncertainty, or fallback behavior.

## Completed native observations and outstanding acceptance

A macOS arm64 packaged launch using the same final launcher and policy was exercised under a temporary HOME, an isolated data root containing spaces, and non-conflicting loopback ports. It reached `/api/health` with `embedded_availability=ready`; Chromium rendered the required ready label; lsof showed the app, bridge, and AI services on numeric loopback. That run exposed and fixed a FIFO/readiness race; the correction is in candidate source `1fbe683`.

The previous accepted native Wireshark regression opened both full and evidence captures for high-RTT and DNS-delay cases, with argv/filter and original-capture hashes recorded in `artifacts/embedded-ai/regression.json`. Exact final archive checks still needed for the remaining Section 22 cases include on-candidate process-loss fallback/recovery, persistence across packaged stop/start, port conflict and tamper degradation, and the final archive’s no-download/network observation. EAI.14 remains BLOCKED until all 16 checks are individually recorded against the frozen archive.

The final exact-head CI run, independent whole-branch review, and draft PR number/link are pending. No PR has been merged.
