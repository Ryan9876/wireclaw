# Embedded Qwen benchmark comparison

Current qualified diagnostic and official candidate source: 647c267cb90307454d949a8e10cdaade0eef2e20.

The earlier greater than 8 GiB failures came from llama.cpp's default prompt-state cache. Its default limit was 8,192 MiB and independent prompt states retained about 355 MiB each. In the extended 22-prompt diagnostic, 21 retained states accounted for about 7,463 MiB. This was real physical memory growth: peak RSS reached 9.85 GiB and peak physical footprint reached 9.72 GiB. The approved fix pins --cache-ram 0; runtime policy and release metadata record it.

Model SHA-256: 4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc.

llama.cpp revision: 8345f333951c661d166b00e6f9362e553768f292; llama-server SHA-256: 84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034.

Prompt-cache RAM: **0 MiB** (--cache-ram 0). Context 16,384; batch 128; micro-batch 32; one slot; Metal and mmap enabled; generation cap 2,048.

## Three full official qualification runs

Each row is a complete unchanged 22-scenario official benchmark run. Every peak is retained separately.

| Run | Verdict | Peak AI RSS (bytes) | Peak (GiB) | Cold readiness | Median provider step | Semantic regressions | Unsupported claims | Invalid evidence | Unauthorized capabilities | Privacy leaks | Unsafe provider failures | Uncertainty failures | Original PCAP hashes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | PASS | 5,094,866,944 | 4.744 | 0.828 s | 15,360 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |
| 2 | PASS | 5,084,643,328 | 4.735 | 1.032 s | 15,278 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |
| 3 | PASS | 5,059,117,056 | 4.711 | 1.031 s | 15,377 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |

Each run met the model-size bound (2,497,279,040 bytes), readiness bound (30 s), provider-step bound (20 s), and RSS bound (8 GiB). Per-run scenario evidence is in artifacts/embedded-ai/runs/647c267/run-{1,2,3}/benchmark.json; canonical benchmark.json is run 3.

## Product and recovery behavior

Disabling llama.cpp prompt caching did not change Gate 7 evidence validation, capability behavior, fallback behavior, deterministic findings, or investigation completion. Each provider request rebuilds its bounded context from Wireclaw-owned persisted case and reasoning state; correctness does not depend on retained llama-server prompt state.

Exact-head CI then exposed a separate startup recovery ordering defect: the parent service constructor runs recovery through Gate 7's overridden get()/ai_status() before Gate 7 initialized its runtime failure field. That caused three recovery tests to fail on Linux/Docker. The field now initializes before the parent constructor; a regression test failed before the fix and passes after it. The corrected 647c267 head passes all exact-head workflows and its new immutable candidate passed the full benchmark three times.

## Disposition

The 8 GiB target and benchmark measurement semantics are unchanged. EAI.12 and EAI.14 pass for the frozen 647c267 candidate. Release closeout remains blocked only on independent whole-branch/security review; draft PR #13 remains open and unmerged.
