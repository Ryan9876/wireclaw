# Embedded Qwen benchmark comparison

Accepted diagnostic and official qualification candidate source: `b64a0fdaa80ef5a9c4115a757e677942cd685beb`.

This candidate supersedes the `fed0ea7` candidate for acceptance. The earlier >8 GiB failures were caused primarily by llama.cpp's default 8,192 MiB prompt-state cache retaining independent prompt states (about 355 MiB each). In the 22-prompt diagnostic, 21 retained states accounted for about 7,463 MiB. This was a real physical-memory increase: peak physical footprint reached 9.72 GiB alongside 9.85 GiB RSS. The approved fix pins `--cache-ram 0`; cache behavior is part of the runtime policy and release manifest.

Model SHA-256: `4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc`.

llama.cpp revision: `8345f333951c661d166b00e6f9362e553768f292`; llama-server SHA-256: `84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034`.

Prompt-cache RAM: **0 MiB** (`--cache-ram 0`). Context 16,384; batch 128; micro-batch 32; one slot; Metal and mmap enabled; generation cap 2,048.

## Three full official qualification runs

Each row is one complete unchanged 22-scenario official benchmark run. No peak is averaged away.

| Run | Verdict | Peak AI RSS (bytes) | Peak (GiB) | Cold readiness | Median provider step | Semantic regressions | Unsupported claims | Invalid evidence | Unauthorized capabilities | Privacy leaks | Unsafe provider failures | Uncertainty failures | Original PCAP hashes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | PASS | 5,096,046,592 | 4.745 | 0.821 s | 15,287 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |
| 2 | PASS | 5,096,472,576 | 4.745 | 0.820 s | 15,348 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |
| 3 | PASS | 5,083,529,216 | 4.733 | 1.049 s | 15,341 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |

All three runs also met the model-size bound (2,497,279,040 bytes), readiness bound (30 s), provider-step bound (20 s), and RSS bound (8 GiB). Per-run machine-readable results are in `artifacts/embedded-ai/runs/b64a0fd/run-{1,2,3}/benchmark.json`; the canonical `benchmark.json` is run 3 and retains all scenario-level evidence.

## Product behavior

Disabling llama.cpp prompt caching did not change Gate 7 reasoning validation, same-case evidence checks, capability behavior, fallback behavior, deterministic findings, or investigation completion. Provider requests rebuild bounded context from Wireclaw-owned persisted case and reasoning state; no correctness behavior depends on retained llama-server prompt state. The unchanged corpus passed its safety and semantic checks on every run.

The 8 GiB target is unchanged. EAI.12 has passed on the new frozen candidate; release disposition remains blocked until exact-head CI, independent reviews, and remaining closeout evidence are complete.
