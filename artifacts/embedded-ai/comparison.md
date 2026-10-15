# Embedded Qwen benchmark comparison

The current official qualification candidate is source `f38bac27cb893aec2530931c93cc2d1806a1b1d5`. Candidate `647c267cb90307454d949a8e10cdaade0eef2e20` is superseded for final release qualification because independent review required recommendation-binding validation and live runtime status reporting changes. Its evidence remains historical and is not combined with the new candidate's results.

The earlier greater-than-8-GiB failures came from llama.cpp's default prompt-state cache: an 8,192 MiB limit, approximately 355 MiB per independent prompt, and approximately 7,463 MiB retained for 21 states. That diagnostic reached 9.85 GiB RSS and 9.72 GiB physical footprint. The explicit approved policy is `--cache-ram 0`; it is fixed in launcher argv, runtime manifest, release metadata, and candidate record. The 8 GiB target and RSS collection semantics are unchanged.

Model SHA-256: `4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc`. llama.cpp revision: `8345f333951c661d166b00e6f9362e553768f292`; llama-server SHA-256: `84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034`. Context 16,384; batch 128; micro-batch 32; one slot; Metal and mmap enabled; generation cap 2,048; prompt-cache RAM 0 MiB.

## Three full official 22-scenario qualification runs

Each row is a separate complete unchanged-corpus run. Every peak is retained separately; there is no averaging of failures.

| Run | Verdict | Peak AI RSS (bytes) | Peak (GiB) | Cold readiness | Median provider step | Semantic regressions | Unsupported claims | Invalid evidence | Unauthorized capabilities | Privacy leaks | Unsafe provider failures | Uncertainty failures | Original PCAP hashes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | PASS | 5,060,542,464 | 4.713 | 1.448 s | 15,420 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |
| 2 | PASS | 5,065,523,200 | 4.718 | 1.039 s | 15,415 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |
| 3 | PASS | 5,060,771,840 | 4.713 | 0.831 s | 15,440 ms | 0 | 0 | 0 | 0 | 0 | 0 | 0 | unchanged |

Every run passed all target thresholds: model 2,497,279,040 bytes, RSS at most 8 GiB, readiness at most 30 seconds, median provider step at most 20 seconds. Each run had 22 scenarios, zero unsafe provider failures, and unchanged original PCAP hashes. Recommendation-binding was additionally exercised inside the packaged core image; an unrelated allowlisted `browser_har` code was rejected while the matching fixed `application_logs` code was accepted and deterministic remaining hypotheses stayed unchanged. See `native/f38bac2/recommendation-binding.json`.

Full per-run JSON is under `artifacts/embedded-ai/runs/f38bac2/run-{1,2,3}/benchmark.json`; canonical `benchmark.json` is run 3.

## Product impact and recovery

Wireclaw sends self-contained bounded provider context from Wireclaw-owned case/reasoning state; correctness does not rely on hidden llama-server prompt state. `--cache-ram 0` did not weaken validation, deterministic findings, fallback, or investigation completion.

The current candidate also passed all 16 native macOS EAI.14 checks. Runtime loss changed public status before another investigation while core health stayed healthy; rules-only fallback retained deterministic `tcp.rtt`; restart restored ready status and preserved the prior case/evidence. Port conflict and tamper checks degraded safely. See `artifacts/embedded-ai/macos-f38bac2.json`.

## Disposition

EAI.12 and EAI.14 pass for the frozen `f38bac27` candidate. EAI.15 remains BLOCKED pending independent whole-branch and security re-review and final exact-head CI. PR #13 remains draft and must not be merged.
