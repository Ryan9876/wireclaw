# Embedded Qwen benchmark comparison

Source: `bae67a0996afa7ca34c2890295e72de0acd02221`

Model: `wireclaw-qwen3-4b-instruct-2507-q4_k_m` (4169f9cf383f6aeb8b2fc9cc23fe061e276a0d10b0843ae959ab4d895020aafc)

Runtime: `llama.cpp` 8345f333951c661d166b00e6f9362e553768f292 (84b7ae18c4e90534a8c44b9190770b1f91fda2c002bac21af6a758c477d98034)

Prompt-cache RAM: 0 MiB

## Safety and performance

- Verdict: **PASS**
- Deterministic semantic regressions: 0
- Unsupported authoritative claims: 0
- Invalid evidence references: 0
- Unauthorized capabilities: 0
- Provider failures without fallback: 0
- Uncertainty failures: 0
- Privacy leaks: 0
- Original capture hashes unchanged: True
- Cold readiness: 1.64s (target <=30s)
- Peak AI RSS: 4.68 GiB (target <=8 GiB)
- Median provider step: 15396ms (target <=20s)
- Q4_K_M model size: 2497279040 bytes
- Release payload estimate: 2671514632 bytes (core-image.tar + staged AI assets + packaged source payloads + darwin/arm64 bridge, excluding archive metadata)

## Product-value observations

- Hypothesis finding order changed in 0 scenarios; model ranking never creates or rewrites packet findings.
- Next-evidence guidance count increased in 0 scenarios. All added guidance remains drawn from the fixed allowlist.
- Explanation remains deterministic and evidence-linked; the model does not supply finding prose.
- The run therefore does not show a material ranking or next-evidence improvement while preserving deterministic findings and uncertainty.
- Scripted adversarial responses exercise invented/cross-case evidence, repeated/invalid capabilities, malformed output, and runtime failure. They are contract tests, not model-generated outputs.

Windows/Linux embedded-AI implementation and qualification: NOT_RUN.
