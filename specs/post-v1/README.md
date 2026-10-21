# Wireclaw Post-V1 Specifications

This directory contains approved development specifications for behavior that intentionally extends the accepted V1 product.

Post-V1 work must preserve the V1 constitution, deterministic-evidence boundary, uncertainty policy, privacy rules, execution safety, original-capture immutability, and native Wireshark requirements unless a higher-authority specification is deliberately revised first.

Authority for post-V1 feature work is:

1. `specs/v1/constitution.md`
2. applicable safety/evidence/privacy requirements in `specs/v1/requirements.md`
3. applicable architecture boundaries in `specs/v1/solution.md`
4. accepted ADRs
5. the applicable file in this directory
6. accepted implementation plans and tests
7. implementation

A post-V1 specification does not retroactively change the frozen V1 acceptance record.

Current review candidates:

- `embedded-local-ai.md` — bundle and qualify a local Qwen3-4B-Instruct-2507 Q4_K_M reasoning runtime on macOS arm64 while preserving the Gate 7 evidence/provider boundary.
