# Embedded Local AI Design

Date: 2026-10-14

Status: **Approved architectural design; implementation gated on review of the written development specification**

## Goal

Make AI-assisted troubleshooting feel intrinsic to Wireclaw. The packaged macOS arm64 application should include the selected Qwen3-4B-Instruct-2507 Q4_K_M model and its inference runtime so the user launches Wireclaw and receives local AI assistance without installing or configuring an external LLM stack.

## Design summary

Wireclaw keeps deterministic packet analysis and model reasoning separate.

- The existing Docker core remains authoritative for packet facts, normalized evidence, case state, capability validation, and final report validation.
- The release adds a native macOS arm64 llama.cpp server runtime plus a pinned Q4_K_M GGUF.
- The macOS launcher verifies hashes, starts the AI server on loopback with fixed Wireclaw-owned arguments and an ephemeral token, then configures the core to use it through the existing OpenAI-compatible provider interface.
- The new logical provider mode is `embedded_local` and becomes the normal default for the new post-V1 packaged release.
- Rules-only mode remains available and is the safe fallback if embedded AI is unavailable.
- External custom-local/cloud providers remain supported.

The selected runtime approach is recorded in `docs/decisions/ADR-0007-embedded-local-ai-native-runtime.md`. The detailed requirements and acceptance contract are in `specs/post-v1/embedded-local-ai.md`.

## Model and provenance

The source model is pinned to:

```text
Qwen/Qwen3-4B-Instruct-2507
revision cdbee75f17c01a7cc42f958dc650907174af0554
Apache-2.0
```

Wireclaw release engineering produces a Q4_K_M GGUF using a pinned llama.cpp conversion/quantization toolchain. The resulting model SHA-256, byte size, conversion provenance, upstream revision, license, and runtime commit are recorded in model/runtime manifests and release metadata.

The multi-gigabyte GGUF is not committed to normal Git history.

## Data flow

```text
PCAP/PCAPNG
   |
   v
Deterministic Wireclaw analyzers
   |
   v
Normalized evidence + evidence IDs + limitations
   |
   v
Gate 7 reasoning boundary
   |
   v
embedded_local provider
   |
   v
Native llama-server + Qwen3-4B Q4_K_M
   |
   v
strict JSON response
   |
   v
local schema/evidence/capability validation
   |
   v
validated report / deterministic fallback
```

The model never becomes the source of packet facts and never receives arbitrary process, file, Docker, bridge, or Wireshark capabilities.

## Runtime boundary

The native server is a Wireclaw-managed reasoning service only.

- Numeric loopback listener only.
- Ephemeral authentication token per start.
- Fixed model/runtime paths beneath the release root.
- Fixed reviewed runtime settings.
- No generic runtime tool/agent/file functionality.
- No runtime web UI in the accepted configuration when the pinned runtime supports disabling it.
- No internet model download during normal startup.
- No LAN fallback if Docker-to-host loopback reachability fails.

The Docker core reaches the local service through Docker Desktop's supported host path and reuses the existing OpenAI-compatible provider contract.

## Failure behavior

Embedded AI must fail independently.

Missing/tampered model/runtime files, port conflicts, startup failures, timeouts, crashes, invalid responses, or provider-validation failures result in explicit AI-unavailable state and rules-only deterministic investigation. They must not destroy case data, change original captures, or prevent normal deterministic analysis.

## Release shape

The product remains one Wireclaw release bundle from the user's perspective. It gains an `ai/` subtree containing:

- model manifest;
- runtime manifest;
- Q4_K_M model;
- macOS arm64 llama.cpp runtime/resources;
- required model/runtime licenses.

Future Windows/Linux runtimes may be added as sibling platform directories behind the same manifest/provider/process contract, but this stage qualifies macOS arm64 only.

## Validation strategy

Success is not defined by fluent prose. The embedded model is compared with rules-only behavior across the Gate 9 corpus plus dedicated reasoning/adversarial scenarios.

Release acceptance requires:

- no deterministic Gate 9 semantic regression;
- no unsupported model claim admitted as packet fact;
- no invalid/cross-case evidence accepted;
- no unauthorized capability invocation;
- required uncertainty preserved;
- privacy/secret sentinels absent from model context/logs/artifacts;
- deterministic fallback on every provider/runtime failure case;
- native macOS startup/stop/restart and Wireshark regression passing;
- recorded model/runtime identities and resource measurements;
- owner-reviewed evidence that local AI materially improves hypothesis ranking, explanation, or next-evidence guidance on representative cases.

## Scope boundary

This design does not change the accepted Wireclaw V1 release. It defines a new post-V1 stage. Windows/Linux embedded-AI qualification is intentionally deferred.
