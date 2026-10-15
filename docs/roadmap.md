# Product Roadmap

This roadmap is directional. `specs/v1/` remains authoritative for V1 scope. Approved post-V1 feature specifications live under `specs/post-v1/`.

## V1 — macOS PCAP investigator

Goal: make a single local capture useful for defensible troubleshooting on the first supported release host, macOS.

Core capabilities:
- PCAP/PCAPNG intake
- capture-quality assessment
- DNS/TCP/TLS analysis
- time attribution where protocol visibility permits
- fault-domain reasoning
- explicit ambiguity/insufficient-evidence outcomes
- rules-only operation
- optional LLM-assisted iterative analysis
- full/evidence capture Wireshark launch
- Dockerized core packaged and release-qualified on macOS

Existing Windows/Linux host-bridge code and CI coverage are portability groundwork only; they are not V1 support claims.

## Post-V1 next — Embedded local AI

Goal: make AI-assisted troubleshooting work as an intrinsic Wireclaw capability with no separately installed/configured LLM stack.

Approved design direction:

- bundle Qwen3-4B-Instruct-2507 as a Q4_K_M GGUF release asset;
- bundle a pinned native macOS arm64 llama.cpp server runtime with Metal support;
- make `embedded_local` the normal provider default for the new packaged macOS release;
- preserve the Gate 7 normalized-evidence, typed-capability, evidence-validation, uncertainty, and deterministic-fallback boundaries;
- keep the model/runtime loopback-only and Wireclaw-managed;
- package model/runtime licenses and immutable provenance/hash metadata;
- compare embedded-AI reasoning against rules-only behavior over the Gate 9 corpus before promotion;
- retain `none`, custom local, and cloud provider modes;
- design the runtime/package contract so Windows/Linux platform runtimes can be added later without redesigning the reasoning layer.

Implementation and acceptance are governed by `specs/post-v1/embedded-local-ai.md` and ADR-0007. This stage qualifies macOS arm64 only. The accepted V1 release record remains unchanged.

Current implementation evidence is tracked in `docs/post-v1-embedded-ai-acceptance.md`. The exact-head benchmark meets all recorded size, memory, readiness, and latency targets. Full frozen-package native acceptance, exact-head hosted CI, independent review, and the draft PR remain outstanding; this work is not yet release-qualified. Windows/Linux embedded-AI qualification remains `NOT_RUN`.

## Post-V1 — Windows and Linux release qualification

Goal: extend the macOS-qualified product to Windows and Linux without weakening the local-first/security model or redesigning the core analysis architecture.

For each platform, qualification requires:
- native host-bridge behavior accepted in a real desktop session
- **Open Full Capture in Wireshark** verified with the immutable original and approved filter
- **Open Evidence Capture in Wireshark** verified with a bounded derived artifact and provenance
- paths-with-spaces and platform-specific argument handling
- bridge-unavailable and Wireshark-unavailable degradation
- packaged start/stop launcher
- host-bridge install/uninstall flow
- Docker/core release workflow without a developer toolchain
- pinned analyzer/runtime identities
- release smoke tests on the actual host OS
- Gate 9-equivalent end-to-end, privacy, immutability, and security acceptance
- documentation of OS/version, architecture, Wireshark version, source SHA, image digest, and bridge binary hash

For the embedded-AI product line, each future platform must additionally qualify its native inference runtime/model packaging, process isolation, local-only exposure, resource behavior, and deterministic fallback before embedded AI is claimed as supported there.

Windows and Linux should be promoted to supported platforms only after this qualification is complete. Automated build/test jobs remain useful before then but do not substitute for native release acceptance.

## V1.1 — Additional evidence correlation

Candidates:
- browser HAR import
- second-side/client-server capture correlation
- load-balancer timing/log import
- application/server log import
- interface counter snapshots

Purpose:
- resolve cases where a single packet capture localizes a delay boundary but cannot identify the underlying component

## V1.2 — Active validation

Candidates:
- DNS resolution test
- TCP connect timing
- TLS connect timing
- HTTP request/TTFB test
- ping where platform/container privileges allow
- traceroute/MTR-style path measurements

Design principle:
active tests complement historical capture evidence and must be labeled with their execution time so they are not confused with conditions present during the original capture.

## V1.3 — Infrastructure/network context

Candidates:
- SNMP/interface error/drop snapshots
- NetFlow/IPFIX context
- route/path metadata
- optional ThousandEyes result/API import

Purpose:
- improve fault localization beyond what packet perspective alone can prove

## V2 — Team workflows

Candidates:
- redacted/shareable case bundles
- team case history
- centralized optional deployment
- role-based access
- collaborative annotations
- organization policy for model/data handling

Centralized mode must be separately threat-modeled; it should not emerge by simply binding the V1 localhost service to a LAN address.

## Explicitly not prioritized

- training a custom packet foundation model
- replacing Wireshark
- IDS/IPS replacement
- autonomous network remediation
- automatic device configuration changes

These only become candidates if evidence shows they improve Wireclaw's troubleshooting objective more than the deterministic + reasoning architecture.
