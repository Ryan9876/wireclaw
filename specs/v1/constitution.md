# Wireclaw V1 Constitution

Status: **Authoritative**

This document defines non-negotiable V1 product principles. Requirements, design, tasks, tests, and implementation must conform to it.

## C1. Purpose

Wireclaw exists to reduce the time and expertise required to investigate packet-capture evidence for ambiguous network/application complaints such as:

- "the application is slow"
- "connections randomly fail"
- "users disconnect"
- "this only happens sometimes"
- "the network looks fine but the user experience is bad"

Wireclaw must turn captures into an evidence-backed explanation of what is observed, what is likely, what is not supported, and what should be measured next.

## C2. Deterministic evidence precedes model reasoning

Packet facts must come from deterministic analyzers and derived calculations. The reasoning model may plan analysis, correlate evidence, rank hypotheses, and explain results, but it may not invent packet facts.

Every material conclusion must have traceable evidence.

## C3. Explicit epistemic states

Wireclaw must distinguish:

- **Observed** — directly reported by a deterministic tool or capture metadata.
- **Derived** — calculated reproducibly from observed data.
- **Inferred** — interpretation supported by observed/derived evidence.
- **Unknown** — not establishable from available evidence.

The UI and report must not present inferred information as observed fact.

## C4. Capture quality before diagnosis

Every investigation begins by assessing whether the capture can support the requested conclusion. Capture quality includes, where measurable:

- capture duration and packet count
- truncation/snap length
- capture drops if available
- start-midstream indicators
- one-sided/asymmetric visibility
- checksum-offload artifacts
- duplicate capture artifacts
- timestamp anomalies
- presence/absence of relevant handshakes or transactions

A poor or incomplete capture may lower confidence or prevent a root-cause conclusion.

## C5. Local-first privacy

Wireclaw runs locally by default. Packet captures and raw payload bytes remain on the workstation unless the user explicitly enables a different policy.

Cloud-model reasoning must default to normalized evidence rather than raw capture content.

## C6. No arbitrary command execution

Neither user text nor model output may become arbitrary shell execution. Analysis occurs through predefined capabilities with validated parameters and bounded resource use.

The host bridge is not a command-execution service.

## C7. Wireshark is a first-class verification path

For each applicable packet-level finding, the UI must always display both:

- **Open Full Capture in Wireshark**
- **Open Evidence Capture in Wireshark**

The UI must also make the corresponding display filter and packet/stream references available.

The original capture remains immutable.

## C8. macOS-first V1 with portable architecture

The supported V1 release host is macOS using Docker-compatible packaging plus native host integration.

Platform-specific code must remain isolated so Windows and Linux can be qualified in future post-V1 releases without redesigning the analyzer, API, evidence model, or host-bridge protocol. Windows/Linux build or portability checks may remain in CI, but they are not V1 release-support claims.

## C9. Explainable conclusions

A finding must contain enough information for a network engineer to understand and independently validate it:

- finding statement
- affected endpoints/stream/transaction when known
- evidence
- confidence
- likely impact
- alternate explanations when material
- recommended next validation

A confidence score without evidence is insufficient.

## C10. Ambiguity is a valid outcome

Wireclaw must prefer "insufficient evidence" over fabricated certainty.

When multiple explanations remain plausible, it must identify the evidence needed to discriminate among them—for example a server-side capture, interface counters, a browser HAR, load-balancer timing, or an active path test.

## C11. Troubleshooting, not merely anomaly detection

The product goal is not to list unusual packets. It must connect protocol evidence to user impact and fault-domain hypotheses.

For "slow" complaints, the system should attempt time attribution among available stages such as:

- DNS
- TCP establishment
- TLS establishment
- network transport
- server/application response delay
- transfer time

## C12. Safe degradation

The product must remain useful when:

- no LLM provider is configured
- Zeek cannot parse a protocol
- a capture is encrypted
- payload visibility is unavailable
- a host bridge is not installed
- one analyzer fails

A component failure should be reported as a limitation, not silently converted into a diagnosis.

## C13. Reproducibility

Given the same capture, analyzer versions, and configuration, deterministic evidence generation should be reproducible.

Tool versions used for a case must be recorded in case metadata.

## C14. Spec-first governance

Material behavior changes require specification and acceptance-criteria updates before implementation. Architecture decisions with long-lived consequences require an ADR.
