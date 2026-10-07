# ADR-0002: Deterministic Analysis First, LLM as Reasoning Layer

Status: Accepted

Date: 2026-10-07

## Context

Wireclaw must diagnose ambiguous traffic problems accurately enough for engineers to validate the result. General and packet-specialized LLMs can reason about traffic descriptions, but they are not reliable substitutes for mature protocol dissectors and deterministic timing/transport calculations.

Directly asking an LLM to interpret large raw captures also creates context-size, privacy, reproducibility, and hallucination problems.

## Decision

Use deterministic packet-analysis tools to establish evidence. Use an LLM only to:
- interpret the user's symptom
- choose among predefined typed analyzer capabilities
- correlate normalized evidence
- rank supported hypotheses
- explain findings
- recommend additional discriminating evidence

The LLM cannot:
- execute arbitrary commands
- directly invoke executables
- create packet facts
- modify evidence records
- promote unsupported claims into final findings

Wireclaw must remain useful in rules-only/no-model mode.

## Consequences

Positive:
- reproducible packet facts
- lower hallucination risk
- smaller model context
- raw capture can remain local
- provider independence
- easier testing and regression control
- engineers can validate findings directly in Wireshark

Negative:
- more engineering is required to build normalized analyzer capabilities
- diagnostic coverage grows capability-by-capability
- some protocols will initially have limited semantic understanding

## Rejected alternatives

### Specialized PCAP LLM as primary analyzer

Rejected for V1 because deterministic protocol tools provide stronger traceability and mature packet semantics for troubleshooting.

### General LLM over raw `tshark -V` output

Rejected because verbose output scales poorly, is difficult to bound, may expose payload data, and encourages untraceable inference.

### Static analyzer only, no reasoning layer

Not rejected as a fallback, but insufficient as the complete product because ambiguous symptoms benefit from iterative evidence selection and correlation.
