# Copilot Instructions for Wireclaw

Read and follow `AGENTS.md` before making changes. The authoritative V1 specification lives in `specs/v1/`.

Key constraints:

- Spec-first: update requirements/acceptance criteria before changing intended behavior.
- Deterministic analyzers establish facts; LLM output never counts as packet evidence.
- Do not execute arbitrary shell commands from model or user input.
- Use structured subprocess argument arrays and allowlisted analyzer capabilities.
- The default app is local-only and loopback-bound.
- Raw PCAP payloads remain local by default.
- The original capture is immutable.
- Every packet-level finding must always show both **Open Full Capture in Wireshark** and **Open Evidence Capture in Wireshark**.
- Host-bridge functionality is limited to native integration such as launching Wireshark; it must not expose general command execution.
- Add fixture-based tests for analyzer behavior and ambiguous/negative cases.

Preferred stack: React/TypeScript web UI, FastAPI/Python API and analyzer, SQLite local metadata, Go host bridge, Docker Compose packaging.
