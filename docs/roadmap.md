# Product Roadmap

This roadmap is directional. `specs/v1/` remains authoritative for V1 scope.

## Current delivery status — 2026-10-13

| Gate | Status | Notes |
| --- | --- | --- |
| 0 — repository/spec baseline | Complete | Accepted on `main` |
| 1 — deterministic analyzer | Complete | Accepted on `main` |
| 2 — TCP/DNS/TLS diagnostics | Complete | Accepted on `main` |
| 3 — local API/case model | Complete | Accepted on `main` |
| 4 — rules-only investigation/report | Complete | Accepted on `main` |
| 5 — web UI | Complete | PR #6 merged 2026-10-09 |
| 6 — evidence capture/Wireshark integration | In progress | Implemented on `gate6-wireshark-evidence-bridge`; not merged |
| 7 — reasoning provider/iterative investigation | Not started | Follows Gate 6 acceptance |
| 8 — Docker packaging/cross-platform release | Not started | Follows provider/integration work |
| 9 — V1 acceptance/hardening | Not started | Final V1 release gate |

Gate 6 is the active delivery gate. Its branch is 19 commits ahead of `main`. The latest workflow at commit `d21ceae8047db7c28f45ba7a12b4100ba6585e4e` passed Python, Go and web validation and passed host-bridge test/build jobs on Ubuntu, macOS and Windows. The remaining CI blocker is the Linux full job's production browser validation. See [Gate 6 progress](gate6-progress.md) for the current evidence and acceptance boundary.

Task checkboxes in `specs/v1/tasks.md` should be read as accepted mainline delivery state, not merely code existing on a development branch. Gate 6 tasks should remain unchecked until the gate's validation and merge criteria are satisfied.

## V1 — PCAP investigator

Goal: make a single local capture useful for defensible troubleshooting.

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
- Dockerized cross-platform core

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
