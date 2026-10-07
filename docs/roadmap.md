# Product Roadmap

This roadmap is directional. `specs/v1/` remains authoritative for V1 scope.

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
