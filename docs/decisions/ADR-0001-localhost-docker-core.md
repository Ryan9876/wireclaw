# ADR-0001: Localhost Docker Core with Native Host Bridge

Status: Accepted

Date: 2026-10-07

## Context

Wireclaw must be simple to share across macOS, Windows, and Linux while packaging a consistent packet-analysis toolchain. It also must launch the native Wireshark GUI, which is inherently host-specific.

A traditional centrally hosted web server would add deployment, privacy, authentication, storage, and network-exposure complexity that V1 does not require.

Running every dependency natively would make installation and analyzer-version consistency difficult across platforms.

## Decision

Use a Dockerized localhost core for:
- web UI
- API/orchestrator
- deterministic analyzer toolchain
- SQLite/local application runtime

Use a small native host bridge only for operations that require host GUI integration, initially launching Wireshark.

Publish application ports to loopback only by default.

Use a host bind-mounted Wireclaw data root so container services and the host bridge refer to the same case artifacts through controlled mappings.

## Consequences

Positive:
- reproducible analyzer environment
- simpler cross-platform sharing
- raw captures remain local
- user does not need native Python/Node/Zeek/TShark setup
- Wireshark stays native and familiar

Negative:
- Docker is a prerequisite
- host bridge requires platform-specific packaging/testing
- path mapping between container and host must be explicit
- browser-to-host-bridge security requires careful design

## Rejected alternatives

### Central web server

Rejected for V1 because it introduces unnecessary raw-capture transport/storage and operational complexity.

### Entirely native desktop application

Rejected for V1 because dependency packaging and analyzer consistency would be harder across three OS families.

### Wireshark GUI inside container

Rejected because it complicates GUI/display integration and provides a worse user experience than the installed native Wireshark application.
