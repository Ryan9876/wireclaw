# ADR-0005: V1 Single-Core Container and Host-Loopback Publication

Status: Accepted

Date: 2026-10-13

## Context

The authoritative solution intentionally deferred whether the web UI and API would ship in one release container or separate containers. Gate 8 must now choose a topology before implementation depends on it.

There is also a deployment wording ambiguity that must be resolved explicitly rather than hidden in Compose implementation details:

- R-S001 says the web/API services bind to loopback by default.
- ADR-0001 says application ports are published to host loopback only by default.
- A normal Docker-published port requires the application process inside the isolated container network namespace to listen on a container interface reachable by Docker's port-forwarding path; binding only to container `127.0.0.1` would not make the service reachable through a published host port.

Current Wireclaw implementation already serves the compiled React application and API from one FastAPI origin, and deterministic analyzer wrappers run as part of the local core rather than through a separate analyzer RPC service.

## Decision

### 1. V1 ships one Dockerized core application container

The V1 release uses one `wireclaw-core` container containing:

- the compiled React web UI
- the FastAPI API/orchestrator
- the Python deterministic analyzer runtime
- pinned command-line analyzer tools required by the release
- SQLite/local application runtime

The native Go host bridge remains outside Docker and continues to launch native Wireshark.

Do not introduce a new analyzer network service or RPC protocol solely for packaging.

This decision satisfies R-D001 because web, API/orchestrator, and analyzer all run through Docker-compatible packaging; R-D001 does not require them to be separate containers.

### 2. Host exposure is loopback-only by default

Inside the isolated `wireclaw-core` container, the application process may listen on the container interface necessary for Docker port publication (for example `0.0.0.0:8765`).

The release boundary required by R-S001/R-S002 is enforced at host publication:

```text
127.0.0.1:<host-port> -> wireclaw-core:<container-port>
```

The default Compose configuration must not publish the application on:

- `0.0.0.0`
- `::`
- a LAN interface
- host networking

No general LAN/WAN service is introduced.

The container-private listen address is not permission to add remote host exposure.

### 3. Same-origin web/API remains the release contract

The browser is served from the same Wireclaw application origin used by the API.

Do not add a configurable arbitrary browser API URL or a development proxy to the release architecture.

### 4. Shared host data root remains the artifact boundary

Compose bind-mounts one host Wireclaw data root into the core container. The native host bridge receives the corresponding host path.

Application metadata continues to use logical artifact IDs and relative case paths; container paths are not exposed as browser-controlled launch paths.

### 5. Native bridge remains separate

The Go host bridge:

- runs natively on macOS, Windows, and Linux
- binds only to numeric host loopback
- is not placed inside the Docker container
- is not exposed through the Docker network
- keeps the Gate 6 one-time-grant/path-confinement/executable restrictions

### 6. Same-host local model endpoints

When Gate 7 is configured for an OpenAI-compatible model server running on the same host, the Dockerized core cannot treat container `127.0.0.1` as the host.

Gate 8 therefore documents `host.docker.internal` as the same-host provider address. On Linux Compose must add the supported host-gateway mapping when required by the target Docker runtime.

This networking accommodation is for outbound provider access only and does not broaden Wireclaw's inbound host exposure.

## Consequences

Positive:

- release topology matches the existing same-origin application design
- no analyzer RPC surface is invented
- only one Docker application port needs host publication
- host exposure remains loopback-only
- native Wireshark integration stays outside Docker
- artifact mapping stays explicit and consistent with ADR-0001
- local model servers remain reachable after containerization

Negative:

- web/API/analyzer do not scale independently in V1
- application process binding inside the container differs from native-development loopback binding
- launchers must coordinate one host data-root path between Docker and the native bridge
- same-host local model configuration must use a host-reachable Docker hostname rather than container loopback

## Security invariants

This ADR does not relax:

- R-S001 loopback default at the host boundary
- R-S002 no general remote exposure
- R-S003 no shell interpolation
- R-S006 raw-capture locality
- R-S009 host-bridge restriction
- R-S010 path confinement

Compose must not use host networking, privileged mode, Docker-socket mounting, or a wildcard host port publication as a convenience workaround.

## Rejected alternatives

### Bind application only to container `127.0.0.1`

Rejected because Docker's normal host port publication cannot reach a service bound only to the container loopback interface.

### Separate web, API, and analyzer services for V1

Rejected because the current architecture does not require an analyzer RPC boundary, the API already serves the compiled UI, and splitting services would add network/configuration surfaces without satisfying an unmet V1 requirement.

### Host networking

Rejected because it weakens the explicit host-loopback publication boundary and behaves inconsistently across supported platforms.

### Native-only release

Rejected by ADR-0001 and R-D001/R-D006 because it would reintroduce platform-specific analyzer dependency installation and version drift.
