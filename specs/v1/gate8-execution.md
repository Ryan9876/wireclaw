# Wireclaw V1 — Gate 8 Execution Specification

Status: **Subordinate execution specification**

This document defines the implementation contract for Gate 8. It is subordinate to `specs/v1/constitution.md`, `specs/v1/requirements.md`, `specs/v1/solution.md`, and accepted ADRs, including ADR-0001 and ADR-0005.

## 1. Gate objective

Gate 8 turns the development application into a reproducible cross-platform V1 release that a user with Docker and Wireshark can start without installing the Python/Node/analyzer development toolchain.

Gate 8 does not redesign analysis, reasoning, findings, evidence, or the Gate 6 bridge. It packages the accepted Gates 0–7 behavior.

## 2. Requirements and tasks

Primary requirements:

- R-D001 Dockerized core
- R-D002 macOS/Windows/Linux hosts
- R-D003 native Wireshark
- R-D004 equivalent native host bridge
- R-D005 simple startup
- R-D006 reproducible analyzer image
- R-S001 loopback default
- R-S002 no general remote exposure
- R-S003 no shell interpolation
- R-S006 raw-capture locality
- R-S008 secret handling
- R-S009 host-bridge restriction
- R-S010 path confinement
- R-N001 original immutability
- R-N002 resource bounds
- R-N004 reproducibility
- R-N005 auditability
- R-N006 maintainability

Gate tasks:

- G8.1 pinned analyzer Docker image
- G8.2 web/API Docker packaging
- G8.3 `compose.yaml` with loopback-only host publication
- G8.4 bind-mounted data root
- G8.5 `.env.example` with safe defaults
- G8.6 macOS start/stop launcher
- G8.7 Windows start/stop launcher
- G8.8 Linux start/stop launcher
- G8.9 host-bridge install/uninstall scripts for each OS
- G8.10 first-run prerequisite checks for Docker and Wireshark
- G8.11 release smoke tests on macOS, Windows, and Linux

## 3. Accepted release topology

ADR-0005 is binding for Gate 8.

V1 release topology:

```text
Host browser
    |
    | http://127.0.0.1:<app-port>
    v
Docker: wireclaw-core
    - compiled React UI
    - FastAPI API/orchestrator
    - Python analyzer runtime
    - pinned TShark/capinfos/editcap/mergecap/Zeek as required
    - SQLite
    |
    | bind-mounted host data root
    v
Host filesystem: Wireclaw data root
    ^
    |
Native Go host bridge on 127.0.0.1:<bridge-port>
    |
Native Wireshark
```

Do not introduce a separate analyzer RPC service for V1.

Do not containerize the Wireshark GUI or Gate 6 host bridge.

## 4. Container networking contract

The application process inside `wireclaw-core` may bind to the container interface required for Docker publication, e.g.:

```text
0.0.0.0:8765
```

The host publication must be loopback-only by default:

```yaml
ports:
  - "127.0.0.1:${WIRECLAW_PORT:-8765}:8765"
```

Equivalent Compose syntax is acceptable.

Forbidden release defaults:

```text
0.0.0.0:<port>:8765
::<port>:8765
network_mode: host
privileged: true
Docker socket mount
```

Do not publish analyzer/debug/development ports.

The browser continues to use same-origin `/api/...` resources.

## 5. Required repository layout

Gate 8 should produce or equivalent:

```text
wireclaw/
├── Dockerfile
├── compose.yaml
├── .env.example
├── docker/
│   └── analyzer-versions.lock
├── launch/
│   ├── macos/
│   │   ├── start.sh
│   │   ├── stop.sh
│   │   ├── install-host-bridge.sh
│   │   └── uninstall-host-bridge.sh
│   ├── linux/
│   │   ├── start.sh
│   │   ├── stop.sh
│   │   ├── install-host-bridge.sh
│   │   └── uninstall-host-bridge.sh
│   └── windows/
│       ├── start.ps1
│       ├── stop.ps1
│       ├── install-host-bridge.ps1
│       └── uninstall-host-bridge.ps1
└── services/host-bridge/
```

Names may differ only if documentation and tests use one consistent layout.

## 6. Docker image design

Use a multi-stage build.

Recommended logical stages:

```text
web-build
python/runtime-build as needed
core-runtime
```

### Web build stage

- use a pinned Node major/version strategy consistent with CI
- copy only files required for dependency installation first
- run `npm ci`, never `npm install`
- run the production web build
- no Vite development server in final image

### Core runtime stage

The final image contains:

- supported Python runtime
- installed Wireclaw API/analyzer packages
- compiled web assets
- SQLite runtime dependencies
- pinned packet analyzer binaries/tools
- required CA certificates for configured HTTPS cloud providers

The final image must not require:

- Node runtime
- npm
- Go compiler
- source checkout at runtime
- test-only Python packages
- development web server

Do not install Wireshark GUI into the container.

## 7. Analyzer version pinning

R-D006 requires analyzer versions to be pinned in built releases.

Create `docker/analyzer-versions.lock` or an equivalent machine-readable release lock containing at least the exact release-tested versions of:

- TShark/Wireshark CLI
- capinfos
- editcap
- mergecap when packaged
- Zeek when packaged
- Python runtime

Also pin the Docker base image by immutable digest in the release Dockerfile or release build metadata.

Do not invent version numbers in the specification. During implementation, Codex must select versions that build on supported architectures, record them in the lock, and add a build/runtime assertion that the installed versions match the release lock.

A floating `latest` analyzer image or unrecorded distro package set does not satisfy G8.1/R-D006.

## 8. Image security/runtime user

Run the core as a non-root user unless a documented analyzer tool proves impossible under that model. Do not grant packet-capture capabilities; Wireclaw analyzes uploaded files and does not need live-capture privileges in V1.

Compose should use, where compatible with the accepted runtime:

```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
init: true
```

Do not add privileged mode or Docker-socket access.

If a hardening setting is incompatible with a required analyzer, document the specific reason and retain the smallest privilege set possible.

## 9. Data-root mapping

Use one host-controlled Wireclaw data root.

Logical defaults:

```text
host:      ${WIRECLAW_DATA_ROOT}
container: /var/lib/wireclaw
```

The exact container path may differ, but it must be fixed and documented.

Requirements:

- one host data root is mounted read/write into `wireclaw-core`
- case-relative layout remains unchanged logically
- original capture immutability is preserved
- SQLite and artifact files persist across container recreation
- the native bridge receives the host path, not the container path
- browser requests continue to use logical IDs, not either path
- paths containing spaces and Unicode must work on all supported hosts

The launcher should resolve a stable absolute host data-root path before starting the bridge.

## 10. Compose contract

`compose.yaml` must define the V1 core without requiring a developer toolchain.

Minimum behavior:

- build or reference `wireclaw-core`
- publish only the application port to host loopback
- mount the configured data root
- set safe provider defaults
- define healthcheck
- restart behavior must not create multiple API processes against one data root
- Linux same-host provider mapping is present when needed

Do not use multiple API workers because ADR-0003 enforces one service process per data root and synchronous bounded mutation semantics.

## 11. Healthcheck

The Docker healthcheck should use the Wireclaw API health endpoint from inside the container.

Health must reflect the core service, not require the optional native bridge or model provider to be available.

A missing Wireshark bridge must not mark the core container unhealthy.

## 12. Safe `.env.example`

Commit an `.env.example` containing no secrets.

At minimum expose documented equivalents for:

```text
WIRECLAW_PORT=8765
WIRECLAW_DATA_ROOT=<safe documented local path/default>
WIRECLAW_PROVIDER_MODE=none
WIRECLAW_PROVIDER_BASE_URL=
WIRECLAW_PROVIDER_MODEL=
WIRECLAW_BRIDGE_PORT=8766
```

Do not include real API keys.

Secret values must come from the user's uncommitted environment/configuration.

`provider_mode=none` is the release default.

## 13. Cloud-provider packaging behavior

Gate 8 must preserve Gate 7 cloud privacy behavior unchanged.

The container may make outbound HTTPS requests only when a cloud provider is explicitly configured.

Raw PCAP and payload bytes remain excluded under the Gate 7 policy.

Do not add a cloud file-upload path as part of packaging.

## 14. Same-host local model behavior

When the OpenAI-compatible local provider runs on the Docker host, configure the provider base URL using:

```text
http://host.docker.internal:<provider-port>/v1
```

or the exact base-path convention accepted by the Gate 7 adapter.

For Linux, Compose must add the supported mapping when necessary:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Test this behavior with a fake local provider. Do not assume container `127.0.0.1` refers to the host.

## 15. Host bridge release binaries

Build the Go bridge as native binaries for the supported OS families.

Release artifact naming should clearly distinguish platform, e.g.:

```text
wireclaw-host-bridge-darwin-<arch>
wireclaw-host-bridge-windows-<arch>.exe
wireclaw-host-bridge-linux-<arch>
```

The release must declare which architecture was tested for each OS. R-D002 requires the OS families; it does not silently create a promise for every CPU architecture.

Do not claim an architecture is supported unless a release binary/build and smoke test exist for it.

Record SHA-256 hashes for distributed bridge binaries in release verification metadata.

## 16. Bridge install/uninstall scripts

Install scripts must:

- operate on the packaged bridge binary only
- select/create a per-user or otherwise documented non-privileged install location where practical
- preserve Gate 6 executable/path/origin restrictions
- accept the configured Wireclaw data root and application port through documented admin configuration
- not write secrets to the repository
- not install arbitrary executables

Uninstall scripts must remove only Wireclaw-managed bridge files/configuration and must not delete case data unless the user explicitly requests case/data deletion through a separate path.

Do not require a background system service for V1 unless an accepted ADR adds it. A launcher-managed native bridge process is sufficient.

## 17. Start/stop launcher contract

Each platform gets a documented start and stop path.

### Start

The launcher must:

1. verify Docker/Compose availability;
2. verify the configured data root can be created/accessed;
3. verify/install-check the packaged host bridge;
4. check whether Wireshark is discoverable or explain how to configure it;
5. start `wireclaw-core` through Compose;
6. wait for bounded core health readiness;
7. start the native bridge with the same host data root and configured application/bridge ports;
8. print the localhost UI URL and clear status;
9. exit nonzero on startup failure with a bounded actionable message.

Opening a browser automatically is optional; printing the URL is required.

### Stop

The launcher must:

1. stop the Wireclaw-managed bridge process;
2. stop/remove the Compose runtime without deleting the host data root;
3. preserve cases/artifacts for the next start;
4. report failures without deleting data.

Do not make `stop` equivalent to `docker compose down -v` if that would destroy user data.

## 18. Platform launcher constraints

### macOS

Use POSIX shell compatible with the documented macOS environment. Do not depend on Homebrew for Wireclaw runtime dependencies beyond the user's Docker/Wireshark installation.

### Linux

Use POSIX/Bash shell as documented. Do not require a particular desktop environment for core startup. Native Wireshark acceptance still requires a GUI desktop session.

### Windows

Use PowerShell. Quote/resolve paths as native PowerShell argument arrays. Do not route analyzer or bridge execution through `cmd /c`.

Paths containing spaces must be included in platform smoke tests.

## 19. Prerequisite checks

G8.10 must detect and explain at least:

- Docker not installed/unavailable
- Compose unavailable
- Docker daemon/runtime not running
- configured app port already in use
- configured bridge port already in use
- data root inaccessible
- host bridge missing/not installed
- Wireshark not discoverable

A missing model provider must not prevent startup when `provider_mode=none`.

The launcher does not need to install Docker or Wireshark automatically.

## 20. Release build reproducibility

A release verification record must capture:

- source commit SHA
- Dockerfile/Compose revision
- core image immutable digest
- base image digest
- analyzer version lock
- Python version
- built web artifact revision
- host-bridge binary SHA-256 per platform/architecture

The same source/version lock should produce equivalent deterministic evidence on supported hosts, subject to architecture/tool reproducibility limits explicitly documented.

## 21. No development dependencies at runtime

Acceptance must prove a clean host can operate the release without locally installed:

- Python development environment
- Node/npm
- Go compiler
- TShark/capinfos/Zeek

Required host prerequisites are Docker-compatible runtime and native Wireshark, plus the packaged native bridge/launcher.

## 22. Upgrade/restart behavior

Gate 8 does not require an auto-updater.

It must, however, prove that:

- stopping and starting the same release preserves cases;
- recreating the container against the same data root preserves cases;
- a service restart does not mutate original captures;
- persisted case/report/evidence contracts remain readable by the same release.

Cross-version migration beyond V1 is not introduced unless an existing schema change requires it.

## 23. Packaging security tests

Required automated checks include:

1. Compose publishes only `127.0.0.1` application ports by default.
2. No host-network mode.
3. No privileged mode.
4. No Docker socket mount.
5. No bridge container/service.
6. Core health succeeds with bridge absent.
7. Browser/API still reject unapproved Host/Origin values.
8. Raw case data stays in the configured host data root.
9. container restart preserves immutable original hash.
10. rules-only startup works with no provider credentials.
11. fake local provider is reachable through the documented host mapping.
12. cloud-provider privacy tests from Gate 7 still pass in the containerized runtime.

Tests may inspect `docker compose config` to validate publication and mounts.

## 24. Cross-platform smoke-test procedure

Perform G8.11 on real supported host OS environments, not only cross-compilation.

For each OS record:

```text
OS/version
architecture
Docker/runtime version
Compose version
Wireshark version
Wireclaw commit
core image digest
bridge binary SHA-256
```

Then:

1. start from the documented release bundle;
2. do not use a local Python/Node/Go development environment;
3. run the platform start launcher;
4. open the localhost UI;
5. create a case from a known fixture;
6. investigate and view deterministic report/evidence;
7. run one rules-only case;
8. if Gate 7 is configured, run fake/local-provider smoke coverage;
9. open Full Capture in native Wireshark;
10. open Evidence Capture in native Wireshark;
11. verify path-with-spaces behavior;
12. stop and restart Wireclaw;
13. verify the case persists;
14. stop the bridge and verify graceful degradation;
15. run the platform stop launcher;
16. verify user data remains.

CI cross-build is useful but does not substitute for actual release smoke behavior on the three host OS families.

## 25. Offline/rules-only release acceptance

The release must work with:

```text
WIRECLAW_PROVIDER_MODE=none
```

and no network access to a model provider.

Deterministic packet analysis, reporting, evidence capture, and native Wireshark validation must remain usable.

## 26. Release bundle

Produce the solution's V1 release shape or an equivalent documented artifact:

```text
wireclaw-release/
├── compose.yaml
├── .env.example
├── README.md
├── launch/
│   ├── macos/
│   ├── windows/
│   └── linux/
└── host-bridge/
    ├── macos/
    ├── windows/
    └── linux/
```

If the core image is published to a registry, pin/reference its immutable release tag/digest. If the release builds locally, document that workflow and still record the resulting digest.

## 27. CI requirements

Add Gate 8 validation that at minimum:

- builds `wireclaw-core` from scratch;
- runs core health;
- runs representative Python/analyzer integration tests in the image;
- runs web production tests;
- validates `docker compose config` security boundaries;
- verifies analyzer version lock;
- builds/tests the host bridge on Ubuntu/macOS/Windows;
- exercises startup scripts in non-GUI portions where feasible;
- preserves all Gate 7 privacy/fallback tests.

Do not allow a successful image build to hide skipped real packet-tool tests.

## 28. Verification record

Create `docs/gate8-verification.md` containing:

- validated source SHA
- image digest
- analyzer version lock
- task matrix G8.1–G8.11
- Compose security assertions
- launcher/prerequisite results
- data-root persistence results
- local-provider host mapping result
- rules-only result
- macOS smoke result
- Windows smoke result
- Linux smoke result
- native Wireshark acceptance references
- known limitations/untested architectures

## 29. Gate 8 exit criteria

Gate 8 is complete only when:

1. accepted ADR-0005 topology is implemented;
2. the compiled web UI, API/orchestrator, and analyzer runtime run in Docker-compatible packaging;
3. analyzer/runtime versions are pinned and verified for the release;
4. only the application port is published to host loopback by default;
5. no host networking/privileged/Docker-socket workaround exists;
6. one host data root persists cases and maps correctly to the native bridge;
7. `.env.example` contains safe defaults and no secrets;
8. `provider_mode=none` starts successfully without a model;
9. cloud-provider privacy behavior remains unchanged;
10. same-host local provider behavior works through the documented Docker host mapping;
11. macOS start/stop launcher works from release artifacts;
12. Windows start/stop launcher works from release artifacts;
13. Linux start/stop launcher works from release artifacts;
14. host-bridge install/uninstall path exists and is tested for all three OS families;
15. prerequisite failures are clear and non-destructive;
16. a user with Docker and Wireshark can run the core workflow without Python/Node/Go/analyzer development installs;
17. stop/restart preserves case data and immutable originals;
18. Full/Evidence Wireshark actions remain functional in release packaging;
19. real host release smoke tests pass on macOS, Windows, and Linux;
20. `docs/gate8-verification.md` records exact source/image/binary identities and results;
21. all prior Gates 0–7 regressions remain green;
22. Gate 9 acceptance has not been declared complete before Gate 8 is accepted.
