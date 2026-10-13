# Wireclaw V1 — Gate 8 Execution Specification

Status: **Subordinate execution specification**

This document defines the implementation contract for Gate 8. It is subordinate to `specs/v1/constitution.md`, `specs/v1/requirements.md`, `specs/v1/solution.md`, and accepted ADRs, including ADR-0001, ADR-0005, and the macOS-first V1 platform-scope decision recorded in ADR-0006 once this branch is reconciled with Gate 6.

## 1. Gate objective

Gate 8 turns the development application into a reproducible **macOS V1 release** that a user with Docker and Wireshark can start without installing the Python/Node/analyzer development toolchain.

Windows and Linux are post-V1 release-qualification targets. Existing bridge code and CI on those hosts may remain as portability evidence, but Gate 8 must not build Windows/Linux launchers or block V1 on those platforms.

Gate 8 does not redesign analysis, reasoning, findings, evidence, or the Gate 6 bridge. It packages the accepted Gates 0–7 behavior.

## 2. Requirements and V1 tasks

Primary requirements:

- R-D001 Dockerized core
- R-D002 macOS V1 host
- R-D003 native Wireshark
- R-D004 native macOS host bridge
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

Gate 8 V1 tasks:

- G8.1 pinned analyzer Docker image
- G8.2 web/API Docker packaging
- G8.3 `compose.yaml` with loopback-only host publication
- G8.4 bind-mounted data root
- G8.5 `.env.example` with safe defaults
- G8.6 macOS start/stop launcher
- G8.9 macOS host-bridge install/uninstall scripts
- G8.10 first-run prerequisite checks for Docker and Wireshark on macOS
- G8.11 macOS release smoke tests

Legacy task IDs G8.7 (Windows launcher) and G8.8 (Linux launcher) are deferred post-V1 and are not Gate 8 exit criteria.

## 3. Accepted release topology

ADR-0005 remains binding for container topology. V1 host qualification is macOS.

```text
macOS browser
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
    | bind-mounted macOS data root
    v
Host filesystem: Wireclaw data root
    ^
    |
Native macOS Go host bridge on 127.0.0.1:<bridge-port>
    |
Native Wireshark
```

Do not introduce a separate analyzer RPC service for V1.

Do not containerize Wireshark GUI or the Gate 6 host bridge.

## 4. Container networking contract

The application process inside `wireclaw-core` may bind to the container interface required for Docker publication, for example `0.0.0.0:8765`.

The host publication must be loopback-only:

```yaml
ports:
  - "127.0.0.1:${WIRECLAW_PORT:-8765}:8765"
```

Forbidden release defaults:

```text
0.0.0.0:<host-port>:8765
::<host-port>:8765
network_mode: host
privileged: true
Docker socket mount
```

Do not publish analyzer/debug/development ports.

The browser continues to use same-origin `/api/...` resources.

## 5. Required V1 repository layout

Gate 8 should produce or equivalent:

```text
wireclaw/
├── Dockerfile
├── compose.yaml
├── .env.example
├── docker/
│   └── analyzer-versions.lock
├── launch/
│   └── macos/
│       ├── start.sh
│       ├── stop.sh
│       ├── install-host-bridge.sh
│       └── uninstall-host-bridge.sh
└── services/host-bridge/
```

Windows/Linux release directories are not required for V1.

## 6. Docker image design

Use a multi-stage build.

Recommended logical stages:

```text
web-build
python/runtime-build as needed
core-runtime
```

### Web build stage

- use a pinned Node major/version strategy consistent with CI;
- copy dependency manifests before application sources where practical;
- run `npm ci`, never `npm install`;
- run the production web build;
- do not ship the Vite development server in the final image.

### Core runtime stage

The final image contains:

- supported Python runtime;
- installed Wireclaw API/analyzer packages;
- compiled web assets;
- SQLite runtime dependencies;
- pinned packet analyzer binaries/tools;
- CA certificates required for configured HTTPS cloud providers.

The final image must not require Node/npm, Go compiler, source checkout, test-only Python packages, or a development web server.

Do not install Wireshark GUI in the container.

## 7. Analyzer version pinning

R-D006 requires exact analyzer versions to be pinned in built releases.

Create `docker/analyzer-versions.lock` or equivalent containing at least:

- TShark/Wireshark CLI
- capinfos
- editcap
- mergecap when packaged
- Zeek when packaged
- Python runtime

Also pin the Docker base image by immutable digest in release build metadata.

Do not invent version numbers in this specification. During implementation, select versions that build and pass the macOS-hosted Docker release workflow, record them, and add a runtime/build assertion that installed versions match the lock.

The known local macOS TShark 4.6.9 versus CI 4.2.2 classification differences are specifically why Gate 8 must pin the analyzer image instead of depending on arbitrary host TShark versions.

## 8. Runtime hardening

Run the core as a non-root user unless a documented analyzer incompatibility requires otherwise. Wireclaw analyzes uploaded files and does not need live packet-capture privileges in V1.

Use, where compatible:

```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
init: true
```

Do not add privileged mode or Docker-socket access.

## 9. Data-root mapping

Use one host-controlled Wireclaw data root.

Logical defaults:

```text
host:      ${WIRECLAW_DATA_ROOT}
container: /var/lib/wireclaw
```

Requirements:

- mount one host data root read/write into `wireclaw-core`;
- preserve case-relative layout;
- preserve original capture immutability;
- persist SQLite and artifacts across container recreation;
- pass the host path, not the container path, to the native bridge;
- keep browser requests on logical IDs;
- support macOS paths containing spaces and Unicode.

The launcher resolves a stable absolute host data-root path before starting the bridge.

## 10. Compose contract

`compose.yaml` must define the V1 core without a developer toolchain.

Minimum behavior:

- build or reference `wireclaw-core`;
- publish only the app port to host loopback;
- mount the configured data root;
- set safe provider defaults;
- define a core healthcheck;
- avoid multiple API workers against one data root.

ADR-0003 synchronous single-process case semantics remain binding.

## 11. Healthcheck

Use the Wireclaw API health endpoint from inside the container.

Core health must not require the optional model provider or native bridge to be available.

A missing Wireshark bridge must not mark the core container unhealthy.

## 12. Safe `.env.example`

Commit an `.env.example` with no secrets. At minimum expose documented equivalents for:

```text
WIRECLAW_PORT=8765
WIRECLAW_DATA_ROOT=<safe documented macOS path/default>
WIRECLAW_PROVIDER_MODE=none
WIRECLAW_PROVIDER_BASE_URL=
WIRECLAW_PROVIDER_MODEL=
WIRECLAW_BRIDGE_PORT=8766
```

`provider_mode=none` is the release default.

Real API keys remain uncommitted user configuration.

## 13. Provider packaging behavior

Gate 8 must preserve Gate 7 privacy behavior unchanged.

Cloud provider mode may make outbound HTTPS requests only when explicitly configured. Raw PCAP and payload bytes remain excluded by default.

Do not add a cloud capture/file-upload path.

## 14. Same-host local model on macOS

When an OpenAI-compatible local provider runs on the macOS Docker host, use the Docker host name rather than container loopback, for example:

```text
http://host.docker.internal:<provider-port>/v1
```

Test this behavior with a controlled fake local provider.

Linux-specific `host-gateway` configuration is deferred with Linux release qualification and is not a V1 Gate 8 requirement.

## 15. macOS host-bridge release binary

Build and package the native Go bridge for the macOS architecture(s) actually supported by the V1 release.

Example artifact naming:

```text
wireclaw-host-bridge-darwin-arm64
```

Do not claim an architecture is supported until its binary and release smoke test exist.

Record the distributed bridge binary SHA-256 in release verification metadata.

Windows/Linux bridge builds may continue in CI but are not V1 release artifacts.

## 16. macOS bridge install/uninstall scripts

Install scripts must:

- operate only on the packaged Wireclaw bridge binary;
- use a documented per-user/non-privileged install location where practical;
- preserve Gate 6 executable/path/origin restrictions;
- configure the Wireclaw data root and app/bridge ports safely;
- never write secrets to source control;
- never install arbitrary executables.

Uninstall must remove only Wireclaw-managed bridge files/config and must not delete case data by default.

A background system daemon is not required for V1 unless a later ADR explicitly adds it.

## 17. macOS start/stop launcher contract

### Start

The launcher must:

1. verify Docker/Compose availability;
2. verify/create the configured data root;
3. verify the packaged host bridge is present/installed;
4. verify Wireshark is discoverable or explain how to configure its path;
5. start `wireclaw-core` through Compose;
6. wait for bounded core readiness;
7. start the native bridge with the same host data root and configured ports;
8. print the localhost UI URL and status;
9. exit nonzero on failure with an actionable bounded message.

Opening the browser automatically is optional; printing the URL is required.

### Stop

The launcher must:

1. stop the Wireclaw-managed bridge process;
2. stop/remove the Compose runtime without deleting the host data root;
3. preserve cases/artifacts;
4. report failures without deleting data.

Never make normal stop equivalent to destructive `docker compose down -v` behavior.

## 18. macOS launcher constraints

Use shell behavior available in the documented macOS environment. Do not require Homebrew for Wireclaw runtime dependencies beyond the user's Docker/Wireshark installation.

Quote paths safely and verify data roots/filenames containing spaces.

Windows PowerShell and Linux launcher constraints belong to the post-V1 platform qualification work.

## 19. Prerequisite checks

G8.10 must detect and explain at least:

- Docker missing/unavailable;
- Compose unavailable;
- Docker daemon not running;
- configured app port already in use;
- configured bridge port already in use;
- data root inaccessible;
- host bridge missing/not installed;
- Wireshark not discoverable.

A missing model provider must not prevent startup in `provider_mode=none`.

The launcher does not need to install Docker or Wireshark automatically.

## 20. Release build reproducibility

Record:

- source commit SHA;
- Dockerfile/Compose revision;
- core image immutable digest;
- base image digest;
- analyzer version lock;
- Python version;
- compiled web revision;
- macOS host-bridge binary SHA-256.

The same source/version lock should reproduce equivalent deterministic evidence for the supported release environment, subject to explicitly documented architecture/tool limits.

## 21. No development dependencies at runtime

Acceptance must prove a clean macOS host can operate the release without locally installed:

- Python development environment;
- Node/npm;
- Go compiler;
- TShark/capinfos/Zeek for analysis.

Required host prerequisites are Docker-compatible runtime, native Wireshark, and the packaged Wireclaw bridge/launcher.

## 22. Restart/persistence behavior

Gate 8 does not require an auto-updater.

It must prove:

- stopping/starting the same release preserves cases;
- recreating the container against the same data root preserves cases;
- service restart does not mutate original captures;
- persisted report/evidence contracts remain readable by the same release.

## 23. Packaging security tests

Required automated checks include:

1. Compose publishes only `127.0.0.1` app ports by default.
2. No host-network mode.
3. No privileged mode.
4. No Docker socket mount.
5. No bridge container/service.
6. Core health succeeds with bridge absent.
7. Browser/API still reject unapproved Host/Origin values.
8. Raw case data stays in the configured host data root.
9. Container restart preserves original SHA-256.
10. Rules-only startup works without provider credentials.
11. Fake macOS-host local provider is reachable through the documented Docker host mapping.
12. Gate 7 cloud-provider privacy tests still pass in the containerized runtime.

`docker compose config` may be inspected to assert publication and mounts.

## 24. macOS release smoke procedure

Perform G8.11 on a real macOS host, not only inside generic CI.

Record:

```text
macOS version
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
2. do not use local Python/Node/Go development tooling;
3. run the macOS start launcher;
4. open localhost UI;
5. create a case from a known fixture;
6. investigate and view deterministic report/evidence;
7. run one rules-only case;
8. run fake/local-provider smoke coverage when Gate 7 is configured;
9. open Full Capture in native Wireshark;
10. open Evidence Capture in native Wireshark;
11. verify path-with-spaces behavior;
12. restart Wireclaw;
13. verify case persistence;
14. stop the bridge and verify graceful degradation;
15. run the stop launcher;
16. verify user data remains.

Windows/Linux release smoke is deferred post-V1.

## 25. Offline/rules-only release acceptance

The release must work with:

```text
WIRECLAW_PROVIDER_MODE=none
```

and no model-provider network access.

Deterministic analysis, reporting, evidence capture, and native Wireshark validation remain usable.

## 26. V1 release bundle

Produce:

```text
wireclaw-release/
├── compose.yaml
├── .env.example
├── README.md
├── launch/
│   └── macos/
└── host-bridge/
    └── macos/
```

If the core image is registry-published, reference an immutable release tag/digest. If built locally, document the build and record the resulting digest.

## 27. CI requirements

Gate 8 CI must at minimum:

- build `wireclaw-core` from scratch;
- run core health;
- run representative Python/analyzer integration tests in the image;
- run web production tests;
- validate Compose security boundaries;
- verify analyzer version lock;
- build/test the host bridge on macOS;
- exercise non-GUI launcher portions where feasible;
- preserve Gate 7 privacy/fallback tests.

Existing Ubuntu/Windows host-bridge build jobs may remain as portability checks but are not Gate 8 release gates.

Do not hide required real packet-tool tests behind silent skips.

## 28. Verification record

Create `docs/gate8-verification.md` containing:

- validated source SHA;
- image digest;
- analyzer version lock;
- V1 task matrix;
- Compose security assertions;
- launcher/prerequisite results;
- data-root persistence results;
- local-provider host mapping result;
- rules-only result;
- macOS release smoke result;
- native Wireshark acceptance reference;
- known limitations/untested macOS architectures;
- explicit note that Windows/Linux are not V1-supported hosts.

## 29. Gate 8 exit criteria

Gate 8 is complete only when:

1. accepted ADR-0005 topology is implemented;
2. the compiled web UI, API/orchestrator, and analyzer runtime run in Docker-compatible packaging;
3. analyzer/runtime versions are pinned and verified;
4. only the app port is published to host loopback by default;
5. no host networking/privileged/Docker-socket workaround exists;
6. one host data root persists cases and maps correctly to the native bridge;
7. `.env.example` contains safe defaults and no secrets;
8. `provider_mode=none` starts successfully;
9. cloud-provider privacy behavior remains unchanged;
10. same-host local provider behavior works through documented macOS Docker host mapping;
11. macOS start/stop launcher works from release artifacts;
12. macOS host-bridge install/uninstall path works;
13. prerequisite failures are clear and non-destructive;
14. a macOS user with Docker/Wireshark can run the core workflow without developer tooling;
15. restart preserves case data and original capture hashes;
16. Full/Evidence Wireshark actions work in release packaging;
17. real macOS host release smoke passes;
18. `docs/gate8-verification.md` records exact source/image/binary identities;
19. all prior Gates 0–7 regressions remain green;
20. Gate 9 has not been declared complete before Gate 8 acceptance.

Windows/Linux launchers, installers, and release smoke tests are explicitly deferred to the post-V1 platform roadmap.
