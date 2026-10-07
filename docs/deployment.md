# Deployment Design

Wireclaw V1 is a local application distributed as a Dockerized core plus a small native Wireshark host bridge.

## User prerequisites

Required:
- Docker Desktop or compatible Docker/Compose runtime
- native Wireshark installation

Not required for end users:
- Python
- Node.js
- Go
- Zeek installed on the host
- TShark installed separately on the host for analysis

Analyzer dependencies are packaged in the Wireclaw image.

## Runtime topology

```text
Host
├── Browser
├── Docker runtime
│   └── Wireclaw core
│       ├── web
│       ├── API/orchestrator
│       ├── analyzer toolchain
│       └── SQLite
├── Wireclaw data root
├── Wireclaw host bridge
└── Native Wireshark
```

The core application is published to loopback only.

Example conceptual Compose port binding:

```yaml
ports:
  - "127.0.0.1:8765:8765"
```

The final port remains configurable.

## Data persistence

Use a host bind mount so both Docker and the native host bridge can refer to the same logical case artifacts.

Conceptually:

```text
<wireclaw-home>/data  <->  /wireclaw/data
```

The API stores logical artifact IDs and container-relative paths. The bridge maps the same logical IDs to canonical host paths beneath its configured data root.

## Release contents

Target release bundle:

```text
wireclaw/
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

## First-run behavior

Launcher should:

1. verify Docker is available
2. verify Wireshark is installed or request its path
3. create Wireclaw data/config directories
4. create/generate local bridge credential
5. install/start host bridge
6. start Docker services
7. wait for local health endpoint
8. open localhost application in default browser

Failure should identify the exact missing prerequisite and corrective action.

## Platform specifics

### macOS

- discover standard Wireshark application path first
- native bridge distributed for supported architectures
- launcher may use a `.command` wrapper or packaged installer, but product behavior should not depend on Terminal expertise

### Windows

- discover common Wireshark installation path and registry information where appropriate
- bridge distributed as native executable
- launcher should not require PowerShell policy changes for ordinary use when avoidable

### Linux

- support common Docker/Compose installations
- resolve Wireshark from configured path/PATH with validation
- account for display/session differences only in host bridge; analyzer remains containerized

## Configuration

Configuration categories:

### Safe user-facing
- application port
- data root
- model-provider mode
- provider endpoint/model
- analysis limits

### Sensitive
- cloud model API key
- bridge credential

Sensitive values must not be committed to the repository. Release docs should prefer OS/container secret/environment mechanisms suitable for a local app.

## Upgrade policy

A release should pin:
- Wireclaw application version
- TShark/Wireshark CLI version in analyzer image
- Zeek version
- Python dependencies
- Node/web dependencies
- host bridge version

On upgrade:
- preserve cases/data
- migrate SQLite schema explicitly
- never rewrite original captures
- report analyzer-version differences when a historical case is re-run

## Uninstall policy

Uninstalling application binaries/containers must not silently delete case data.

The user should explicitly choose whether to preserve or delete:
- original captures
- evidence captures
- reports
- local database/configuration
