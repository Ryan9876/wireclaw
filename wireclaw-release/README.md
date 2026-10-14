# Wireclaw V1 for macOS

This bundle is the macOS V1 release package. It runs the compiled web UI, API,
SQLite metadata, and deterministic analyzer in one Docker core container. The
Go host bridge runs natively and opens approved captures in native Wireshark.

## Requirements

- macOS arm64 (the only architecture included in this candidate)
- Docker Desktop or another Docker-compatible runtime with Compose v2
- Wireshark for macOS

Python, Node/npm, Go, TShark, capinfos, editcap, and mergecap are not needed on
the Mac for normal operation. Analyzer tools run inside the core image. Zeek is
not installed because no accepted V1 capability invokes it.

## First start

1. Copy or unzip this complete `wireclaw-release` directory to a user-writable
   location.
2. Run `launch/macos/install-host-bridge.sh` once.
3. Run `launch/macos/start.sh`.
4. Open the printed `http://127.0.0.1:<port>` URL.

The packaged `darwin-arm64` bridge binary is in `host-bridge/macos/`.

On first start the launcher copies `.env.example` to `.env`. Defaults use
rules-only mode and store data under `~/Library/Application Support/Wireclaw/data`.
Edit `.env` to change ports, data location, or opt into a provider. The launcher
reads only the documented keys as data; it never sources or evaluates `.env`.
Paths containing spaces are supported.

For an OpenAI-compatible model server running on this Mac, set the base URL to
`http://host.docker.internal:<port>/v1`. Cloud mode requires an HTTPS endpoint.
The core sends normalized evidence according to Gate 7; raw capture files and
payload bytes remain local by default.

## Stop and uninstall

Run `launch/macos/stop.sh` to stop only the Wireclaw bridge and Compose core.
It preserves SQLite, original captures, evidence captures, and reports. Run
`launch/macos/uninstall-host-bridge.sh` to remove the Wireclaw-managed bridge.
Uninstall does not remove case data. To remove case data, delete the documented
Wireclaw data directory yourself after separately backing it up if desired.

## Release build

This bundle contains the exact Docker build context and packaged bridge. The
first launcher start builds the core image locally. `release-metadata.json`
records source identity, pinned base images, tool versions, and bridge SHA-256.
The core image ID is recorded by the release builder after `docker compose build`.

Windows and Linux are future qualification targets, not supported V1 hosts.
