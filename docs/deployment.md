# Deployment

Wireclaw V1 is released for **macOS arm64** as a staged Docker build context,
the exact core image archive, and a prebuilt native Go host bridge. Windows and
Linux remain post-V1 qualification targets; existing bridge code and CI are
portability groundwork only.

## macOS V1 prerequisites

- macOS arm64
- Docker-compatible runtime with Compose v2
- Native Wireshark for macOS
- The complete `wireclaw-release` bundle

The user does not need Python, Node/npm, Go, TShark, capinfos, editcap, or
mergecap. The core image contains the API, compiled React assets, Python
analyzer, and pinned TShark/capinfos/editcap/mergecap binaries. Zeek is not
packaged because no accepted V1 capability runs it.

## Release use

1. Unpack the complete release bundle into a user-writable directory.
2. Run `launch/macos/install-host-bridge.sh` once.
3. Run `launch/macos/start.sh` and open its printed localhost URL.
4. Run `launch/macos/stop.sh` to stop the core and managed bridge.

The first start copies `.env.example` to `.env`. The defaults bind only
`127.0.0.1:8765` and use `WIRECLAW_PROVIDER_MODE=none`. The launcher reads
allowlisted values without sourcing or evaluating the file, validates both
ports, and resolves `~/Library/Application Support/Wireclaw/data` to an absolute
host path. Custom data roots may contain spaces or Unicode.

To use a local OpenAI-compatible model server on the Mac, configure its URL as
`http://host.docker.internal:<port>/v1` and choose local provider mode. Cloud
mode requires HTTPS. Gate 7 sends normalized evidence; raw captures and packet
payloads stay local by default. A provider is optional and is not part of the
core health check.

The host bridge shares the host data path, listens only on numeric loopback, and
launches only the configured/discovered native Wireshark executable using the
accepted Gate 6 grants. If Wireshark is outside the standard application path,
set `WIRECLAW_WIRESHARK_PATH` in the environment before running the launcher.
Bridge uninstall removes only the packaged bridge and its Wireclaw runtime
state; it preserves all case data.

Normal stop runs `docker compose down --remove-orphans`; it does not remove
volumes or delete the host data root. SQLite, original captures, derived
evidence captures, reports, and reasoning audit metadata persist in that one
bind-mounted root.

## Release build and verification

The release bundle contains its full Docker build context, `.env.example`,
macOS launch/install scripts, the verified `darwin-arm64` bridge, and
`core-image.tar`. Start loads that archive when the local image ID does not
match the bundled `core-image-id`; it verifies the loaded ID and starts without
rebuilding. The packaging process records source SHA, Dockerfile/Compose hashes,
immutable base image identities, analyzer lock, compiled web asset hash, core
image ID and archive SHA-256, and bridge SHA-256 in `release-metadata.json`.
This keeps the exact image tested by release engineering in the staged bundle.

To stage a candidate from a clean committed source tree on a macOS arm64 build
host, run:

```sh
python scripts/package_release.py /path/to/output
```

This command is for release engineering and uses Go and Docker during the build.
End users do not run it or need those development tools.

## Post-V1 embedded AI package

The separate post-V1 macOS arm64 package includes the pinned Qwen model, native llama.cpp Metal runtime, licenses, manifests, and host bridge. Its default is embedded local AI; no separate model server or first-launch model download is required. See [embedded AI operations](embedded-ai-operations.md) for packaged start/stop, fallback, provider overrides, privacy, and troubleshooting. The current implementation/benchmark evidence and outstanding acceptance status are in [post-V1 embedded AI acceptance](post-v1-embedded-ai-acceptance.md). Do not treat this candidate as release-qualified until EAI.14 and EAI.15 are PASS.

## Development setup

Development continues to use the repository Python environment, npm, Go, and
host packet tools as documented in the API, analyzer, web, and bridge READMEs.
Those development commands are separate from the staged release launch path.

## Future platforms

Windows and Linux are not supported V1 release hosts. Their bridge code and
build checks may remain, but launchers/installers and native release acceptance
are deferred until each platform completes its own qualification.
