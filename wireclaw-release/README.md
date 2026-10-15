# Wireclaw post-V1 package for macOS

This package runs the compiled web UI, API, SQLite metadata, and deterministic
analyzer in one Docker core container. The Go host bridge runs natively and
opens approved captures in native Wireshark. It also includes the pinned native
macOS arm64 llama.cpp runtime and Qwen model for optional local reasoning.

## Requirements

- macOS arm64 (the only architecture included in this candidate)
- Docker Desktop or another Docker-compatible runtime with Compose v2
- Wireshark for macOS

Python, Node/npm, Go, TShark, capinfos, editcap, and mergecap are not needed on
the Mac for normal operation. Analyzer tools run inside the core image. Zeek is
not installed because no accepted V1 capability invokes it.

No separate Ollama, LM Studio, llama.cpp, model selection, or model download is
needed. The release contains `ai/model-manifest.json`,
`ai/runtime-manifest.json`, the Qwen3-4B-Instruct-2507 Q4_K_M GGUF, the native
`ai/macos-arm64/` runtime and its libraries, and both upstream licenses.
`release-metadata.json` records the locked model/runtime identities and file
hashes.

## First start

1. Copy or unzip this complete `wireclaw-release` directory to a user-writable
   location.
2. Run `launch/macos/install-host-bridge.sh` once.
3. Run `launch/macos/start.sh`.
4. Open the printed `http://127.0.0.1:<port>` URL.

The packaged `darwin-arm64` bridge binary is in `host-bridge/macos/`.

On first start the launcher copies `.env.example` to `.env`. The packaged
default starts embedded local AI and stores data under
`~/Library/Application Support/Wireclaw/data`. The launcher verifies the
packaged assets, starts the model runtime on numeric loopback, and creates an
ephemeral authentication secret for that launch. The secret is not written to
`.env` or case data. Normal startup performs no model or runtime download.

To run without reasoning, set `WIRECLAW_PROVIDER_MODE=none` in `.env`. The
deterministic analyzer remains available if the model/runtime is unavailable or
cannot be reached. The UI reports that state instead of describing a fallback
report as AI-assisted. You can configure an administrator-selected
OpenAI-compatible local or cloud provider using the documented API settings.
The launcher reads only documented keys as data; it never sources or evaluates
`.env`. Paths containing spaces are supported.

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

This bundle contains the exact Docker build context, the packaged core image
archive, and the native bridge. The launcher loads `core-image.tar` when the
local `wireclaw-core:gate8` tag does not match `core-image-id`; it checks the
loaded image ID and never rebuilds the release image during normal startup.
`release-metadata.json` records the archive hash, source identity, pinned base
images, tool versions, compiled web hash, core image ID, and bridge SHA-256.

This post-V1 embedded-AI package is qualified for macOS arm64 only. Windows and
Linux embedded-AI implementation and qualification are outside this stage.
