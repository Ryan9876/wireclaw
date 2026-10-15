# Embedded AI operations (post-V1 macOS arm64)

## End-user prerequisites

Use the complete `wireclaw-release` package on macOS arm64 with Docker Desktop (or compatible Docker runtime with Compose v2) and native Wireshark. The bundle includes the Qwen model and pinned llama.cpp runtime. Do not install a separate LLM server or download a model.

## Start and stop

From the unpacked release directory:

```sh
launch/macos/install-host-bridge.sh
launch/macos/start.sh
```

Open the printed `http://127.0.0.1:<port>` address. The packaged default selects `embedded_local`; the launcher verifies model/runtime hashes, starts the authenticated native service on `127.0.0.1:8767`, then starts the deterministic core and host bridge. Normal startup performs no model/runtime download.

Stop with:

```sh
launch/macos/stop.sh
```

Stop preserves case data, original captures, evidence captures, reports, and model assets. It signals only a verified Wireclaw-owned AI process. To uninstall only the native host bridge, run `launch/macos/uninstall-host-bridge.sh`.

## Status and fallback

The UI reports one of: Local embedded AI ready; Rules-only mode; Local embedded AI unavailable — deterministic analysis remains available; Custom local provider; Cloud provider. An AI outage leaves deterministic capture analysis usable. A fallback report is marked `model_fallback`, never AI-assisted. Check `/api/health` and `/api/config/capabilities` for the effective provider and safe availability code.

To explicitly use rules-only mode, set `WIRECLAW_PROVIDER_MODE=none` in the release `.env` and restart. To select a custom local or cloud OpenAI-compatible provider, configure the documented provider mode, URL, model, and credential in `.env`; cloud mode requires HTTPS. A user-selected provider is not silently replaced with embedded AI.

## Model, privacy, and resource policy

The release pins Qwen3-4B-Instruct-2507 at `cdbee75f17c01a7cc42f958dc650907174af0554`, Q4_K_M, and llama.cpp `8345f333951c661d166b00e6f9362e553768f292`. The packaged runtime uses a 16,384-token context, 2,048-token generation cap, batch 128, micro-batch 32, one inference slot, a zero MiB server prompt-cache limit, loopback-only listening, and a high-entropy ephemeral per-launch API secret. This cache limit is fixed release policy and is recorded in the runtime manifest.

Only Gate 7’s canonical normalized reasoning context is sent to the model. Captures, payloads, absolute paths, provider secrets, and host-bridge tokens are excluded. The model can request only validated named capabilities and cite existing same-case evidence. Deterministic analyzers remain the packet-fact authority; uncertainty and Wireshark actions remain available.

The measured reference-host benchmark used 7,422,312,448 bytes peak AI RSS, 1.25 s cold readiness, 18.609 s median provider step, and a 2,497,279,040-byte model. These are benchmark measurements, not guarantees for every host.

## Troubleshooting

- **AI unavailable:** continue with deterministic analysis; inspect the safe failure code from `/api/health`. Verify the release model/runtime files against the packaged manifests. Do not replace the executable or add arbitrary runtime flags.
- **Port conflict:** stop the process that owns the configured loopback port, then run the Wireclaw start command again. Wireclaw will not kill an unrelated process.
- **Docker cannot reach AI:** verify Docker Desktop is running and the AI service is bound only to `127.0.0.1:8767`. The approved route is `host.docker.internal`; do not bind to LAN interfaces or publish the AI port in Compose.
- **Cases or captures:** stop/start does not delete case data. Back up the configured Wireclaw data directory using normal filesystem tools before manual maintenance.

Windows and Linux embedded-AI support are not qualified by this guide.
