# Embedded AI App Sandbox Architecture Design

Date: 2026-10-16

Status: **Design approved; implementation planning not started; lifecycle amendment approved after native EPERM evidence**

## Purpose and authority

This design records the approved architectural remediation for the macOS embedded-AI runtime. It supplements the post-V1 embedded-AI specification and the accepted native-runtime design. It does not amend the V1 acceptance record, authorize implementation by itself, or weaken any higher-authority requirement. If implementation reveals a conflict with the approved requirements, stop and resolve the specification conflict before coding.

The remediation preserves the existing requirement verbatim:

> AI runtime compromise does not grant access to the Docker socket or Wireclaw host-bridge token.

The existing unsandboxed `llama-server` does not meet this requirement because it runs with the launching user's authority. The approved remediation is to place inference in a macOS App Sandbox while preserving native Apple-Silicon Metal inference and Docker core connectivity.

## 1. Architecture

Add a small, signed, headless macOS application bundle that owns embedded-AI verification and lifecycle. The conceptual bundle is:

```text
WireclawAI.app/
  Contents/
    Info.plist
    MacOS/
      WireclawAI
      llama-server
    Frameworks/
      pinned signed llama.cpp / Metal libraries
    Resources/
      ai/
        model.gguf
        runtime-manifest.json
        model-manifest.json
```

`WireclawAI` is trusted code. The embedded `llama-server` is treated as compromiseable and receives an inherited App Sandbox. The existing Docker Wireclaw core continues using the OpenAI-compatible provider boundary at `http://host.docker.internal:8767/v1`. The server binds to `127.0.0.1:8767`; Compose does not publish the AI port.

The implementation may adjust bundle layout to satisfy Apple signing and helper-tool requirements, while preserving the trust boundaries, verification order, entitlements, and testable interfaces in this design.

## 2. Trust boundary

The wrapper is trusted lifecycle and verification code. The inference server is untrusted after launch. A compromised runtime must not gain access to:

- Docker Engine/control sockets;
- the Wireclaw data root, case data, SQLite, or runtime state;
- host-bridge state, grant manifests, or host-bridge token;
- the Wireclaw Core API or host bridge over the network;
- the per-launch AI key from host state or Docker Engine metadata;
- arbitrary user home-directory contents.

The runtime receives only the packaged runtime libraries and model, its private AI API key, private bounded runtime/temp state, and the incoming server connection needed to serve inference. The sandbox is the OS-enforced boundary; environment scrubbing, secret naming, model instructions, and file permissions alone are not substitutes.

## 3. App Sandbox entitlements

The parent `WireclawAI` has exactly these App Sandbox capabilities:

- `com.apple.security.app-sandbox = true`
- `com.apple.security.network.server = true`

The parent explicitly does not have:

- `com.apple.security.network.client`;
- user-selected-file access;
- broad filesystem exceptions;
- home-directory exceptions;
- Docker filesystem exceptions;
- Wireclaw state/data exceptions.

The `llama-server` helper has:

- `com.apple.security.app-sandbox = true`;
- `com.apple.security.inherit = true`.

The helper has no independent `network.client` or filesystem entitlement. Its production-signed entitlements must match this reviewed design. Packaging and native tests must inspect the signed entitlements, not only source entitlement files.

## 4. Network model

Normal packaged launch uses fixed, Wireclaw-owned arguments including:

```text
--host 127.0.0.1
--port 8767
```

Normal-operation qualification proves that the only AI listener is `127.0.0.1:8767`, with no wildcard or LAN listener, that Compose does not expose the AI port, and that Docker core can reach the model using `host.docker.internal`.

`network.server` is a broader OS capability than the normal listener configuration: a compromised runtime may attempt to bind additional listener addresses or ports. The approved specification requires fixed numeric loopback binding in normal operation; it does not require kernel-enforced post-compromise confinement to one address and port. Record this as a residual capability. Do not claim the sandbox enforces the exact listener address or port after arbitrary code compromise.

## 5. Outbound network denial

There is no `network.client` entitlement. Production qualification proves the sandboxed runtime cannot initiate connections to:

- the Wireclaw Core API;
- the Wireclaw host bridge;
- arbitrary outbound targets in the security test corpus.

This prevents a compromised runtime from obtaining a host-bridge grant token through the Core API. The required inbound Core-to-AI connection remains functional.

## 6. Docker boundary and vmnetd

Production qualification discovers or otherwise verifies the actual Docker Engine/control socket locations on the test host, then proves access is denied. It must include, at minimum, the known Docker Desktop paths:

```text
~/.docker/run/docker.sock
~/Library/Containers/com.docker.docker/Data/docker.raw.sock
```

These paths are minimum reference-host checks, not an exhaustive list hard-coded as the only possible Engine sockets. Qualification records discovered paths and tests the active Engine endpoint without sending Docker API requests from the sandboxed runtime.

`/var/run/com.docker.vmnetd.sock` is a distinct Docker privileged-helper endpoint, not the Docker Engine/control socket. Its exact authority on the reference host remains unresolved. A successful `connect()` to it does not prove Docker Engine or container-control authority. Qualification may record its presence and connection result for diagnostics, but must not send undocumented protocol messages or claim the helper is harmless.

For the currently approved Docker Engine/control threat boundary, vmnetd is informational and outside scope. If future evidence shows that it exposes Docker Engine, container control, arbitrary host commands, or equivalent authority, reassess the threat model and security approval before proceeding.

## 7. Filesystem and state model

The packaged model, runtime libraries, and manifests are read-only application-bundle resources. Writable AI state is confined to sandbox-authorized private container/runtime/temp locations.

The following remain outside the runtime's sandbox access:

- Wireclaw case data and SQLite/state;
- host-bridge runtime state and bridge-grant manifests;
- Docker sockets;
- ordinary user home-directory contents.

Do not add filesystem exceptions for convenience. Tests prove required bundle reads and bounded private writes succeed while representative Wireclaw, Docker, and home paths remain denied.

## 8. AI API key

The trusted outer Wireclaw launcher generates the high-entropy embedded-AI API key for each launch. Preserve the current representation: 32 cryptographically random bytes encoded as 64 lowercase hexadecimal characters followed by one newline. The launcher passes the key to `WireclawAI start` only through a dedicated inherited anonymous pipe on file descriptor 3. The key is never passed in argv, stdout, stderr, a persisted `.env`, a generated Compose file, or a general IPC socket.

`WireclawAI start` reads exactly one bounded record from fd 3, validates the representation and length, rejects missing, malformed, or extra input, writes the key into sandbox-private container state with restrictive permissions, and closes fd 3 before launching the helper. `llama-server` receives only the sandbox-private key-file path through its fixed arguments. It does not receive the key in argv or environment. At shutdown or before restart, remove the private key file; every new launch uses a newly generated key.

The outer launcher keeps the key out of its exported environment while invoking `WireclawAI start`, using a minimal allowlisted wrapper environment that omits the key. The wrapper's environment must not contain the key. The launcher supplies the same key to Docker core only through the existing trusted startup boundary and the Core process environment, as a per-command environment value for the Compose operation. It must not put the value in argv or print it, and must not persist it in `.env`, Compose configuration/source, SQLite, Wireclaw host state, reports, artifacts, logs, browser responses, prompts/model context, or public health/status. Do not expose other sandbox state to Docker core as part of key delivery.

Docker necessarily receives the value as part of the container process environment. Docker Engine may retain that environment in its container configuration/inspection metadata for the lifetime of the container, where a Docker Engine client authorized to use the control API can inspect it. This is Docker-managed runtime metadata, not a Wireclaw `.env` or case/state record. The embedded runtime's sandbox denies access to the Docker Engine/control API, so a compromised `llama-server` cannot inspect that metadata. The trusted launcher must cause the Core container to be recreated whenever the per-launch key changes and removed on shutdown, so obsolete key metadata is not retained in a stopped container.

The key must never enter prompts or model context. Tests use secret sentinels to verify all prohibited sinks remain clear.

## 9. Trusted wrapper responsibilities

Keep `WireclawAI` intentionally small. Its complete public command interface is:

```text
WireclawAI start
WireclawAI status
WireclawAI stop
```

The command accepts no other subcommands or arguments. `start` requires the key only on fd 3. The executable path, model path, and llama.cpp arguments are fixed by the signed bundle and verified manifests. There is no arbitrary command execution, general IPC socket, XPC/general RPC interface, or long-lived privileged daemon.

`start`:

- consumes and closes the bounded key record from fd 3;
- verifies the signed bundle, runtime/model manifests, artifact hashes, fixed executable identity, and manifest-declared model identity before execution;
- writes the key into private container state;
- constructs the fixed `llama-server` arguments and starts the sandbox-inheriting helper;
- records the child PID, process-start identity, and executable identity in sandbox-private state;
- returns a bounded INTERNAL identity receipt to the trusted host launcher containing only PID, process-start identity, fixed helper executable identity, and expected helper hash/signature identity as needed;
- reports bounded launch success/failure without exposing the key.

The internal identity receipt contains no AI key, bridge token, arbitrary runtime-controlled path, or model-controlled data. The trusted host launcher independently verifies the launch identity and writes its own authoritative mode-0600 host lifecycle receipt.

`status` is a fresh sandbox invocation. It reads only sandbox-private lifecycle state, verifies the current child PID/start/executable identity, and returns a small bounded INTERNAL machine-readable verified status/identity receipt. It performs NO signaling. The receipt may be used only as recovery input when trusted host state is missing or stale. The host launcher must independently verify every identity field against the fixed packaged helper before signaling; if exact identity cannot be established, it fails closed and does not signal. Status exposes no secret or arbitrary path. It does not probe the HTTP endpoint because the sandbox has no `network.client` entitlement. After `start`, the trusted outer launcher performs the authenticated `/models` identity check against the manifest-declared model and verifies Docker-core reachability, then publishes the existing public ready/unavailable state.

`stop` is cleanup-only and MUST NOT call `kill()`. It reads private lifecycle state and verifies that the recorded helper is no longer alive as the managed identity. If the expected helper remains alive, it returns bounded failure and preserves private key/lifecycle state. Only after confirmed helper exit may it remove sandbox-private key and lifecycle state. Its output is bounded and contains no secret.

The wrapper is responsible for:

- verifying runtime and model manifests and artifact hashes before execution;
- verifying the fixed runtime executable and manifest-declared model identity;
- constructing fixed `llama-server` arguments;
- accepting the key only on fd 3 and creating its private sandbox copy;
- launching the embedded helper and verifying its initial process identity;
- recording child PID and start/executable identity in sandbox-private state and returning the bounded internal identity receipt;
- reporting bounded launch success/failure through the approved launcher boundary;
- private-state cleanup after the host launcher confirms child exit.

The helper's stdout/stderr must not carry the key. Redirect runtime diagnostics to bounded private logging within the sandbox container; the trusted launcher reports only normalized readiness/failure states. The authenticated `/models` identity is checked by the trusted outer launcher after `start`, not by the sandboxed wrapper.

It is not a general command runner, file broker, arbitrary argument pass-through, Docker client, host-bridge client, or broad filesystem broker. No user, capture, or model input controls executable paths, model paths, or llama.cpp arguments.

## 10. Process ownership and shutdown

Use the **child-persists-after-start** lifecycle model. `WireclawAI start` is short-lived: it verifies and launches the fixed helper, records sandbox-private lifecycle state, verifies initial child identity, returns a bounded internal identity receipt to the trusted launcher, then exits. The child remains in its inherited App Sandbox. A fresh `WireclawAI status` verifies sandbox-private state and returns a bounded internal status/identity receipt. Neither status nor any later sandbox invocation signals the child.

Native evidence established that a separate signed status invocation verified helper identity, while a separate signed stop invocation received `EPERM` from `kill(pid, SIGTERM)`. Therefore fresh-sandbox signaling is not a supported lifecycle mechanism. No entitlement or architecture relaxation was attempted. Unified sandbox-denial log access was unavailable; do not claim a denial log was captured. An enclosing-command-sandbox pre-start `SIGABRT` is a distinct harness limitation and is not the evidence for this process-control decision.

The trusted unsandboxed macOS launcher owns signaling and an authoritative host lifecycle receipt. The receipt is stored beneath the existing trusted Wireclaw user runtime directory with mode `0600` and contains only PID, process-start identity, fixed expected executable identity/path, and expected helper hash/signature identity where applicable. It contains no AI key, bridge token, or runtime/model-controlled arbitrary paths/arguments. The sandboxed helper must not be able to read or modify it. Sandbox-private lifecycle state is not authoritative for host signaling because a compromised helper shares that sandbox/container domain.

For stop, the host launcher loads the authoritative receipt and independently verifies PID, process-start identity, fixed packaged helper executable identity/path, and expected hash/signature where applicable before `SIGTERM`. It waits a bounded graceful interval. If the helper remains alive, it rereads and freshly verifies all identity fields immediately before `SIGKILL`; any mismatch or failed check means no signal and fail-closed handling. It confirms exit, invokes `WireclawAI stop` only for private cleanup, then removes the host receipt. `WireclawAI stop` never calls `kill()` and preserves private key/lifecycle state if the expected helper remains alive.

If host receipt is missing or stale, the launcher may request the bounded verified status receipt as recovery input. The host independently verifies every field against the fixed packaged helper before signaling. If exact identity cannot be established, it fails closed and does not signal. Runtime/model-controlled identity is never sufficient authority, and no general process-control API is introduced. Never signal by process name or disturb a mismatched/reused process.

Retain the numeric-PID time-of-check/time-of-use residual between final identity verification and signal delivery; do not claim atomic identity-bound signaling. Process-loss handling publishes AI unavailable, preserves deterministic analysis, and supports restart only after trusted-launcher identity and readiness checks succeed.

## 11. Signing, Hardened Runtime, and notarization

Ad-hoc signing is permitted only for local development, sandbox/inference testing, and development qualification. Because ad-hoc signatures cannot provide the matching Team ID required by Hardened Runtime library validation for bundled non-platform llama.cpp dylibs, development signing must omit Hardened Runtime. It preserves the exact App Sandbox entitlements and does not disable library validation. It does not qualify production signing.

Production packaging requires:

- Developer ID signing for the parent app, helper, and nested executable libraries/frameworks;
- Hardened Runtime for the app and command-line helper targets;
- correct nested-code signing order and verification of final signatures/entitlements;
- notarization of the final production deliverable.

Production signing must never silently fall back to ad-hoc. When Developer ID or notarization credentials are unavailable, production qualification is `NOT_RUN`. Development qualification may use the exact ad-hoc-signed App Sandbox bundle with Hardened Runtime off; it must report Developer ID, Hardened Runtime production validation, notarization, and stapling as `NOT_RUN`.

Test the actual Developer-ID-signed, hardened, notarized bundle during native release qualification; an ad-hoc sandbox POC is insufficient. CI without Developer ID/notarization credentials may run source, packaging-contract, entitlement, and local signing tests, but must report that limitation and cannot claim production signing/notarization acceptance. Native qualification with release credentials verifies the final distributed bundle.

## 12. Metal and inference policy

Preserve native Apple-Silicon Metal inference. The disposable POC demonstrated successful server startup, `libggml-metal` load, Apple M3 Pro detection, inference, authenticated `/models` and `/chat/completions`, and Docker-core connectivity. Production qualification must repeat these checks against the real signed bundle.

Do not change the selected Qwen3-4B-Instruct-2507 Q4_K_M model unless implementation demonstrates a necessity and obtains a separate design approval. Preserve:

- context cap at or below 16,384;
- generation cap at or below 2,048;
- one parallel/inference slot;
- `--cache-ram 0`.

## 13. Failure behavior

Sandbox, signature, manifest, hash, packaging, startup, readiness, network, or process failures leave deterministic Wireclaw analysis usable. Embedded-AI failures normalize to the existing deterministic fallback model.

This includes invalid signatures/manifests/hashes, missing sandbox bundle/helper, helper launch failure, lost readiness, Docker-core connectivity failure, and runtime process death. Such failures must not block deterministic analysis or damage case data, reports, or original captures.

## 14. Test requirements

The implementation and native qualification must provide evidence for:

- exact parent and helper entitlements, including helper sandbox inheritance;
- absence of `network.client` and broad filesystem entitlements;
- inherited fd 3 key bootstrap, bounded input validation, no key in argv/stdout/stderr, same key in the Core process environment, and removal/rotation across stop/restart;
- identical per-launch key delivery to the Core process environment, no key in Wireclaw persistence/output sinks, and accurate inspection of Docker-managed container environment metadata;
- fixed `start`/`status`/`stop` interface, rejection of extra commands/arguments, helper survival after `start` exits, bounded status receipts, and cleanup-only stop behavior;
- manifest, hash, model-identity, and executable verification before launch;
- fixed executable and argument construction;
- denial of discovered Docker Engine sockets and Wireclaw data/state/host-bridge state;
- denial of Core API and host-bridge network connections and inability to obtain a bridge grant;
- successful reads of packaged model/runtime/private key and bounded private runtime/temp writes;
- normal-operation loopback-only `127.0.0.1:8767` binding, no Compose publication, and Docker-core reachability;
- authenticated model identity, chat, and Metal inference;
- startup, shutdown, process loss to deterministic fallback, and restart to ready;
- host receipt mode/content and sandbox inaccessibility; wrapper status/stop never signaling; cleanup refusal while helper is live; host PID/start/executable/hash verification before TERM and fresh re-verification before KILL; status-assisted recovery with independent host verification; stale/mismatched/reused PID preservation; and repeated-stop idempotence;
- continued evidence, capability, recommendation, privacy, and deterministic-fallback protections.

The vmnetd check is diagnostic/informational only. Do not infer capability from `connect()` and do not send undocumented protocol messages.

Native lifecycle evidence: a separate signed status invocation verified process identity; a separate signed stop invocation received `EPERM` from `kill(pid, SIGTERM)`. No entitlement relaxation was attempted, and unified sandbox-denial log access was unavailable. An enclosing-command-sandbox pre-start `SIGABRT` is a separate harness limitation, not evidence for this lifecycle decision.

## 15. Qualification reset

When production implementation changes source or packaged runtime architecture, the previously qualified `bae67a0996afa7ca34c2890295e72de0acd02221` candidate is superseded for final qualification. Freeze a new immutable candidate and require exact-head CI. Against that same new candidate:

- rerun three complete, unchanged official 22-scenario benchmark runs;
- rerun all 16 EAI.14 checks from the beginning;
- run the new production sandbox-isolation checks;
- verify the Developer-ID-signed, Hardened-Runtime, notarized package where release credentials and environment permit;
- complete a new whole-branch review and a new security review.

No prior candidate's benchmark or EAI.14 evidence counts as final qualification for the changed architecture. Acceptance documentation may be updated only after the new qualification criteria pass.

## 16. Non-blocking residuals

### vmnetd

The process may be able to connect to `/var/run/com.docker.vmnetd.sock` on the reference host. Its exact authority remains unresolved. It is distinct from the Docker Engine/control socket. Do not characterize it as harmless. It is informational and non-blocking under the current approved threat boundary; new evidence of Engine/control-equivalent authority requires reassessment.

### `network.server`

After arbitrary-code compromise, the runtime may attempt to bind additional listener addresses or ports because `network.server` is broader than the normal fixed bind. The approved spec requires loopback-only binding during normal operation, not kernel-enforced post-compromise listener confinement. This is a documented residual, not a current blocker.

## 17. Non-goals

This remediation does not add:

- `sandbox-exec` as production isolation;
- separate macOS user provisioning;
- a Network Extension or firewall subsystem;
- Docker Desktop configuration mutation;
- a general IPC broker;
- runtime model downloads, arbitrary runtime selection, or model hot-swapping;
- an external Ollama/oMLX dependency;
- App Store distribution requirements beyond direct Developer ID distribution.

## Design review checklist

Before implementation is considered ready, verify that the implementation plan and tests preserve the original runtime-compromise requirement, match the reviewed entitlements, distinguish normal loopback binding from the `network.server` residual, leave vmnetd accurately unresolved and outside the current Engine/control boundary, include production signing/notarization, and reset candidate qualification as specified above.
