# Embedded AI App Sandbox Architecture Design

Date: 2026-10-16

Status: **Design approved; implementation planning not started**

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

The high-entropy embedded-AI API key is held in sandbox-private state. It is generated per launch or lifecycle as already required, has the most restrictive applicable permissions, is readable only by the trusted lifecycle path and runtime that need it, and is removed or rotated at shutdown/restart.

The trusted launch boundary supplies the same key to Docker core only for the embedded provider's authenticated requests. The handoff must be ephemeral and restricted to the Core process environment; it must not persist the key in `.env`, Compose configuration, SQLite, reports, artifacts, logs, browser responses, or public health/status. Do not expose other sandbox state to Docker core as part of key delivery.

The key must never enter prompts or model context. Tests use secret sentinels to verify all prohibited sinks remain clear.

## 9. Trusted wrapper responsibilities

Keep `WireclawAI` intentionally small. It is responsible for:

- verifying runtime and model manifests and artifact hashes before execution;
- verifying the fixed runtime executable and expected model identity;
- constructing fixed `llama-server` arguments;
- creating private sandbox state and the AI key;
- launching and supervising the embedded helper;
- recording child PID and start/executable identity;
- reporting readiness/failure through the approved launcher boundary;
- orderly shutdown and safe process-loss recovery.

It is not a general command runner, file broker, arbitrary argument pass-through, Docker client, host-bridge client, or broad filesystem broker. No user, capture, or model input controls executable paths, model paths, or llama.cpp arguments.

## 10. Process ownership and shutdown

Preserve verify-before-signal safety. Process state identifies the trusted `WireclawAI` lifecycle owner and the child `llama-server` by PID, process start identity, and signed bundle executable identity/path. The implementation must define which private state records these identities and how the normal launcher invokes start, status, and stop without creating a general IPC or process-control service.

Shutdown sends `TERM` only after verifying the recorded child identity. If the bounded graceful period expires, re-check identity immediately before any `KILL`. A stale or mismatched PID is discarded without signaling the process it currently names. Retain the documented PID-reuse residual; do not claim atomic PID identity protection.

Process-loss handling must publish AI unavailable, preserve deterministic analysis, and support restart through the trusted wrapper with readiness re-established before reporting recovery.

## 11. Signing, Hardened Runtime, and notarization

Ad-hoc signing is permitted only for local development and POC tests. It does not qualify the release package.

Production packaging requires:

- Developer ID signing for the parent app, helper, and nested executable libraries/frameworks;
- Hardened Runtime for the app and command-line helper targets;
- correct nested-code signing order and verification of final signatures/entitlements;
- notarization of the final production deliverable.

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
- manifest, hash, model-identity, and executable verification before launch;
- fixed executable and argument construction;
- denial of discovered Docker Engine sockets and Wireclaw data/state/host-bridge state;
- denial of Core API and host-bridge network connections and inability to obtain a bridge grant;
- successful reads of packaged model/runtime/private key and bounded private runtime/temp writes;
- normal-operation loopback-only `127.0.0.1:8767` binding, no Compose publication, and Docker-core reachability;
- authenticated model identity, chat, and Metal inference;
- startup, shutdown, process loss to deterministic fallback, and restart to ready;
- safe PID ownership checks, including stale/mismatched PID behavior;
- continued evidence, capability, recommendation, privacy, and deterministic-fallback protections.

The vmnetd check is diagnostic/informational only. Do not infer capability from `connect()` and do not send undocumented protocol messages.

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
