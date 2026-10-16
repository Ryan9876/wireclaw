# Sandboxed Embedded AI Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the unsandboxed macOS embedded-AI process with a signed, headless App Sandbox bundle while preserving native Metal inference, Docker-core access, deterministic fallback, and the existing runtime-compromise security requirement.

**Architecture:** A trusted Go `WireclawAI.app` command receives a per-launch key over inherited fd 3, verifies its signed resources, then launches a fixed sandbox-inheriting `llama-server` child that persists after `start` exits. The existing Bash launcher passes the same key to Docker Core through the Compose process environment, recreates/removes the Core container across key lifetimes, and retains ownership of public readiness checks and fallback.

**Tech Stack:** Go 1.23 (existing host-bridge toolchain), narrow macOS Security.framework/libproc bindings where required, Bash launcher, Python packaging/acceptance scripts, Docker Compose, codesign/Hardened Runtime/Developer ID/notarytool, pytest, Go tests, and native macOS qualification.

**Spec:** `docs/superpowers/specs/2026-10-16-embedded-ai-app-sandbox-design.md`; preserve `specs/post-v1/embedded-local-ai.md`, especially EAI.14 and its 16 native checks.

## Global Constraints

- Preserve verbatim: “AI runtime compromise does not grant access to the Docker socket or Wireclaw host-bridge token.”
- Parent entitlements are exactly `com.apple.security.app-sandbox=true` and `com.apple.security.network.server=true`; no `network.client`, user-selected-file, or broad filesystem entitlement.
- Helper entitlements are `com.apple.security.app-sandbox=true` and `com.apple.security.inherit=true`; no independent network-client or filesystem entitlement.
- The only public wrapper operations are `WireclawAI start`, `WireclawAI status`, and `WireclawAI stop`, with no extra arguments or general IPC/XPC/daemon.
- Key wire representation is 64 lowercase hexadecimal characters plus one newline, transferred to `start` only over inherited anonymous fd 3; the same per-launch value enters Core only through the trusted Compose/Core process environment.
- The helper binds `127.0.0.1:8767`; Compose does not publish that port; Core uses `http://host.docker.internal:8767/v1`.
- `start` exits while the sandboxed helper persists. Fresh `status` verifies and reports identity; fresh sandbox `stop` never signals. The trusted unsandboxed launcher owns authoritative host lifecycle state and all TERM/KILL signaling.
- Verify PID, process-start identity, fixed executable identity/path, and expected helper hash/signature before TERM; re-read and re-verify immediately before KILL. Retain the numeric-PID reuse TOCTOU residual; make no atomic identity claim.
- Recreate Core whenever its key changes and remove the Core container on shutdown. Rotate/remove sandbox-private key state at stop/restart.
- Every sandbox, signature, manifest, hash, startup, readiness, network, or process failure leaves deterministic analysis usable.
- Preserve Qwen3-4B-Instruct-2507 Q4_K_M; context <= 16384, generation <= 2048, one inference slot, and `--cache-ram 0`.
- `network.server` permits a broader post-compromise bind capability; document it as a residual and test only the fixed normal-operation bind. Do not claim kernel enforcement of one listener.
- `/var/run/com.docker.vmnetd.sock` remains informational/unresolved; do not infer capability from `connect()` or send undocumented protocol messages.
- Ad-hoc signing is development-only. CI must not claim Developer ID, Hardened Runtime release, or notarization acceptance without the required release credentials and native evidence.
- Once production source or runtime packaging changes, prior candidate evidence is superseded: require exact-head CI, a new immutable candidate, three full unchanged 22-scenario benchmarks, all 16 EAI.14 checks, sandbox-isolation checks, whole-branch review, and security review.
- Do not update acceptance to PASS until all new-candidate qualification criteria pass.

## Repository Map and Decisions

### Existing integration points

- `launch/macos/start.sh` — reads release configuration, starts embedded AI, prepares provider environment, checks model identity and Docker reachability, starts Compose Core, and reports readiness.
- `launch/macos/stop.sh` — stops AI, bridge, and Compose. Core shutdown currently uses `down --remove-orphans`; preserve case data.
- `launch/macos/common.sh` — current manifest/hash checks, AI key/status/log/PID paths, process identity and listener checks, provider environment setup, Docker-side probe, and host-bridge lifecycle. Replace direct llama-server/key ownership with the fixed wrapper boundary while retaining bridge ownership.
- `ai/embedded-ai.lock.json`, `scripts/build_embedded_ai.py`, `ai/model-manifest.json` and `ai/runtime-manifest.json` (generated release inputs) — immutable source/runtime/model identities and limits. Extend packaging metadata to describe the `.app` and signed nested code; do not commit model/runtime binaries.
- `scripts/package_release.py` — stages the release tree, model/runtime assets and metadata. It must build/stage `WireclawAI.app` without changing the pinned model/runtime policy.
- `compose.yaml`, `wireclaw-release/.env.example`, and `tests/packaging/test_compose_contract.py` — provider environment mapping and the no-AI-port-publication contract.
- `scripts/freeze_embedded_ai_candidate.py`, `scripts/benchmark_embedded_ai.py`, `scripts/validate_container_release.py`, and `tests/acceptance/test_embedded_ai_benchmark.py` — candidate identity, unchanged 22-scenario benchmark, and container validation. Update identity validation for the signed app bundle.
- `specs/post-v1/embedded-local-ai.md` Section 22 — authoritative EAI.14 16-check list. No checked-in native EAI.14 runner currently exists; add repeatable native qualification tooling rather than relying on preserved external run evidence.
- `tests/packaging/test_macos_launchers.py`, `test_release_bundle_contract.py`, `test_compose_contract.py`, `test_embedded_ai_build.py` — current launcher, release, Compose, and manifest test seams.
- `tests/unit/test_reasoning.py`, `tests/integration/test_gate7.py`, `tests/acceptance/test_embedded_ai_contract.py` — provider, deterministic fallback, evidence/capability, and privacy regressions.
- `.github/workflows/gate6-validation.yml` — current Linux/full, platform bridge, and Docker release CI. It has no macOS app-sandbox build/signing job. Add macOS source/contract/local-signing validation, and keep production Developer ID/notarization as a separate credentialed native release qualification.

### Wrapper language/toolchain

Use **Go 1.23** for the headless `WireclawAI` executable. This is the repository's existing pinned native executable toolchain (`services/host-bridge/go.mod`, `services/host-bridge/bridge.go`) and already has Go tests and macOS CI coverage. Go's standard library covers bounded fd-3 reads, hashing/manifests, fixed child launch, and machine-readable status without adding a runtime dependency. Use only narrow macOS Security.framework/libproc bindings for code-signature and process-identity checks that cannot be established safely by portable Go. Package/sign the resulting Mach-O as the main executable in `WireclawAI.app`; bundle signing and entitlements apply to the executable independent of its implementation language. This avoids adding a second native language/runtime solely for the wrapper. Do not make the wrapper a general subprocess or argument broker.

### Planned file changes

- Create `ai/macos/WireclawAI/main.go`, focused Go files for key input, bundle verification, child lifecycle, status, and process identity, plus macOS-only Security/libproc bindings and unit tests.
- Create parent/helper entitlement plists and app `Info.plist` under `ai/macos/`; add a deterministic app-bundle assembly/sign/verify step in `scripts/build_macos_ai_app.py` (or a focused extension to `scripts/build_embedded_ai.py` if it stays cohesive).
- Modify `scripts/build_embedded_ai.py`, `scripts/package_release.py`, release metadata, and release bundle tests to stage the signed app, pinned nested libraries, read-only assets, and both manifests.
- Modify `launch/macos/common.sh`, `start.sh`, and `stop.sh` for fd-3 bootstrap, fixed wrapper commands, ephemeral Core key environment, Core recreation/removal, and deterministic fallback.
- Modify `compose.yaml` only if its environment interpolation must change; preserve no published AI port. Extend `tests/packaging/test_compose_contract.py`.
- Extend `tests/packaging/test_macos_launchers.py`, `test_release_bundle_contract.py`, and `test_embedded_ai_build.py`; add wrapper Go unit tests and native sandbox tests under `tests/packaging/`.
- Add `scripts/qualify_macos_embedded_ai.py` and native test fixtures/evidence schema for EAI.14 plus sandbox checks; retain `scripts/freeze_embedded_ai_candidate.py` as immutable candidate identity tooling.
- Add macOS CI workflow or job for Go wrapper tests, bundle/entitlement contract validation, and ad-hoc local signing only. Add a separately gated native release procedure for Developer ID/Hardened Runtime/notarization; absent credentials must be recorded as unavailable, not PASS.
- Update operational packaging documentation only after interfaces are implemented. Do not edit `docs/post-v1-embedded-ai-acceptance.md` to claim qualification before new candidate results exist.

## Review Focus

1. **Secret-bearing process boundaries:** partial, oversized, malformed, missing, and extra fd-3 input; assert the key is absent from argv, wrapper/helper environment, stdout, stderr, `.env`, Compose files, persisted host state, SQLite, reports, artifacts, browser responses, prompts, and logs. Core's Docker-managed environment metadata is the one documented exception; the sandboxed runtime must be unable to reach Docker Engine to inspect it.
2. **Lifecycle state substitution:** host receipt tampering, sandbox read/write attempts, stale/replaced state, PID reuse, PID/start/executable/hash mismatch, symlinked state, executable/model/bundle substitution, and stop races must never signal a mismatched process or launch an unverified artifact. Sandbox-private state is not authoritative for host signaling.
3. **Overbroad signed capabilities:** inspect entitlements embedded in the signed parent/helper and reject any extra capability, including `network.client`, home/Docker/Wireclaw filesystem access, or user-selected-file access.
4. **Isolation versus required connectivity:** prove Docker Engine sockets, Wireclaw state and bridge state are denied; outbound Core/bridge/arbitrary targets fail; packaged assets and bounded private writes work; authenticated Core-to-runtime requests still work on the fixed loopback path.
5. **Failure and recovery:** invalid signature/manifest/hash/model, absent bundle, helper startup/readiness failure, process loss, and restart must each preserve deterministic analysis and report only normalized public status.

---

## Tasks

### Task 1: App bundle layout and entitlement contracts

**Files:**
- Create: `ai/macos/Info.plist` and parent/helper entitlement plist templates; the builder emits the generated `.app` under its staging directory, not Git.
- Create: focused bundle assembly support in `scripts/build_macos_ai_app.py`.
- Test: `tests/packaging/test_macos_ai_bundle.py`.

**Interfaces:** Produces a deterministic app layout with parent executable at `Contents/MacOS/WireclawAI`, helper and signed nested llama.cpp/Metal code in the approved bundle, and manifests/model under read-only Resources. Entitlement values are exactly those in Global Constraints.

- [ ] Write tests for expected bundle paths, fixed bundle identifier, exact parent/helper entitlement dictionaries, and rejection of `network.client`, broad filesystem, user-selected-file, or extra entitlements.
- [ ] Run `pytest tests/packaging/test_macos_ai_bundle.py -q`; confirm it fails against missing bundle contracts.
- [ ] Implement only the bundle layout, plist templates, and entitlement validator; keep generated binaries out of Git.
- [ ] Run the focused test and confirm PASS; run `plutil -lint` on generated plist files.
- [ ] Commit `build: define sandboxed WireclawAI app bundle`.

### Task 2: Fixed start/status/stop command surface

**Files:**
- Create: `ai/macos/WireclawAI/main.go` and command dispatch tests.
- Test: `ai/macos/WireclawAI/main_test.go`.
- Create: `ai/macos/WireclawAI/go.mod`, pinned to Go 1.23 with no external dependencies.

**Interfaces:** Only `WireclawAI start`, `WireclawAI status`, and `WireclawAI stop` are accepted. No command accepts trailing arguments. Output is bounded machine-readable status with normalized reasons and no PID/path/secret fields.

- [ ] Add failing dispatch tests for the three accepted operations and rejection of missing command, unknown command, and any extra argument.
- [ ] Run `cd ai/macos/WireclawAI && go test ./...`; confirm the new command contract fails.
- [ ] Implement a small dispatcher and bounded JSON result writer; keep operational functions behind narrow interfaces for unit tests.
- [ ] Run `cd ai/macos/WireclawAI && go test ./... && go vet ./...`; confirm PASS.
- [ ] Commit `feat: add fixed WireclawAI lifecycle commands`.

### Task 3: fd 3 key bootstrap and sandbox-private key state

**Files:**
- Create/modify: wrapper key-input and private-state files under `ai/macos/WireclawAI/`.
- Test: wrapper key-input tests and `tests/packaging/test_macos_ai_bundle.py`.

**Interfaces:** `start` reads at most 66 bytes from inherited fd 3, accepts exactly 64 lowercase hex characters plus one LF, writes mode-restricted key state only inside the sandbox container, closes fd 3 before helper launch, and zeroes transient buffers where feasible.

- [ ] Add failing tests for valid input, partial input/EOF, oversized input, malformed/uppercase key, missing fd, extra bytes/records, write failure, and descriptor closure before launch.
- [ ] Run the focused Go tests and confirm they fail on the unimplemented parser/consumer.
- [ ] Implement bounded fd-3 consumption and atomic private-state write; do not read the key from argv/environment or print it.
- [ ] Add sentinel assertions that key bytes do not occur in command arguments, environment, stdout, stderr, or wrapper error text; run tests and confirm PASS.
- [ ] Commit `feat: bootstrap embedded AI key over private fd`.

### Task 4: Signature, manifest, hash, and model verification before execution

**Files:**
- Create/modify: wrapper verification files in `ai/macos/WireclawAI/` and macOS Security.framework binding.
- Modify: `scripts/build_embedded_ai.py`, `scripts/package_release.py` as necessary to place signed runtime/model manifests and bundle identity consistently.
- Test: wrapper verification tests and `tests/packaging/test_embedded_ai_build.py`.

**Interfaces:** `verifyBundle() -> VerifiedBundle` is the only source of executable/model paths accepted by launch. It checks the signed app/helper/nested runtime identity, fixed manifest locations, schema/policy, model identity, artifact hashes/sizes, and rejects symlink/path escape or unmanifested executable content before any child starts.

- [ ] Add failing tests for signature failure, manifest/hash/model mismatch, wrong bundle identity, helper/model/library substitution, symlink escape, and verification-order proof that no launch occurs before all checks pass.
- [ ] Run focused Go/Python tests and confirm failure on absent verifier behavior.
- [ ] Implement fixed-path verification; use Security.framework for code validity and existing pinned manifest policy for contents; reject instead of resolving an alternate path.
- [ ] Run wrapper and packaging tests; confirm altered signed resources/helper/model are rejected before execution.
- [ ] Commit `feat: verify signed embedded AI bundle before launch`.

### Task 5: Fixed llama-server launch and persistent-child lifecycle

**Files:**
- Modify: wrapper launch/process-state implementation.
- Modify: app bundle builder/runtime staging to include helper-inherit signature and fixed resources.
- Test: wrapper lifecycle tests and `tests/packaging/test_macos_ai_bundle.py`.

**Interfaces:** `start` uses only the verified fixed `llama-server` and model. It supplies fixed arguments: `--model`, approved model alias, `--host 127.0.0.1`, `--port 8767`, `--ctx-size 16384`, approved batch values, `--n-predict 2048`, `--parallel 1`, sandbox-private `--api-key-file`, `--no-agent`, `--no-webui`, and `--cache-ram 0`. The helper inherits the App Sandbox, serves on numeric loopback, and persists after `start` exits.

**Completion record:** This fixed verified helper launch is complete and committed as `00fa8e3` (`feat: launch fixed sandboxed inference helper`). Its recorded child identity remains valid launch input for trusted host receipt creation. It does not authorize a later sandboxed `WireclawAI stop` invocation to signal the helper.

- [x] Add failing tests that capture executable/argv/environment, assert all fixed options and no user-controlled args, verify helper key is a file path rather than key value, and prove child remains alive after the start invocation exits.
- [x] Add invalid helper/model/bundle substitution tests that assert no process is launched.
- [x] Run focused tests and confirm failure before implementation.
- [x] Implement fixed `exec.Command` launch with a minimal allowlisted environment, bounded private logs, inherited sandbox code signature, child PID/start/executable identity recording, and immediate start exit after launch succeeds.
- [x] Run wrapper tests and a disposable ad-hoc signed macOS parent/helper probe; verify helper survives parent exit and signed helper carries only `app-sandbox` plus `inherit`.
- [x] Commit `feat: launch fixed sandbox-inheriting inference helper` — `00fa8e3`.

### Task 6: Status, cleanup-only stop, host signaling, recovery, and PID safety

**Files:**
- Modify: wrapper state/status/stop code and macOS process identity binding.
- Test: wrapper lifecycle/process tests.

**Interfaces:** `status` verifies sandbox-private state and returns a bounded non-secret internal status/identity receipt; it never signals. `stop` is cleanup-only, never calls `kill()`, and refuses to clear key/lifecycle state while the expected helper remains alive. The trusted unsandboxed launcher owns an authoritative mode-0600 host receipt, verifies the exact fixed helper before TERM and freshly before KILL, confirms exit, invokes wrapper cleanup, then removes host state. A verified status receipt may support recovery only after independent host verification against the fixed packaged helper. Unverifiable or mismatched state fails closed. Task 5's recorded identity remains launch input for host receipt creation, not authority for a later sandboxed stop to signal.

**Task 6/7 boundary ruling (approved at `57136b7d1f780b4b4cba9dc9711080c00cba1bfe`):**

Task 6 owns lifecycle primitives and security contracts:
- `WireclawAI status` verifies sandbox-private state, returns a bounded internal identity/status receipt, and never signals.
- `WireclawAI stop` performs cleanup only, never signals, refuses cleanup while its managed helper remains alive, and clears private state only after confirmed exit.
- Trusted-host primitives own the mode-0600 non-secret receipt, receipt parsing/validation, PID/start/executable/hash identity verification, verify-before-TERM, bounded wait, fresh verify-before-KILL, fail-closed mismatch behavior, and recovery verification.

Task 7 owns normal launcher orchestration:
- `start.sh` writes the authoritative host receipt from independently verified `WireclawAI start` identity and wires start/readiness/fallback behavior.
- `stop.sh` loads the host receipt, calls Task 6 verified TERM/KILL primitives, confirms exit, invokes `WireclawAI stop` for cleanup, and removes the host receipt.
- Normal launcher behavior wires status-receipt recovery.

Focused changes in `launch/macos/common.sh` are permitted for Task 6 primitives. Do not wire the full production `start.sh`/`stop.sh` flow until Task 7.

Ruling: Keep sandbox-private status/cleanup in `WireclawAI` and host signaling in trusted-host primitives; this follows the approved amendment after native `EPERM` evidence and prevents the sandbox from acquiring cross-invocation signal authority. If this boundary is wrong, Task 7 orchestration may need rework; no entitlement or sandbox relaxation is authorized.

**Read-only review of `stash@{0}` (`WIP Task 6 pre-amendment: fresh-sandbox signaling design`):**
- `ai/macos/WireclawAI/main.go`: The removal of `not_implemented` status/stop stubs is category A in intent and will be implemented manually. The `signal` and `wait` fields are category B and will not be restored.
- `ai/macos/WireclawAI/status_stop.go`: `stopWith`, `syscall.Kill`, TERM/KILL ordering, and wrapper signaling are category B and obsolete. Bounded state parsing and identity/hash checks are category C because the amended contract distinguishes an internal status receipt, private cleanup, and a separate authoritative host receipt; reimplement against the amendment instead of restoring this file.
- `ai/macos/WireclawAI/status_stop_test.go`: Status privacy/identity cases are category C and will be rewritten for the bounded receipt contract. Any stop tests expecting the wrapper to signal (TERM, timeout, KILL, or signal preservation) are category B; host-signal tests belong to the trusted-host primitive boundary.
- The stash ledger note describing sandboxed `EPERM` as an unresolved blocker is category B as a current decision; the native evidence itself remains documented by the approved amendment. The enclosing-harness pre-start `SIGABRT` limitation remains valid and is not a product failure.

- [x] Add failing tests for host receipt mode/contents and absence of key/token; sandbox denial of host receipt read/write; bounded status identity receipt; status never signaling; wrapper stop never signaling; cleanup refusal while helper is live; cleanup after confirmed exit; host TERM requiring PID/start/executable/hash verification; TERM mismatch preserving unrelated process; fresh KILL re-verification; identity change between TERM and KILL preventing KILL; stale host receipt fail-closed behavior; recovery from missing host receipt through verified status with independent fixed-helper checks; unverified recovery never signaling; repeated stop safe/idempotent; and documented PID-reuse residual. Added coverage also rejects receipt and sandbox-private state substitution races and verifies cleanup retry after partial file removal.
- [x] Run the focused tests and confirm mismatched identities currently fail.
- [x] Implement bounded status receipt and cleanup-only wrapper stop. Implement host-side receipt creation/validation and signaling in the trusted launcher; never accept runtime/model-controlled identity as sufficient authority.
- [x] Run tests plus native start-exit/status/launcher-stop/cleanup sequence. Verify the launcher stops only the verified helper, wrapper status/stop cannot signal, and mismatched/reused processes survive.
- [x] Commit `feat: separate sandbox status from trusted host signaling`.

### Task 7: macOS launcher integration

**Files:**
- Modify: `launch/macos/common.sh`, `launch/macos/start.sh`, `launch/macos/stop.sh`.
- Test: `tests/packaging/test_macos_launchers.py`.

**Interfaces:** The launcher generates one key per start, invokes only the fixed wrapper operation with an anonymous pipe duplicated to fd 3 and a key-free allowlisted wrapper environment, writes the authoritative mode-0600 host lifecycle receipt from independently verified start identity, asks `status` for bounded identity/status and recovery only, and performs authenticated `/models` and listener checks from the trusted outer launcher. The outer launcher owns TERM/KILL and invokes wrapper `stop` only for cleanup after confirmed child exit. No general process-control API is introduced. Failure selects deterministic fallback.

Native evidence driving this task boundary: a separate signed status invocation verified process identity; a separate signed stop invocation received `EPERM` at `kill(pid, SIGTERM)`. Thus fresh-sandbox signaling is unsupported; no entitlement relaxation was attempted, and unified sandbox-denial log access was unavailable. The enclosing-command-sandbox pre-start `SIGABRT` is a distinct harness limitation and is not this evidence.

- [x] Add failing launcher tests proving only the three fixed wrapper operations are called, fd 3 carries the key without key in argv/stdout/stderr/wrapper environment, host receipt is mode 0600/non-secret/sandbox-inaccessible, readiness uses authenticated expected-model identity, host TERM/KILL require independent identity checks, and no direct `llama-server` launch remains in Bash.
- [x] Add fallback tests for missing app, signature/verification failure, helper startup failure, lost readiness, and process loss.
- [x] Run `pytest tests/packaging/test_macos_launchers.py -q`; verify expected failure.
- [x] Replace direct runtime launch/key handling with the wrapper boundary while retaining trusted host receipt and verified signaling in the outer launcher; preserve bridge behavior, normalized diagnostics, and authenticated bounded no-proxy/no-redirect readiness checks.
- [x] Run focused tests plus `bash -n launch/macos/*.sh`; confirm PASS (`32 passed`; native Task 6 lifecycle probe PASSed outside the enclosing command sandbox).
- [x] Commit `feat: integrate sandboxed AI lifecycle with macOS launcher`.

### Task 8: Core key handoff, rotation, recreation, and removal

**Files:**
- Modify: `launch/macos/start.sh`, `stop.sh`, `common.sh`, and `compose.yaml` only if required for ephemeral environment interpolation.
- Test: `tests/packaging/test_compose_contract.py`, `tests/packaging/test_macos_launchers.py`.

**Interfaces:** The exact same 64-hex key consumed by wrapper fd 3 is passed only as `WIRECLAW_PROVIDER_API_KEY` in the trusted Compose/Core process environment. It never enters `.env`, Compose source/config output, argv, or persisted host state. Core is force-recreated on key rotation; shutdown removes the Core container, not its case data.

- [x] Add failing tests that capture fd-3 input and Compose process environment and assert byte-for-byte key equality, absence from argv/files/logs, forced recreation after rotation, and container removal at stop.
- [x] Add a Compose metadata test documenting the intentional Docker-managed process-environment metadata exposure and that the Compose file publishes no AI port.
- [x] Run the focused tests and confirm they fail on existing persisted/configured key handoff.
- [x] Implement per-command environment injection, `--force-recreate` (or equivalent proved recreation), and `down --remove-orphans`; ensure probe commands receive the same transient key without printing it.
- [x] Run Compose/launcher tests and verify changing the key recreates Core while preserving case data.
- [x] Commit `feat: rotate embedded key with Core container lifecycle`.

Compose resolves the transient key in memory to create Core. The launcher invokes only `config --quiet` and emits or writes no expanded config. Docker-managed container environment metadata retains the key for the container lifetime; this is the documented exception.

### Task 9: Native App Sandbox isolation tests

**Files:**
- Create: native sandbox test helper/fixtures under `tests/packaging/macos/` and repeatable checks in `scripts/qualify_macos_embedded_ai.py`.
- Modify: `tests/packaging/test_macos_ai_bundle.py` and macOS CI workflow.

**Interfaces:** Tests inspect entitlements from the signed code, run probes inside the actual inherited sandbox, and emit bounded PASS/FAIL evidence without secrets. vmnetd is informational only; no protocol messages are sent.

- [ ] Add failing native checks for denied discovered Docker Engine sockets (including both known Docker Desktop paths), Wireclaw data/state and bridge-state reads, trusted host lifecycle receipt read/write, Core API/bridge/arbitrary outbound connections, and inability to obtain a bridge grant.
- [ ] Add positive checks for packaged model/runtime/private-key reads, bounded private temp/runtime writes, successful inbound Core request, and normal listener exactly `127.0.0.1:8767` with no wildcard/LAN listener.
- [ ] Add signed-entitlement checks that reject broader-than-approved parent/helper entitlements and confirm helper inheritance; assert no network.client.
- [ ] Run native tests on Apple Silicon with an ad-hoc signed disposable bundle; confirm the new security checks fail before implementation and do not classify vmnetd by connect alone.
- [ ] Implement the minimum test probes needed to exercise the real parent/helper sandbox; prove compromised/runtime-controlled state cannot select a host signal target; retain logs without credential content.
- [ ] Re-run native isolation tests; record `network.server` listener scope as the approved residual, not a test failure.
- [ ] Commit `test: prove embedded runtime sandbox boundaries`.

### Task 10: Real llama-server, Metal, authentication, and Docker-Core integration

**Files:**
- Modify: native qualification script/fixtures and `tests/packaging/test_release_bundle_contract.py`.
- Use: `scripts/build_embedded_ai.py`, `scripts/package_release.py`, `compose.yaml`, packaged release bundle.

**Interfaces:** Against the built signed app, verify model identity, authenticated `/v1/models`, authenticated `/v1/chat/completions`, Metal load/device, numeric loopback bind, and actual Docker Core access through `host.docker.internal:8767`.

- [x] Add failing integration assertions for wrong model identity/auth, redirect/proxy behavior, absent Metal, extra listener, wrong endpoint, and Core reachability failure.
- [x] Build fixture-sized package contract tests without downloading the production model; confirm they fail on unsigned/incorrect bundle metadata.
- [x] Implement only missing integration/metadata seams; retain Q4_K_M and all runtime limits.
- [x] On Apple Silicon, run one packaged inference and Core request with a real release-sized model; verify Metal and the fixed listener. If an architecture/signing incompatibility appears, stop and revise the approved design before broad qualification. PASS on the exact-HEAD ad-hoc development bundle; production signing checks remain `NOT_RUN`.
- [x] Run relevant packaging and integration tests; commit `test: validate sandboxed Metal provider integration` (`8e08fb2`).

### Task 11: Developer ID, Hardened Runtime, and notarized packaging

**Files:**
- Modify: `scripts/build_macos_ai_app.py`, `scripts/package_release.py`, release docs, `.github/workflows/gate6-validation.yml` or a new focused macOS workflow.
- Test: `tests/packaging/test_release_bundle_contract.py`, new signing-contract tests.

**Interfaces:** Local development may ad-hoc sign. CI source/contract jobs may verify bundle structure and local signing but must label Developer ID/notarization `NOT_RUN` without credentials. Production release signing signs nested libraries/helper before parent, enables Hardened Runtime, verifies exact entitlements and signatures, then notarizes/staples the final deliverable.

- [ ] Add failing contract tests for signing order, parent/helper hardened-runtime flags, exact signed entitlements, invalid signature rejection, and CI absence of production signing claims.
- [ ] Run release bundle/signing tests and confirm missing signing pipeline is detected.
- [ ] Implement credential-gated Developer ID signing and notarization with secrets supplied only by protected release environment; do not mutate Docker Desktop configuration or add App Store requirements.
- [ ] Run macOS CI with ad-hoc signing and explicitly record production signing as unavailable; run a credentialed native release dry run only where Developer ID/notary credentials exist.
- [ ] Commit `build: sign and notarize sandboxed AI bundle`.

### Task 12: Gate 7, privacy, and security regression coverage

**Files:**
- Modify: `tests/unit/test_reasoning.py`, `tests/integration/test_gate7.py`, `tests/acceptance/test_embedded_ai_contract.py` as needed; production reasoning source only if the new boundary exposes a defect.

**Interfaces:** Sandboxing changes transport/lifecycle only; deterministic findings, evidence authorization, capability allowlists, recommendation binding, provider status, prompt privacy, and fallback semantics remain unchanged.

- [ ] Add/retain regression assertions for arbitrary prose exclusion, evidence/cross-case validation, deterministic hypothesis authority, recommendation evidence binding, privacy sentinels, and normalized provider/runtime-unhealthy fallback.
- [ ] Run focused Gate 7/security tests and confirm any intended architecture behavior changes are isolated to runtime availability/key lifecycle.
- [ ] Make no unrelated reasoning changes; if a new product defect is found, add the failing regression first and stop to scope it against the governing spec.
- [ ] Run focused tests plus full Python regression when implementation is complete; commit `test: retain Gate 7 guarantees under sandbox failures`.

### Task 13: Candidate and native qualification reset tooling

**Files:**
- Create: `scripts/qualify_macos_embedded_ai.py` and tests for its evidence schema/check ordering.
- Modify: `scripts/freeze_embedded_ai_candidate.py`, `scripts/benchmark_embedded_ai.py`, `tests/acceptance/test_embedded_ai_benchmark.py`, and release acceptance instructions as required.
- Reference: `specs/post-v1/embedded-local-ai.md` Section 22, `.github/workflows/gate6-validation.yml`.

**Interfaces:** Candidate freeze records source, signed-app bundle/tree/archive identity, nested code/signature/entitlement identities, image/model/runtime/manifests, and fixed runtime policy. Native runner executes all 16 EAI.14 checks plus sandbox isolation against one immutable candidate and stores each result/evidence separately. Benchmark remains the unchanged 22-scenario harness.

- [ ] Add failing tests requiring exactly the 16 named EAI.14 checks, one candidate identity across native evidence, and required sandbox tests; reject missing/duplicate checks or mixed candidate hashes.
- [ ] Add tooling tests for immutable bundle/archive verification before/after qualification and fixture isolation for destructive tamper/port-conflict checks.
- [ ] Run tests and confirm the current repository's lack of a checked-in native EAI.14 runner is exposed.
- [ ] Implement repeatable native EAI.14 + sandbox runner, evidence schema, candidate hash rechecks, and truthful signing-credential status. Preserve original benchmark corpus/scenarios and no averaging across three runs.
- [ ] Run tooling tests; do not run final three benchmarks or complete EAI.14 until exact-head CI and a new frozen candidate exist.
- [ ] Commit `test: add repeatable sandboxed AI qualification tooling`.

## Implementation Verification and Qualification Gate

After implementation tasks complete, run focused tests first, then full practical regression: full Python suite, web tests/lint/typecheck/build, bridge Go tests/vet, packaging tests, shell syntax, Ruff check/format, and `git diff --check`. Require exact-head CI on the implementation commit. Do not claim release signing acceptance from ad-hoc CI.

Only after exact-head CI passes, freeze a new immutable candidate from that exact commit. On that same candidate run three complete unchanged 22-scenario official benchmark runs, all 16 EAI.14 checks from the beginning, and all new App Sandbox isolation checks. Verify Developer ID/Hardened Runtime/notarized final package in the native credentialed environment. Any failure stops qualification and acceptance editing. After all pass, obtain fresh whole-branch and security reviews, then update acceptance in a separate documentation/evidence commit. No previous candidate's benchmark/EAI.14 results count.

## Self-Review Against the Approved Spec

- Sections 1–3: Tasks 1, 4, 5, 9, and 11 define the signed headless bundle, parent/helper entitlements, inherited sandbox, no client entitlement, and signed-code inspection.
- Sections 4–7 and residuals: Tasks 5, 9, and 10 test fixed normal loopback, Docker path, outbound denial, filesystem boundaries, vmnetd informational treatment, and post-compromise `network.server` residual without overclaiming kernel confinement.
- Sections 8–10: Tasks 3, 5–9 preserve fd 3, one per-launch key, no prohibited secret sinks, fixed commands, child persistence, fresh status and cleanup-only stop, authoritative sandbox-inaccessible host receipt, host-owned verified TERM/KILL, recovery verification, Core recreation/removal, and Docker metadata caveat. Task 5 remains complete at `00fa8e3`; its recorded identity is launch input for host receipt creation, not authority for a later sandboxed stop to signal.
- Sections 11–13: Task 11 separates ad-hoc CI from Developer ID/Hardened Runtime/notarization; Tasks 5, 10, and 12 preserve Metal/model limits and deterministic fallback.
- Sections 14–15: Tasks 9–13 cover sandbox probes, security and Gate 7 protections, immutable new candidate, exact-head CI, three unchanged benchmark runs, all 16 EAI.14 checks, and fresh reviews.
- Section 17: No sandbox-exec production design, separate user, network extension, Docker Desktop mutation, general broker, downloads, runtime selection, hot swap, external model server, or App Store requirement is introduced.
- The only discovered tooling gap is that EAI.14's authoritative 16 checks exist in the post-V1 spec/acceptance evidence, but no native runner is checked into the repository; Task 13 closes this with repeatable tooling.
- Wrapper toolchain decision is grounded in the current Go 1.23 host-bridge toolchain and macOS CI matrix. The plan uses narrow platform bindings only for macOS signature/process identity APIs and adds no third-party Go dependency.
