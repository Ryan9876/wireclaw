# Wireclaw Post-V1 Embedded Local AI Development Specification

Status: **Review candidate — approved design, not yet authorized for implementation**

This specification defines the next post-V1 development stage: ship a local reasoning model as an integral part of Wireclaw so a macOS arm64 user gets AI-assisted troubleshooting immediately after launching the packaged application, without separately installing or configuring Ollama, LM Studio, llama.cpp, a model, an API key, or a provider endpoint.

This specification does not change or invalidate the accepted Wireclaw V1 release. `docs/v1-acceptance.md` remains the acceptance record for the frozen V1 candidate.

## 1. Authority and compatibility

For this post-V1 feature, authority is:

1. `specs/v1/constitution.md`
2. V1 safety, evidence, privacy, and uncertainty requirements in `specs/v1/requirements.md`
3. applicable architecture boundaries in `specs/v1/solution.md`
4. accepted ADRs, including ADR-0002, ADR-0005, ADR-0006, and ADR-0007
5. this specification
6. accepted post-V1 implementation plans and tests
7. implementation

Where a V1 document states a set is exact for V1, this post-V1 specification may extend that set only for the post-V1 product. It must not weaken the V1 deterministic-evidence, privacy, host-bridge, or uncertainty contracts.

## 2. Objective

Add an embedded local reasoning capability with these product properties:

- the model and inference runtime are part of the Wireclaw release bundle;
- the default packaged post-V1 experience requires no model installation, download, account, API key, model choice, or endpoint configuration;
- inference runs locally on the supported macOS arm64 host and uses Apple Silicon acceleration where supported by the pinned runtime;
- deterministic analyzers remain the only source of packet facts;
- the embedded model receives only the same bounded normalized context allowed by the Gate 7 reasoning boundary;
- model failure never destroys or blocks deterministic packet analysis;
- rules-only mode remains available;
- cloud and custom local OpenAI-compatible providers remain supported configuration choices;
- the runtime/package contract is deliberately portable so Windows/Linux embedded runtimes can be added and qualified later without redesigning the reasoning boundary.

## 3. Supported scope

This stage implements and release-qualifies embedded AI only on:

```text
platform: macOS
architecture: arm64
release topology: Docker core + native host bridge + native embedded-AI runtime
```

Windows and Linux embedded-AI runtimes are explicitly out of scope for this stage. Their future directory/layout, manifest, provider, and process-control interfaces must be anticipated, but no Windows/Linux support claim may be made until each platform receives native qualification.

## 4. Non-goals

This stage does not:

- train or fine-tune a custom network model;
- ask an LLM to parse raw PCAP/PCAPNG bytes;
- let the model replace TShark/capinfos/editcap/mergecap or deterministic derivations;
- give the model arbitrary shell, filesystem, Docker, host-bridge, or Wireshark access;
- expose a generic local model server to the LAN;
- add autonomous network remediation or device configuration;
- require Docker Model Runner, Ollama, LM Studio, Homebrew, Python, Node, Go, or llama.cpp to be installed by the end user;
- broaden cloud-provider data policy;
- qualify Windows or Linux releases.

## 5. Selected model

The embedded model is:

```text
upstream repository: Qwen/Qwen3-4B-Instruct-2507
upstream revision: cdbee75f17c01a7cc42f958dc650907174af0554
upstream license: Apache-2.0
parameter count: approximately 4.02B
release quantization: Q4_K_M GGUF
Wireclaw model ID: wireclaw-qwen3-4b-instruct-2507-q4_k_m
```

The upstream revision is immutable input to release engineering. Do not follow a floating `main` branch when producing an accepted Wireclaw model artifact.

### 5.1 GGUF provenance

The preferred release process is to produce the Q4_K_M GGUF from the pinned upstream revision using a pinned llama.cpp source commit and its conversion/quantization tooling.

The accepted model manifest must record at minimum:

- upstream repository and immutable revision;
- upstream license identifier and bundled license path;
- source file hashes or an equivalent immutable source snapshot identity;
- llama.cpp repository and immutable commit used for conversion/quantization;
- conversion settings;
- quantization `Q4_K_M`;
- resulting GGUF filename;
- GGUF SHA-256;
- GGUF byte size;
- GGUF metadata/model architecture validation result;
- Wireclaw model ID.

A reviewed prebuilt GGUF may be used for a development spike, but it cannot become a release artifact unless its origin, immutable revision, license, and SHA-256 are recorded with equivalent provenance.

The GGUF is a release asset, not source code. Do not commit the multi-gigabyte model file to normal Git history.

## 6. Selected runtime

Wireclaw will bundle a native macOS arm64 `llama-server` runtime built from an immutable llama.cpp source commit selected and tested during implementation.

The accepted runtime manifest must record:

- llama.cpp repository and commit;
- build configuration;
- target OS/architecture;
- Metal acceleration configuration;
- runtime binary and required resource/library filenames;
- SHA-256 and byte size for every shipped executable/library/resource;
- license notices required by the runtime and dependencies;
- supported OpenAI-compatible API route used by Wireclaw.

The runtime must be shipped inside the Wireclaw release. End users do not install llama.cpp themselves.

## 7. Logical architecture

```text
Browser UI
    |
    v
Wireclaw Docker core
    |
    +--> deterministic analyzer capabilities
    |      TShark / capinfos / editcap / mergecap / Python derivations
    |
    +--> Gate 7 reasoning boundary
            normalized context only
            typed capability requests
            evidence-ID validation
            bounded steps and responses
            |
            v
      embedded-local provider adapter
            |
            | OpenAI-compatible HTTP
            | host.docker.internal:<AI_PORT>
            v
Native Wireclaw AI runtime on macOS
    llama-server + Qwen3-4B-Instruct-2507 Q4_K_M
    loopback listener only
    fixed Wireclaw-owned argv
    ephemeral authentication token
```

The native runtime is a reasoning service only. It is not a host bridge, analyzer, file service, tool server, MCP server, or general command endpoint.

## 8. Provider modes

Post-V1 supports these logical provider modes:

```text
embedded_local
none
openai_compatible_local
openai_compatible_cloud
```

For the packaged post-V1 macOS release, `embedded_local` is the default.

`embedded_local` is Wireclaw-owned configuration. Browser requests and case input cannot inject or change its model path, executable path, base URL, authentication token, context size, runtime flags, or provider mode.

`none` remains the explicit rules-only mode.

The existing custom local/cloud modes remain administrator configuration and retain the Gate 7 privacy and validation contracts.

## 9. Embedded runtime startup contract

The macOS launcher owns the embedded-AI lifecycle.

On start it must, in order:

1. resolve the release directory without assuming paths contain no spaces;
2. load and validate the embedded model/runtime manifests;
3. verify the SHA-256 of the GGUF and every native runtime artifact before execution;
4. verify the runtime and model paths remain beneath the packaged release root;
5. reject symlink/path substitution that escapes the package root;
6. validate the configured AI port;
7. generate a cryptographically random ephemeral provider token for this launch;
8. start only the packaged runtime with a fixed, reviewed argument set;
9. bind the inference server to numeric loopback only;
10. disable runtime features not required by Wireclaw, including generic agent/tool/file capabilities and any runtime web UI that can broaden the interface;
11. wait for bounded readiness/health;
12. verify the running server identifies the expected Wireclaw model alias;
13. verify the Docker core can reach the loopback host service through the supported Docker Desktop `host.docker.internal` path while the runtime remains loopback-only;
14. inject the internal endpoint, model alias, and ephemeral token into the Wireclaw core process environment without persisting the token to `.env`, SQLite, case data, reports, or logs;
15. start/continue the normal Wireclaw core and host-bridge workflow.

If step 13 cannot be satisfied on the supported release environment while preserving loopback-only binding, acceptance is BLOCKED. Do not solve connectivity by binding the model server to `0.0.0.0` or a LAN interface.

### 9.1 Fixed runtime policy

The runtime configuration is product configuration, not user/capture/model-controlled input. The accepted implementation must enforce the equivalent of:

```text
listen address: 127.0.0.1
model: packaged Q4_K_M GGUF
model alias: wireclaw-qwen3-4b-instruct-2507-q4_k_m
context size: 16384 tokens
maximum generated tokens per provider response: 2048
parallel inference slots: 1 unless benchmark evidence justifies more
prompt-cache RAM: 0 MiB (disabled; requests carry explicit Wireclaw-owned context)
API authentication: required, ephemeral per launch
runtime agent/tool/file execution features: disabled
runtime browser UI: disabled when the pinned runtime supports disabling it
network model download: disabled for normal application startup
```

Implementation may use different concrete flags when required by the pinned llama.cpp revision, but the effective behavior above is mandatory.

## 10. Process ownership and shutdown

Wireclaw must manage only the fixed packaged AI helper it starts. Process signaling belongs to the trusted, unsandboxed macOS launcher; a later sandboxed `WireclawAI` invocation must not signal a child launched by an earlier sandbox invocation.

The trust split is:

- **Trusted unsandboxed host launcher:** owns the authoritative host lifecycle receipt and independently verifies the expected helper before signaling. It sends `SIGTERM`, waits for a bounded graceful interval, and re-verifies identity immediately before any `SIGKILL`. It never signals by process name and never treats runtime/model-controlled identity as sufficient authority.
- **Trusted sandboxed `WireclawAI`:** verifies and launches only the fixed helper, records sandbox-private lifecycle state, and may return bounded non-secret identity/status receipts. It performs no cross-invocation process signaling.
- **Untrusted sandboxed `llama-server`:** cannot access or modify the trusted host lifecycle receipt and cannot control signal targets. It remains denied Docker Engine and Wireclaw host authority.

The authoritative host receipt is stored beneath the existing trusted Wireclaw user runtime directory with mode `0600`. It contains only the helper PID, process-start identity, fixed expected executable identity/path, and expected helper hash/signature identity where applicable. It contains no AI key, host-bridge token, runtime/model-controlled arbitrary path, or arguments. The sandboxed helper must be unable to read or modify it. Sandbox-private lifecycle state is not authoritative for host signaling because the compromised helper shares that sandbox/container domain.

Before `SIGTERM`, the host launcher verifies the PID, process-start identity, fixed packaged helper executable identity/path, and expected hash/signature identity where applicable. If the graceful interval expires, it rereads and freshly verifies those same fields immediately before `SIGKILL`. Any failed or mismatched check means no signal and fail-closed handling. It never uses broad process-name kills such as `pkill llama-server`.

`WireclawAI start` remains short-lived: after fixed verified launch and initial identity verification, it records sandbox-private state and returns a bounded internal identity receipt to the trusted launcher. The launcher independently verifies that launch identity and writes its own authoritative host receipt. `WireclawAI status` is a fresh sandbox invocation that verifies private state and may return a bounded internal identity/status receipt, but does not signal. The host may use that receipt only to recover missing or stale host state; before signaling, it must independently verify every identity field against the fixed packaged helper. If exact identity cannot be established, it fails closed and does not signal.

The trusted launcher stop sequence is: load the authoritative host receipt; independently verify the exact helper; send `SIGTERM`; wait a bounded interval; if still alive, reread and reverify immediately; send `SIGKILL` only if the exact identity still matches; confirm exit; invoke `WireclawAI stop` for sandbox-private cleanup; then remove the host receipt. `WireclawAI stop` is cleanup-only and must never call `kill()`. It verifies that the recorded helper is no longer alive as the managed identity; if it remains alive, stop returns a bounded failure and preserves private key/lifecycle state. Only confirmed helper exit permits private cleanup. Repeated start/stop remains idempotent and cannot create duplicate managed AI servers. AI shutdown must not delete case data or model assets.

### Qualification-only App Sandbox residue reset

Native Task 9/EAI.14 qualification is repeatable on the same macOS arm64 reference account; a separate macOS account is not required. The trusted host lifecycle receipt remains the sole authority for stopping a live helper. Sandbox-private `process.json` and `api-key` are sensitive, non-authoritative state and always block qualification reset. A live `WireclawAI`, `llama-server`, listener on `127.0.0.1:8767`, any trusted host lifecycle state, symlink, unsafe directory ownership/mode, or unknown private file blocks reset without mutation.

Only the qualification reset operation may remove explicitly approved diagnostic residue. The sole currently approved residue is a regular, single-link, zero-byte `runtime.log`, owned by the expected account with mode `0600`, inside the expected owner-owned mode-`0700` private directory. Before unlinking it, the runner records its canonical path, type, size, owner UID, mode, timestamps, and SHA-256 in restricted qualification evidence; it does not persist file contents. The reset sends no signals, never removes lifecycle/key files, never recursively deletes contents, and never removes the App Sandbox container. Any failed or ambiguous check leaves the state untouched. Arbitrary/manual App Sandbox container deletion is prohibited.

Numeric-PID signal delivery retains a narrow PID-reuse time-of-check/time-of-use residual between the final identity verification and signal delivery. Do not claim atomic identity-bound signaling. Moving signaling to the already-trusted launcher does not grant the runtime authority over the launcher, Docker Engine, the host bridge, or unrelated processes.

## 11. Release layout

The staged release will contain an equivalent structure:

```text
wireclaw-release/
├── core-image.tar
├── core-image-id
├── release-metadata.json
├── ai/
│   ├── model-manifest.json
│   ├── runtime-manifest.json
│   ├── models/
│   │   └── qwen3-4b-instruct-2507-q4_k_m.gguf
│   ├── macos-arm64/
│   │   ├── llama-server
│   │   └── <required pinned runtime resources/libraries>
│   └── licenses/
│       ├── qwen-apache-2.0.txt
│       └── <runtime dependency notices>
├── host-bridge/
├── launch/
└── <existing release content>
```

Future Windows/Linux implementations may add sibling runtime directories such as `ai/windows-amd64/` or `ai/linux-amd64/`; this stage must not create or claim qualified binaries for them.

## 12. Release metadata and immutability

`release-metadata.json` must gain an `embedded_ai` record that identifies the exact accepted AI artifact set, including:

- logical model ID;
- upstream model repository/revision;
- quantization;
- model SHA-256/size;
- runtime repository/commit;
- runtime artifact SHA-256 values;
- AI manifest SHA-256 values;
- effective context and generation limits;
- default provider mode;
- default AI port;
- supported platform/architecture.

Changing the model bytes, runtime executable/libraries, inference configuration that affects behavior, reasoning contracts, or core runtime after acceptance creates a new release candidate and requires affected acceptance reruns.

Documentation-only corrections may cite the exact previously tested identities.

## 13. Reasoning and evidence boundary

All Gate 7 reasoning safety rules remain mandatory.

The embedded model may receive only the canonical allowlisted normalized reasoning context. It must not receive by default:

- raw PCAP/PCAPNG bytes;
- packet payload bytes;
- arbitrary capture excerpts;
- absolute host/container filesystem paths;
- provider/bridge/AI authentication tokens;
- credentials, cookies, bearer tokens, API keys, session secrets, or similar capture-derived secrets;
- unrestricted analyzer stdout/stderr;
- executable commands;
- chain-of-thought from prior model calls.

The embedded model may:

- rank hypotheses;
- correlate normalized deterministic observations;
- request only named reasoner-callable capabilities with valid typed parameters;
- propose conclusions/hypotheses that cite existing evidence IDs;
- state limitations and remaining uncertainty;
- recommend the next measurement/capture needed.

The embedded model may not:

- create evidence records;
- change deterministic values;
- make a finding authoritative merely by stating it;
- invoke TShark, Docker, the filesystem, Wireshark, the host bridge, or subprocesses;
- request arbitrary provider URLs or model paths;
- bypass validation because it is local.

Local execution does not weaken epistemic validation.

## 14. Deterministic fallback

Embedded AI is an enhancement, not a prerequisite for packet analysis.

If any of the following occurs, Wireclaw must preserve deterministic investigation and produce a rules-only report with an explicit AI availability limitation:

- model or runtime file missing;
- model/runtime/manifest hash mismatch;
- AI port conflict;
- AI server startup timeout;
- Docker-to-host connectivity failure;
- provider timeout;
- invalid/oversized model response;
- malformed JSON;
- unsupported evidence reference;
- repeated capability request;
- model process crash or verified lifecycle-stop failure;
- resource-limit termination.

The application must not silently present a rules-only report as AI-assisted. Effective provider mode/status is visible in health/capability state and persisted investigation metadata.

## 15. UI requirements

The UI must make the effective reasoning mode understandable without exposing unnecessary runtime plumbing.

Required user-visible states:

```text
Local embedded AI ready
Rules-only mode
Local embedded AI unavailable — deterministic analysis remains available
Custom local provider
Cloud provider
```

The normal packaged default should read conceptually as `Local embedded AI`; it should not require the user to know the terms GGUF, llama.cpp, endpoint URL, model alias, or API token.

Reports/case metadata must identify the effective reasoning mode and stable Wireclaw model ID when embedded AI participated.

Do not imply that AI generated packet facts. Do not claim that a local model proved root cause where deterministic evidence did not.

## 16. Audit and privacy

For an embedded-AI investigation, persist enough metadata to reproduce and audit the reasoning boundary without persisting secrets:

- provider mode `embedded_local`;
- Wireclaw model ID;
- model artifact SHA-256 or release identity reference;
- runtime version/commit identity or release identity reference;
- bounded reasoning-step summaries already permitted by Gate 7;
- capability requests/results and evidence references under existing audit policy;
- provider failures using normalized bounded error codes.

Never persist:

- ephemeral AI API token;
- raw hidden model chain-of-thought;
- raw secret-bearing request headers;
- full runtime environment;
- raw packet payloads simply because inference is local.

## 17. Packaging/build requirements

Release engineering must be reproducible and fail closed.

The build/staging workflow must:

1. require a clean committed Wireclaw source tree;
2. fetch/verify the pinned upstream model revision in a controlled build step, not during end-user launch;
3. build or obtain the pinned llama.cpp runtime from an immutable revision;
4. convert/quantize to Q4_K_M with recorded provenance;
5. generate manifests and SHA-256 values;
6. stage the GGUF, runtime, required licenses, and resources into the release;
7. verify the staged runtime starts using only staged files with network access unavailable;
8. run a model identity/protocol smoke test;
9. include AI identities in release metadata;
10. produce an immutable release bundle/archive whose hash is recorded.

Normal end-user startup must not download the model or runtime from the internet.

## 18. Performance/resource targets

On the Wireclaw macOS arm64 reference host used for native qualification, the accepted candidate must meet all hard bounds and record the measurements below.

Hard bounds:

- model context configured at 16,384 tokens or less;
- response generation capped at 2,048 tokens or less;
- one inference slot by default;
- AI readiness timeout no greater than 60 seconds;
- AI process failure cannot terminate the deterministic core;
- model/runtime files are never copied into a case directory.

Release targets, recorded rather than silently waived:

- packaged Q4_K_M GGUF no larger than 3.5 GiB;
- additional peak resident memory for embedded AI no greater than 8 GiB on the reference host during the benchmark corpus;
- cold embedded-AI readiness within 30 seconds on the reference host;
- median end-to-end provider step latency no greater than 20 seconds over the embedded-AI acceptance corpus.

A target miss does not justify weakening safety/resource bounds. The acceptance record must explicitly mark a missed product target and obtain owner approval before release qualification can pass.

## 19. Security requirements

Security acceptance must verify at minimum:

- model/runtime files and manifests are hash-verified before execution;
- path traversal and symlink substitution cannot redirect the launcher to another executable/model;
- runtime binds only to numeric loopback;
- the AI endpoint is not published by Docker Compose;
- provider authentication uses a high-entropy per-launch secret;
- the secret is absent from browser responses, SQLite, reports, artifacts, screenshots, and logs;
- no arbitrary llama.cpp arguments can originate from user/capture/model data;
- runtime agent/tool/file features are disabled;
- prompt-injection strings in normalized evidence cannot gain capabilities;
- invalid evidence IDs/cross-case evidence are rejected exactly as for external providers;
- original captures remain immutable;
- host bridge behavior remains unchanged and cannot be reached through the model;
- stopping/deleting a case cannot be converted into arbitrary host file/process operations;
- AI runtime compromise does not grant access to the Docker socket or Wireclaw host-bridge token.

## 20. Benchmark and product-value gate

Embedded AI is not accepted merely because it returns fluent prose.

Create a versioned embedded-AI benchmark derived from the Gate 9 corpus plus dedicated reasoning/adversarial cases. It must exercise at least:

- healthy/clean traffic;
- DNS delay;
- retransmission/loss;
- high RTT;
- receive-window constraint;
- reset/reconnect;
- TLS delay;
- positive HTTP server/application wait;
- opaque transport silence;
- PMTUD evidence;
- incomplete/one-sided/midstream capture;
- conflicting indicators;
- prompt injection in normalized strings;
- invented/cross-case evidence IDs;
- repeated/invalid capability requests;
- malformed model output and runtime failure.

Automated safety acceptance requires:

- zero deterministic Gate 9 regressions caused by enabling embedded AI;
- zero unsupported model claims admitted as authoritative findings;
- zero invalid or cross-case evidence references admitted;
- zero unauthorized capability invocations;
- all ambiguous fixtures preserve required uncertainty;
- all provider failure cases safely fall back;
- raw capture/payload/secret sentinels absent from model request, non-auth headers, persisted artifacts, and logs;
- the same original-capture hashes before/after AI-assisted investigation;
- model/runtime identities recorded for every AI-assisted benchmark run.

In addition, produce a human-reviewed comparison of `none` versus `embedded_local` for representative corpus scenarios. The review must assess whether embedded AI materially improves hypothesis ranking, explanation, or next-evidence guidance without weakening evidence traceability or uncertainty. The comparison and owner signoff are release evidence.

## 21. Regression gate

Before post-V1 embedded-AI acceptance can pass:

- the complete existing V1 deterministic/core test suite passes in its pinned analyzer environment;
- packaging tests pass;
- web unit/build/E2E tests pass;
- host-bridge tests and native Wireshark actions remain passing;
- the full Gate 9 deterministic corpus remains semantically correct;
- rules-only mode remains independently runnable with the embedded runtime stopped;
- cloud/custom-local provider behavior remains compatible unless an intentional post-V1 spec change says otherwise;
- V1 acceptance documentation is not rewritten as though embedded AI was part of the frozen V1 candidate.

## 22. Native macOS end-to-end acceptance

A real macOS arm64 desktop acceptance run must use one immutable packaged post-V1 candidate and verify:

The frozen candidate archive and bundle remain the evidence anchor throughout
qualification. Task 10 and destructive qualification scenarios run against a
disposable private copy whose provenance is verified against that candidate
before the copy is changed. Runtime `.env` configuration is created only in
that private copy from the packaged `.env.example`, uses a private data root,
and has restrictive permissions; the per-launch AI key is never stored there.
Each Task 10 run uses a unique `COMPOSE_PROJECT_NAME`. Its preflight checks
containers only in that exact Compose project and checks configured host ports
independently. Unrelated Compose projects do not block or become cleanup
targets. Qualification invokes its trusted runner from the exact source
checkout; qualification tooling is not expected inside the release bundle.
The frozen candidate is never edited to supply runtime configuration.

1. no separately installed model runtime is required;
2. no network model download occurs on first normal launch;
3. packaged model/runtime hashes match release metadata;
4. launcher starts embedded AI automatically;
5. Metal/native runtime identity is recorded;
6. Docker core reaches the loopback-only AI service through the approved host path;
7. UI reports Local embedded AI ready;
8. representative AI-assisted cases complete and retain valid evidence links;
9. Full Capture and Evidence Capture native Wireshark actions still work;
10. stopping the AI process causes safe rules-only degradation;
11. restarting restores embedded AI without case corruption;
12. stop/start preserves cases and model assets;
13. paths containing spaces are accepted;
14. port-conflict and hash-tamper cases degrade safely;
15. no LAN listener exists for the model or application;
16. accepted privacy/security sentinel checks pass.

Windows/Linux results remain `NOT_RUN` for this stage and are not blockers because they are outside the approved scope.

## 23. Implementation tasks

Use these task IDs in the implementation plan and acceptance record:

- EAI.1 Establish post-V1 provider/config contracts including `embedded_local`.
- EAI.2 Add model provenance/build pipeline for pinned Qwen3-4B-Instruct-2507 -> Q4_K_M GGUF.
- EAI.3 Pin/build/package native macOS arm64 llama.cpp runtime with Metal support.
- EAI.4 Add AI model/runtime manifests and release metadata identities.
- EAI.5 Extend macOS launcher with hash verification, secure AI process lifecycle, health, authentication, and fallback.
- EAI.6 Wire Docker core to the loopback-only native AI service through the approved Docker Desktop host path.
- EAI.7 Reuse/extend the Gate 7 provider adapter and audit metadata for `embedded_local` without bypassing validation.
- EAI.8 Add API/capability status needed for effective AI-mode reporting.
- EAI.9 Add concise UI state for embedded-AI ready/unavailable/rules-only behavior.
- EAI.10 Extend release packaging/staging for offline model/runtime inclusion and licenses.
- EAI.11 Add security/privacy/adversarial tests for the embedded runtime boundary.
- EAI.12 Add versioned embedded-AI benchmark and rules-only comparison evidence.
- EAI.13 Run full V1/Gate 9 regression and native Wireshark regression.
- EAI.14 Complete native macOS packaged end-to-end acceptance.
- EAI.15 Write post-V1 embedded-AI acceptance/operations documentation.

Tasks must be executed spec-first and test-first where behavior is being changed. Do not mark EAI.14/EAI.15 complete from unit/CI evidence alone.

## 24. Acceptance states

Every EAI task and release criterion must be recorded as exactly one of:

```text
PASS
FAIL
BLOCKED
NOT_RUN
```

Only `PASS` satisfies an in-scope release criterion.

Automatic blockers include:

- runtime/model not immutably identified;
- model/runtime download required during normal end-user startup;
- LAN/non-loopback model listener;
- missing provider authentication;
- raw capture/payload/secret leakage to model context where not already permitted by policy;
- model output admitted as packet evidence;
- unsupported/cross-case evidence admitted;
- arbitrary runtime/model paths or command arguments reachable from untrusted input;
- deterministic Gate 9 semantic regression;
- loss of rules-only fallback;
- broken native Wireshark actions;
- unreviewed license/provenance gap;
- macOS packaged end-to-end failure;
- any in-scope EAI task not `PASS`.

## 25. Definition of done

This post-V1 stage is done only when one immutable macOS arm64 package can be given to a user who has the documented Wireclaw host prerequisites and, without installing/configuring an LLM stack, immediately run AI-assisted investigations whose packet facts remain deterministic, traceable, privacy-bounded, uncertainty-aware, and safely degradable to rules-only mode.
