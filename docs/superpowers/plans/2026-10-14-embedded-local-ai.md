# Embedded Local AI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Qwen3-4B-Instruct-2507 Q4_K_M and a pinned native llama.cpp runtime inside the macOS arm64 Wireclaw release so packaged Wireclaw starts with local AI-assisted troubleshooting without requiring a separately installed/configured LLM stack.

**Architecture:** Preserve Wireclaw's deterministic Docker core as the source of packet facts. Add a Wireclaw-managed native macOS arm64 `llama-server` plus packaged GGUF, bound to numeric loopback and authenticated with a per-launch secret; the core reaches it through the existing OpenAI-compatible provider boundary. Embedded-AI failure degrades explicitly to rules-only operation and may never broaden the deterministic evidence, privacy, command-execution, or Wireshark trust boundaries.

**Tech Stack:** Python 3.12/FastAPI/Pydantic, React/TypeScript, Bash macOS launchers, Docker Compose, native llama.cpp/Metal, GGUF Q4_K_M, pytest, Vitest/Playwright, Go host bridge regression.

**Spec:** `specs/post-v1/embedded-local-ai.md`; also read `docs/decisions/ADR-0007-embedded-local-ai-native-runtime.md`, `specs/v1/gate7-execution.md`, `specs/v1/gate9-acceptance.md`, and `AGENTS.md` before implementation.

## Global Constraints

- Supported/qualified platform for this stage is **macOS arm64 only**. Windows/Linux embedded-AI implementation and qualification remain out of scope and must be `NOT_RUN`.
- Model source is `Qwen/Qwen3-4B-Instruct-2507` at immutable revision `cdbee75f17c01a7cc42f958dc650907174af0554`, Apache-2.0, released as Q4_K_M GGUF with Wireclaw model ID `wireclaw-qwen3-4b-instruct-2507-q4_k_m`.
- Pin llama.cpp to release `v0.6.0`, commit `8345f333951c661d166b00e6f9362e553768f292`, for the first implementation. If the required Qwen/Metal/OpenAI-compatible smoke test fails at this exact revision, stop and amend the plan/spec before selecting another runtime revision.
- Embedded runtime effective policy: `127.0.0.1` only; context <= 16,384 tokens; generated response <= 2,048 tokens; one inference slot by default; readiness timeout <= 60 seconds; per-launch high-entropy API authentication; runtime UI/tool/file/agent features disabled; no network model download during normal startup.
- The packaged post-V1 release default is `embedded_local`; `none`, `openai_compatible_local`, and `openai_compatible_cloud` remain supported administrator modes.
- The multi-GB GGUF and generated native runtime artifacts are release assets and must not be committed to normal Git history.
- Raw PCAP/PCAPNG bytes, packet payloads, absolute paths, authentication tokens, capture-derived credentials, and unrestricted analyzer output remain excluded from reasoning context.
- LLM output never becomes packet evidence. Existing evidence-ID validation, typed capability validation, duplicate-request detection, step bounds, and deterministic findings remain authoritative.
- No shell interpolation for untrusted values. No user/capture/model input may choose executable/model paths or arbitrary llama.cpp arguments.
- Embedded-AI failure must not terminate or corrupt deterministic analysis. Fallback must be visible as rules-only / AI unavailable; do not silently label fallback as AI-assisted.
- Do not change `docs/v1-acceptance.md` as though embedded AI was part of the frozen V1 candidate.
- Do not merge the implementation PR during this plan.

## Review Focus

1. **Docker-to-host loopback reachability:** prove the actual packaged core can reach a host service bound only to `127.0.0.1`; if it cannot, stop `BLOCKED` rather than bind the AI server to `0.0.0.0` or LAN interfaces. Covered by Preflight P0 and Task 4 tests.
2. **Stale/reused PID and symlink substitution:** a malicious/stale state file or symlinked model/runtime path must never cause Wireclaw to signal/execute an unrelated process/file. Covered by Task 3 launcher tests.
3. **Missing/tampered model/runtime:** hash, manifest, model, runtime, or port failures must produce explicit embedded-AI-unavailable state while deterministic analysis remains usable. Covered by Tasks 3, 5, and 8.
4. **Secret/context leakage:** the per-launch token, raw payload sentinels, paths, cookies/credentials, and bridge secrets must be absent from browser/API output, logs, case data, reports, and reasoning context. Covered by Tasks 1, 5, and 8.
5. **Untrusted model output:** malformed JSON, invented/cross-case evidence IDs, invalid/repeated capabilities, prompt injection, and runtime crashes must not alter authoritative findings or gain execution privileges. Covered by Tasks 1 and 8.

---

## File Structure

### New source/control files

- `ai/embedded-ai.lock.json` — immutable model/runtime source identities and fixed runtime policy used by release engineering.
- `ai/README.md` — explains that large model/runtime artifacts are generated release inputs, not Git-tracked source.
- `scripts/build_embedded_ai.py` — controlled release-engineering build: obtain pinned source snapshot, build llama.cpp Metal runtime, convert/quantize Q4_K_M, stage licenses, emit manifests, and smoke-test staged runtime.
- `scripts/freeze_embedded_ai_candidate.py` — freeze one staged post-V1 candidate and record bundle hash/identity without mutating it.
- `scripts/benchmark_embedded_ai.py` — versioned Gate-9-derived none-vs-embedded benchmark runner/evidence writer.
- `tests/packaging/test_embedded_ai_build.py` — source lock, manifest, provenance, release-builder, no-download-at-runtime contract tests using fixture-sized fake artifacts.
- `tests/acceptance/test_embedded_ai_contract.py` — deterministic safety/adversarial acceptance around embedded provider behavior without requiring a multi-GB model.
- `docs/post-v1-embedded-ai-acceptance.md` — EAI.1-EAI.15 acceptance record.
- `docs/embedded-ai-operations.md` — packaged startup/status/fallback/operator documentation.

### Existing files to modify

- `.gitignore` — exclude local GGUF/runtime build/staging outputs.
- `services/api/src/wireclaw_api/config.py` — add `ProviderMode.EMBEDDED`, validate embedded startup-only configuration.
- `services/api/src/wireclaw_api/reasoning/loop.py` — reuse OpenAI-compatible adapter while preserving local endpoint classification and audit model identity.
- `services/api/src/wireclaw_api/app.py` — expose effective provider/AI status in health/capability response without secrets.
- `services/api/src/wireclaw_api/gate7_service.py` — persist effective provider mode/model/release identity where specified.
- `contracts/investigation-result.schema.json` and generated TS artifacts — extend post-V1 reasoning metadata if needed for model/runtime identity while keeping backward compatibility.
- `contracts/api.openapi.json` and `apps/web/src/generated/api.ts` — regenerate after API contract changes.
- `compose.yaml` — allow launcher-injected embedded provider endpoint/model/token; do not publish an AI port.
- `.env.example` — remain safe for developer/rules-only usage unless explicitly documented otherwise.
- `wireclaw-release/.env.example` — create packaged-release defaults with `WIRECLAW_PROVIDER_MODE=embedded_local` and fixed AI port, but never an API token.
- `launch/macos/common.sh` — add AI manifest/hash/path/PID/process helpers.
- `launch/macos/start.sh` — secure embedded runtime lifecycle, readiness, Docker reachability, env injection, explicit fallback.
- `launch/macos/stop.sh` — stop only the verified Wireclaw-managed AI process in addition to existing bridge/core shutdown.
- `scripts/package_release.py` — stage offline AI assets/manifests/licenses and add `embedded_ai` release metadata.
- `wireclaw-release/README.md`, `docs/deployment.md`, `services/api/README.md` — post-V1 packaged behavior/configuration.
- `tests/unit/test_reasoning.py`, `tests/integration/test_gate7.py` — embedded provider contract/fallback/audit regression.
- `tests/packaging/test_macos_launchers.py`, `tests/packaging/test_release_bundle_contract.py`, `tests/packaging/test_compose_contract.py` — launcher, bundle, and no-port-publication contracts.
- `apps/web/src/api.ts`, `apps/web/src/App.tsx`, `apps/web/src/ReportView.tsx`, associated tests/fixtures — accept/report embedded modes and explicit unavailable fallback without exposing runtime plumbing.
- `README.md`, `docs/roadmap.md` — update development status only after acceptance evidence exists; preserve V1 historical statements.

---

### Preflight P0: Prove loopback-only native AI reachability before implementation

**Supports:** EAI.6

**Files:**
- No product changes.
- Evidence output during implementation: `artifacts/embedded-ai/preflight-loopback.json`.

**Interfaces:**
- Consumes: Docker Desktop on the macOS arm64 reference host.
- Produces: a binary go/no-go result for the approved native-loopback architecture.

- [ ] **Step 1: Start a temporary host HTTP server bound exactly to `127.0.0.1:18767`**

Use a standard-library-only temporary server; record its PID and listener address. Do not bind `0.0.0.0`.

- [ ] **Step 2: Probe the host service from the actual Wireclaw Docker environment using `host.docker.internal:18767`**

Run a disposable container or the Wireclaw core image with the same Docker Desktop networking assumptions as the packaged product.

Expected: HTTP success while host `lsof -nP -iTCP:18767 -sTCP:LISTEN` shows only `127.0.0.1:18767`.

- [ ] **Step 3: Record and gate**

Write `artifacts/embedded-ai/preflight-loopback.json` with host OS/arch, Docker/Compose versions, listener address, request result, and `PASS`/`BLOCKED`.

If the container cannot reach the loopback-only service, **stop the plan immediately as `BLOCKED`**. Do not change the listener to `0.0.0.0`, do not add a LAN listener, and do not implement a different topology without a spec/ADR revision.

---

### Task 1: EAI.1 + EAI.7 — Embedded provider/config contract behind Gate 7

**Files:**
- Modify: `services/api/src/wireclaw_api/config.py`
- Modify: `services/api/src/wireclaw_api/reasoning/loop.py`
- Modify: `tests/unit/test_reasoning.py`
- Modify: `tests/integration/test_gate7.py`

**Interfaces:**
- Produces: `ProviderMode.EMBEDDED = "embedded_local"`; existing `OpenAICompatibleProvider` remains the transport implementation.
- Consumes later: launcher supplies `WIRECLAW_PROVIDER_BASE_URL`, `WIRECLAW_PROVIDER_MODEL`, and ephemeral `WIRECLAW_PROVIDER_API_KEY` when mode is `embedded_local`.

- [ ] **Step 1: Add failing config/provider tests**

Add tests asserting:

```python
assert ProviderMode("embedded_local") is ProviderMode.EMBEDDED
policy = Policy(
    provider_mode="embedded_local",
    provider_base_url="http://host.docker.internal:8767/v1",
    provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
    provider_api_key="x" * 32,
)
assert policy.provider_mode is ProviderMode.EMBEDDED
```

Also assert embedded mode rejects missing model/base URL/token, credentials embedded in URL, query/fragment/path traversal, and unsafe/nonlocal administrator values under the same bounds as local providers.

- [ ] **Step 2: Run targeted tests and verify failure**

Run: `pytest tests/unit/test_reasoning.py tests/integration/test_gate7.py -q`

Expected: FAIL because `embedded_local` is not yet a provider mode.

- [ ] **Step 3: Implement minimal provider/config support**

Add `ProviderMode.EMBEDDED`; keep `make_provider(policy)` using `OpenAICompatibleProvider`; classify `CLOUD` as cloud and both `LOCAL`/`EMBEDDED` as local. Require an API key for `EMBEDDED`, because the launcher always generates one.

- [ ] **Step 4: Add untrusted-output regression tests**

For `ProviderMode.EMBEDDED`, reuse existing fake-provider paths to assert malformed JSON, unsupported/cross-case evidence IDs, duplicate/invalid capability requests, and prompt-injection strings cannot become authoritative findings or gain new capabilities.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_reasoning.py tests/integration/test_gate7.py -q`

Expected: PASS.

Commit: `feat: add embedded local provider mode`

---

### Task 2: EAI.2 + EAI.3 + EAI.4 — Reproducible model/runtime provenance and manifests

**Files:**
- Create: `ai/embedded-ai.lock.json`
- Create: `ai/README.md`
- Create: `scripts/build_embedded_ai.py`
- Create: `tests/packaging/test_embedded_ai_build.py`
- Modify: `.gitignore`

**Interfaces:**
- Produces source lock fields: `model.repository`, `model.revision`, `model.quantization`, `model.id`, `runtime.repository`, `runtime.revision`, `runtime.tag`, `policy.context_size`, `policy.max_tokens`, `policy.parallel`, `policy.port`.
- Produces staged `ai/model-manifest.json` and `ai/runtime-manifest.json` consumed by launcher/package tasks.

- [ ] **Step 1: Write failing lock/manifest tests**

Tests must assert exact immutable values:

```python
assert lock["model"]["repository"] == "Qwen/Qwen3-4B-Instruct-2507"
assert lock["model"]["revision"] == "cdbee75f17c01a7cc42f958dc650907174af0554"
assert lock["model"]["quantization"] == "Q4_K_M"
assert lock["model"]["id"] == "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
assert lock["runtime"]["repository"] == "ggml-org/llama.cpp"
assert lock["runtime"]["tag"] == "v0.6.0"
assert lock["runtime"]["revision"] == "8345f333951c661d166b00e6f9362e553768f292"
assert lock["policy"]["context_size"] == 16384
assert lock["policy"]["max_tokens"] == 2048
assert lock["policy"]["parallel"] == 1
assert lock["policy"]["port"] == 8767
```

Also assert no `.gguf`, built `llama-server`, or AI staging directory is tracked under source paths.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/packaging/test_embedded_ai_build.py -q`

Expected: FAIL because lock/builder/manifests do not exist.

- [ ] **Step 3: Implement source lock and builder interfaces**

Implement focused functions in `scripts/build_embedded_ai.py`:

```python
def load_lock(path: Path) -> dict: ...
def sha256(path: Path) -> str: ...
def build_runtime(lock: dict, work: Path, output: Path) -> dict: ...
def build_model(lock: dict, work: Path, output: Path) -> dict: ...
def validate_staged_ai(ai_root: Path, lock: dict) -> dict: ...
def main() -> int: ...
```

Release-engineering build requirements:
- obtain exact Qwen source revision in the build step, never end-user startup;
- build llama.cpp exact commit for `arm64` with Metal enabled;
- convert the pinned upstream model to GGUF then quantize to `Q4_K_M` using that same pinned llama.cpp toolchain;
- copy required Apache-2.0/runtime license notices;
- write model/runtime manifests with hashes, sizes, source revisions, build settings, and effective policy;
- reject model > 3.5 GiB;
- perform `llama-server` model identity/OpenAI-compatible smoke test using only staged files and with network access unavailable for the smoke phase.

Do not put model/runtime bytes in Git.

- [ ] **Step 4: Use fixture-sized fake artifacts to test fail-closed provenance**

Tests cover wrong revision, wrong SHA, oversized model metadata, missing license, missing runtime resource, wrong model ID, and manifest path traversal.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/packaging/test_embedded_ai_build.py -q`

Expected: PASS without downloading/building the real 4B model.

Commit: `build: add embedded AI provenance pipeline`

---

### Task 3: EAI.5 — Secure macOS AI process lifecycle and fallback

**Files:**
- Modify: `launch/macos/common.sh`
- Modify: `launch/macos/start.sh`
- Modify: `launch/macos/stop.sh`
- Modify: `tests/packaging/test_macos_launchers.py`

**Interfaces:**
- Produces launcher helpers conceptually equivalent to `verify_ai_bundle`, `ai_process_matches`, `start_ai`, `stop_ai`, and `probe_ai_health`.
- Produces runtime state beneath `${HOME}/Library/Application Support/Wireclaw/run/` with user-only permissions.

- [ ] **Step 1: Extend launcher fixture builder and add failing tests**

Create fake `ai/model-manifest.json`, `ai/runtime-manifest.json`, fake GGUF, and fake `ai/macos-arm64/llama-server` in test releases. Add tests for:
- exact hash verification before execution;
- model/runtime symlink escaping release root rejected;
- AI port `8767` validated and distinct from app/bridge ports;
- runtime argv contains fixed host/model/alias/context/max-token/parallel/auth controls and no value sourced from case/browser input;
- runtime binds `127.0.0.1` only;
- per-launch token has >= 256 bits of entropy representation and is not written to `.env`;
- missing/tampered AI assets return an explicit AI-unavailable path rather than deleting/stopping deterministic data;
- stale/reused AI PID is ignored without signaling unrelated process;
- `stop.sh` signals only a verified packaged AI executable and never uses `pkill`/process-name kills;
- repeated start cannot leave duplicate managed AI processes.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/packaging/test_macos_launchers.py -q`

Expected: new embedded-AI launcher tests FAIL.

- [ ] **Step 3: Implement minimal launcher lifecycle**

Keep the AI PID file separate from `bridge.pid`; verify executable identity before signal; use direct argv only. Capture AI stdout/stderr to bounded user-only Wireclaw runtime logs that never include the token; if the selected llama.cpp auth flag itself prints secrets, redirect/filter or choose a safe invocation supported by the pinned runtime and add a regression test.

Embedded AI startup failure sets launcher state to unavailable and continues to deterministic core startup. It must not silently switch a user-selected cloud/custom-local mode.

- [ ] **Step 4: Verify and commit**

Run: `pytest tests/packaging/test_macos_launchers.py -q`

Expected: PASS.

Commit: `feat: manage packaged macOS AI runtime safely`

---

### Task 4: EAI.6 — Wire Docker core to loopback-only native AI

**Files:**
- Modify: `compose.yaml`
- Modify: `wireclaw-release/.env.example` (create if absent)
- Modify: `launch/macos/start.sh`
- Modify: `tests/packaging/test_compose_contract.py`
- Modify: `tests/packaging/test_macos_launchers.py`

**Interfaces:**
- Consumes: successful Preflight P0, AI port `8767`, model alias, per-launch token.
- Produces core env for embedded mode: `WIRECLAW_PROVIDER_MODE=embedded_local`, `WIRECLAW_PROVIDER_BASE_URL=http://host.docker.internal:8767/v1`, fixed model ID, ephemeral key.

- [ ] **Step 1: Add failing Compose/launcher tests**

Assert:
- Compose publishes only the existing application port, never `8767`;
- packaged `.env.example` defaults to `embedded_local` and `WIRECLAW_AI_PORT=8767`, but contains no API key;
- launcher overrides embedded base URL/model/token through process environment, not persisted `.env`;
- launcher verifies container-to-host AI connectivity before declaring `Local embedded AI ready`;
- connectivity failure continues with deterministic core in explicit embedded-unavailable/rules-only status and does not rebind the AI listener.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/packaging/test_compose_contract.py tests/packaging/test_macos_launchers.py -q`

- [ ] **Step 3: Implement environment injection and connectivity check**

Do not add Docker socket access, privileged mode, host networking, or an AI port publication. Preserve existing loopback publication for `8765` and bridge behavior.

- [ ] **Step 4: Run real macOS connectivity smoke**

Start the fixture runtime bound to `127.0.0.1:8767`; prove the core can call its authenticated `/v1/models` or health endpoint through `host.docker.internal`. Record result in `artifacts/embedded-ai/preflight-loopback.json`.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/packaging/test_compose_contract.py tests/packaging/test_macos_launchers.py -q`

Expected: PASS.

Commit: `feat: connect core to embedded loopback AI`

---

### Task 5: EAI.8 — Effective AI status and audit metadata

**Files:**
- Modify: `services/api/src/wireclaw_api/app.py`
- Modify: `services/api/src/wireclaw_api/gate7_service.py`
- Modify: `contracts/api.openapi.json`
- Modify: `contracts/investigation-result.schema.json` only if additional identity fields are needed
- Regenerate: `apps/web/src/generated/api.ts`, `apps/web/src/generated/investigation-result.ts`, validators
- Modify: `tests/integration/test_gate7.py`
- Add/modify relevant API contract tests under `tests/unit/` or `tests/integration/`

**Interfaces:**
- Produces non-secret AI status fields sufficient for UI: effective provider mode, embedded availability (`ready|unavailable|not_applicable`), stable Wireclaw model ID when applicable, and normalized failure code when unavailable.
- Never returns endpoint URL, runtime path, API token, authorization header, or full runtime environment.

- [ ] **Step 1: Add failing API/audit tests**

Test health/capabilities for `embedded_local` ready/unavailable and `none`/custom/cloud modes. Assert serialized JSON does not contain a seeded token, model filesystem path, or authorization header.

Assert AI-assisted report/case audit metadata identifies `embedded_local` + stable model ID; fallback records normalized failure but no secret.

- [ ] **Step 2: Run targeted tests and verify failure**

Run: `pytest tests/integration/test_gate7.py -q`

- [ ] **Step 3: Implement narrow status contract and regenerate generated clients**

Keep health endpoint packet-analysis health independent from model availability: AI unavailable must not turn core health into failure when deterministic service is healthy.

- [ ] **Step 4: Verify schemas/generated artifacts**

Run the repository's existing OpenAPI/schema generation and contract checks; then `pytest tests/integration/test_gate7.py -q`.

Expected: PASS.

- [ ] **Step 5: Commit**

Commit: `feat: expose embedded AI status safely`

---

### Task 6: EAI.9 — Concise UI for embedded-AI state

**Files:**
- Modify: `apps/web/src/api.ts`
- Modify: `apps/web/src/App.tsx`
- Modify: `apps/web/src/ReportView.tsx`
- Modify: `apps/web/src/styles.css` only if needed for existing status-chip styling
- Modify/add: `apps/web/tests/api.test.ts`, component tests, `apps/web/tests/workflow.e2e.ts`

**Interfaces:**
- Consumes Task 5 AI status contract.
- Produces exact user-facing states: `Local embedded AI ready`, `Rules-only mode`, `Local embedded AI unavailable — deterministic analysis remains available`, `Custom local provider`, `Cloud provider`.

- [ ] **Step 1: Add failing API/UI tests**

Remove existing `provider_mode === 'none'` assumptions in `checkCase`/`limits` tests. Add accepted modes and verify unknown modes still cause `contract_mismatch`.

Add rendering tests asserting the five required state labels and that no GGUF path, llama.cpp path, endpoint URL, or token appears.

- [ ] **Step 2: Run web unit tests and verify failure**

Run from `apps/web`: `npm test -- --run`

- [ ] **Step 3: Implement minimal status presentation**

Do not add a model picker or runtime-settings UI. Preserve existing investigation/report layout and Wireshark actions.

- [ ] **Step 4: Run web verification**

From `apps/web` run the repository-standard `npm run lint`, `npm run format:check`, `npm run build`, unit tests, and browser E2E.

Expected: all PASS; existing native bridge UI behavior unchanged.

- [ ] **Step 5: Commit**

Commit: `feat: show embedded AI status in UI`

---

### Task 7: EAI.10 — Offline release packaging and immutable candidate freeze

**Files:**
- Modify: `scripts/package_release.py`
- Create: `scripts/freeze_embedded_ai_candidate.py`
- Modify: `tests/packaging/test_release_bundle_contract.py`
- Modify: `tests/packaging/test_embedded_ai_build.py`
- Modify: `wireclaw-release/README.md`

**Interfaces:**
- Consumes staged output from `scripts/build_embedded_ai.py` via an explicit release-engineering input path; normal startup never downloads/builds.
- Produces release tree `ai/{model-manifest.json,runtime-manifest.json,models/,macos-arm64/,licenses/}` and `release-metadata.json.embedded_ai` identities.

- [ ] **Step 1: Add failing packaging/freeze tests**

Use fixture-sized model/runtime inputs and assert:
- packager refuses missing/tampered manifest/artifact;
- staged bundle contains exact offline AI layout/licenses;
- `release-metadata.json["embedded_ai"]` includes model ID/source revision/Q4_K_M/SHA/size, llama.cpp commit/artifact hashes, manifest hashes, context/output/parallel limits, default provider mode, AI port, platform/arch;
- freeze archive hash is deterministic for identical staged bytes;
- no model/runtime network fetch exists in launcher scripts.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/packaging -q`

- [ ] **Step 3: Extend packager/freeze implementation**

Keep `scripts/package_release.py` clean-tree requirement and existing exact core-image behavior. Treat any model/runtime/config byte change as a new candidate identity.

- [ ] **Step 4: Verify and commit**

Run: `pytest tests/packaging -q`

Expected: PASS.

Commit: `build: package embedded AI offline`

---

### Task 8: EAI.11 — Embedded-AI security, privacy, and adversarial acceptance

**Files:**
- Create: `tests/acceptance/test_embedded_ai_contract.py`
- Modify: `tests/unit/test_reasoning.py`
- Modify: `tests/packaging/test_macos_launchers.py`
- Evidence output: `artifacts/embedded-ai/security-privacy.json`

**Interfaces:**
- Consumes provider/context builder, launcher security helpers, fixture AI server.
- Produces automated acceptance evidence for trust-boundary invariants.

- [ ] **Step 1: Add tests for all automatic security blockers**

Seed unique sentinels for raw capture bytes, payload text, absolute host path, Cookie, Authorization/Bearer value, bridge token, embedded AI token, and analyzer stdout. Inspect exact embedded-provider body, non-auth headers, persisted case/report/audit artifacts, and logs. All forbidden sentinels must be absent; the AI token may appear only in the outbound Authorization header/process environment needed for the Wireclaw-owned provider call and must not be persisted/logged.

Also test prompt injection, invalid/cross-case evidence IDs, invalid/repeated capability requests, symlink/path escape, PID reuse, malicious env values, and runtime argument injection.

- [ ] **Step 2: Run acceptance tests and verify they catch injected violations**

Run: `pytest tests/acceptance/test_embedded_ai_contract.py tests/unit/test_reasoning.py tests/packaging/test_macos_launchers.py -q`

- [ ] **Step 3: Fix only actual contract violations; do not weaken tests/spec**

Any required behavioral fix must remain inside approved boundaries.

- [ ] **Step 4: Emit machine-readable evidence and commit**

Write `artifacts/embedded-ai/security-privacy.json` with test source SHA, result counts, sentinel names/digests (not secrets), and PASS/FAIL.

Commit: `test: harden embedded AI trust boundary`

---

### Task 9: EAI.12 — Versioned embedded-AI benchmark and product-value comparison

**Files:**
- Create: `scripts/benchmark_embedded_ai.py`
- Add fixture/config data under `tests/acceptance/embedded_ai/` as needed; reuse existing Gate 9 captures rather than duplicate large captures.
- Evidence output: `artifacts/embedded-ai/benchmark.json`, `artifacts/embedded-ai/comparison.md`

**Interfaces:**
- Runs each representative case in `none` and `embedded_local` against the same deterministic evidence/candidate.
- Produces machine-readable safety/performance metrics and a human-review comparison.

- [ ] **Step 1: Define benchmark manifest with required scenarios**

Include healthy/clean, DNS delay, retransmission/loss, high RTT, receive-window, reset/reconnect, TLS delay, HTTP server wait, opaque silence, PMTUD, incomplete/one-sided/midstream, conflicting indicators, prompt injection, invented/cross-case evidence, repeated/invalid capability, malformed output, and runtime failure.

- [ ] **Step 2: Add benchmark validation tests**

Assert manifest covers every required scenario, original capture SHA values remain identical before/after, and result schema records model/runtime identities, accepted/rejected model proposals, provider-step latency, startup latency, and memory observations.

- [ ] **Step 3: Implement benchmark runner**

The runner must not declare product success from fluent prose. Automated pass criteria: zero deterministic semantic regressions; zero unsupported authoritative claims; zero invalid/cross-case evidence admitted; zero unauthorized capabilities; ambiguity preserved; provider failures safely fall back; privacy sentinels absent; original hashes unchanged.

- [ ] **Step 4: Run real Qwen benchmark on the frozen staged candidate**

Record cold readiness, peak AI RSS, provider-step latencies, package/model size, and none-vs-embedded outcomes. Targets: model <= 3.5 GiB; additional peak AI RSS <= 8 GiB; cold readiness <= 30 s; median provider step <= 20 s. A target miss requires explicit owner review and is not silently waived.

- [ ] **Step 5: Produce human comparison and commit**

`artifacts/embedded-ai/comparison.md` must assess whether Qwen materially improves hypothesis ranking, explanation, or next-evidence guidance without weakening traceability/uncertainty.

Commit: `test: benchmark embedded Qwen troubleshooting`

---

### Task 10: EAI.13 — Full V1/Gate 9 regression and native Wireshark regression

**Files:**
- No product changes unless a real regression is diagnosed and fixed test-first.
- Evidence output: `artifacts/embedded-ai/regression.json`.

**Interfaces:**
- Consumes current implementation candidate.
- Produces regression evidence; V1 frozen acceptance record remains historical/unchanged.

- [ ] **Step 1: Run pinned deterministic/core suite**

Run the same pinned Docker analyzer/core validation used by Gate 9. Required: no deterministic semantic regression under packaged analyzer versions.

- [ ] **Step 2: Run packaging, API, web, and host-bridge suites**

Run full `pytest` packaging/unit/integration suites in the accepted environments; web lint/format/build/unit/E2E; `go test`, `go vet`, darwin/arm64 bridge build.

- [ ] **Step 3: Verify rules-only with embedded runtime stopped**

Explicitly run representative captures with `WIRECLAW_PROVIDER_MODE=none` and with packaged embedded mode unavailable; deterministic reports and evidence/Wireshark controls remain correct.

- [ ] **Step 4: Re-run native Full Capture and Evidence Capture actions**

At minimum use high RTT plus one other packet-level finding; record original/evidence hashes, filters, and native Wireshark launch success.

- [ ] **Step 5: Write regression evidence and commit only necessary fixes/evidence**

Commit: `test: verify embedded AI regression safety`

---

### Task 11: EAI.14 — Freeze and execute native macOS packaged acceptance

**Files:**
- Evidence output under `artifacts/embedded-ai/macos/`
- Candidate freeze metadata from `scripts/freeze_embedded_ai_candidate.py`

**Interfaces:**
- Consumes one immutable staged package.
- Produces final native acceptance identities/results; after freeze, runtime/model/core/package behavior changes require a new candidate and affected reruns.

- [ ] **Step 1: Freeze candidate and record all identities**

Record source SHA, archive SHA, core image ID/archive SHA, model SHA/size/source revision, runtime commit/artifact hashes, manifest hashes, effective inference limits, Docker/Compose/macOS/Wireshark versions.

- [ ] **Step 2: Run the 16 native acceptance checks from spec section 22**

Required PASS includes: no separately installed LLM runtime; no first-launch network download; auto-start; Metal/native runtime identity; loopback-only Docker reachability; UI `Local embedded AI ready`; representative AI-assisted cases; both native Wireshark actions; safe AI-process-loss fallback; restart recovery; persistence; spaces in paths; port conflict; hash tamper; no LAN listener; privacy/security sentinels.

- [ ] **Step 3: Verify listeners/process ownership explicitly**

Record `lsof`/equivalent evidence showing application, bridge, and AI listeners are loopback-only. Demonstrate unrelated `llama-server`/sleep processes are not signaled by Wireclaw stop.

- [ ] **Step 4: Mark EAI.14 exactly PASS/FAIL/BLOCKED/NOT_RUN**

Do not infer native acceptance from unit/CI evidence.

---

### Task 12: EAI.15 — Acceptance/operations docs, exact-head CI, and draft PR

**Files:**
- Create/finalize: `docs/post-v1-embedded-ai-acceptance.md`
- Create/finalize: `docs/embedded-ai-operations.md`
- Modify: `wireclaw-release/README.md`
- Modify: `docs/deployment.md`
- Modify: `services/api/README.md`
- Modify: `README.md`
- Modify: `docs/roadmap.md`

**Interfaces:**
- Consumes all EAI.1-EAI.14 evidence.
- Produces complete reviewable implementation branch and draft PR; no merge.

- [ ] **Step 1: Write acceptance record with EAI.1-EAI.15 states**

Every task and release criterion is exactly `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`; only PASS satisfies in-scope criteria. Windows/Linux are `NOT_RUN` and explicitly outside scope.

- [ ] **Step 2: Document operator experience**

Document one-command packaged start/stop, embedded-ready state, rules-only fallback, custom local/cloud override, model/runtime identities, data/privacy statement, resource expectations, and troubleshooting. Do not instruct normal users to install Ollama/LM Studio/llama.cpp or download a model.

- [ ] **Step 3: Update README/roadmap only to reflect proven state**

Do not say embedded AI is complete until EAI.14 passes. Do not rewrite V1 historical acceptance claims.

- [ ] **Step 4: Run whole-branch verification at exact head**

Run all relevant CI/local checks again after docs/code are final. Record exact head SHA and CI run IDs in the acceptance record.

- [ ] **Step 5: Request independent whole-branch review**

Review focus: deterministic evidence boundary, launcher/process/path security, token/privacy leakage, packaging reproducibility, native listener exposure, fallback semantics, benchmark validity, and no Windows/Linux overclaim.

- [ ] **Step 6: Create a draft PR; do not merge**

PR body must include candidate identity, EAI.1-EAI.15 table, benchmark summary, privacy/security evidence, resource measurements, native Wireshark regression, exact-head CI, known limitations, and any target misses.

Commit: `docs: complete embedded AI acceptance evidence`

---

## Completion Checklist

Before claiming the plan complete:

- [ ] Preflight P0 PASS; loopback-only native service is reachable from packaged Docker core.
- [ ] EAI.1-EAI.15 each recorded with exact state.
- [ ] Exact Qwen source revision and resulting Q4_K_M SHA/size recorded.
- [ ] Exact llama.cpp v0.6.0 commit/runtime hashes recorded.
- [ ] No runtime/model download during normal launch.
- [ ] No AI LAN listener / Docker AI port publication.
- [ ] Per-launch token never persisted or exposed.
- [ ] Gate 7 context/evidence/capability validation unchanged in authority.
- [ ] Rules-only path independently runnable.
- [ ] Full Gate 9 deterministic semantics preserved.
- [ ] Native Full/Evidence Wireshark actions still pass.
- [ ] Benchmark demonstrates safety and documents whether AI materially adds troubleshooting value.
- [ ] One immutable macOS arm64 candidate completes native acceptance.
- [ ] Windows/Linux remain unqualified and `NOT_RUN`.
- [ ] Draft PR exists; implementation is not merged.
