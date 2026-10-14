# ADR-0007: Bundle Embedded Local AI as a Native macOS Runtime

Status: **Proposed for post-V1 embedded-AI stage**

Date: 2026-10-14

## Context

Wireclaw V1 supports optional OpenAI-compatible local/cloud reasoning, but the accepted release does not include a model runtime or model weights. A user must currently supply and configure an external provider to use model-assisted reasoning.

The next product goal is different: the local model should feel like part of Wireclaw itself. A user should be able to launch the packaged application and immediately receive AI-assisted troubleshooting without separately installing Ollama, LM Studio, llama.cpp, a model, an API key, or a provider endpoint.

The chosen model is Qwen3-4B-Instruct-2507 in Q4_K_M GGUF form. Wireclaw must preserve its existing product boundaries:

- deterministic tools establish packet facts;
- the model receives normalized evidence only by default;
- model output is validated and cannot become packet evidence by assertion;
- rules-only analysis remains available;
- application/model services must not become LAN-accessible by default;
- Windows/Linux remain future qualification targets.

Three runtime approaches were considered.

## Option 1: Inference inside a Docker container

Bundle llama.cpp and the GGUF in a second Docker service.

Advantages:

- simple topology and lifecycle;
- straightforward future Linux/Windows container reuse;
- no new native process manager.

Disadvantages:

- macOS container inference does not provide the same direct native Metal path as a host process;
- performance on Apple Silicon would be materially less representative of the hardware Wireclaw already requires for the supported release;
- model/runtime image size and Docker resource behavior become coupled to the deterministic core release workflow.

## Option 2: Packaged native llama.cpp runtime managed by Wireclaw

Bundle a pinned macOS arm64 `llama-server` runtime and pinned Q4_K_M GGUF in the Wireclaw release. The existing launcher verifies and starts the runtime locally; the Docker core reaches it through the supported Docker Desktop host path.

Advantages:

- no external LLM installation/configuration for the user;
- native Apple Silicon/Metal acceleration;
- model/runtime can be versioned independently from the deterministic Docker image while still being one Wireclaw release artifact;
- existing Gate 7 OpenAI-compatible provider interface can be reused;
- rules-only/core isolation remains clear;
- future Windows/Linux runtimes can occupy platform-specific sibling directories behind the same provider/process contract.

Disadvantages:

- adds a second native process lifecycle alongside the host bridge;
- release packaging grows by several gigabytes;
- release engineering must own model provenance, quantization, licenses, hashes, and native runtime dependencies;
- Docker-to-host loopback connectivity must be explicitly qualified without weakening loopback-only exposure.

## Option 3: Docker Model Runner

Use Docker's model runtime/Compose integration.

Advantages:

- clean integration with Docker and model endpoints;
- hardware-accelerated backends may be available;
- less Wireclaw-specific native runtime management.

Disadvantages:

- makes the product depend on an additional Docker feature/version/configuration beyond the existing release prerequisites;
- the user experience can vary with Docker Desktop feature availability/settings;
- weaker control over the exact runtime lifecycle and release artifact set than bundling a pinned Wireclaw-owned runtime;
- conflicts with the requirement that the model work immediately as an intrinsic application component without extra feature enablement.

## Decision

Use **Option 2**.

Wireclaw will ship:

- a pinned native macOS arm64 llama.cpp server runtime;
- a pinned Qwen3-4B-Instruct-2507 Q4_K_M GGUF;
- immutable model/runtime manifests and license notices;
- launcher logic that verifies hashes, starts/stops only the Wireclaw-managed runtime, generates per-launch authentication, and configures the Docker core to use it as `embedded_local`.

The native runtime must bind to numeric loopback only. The Docker core must reach it using the approved Docker Desktop host path while the listener remains loopback-only. If that cannot be qualified on the supported environment, the embedded-AI release stage is BLOCKED rather than broadening the listener to `0.0.0.0` or a LAN interface.

The runtime is not an analyzer and receives no new privileges. It remains behind the Gate 7 normalized-context, typed-capability, evidence-reference, response-bound, and deterministic-fallback boundary.

## Consequences

### Positive

- local AI behaves as an integrated Wireclaw capability;
- end users do not install/configure an LLM stack;
- Apple Silicon acceleration is available to the supported release;
- model/provider safety logic stays in the existing API/orchestrator boundary;
- model failure can be isolated from deterministic analysis;
- a future Windows/Linux runtime can implement the same manifest/process/provider contract.

### Negative

- Wireclaw release bundles become several gigabytes larger;
- release engineering must maintain reproducible model conversion/quantization and native runtime builds;
- native runtime security/process lifecycle becomes part of Wireclaw's attack surface and acceptance burden;
- macOS native acceptance must validate model/runtime hashes, loopback exposure, Docker host connectivity, failure recovery, and resource behavior.

## Guardrails

- Do not commit the GGUF to normal Git history.
- Do not download model/runtime assets during normal end-user startup.
- Do not expose llama.cpp agent/tool/file capabilities.
- Do not let browser/capture/model input control executable path, model path, runtime flags, endpoint, or token.
- Do not persist the per-launch AI authentication secret.
- Do not weaken Gate 7 evidence/uncertainty validation because inference is local.
- Do not modify the frozen V1 acceptance record to imply embedded AI was part of V1.

The authoritative implementation contract is `specs/post-v1/embedded-local-ai.md`.
