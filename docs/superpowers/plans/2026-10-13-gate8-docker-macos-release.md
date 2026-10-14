# Gate 8 Docker and macOS Release Implementation Plan

> **For agentic workers:** Native execution in this session follows the user's explicit implementation request and repository instructions.

**Goal:** Package accepted Gates 0–7 as a reproducible macOS V1 release with one hardened Docker core and a native Wireshark bridge.

**Architecture:** Build a multi-stage core image with compiled React assets, one FastAPI process, deterministic Python analyzer, and pinned packet tools. Distribute a staged release directory with Compose configuration, safe environment defaults, macOS lifecycle scripts, and a prebuilt Go bridge.

**Tech Stack:** Docker/Compose, Python 3.12, Node 24, React/Vite, TShark/capinfos, Go, macOS shell.

**Spec:** `specs/v1/gate8-execution.md`, subordinate to the constitution, requirements, solution, ADR-0005, ADR-0006, and `AGENTS.md`.

## Global Constraints

- One core container; bridge and Wireshark remain native.
- Host publication is only `127.0.0.1`; no host networking, privilege, or Docker socket.
- One persistent host data root maps to `/var/lib/wireclaw`; preserve original captures.
- Provider mode defaults to `none`; provider requests retain Gate 7 minimization.
- macOS only is a V1 support claim; architecture support requires actual release smoke evidence.
- One API process per data root; no multi-worker server.
- Gate 9 is out of scope.

## Review Focus

- Compose interpolation or launcher parsing that broadens host exposure — rendered Compose security assertions.
- Paths with spaces or Unicode crossing Docker and bridge boundaries — staged lifecycle integration.
- Reused/stale PID state causing unrelated process termination — executable identity check tests.
- Analyzer/package drift or missing runtime assets — image version/asset checks and in-image tests.
- Provider packaging leaking capture data or blocking offline use — Gate 7 privacy and rules-only tests in image.

## File Structure

- `Dockerfile`, `docker/analyzer-versions.lock`: reproducible multi-stage core and actual runtime identity.
- `compose.yaml`, `.env.example`: host boundary, persistent mount, safe defaults, healthcheck.
- `services/api/.../web.py`, API/analyzer schema loaders: explicit packaged asset paths with source defaults preserved.
- `launch/macos/*`: prerequisite validation, lifecycle, bridge install/uninstall.
- `scripts/package_release.py` and `wireclaw-release/README.md`: staged, self-contained release bundle.
- `tests/packaging/*`, `tests/integration/*`: config, launcher, image, persistence, provider and data-root behavior.
- `.github/workflows/validation.yml`: keep Gates 0–7 and add Docker/release checks.
- `docs/deployment.md`, `docs/gate8-verification.md`: user procedure and exact evidence, with unmet host acceptance explicitly marked.

## Tasks and evidence mapping

### Task 1 — Runtime assets and dependencies (G8.1/G8.2)

- Audit API/analyzer runtime imports and executable calls; do not add Zeek as a requirement without a current capability.
- Add tests for packaged asset/schema paths, then support explicit runtime paths while retaining checkout defaults.
- Build web assets with pinned Node strategy; install only runtime Python dependencies and tools in a non-root image.
- Verify installed versions against `docker/analyzer-versions.lock` from inside the image.

### Task 2 — Compose and data root (G8.3/G8.4/G8.5)

- Add machine-parsed rendered Compose checks for loopback-only publication, exactly one service, one persistent bind mount, no privileged/host/Docker socket configuration.
- Add safe `.env.example` and rules-only health checks.
- Build/use the core image and test health, Host/Origin rejection, capture ingest, deterministic report/evidence, restart persistence, and unchanged original hash.
- Use a host data path containing spaces (and Unicode when the host permits).

### Task 3 — macOS bridge lifecycle (G8.9/G8.10)

- Test launcher config validation and PID identity behavior before implementation.
- Package a built darwin binary; installer/uninstaller touch only Wireclaw-owned files and preserve case data.
- Test missing Docker/Compose/daemon, port conflicts, inaccessible data root, absent bridge/Wireshark with concise nonzero failures.

### Task 4 — macOS launch/stop and release bundle (G8.6)

- Add bounded start readiness and safe stop; never source `.env` or remove volumes/data.
- Stage release files and the exact verified bridge binary; staged directory must not depend on the source checkout or developer tools.
- Verify staged commands, spaces in paths, no host Python/Node/Go/analyzer invocation, and Compose rendering.

### Task 5 — CI, verification and smoke (G8.11)

- Preserve existing Python, real-tool, Go, web, browser, and generated-contract checks.
- Add core image build/runtime/version/security and release bundle checks.
- Run the real staged macOS smoke including both native Wireshark actions, rules-only, persistence, bridge degradation, and uninstall.
- Record source/image/base/tool/binary identities and each G8 task result in `docs/gate8-verification.md`.
- Run Codex Security diff review when supported, plus manual review of all changed boundaries.

## Exit review

The final verification record will check every criterion in `specs/v1/gate8-execution.md`. A stopped/unavailable Docker daemon or incomplete native smoke remains a documented blocker; generic CI cannot substitute for G8.11.
