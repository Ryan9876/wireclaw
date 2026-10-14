# Gate 8 Verification

## Release identity

| Field | Validated value |
|---|---|
| Starting `main` SHA | `9ac42f4130708fd145e46bac7545f980d1d804da` |
| Release source SHA | `9b4e3718893c20a9450a41af0d24b1c87ff79f97` |
| Platform | macOS 27.0.1, Apple M3 Pro, `arm64` |
| Docker | 29.8.2 |
| Compose | 5.6.0 |
| Native Wireshark | 4.6.9 |
| Go builder | go1.26.5 darwin/arm64 |
| Core image ID | `sha256:9d8d93b906cb326e5fb286bf123d41ee97a75daaec041108f3d195a10e93a820` |
| Core archive SHA-256 | `8c5c27003f4e65de5eddd7049d16b7dc2cb5a376893736958151b303a202ea1e` |
| Base image | `ubuntu:24.04@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60` |
| Web builder | `node:24.15.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6` |
| Python | 3.12.3 (`3.12.3-1ubuntu0.17`) |
| TShark / capinfos / editcap / mergecap | 4.2.2 (`wireshark_deb` `4.2.2-1.1build3`) |
| Zeek | Not packaged; no accepted V1 capability invokes it |
| Compiled web asset SHA-256 | `53c041f45fdf89491697653e222b099beb3ab08c0c30946ed4a4209f56b07faa` |
| Packaged bridge SHA-256 | `8cf8a08d1c24350f9d8f1b0542d7e45303a1a17c81cc0ab2b2f46ff93ad1912e` |

The release bundle contains the full build context, `core-image.tar`, its exact
`core-image-id`, and the prebuilt bridge. The staged launcher was tested after
the image tag was removed: it loaded the archive, verified the resulting ID,
and started the release without rebuilding it.

## Gate 8 task matrix

| Task | Result | Evidence |
|---|---|---|
| G8.1 pinned analyzer Docker image | Passed | Immutable image digests and exact package versions above; runtime verifier passed inside the production image. |
| G8.2 web/API Docker packaging | Passed | Compiled React assets, API, analyzer, packet tools, and SQLite run in the single core image. Production image health and static assets passed. |
| G8.3 Compose loopback publication | Passed | Rendered Compose contains only `127.0.0.1:<port>:8765`; packaging tests reject wildcard publication, host networking, privileged mode, Docker socket mounts, and a bridge service. |
| G8.4 persistent host data root | Passed | One bind-mounted root tested at `/private/tmp/Wireclaw Gate8 Data Ω`; SQLite, original capture, report, and evidence survived stop/recreate. |
| G8.5 safe `.env.example` | Passed | Defaults are provider `none`, no credentials, documented ports and local data path. Launcher parser does not source or evaluate it. Injection and invalid-value tests passed. |
| G8.6 macOS start/stop | Passed | Staged launcher loaded the exact image archive, waited for bounded health, started the native bridge, printed localhost URL, and stopped without deleting data. |
| G8.9 macOS bridge install/uninstall | Passed | Packaged bridge installed in a per-user Wireclaw directory, reported healthy with Wireshark available, and uninstalled without touching case data. |
| G8.10 first-run prerequisites | Passed | Launcher tests cover missing Docker CLI, Compose, daemon, busy ports, invalid ports, inaccessible data root, missing bridge, and invalid Wireshark configuration. Failures are actionable and non-destructive. |
| G8.11 real macOS release smoke | Passed across staged Gate 8 candidates | macOS arm64 staged release ingested a fixture and completed deterministic rules-only analysis. Full Capture and Evidence Capture opened in native Wireshark with the approved `tcp.stream == 0` filter. Final archived-image bundle start, bridge health, bridge-degraded UI, restart persistence, stop, and uninstall also passed. |

The Full/Evidence GUI actions were exercised from a staged Gate 8 bundle before
the image-archive handoff was added. The final bundle's bridge was then installed
and health-checked, and its image archive/start path was exercised. Gate 8 did
not change the Go bridge implementation. Repeated smoke attempts had launched
multiple Wireshark processes; only processes whose executable and capture paths
matched the temporary Wireclaw test data were sent `TERM`, and no test process
remained.

## Runtime and privacy checks

- The production image passed `docker/verify_analyzer_versions.py` and reported
  Python 3.12.3 and TShark/capinfos/editcap/mergecap 4.2.2.
- The release core runs as UID/GID 10001 with a read-only root filesystem,
  `no-new-privileges`, all Linux capabilities dropped, bounded PIDs, and a small
  `noexec` temporary filesystem. It has no host networking or Docker socket.
- The Compose service publishes only the application port on IPv4 loopback. The
  only service is `wireclaw-core`; the bridge and Wireshark stay on macOS.
- The Ubuntu CI acceptance harness opts into a temporary `host-gateway` alias
  solely to exercise the documented provider hostname under Linux Docker Engine.
  This override is test-only; the V1 Compose service does not configure a Linux
  host gateway or add a Linux release route.
- Rules-only mode completed intake, quality checks, deterministic analysis,
  reporting, evidence generation, and both action grant paths without provider
  credentials or model connectivity.
- The controlled local provider was reached through
  `host.docker.internal:<port>/v1` from the container.
- The HTTPS cloud privacy regression ran through the container. Its captured
  request omitted raw capture bytes, packet payloads, the absolute case path,
  bridge-token sentinel, and credential sentinel from the JSON body and logs;
  the credential was present only in the Authorization header as configured.
- API Host and Origin rejection checks passed. The case original SHA-256 was
  `72c8be5c65a54ecc74c53f33d7befb088028e5ced759f50d2341e7233904f22c` before
  and after investigation, restart, bridge uninstall, and release stop.
- With the bridge stopped and the core running, the UI recovered the case and
  disabled both Wireshark actions while preserving packet evidence access.

## Verification runs

- Host Python suite: **315 passed, 147 skipped**, one Starlette/httpx
  deprecation warning. The skips are host-tool-dependent cases; real packet-tool
  integration ran inside the pinned image.
- Docker `core-test` stage: **445 passed**, one Starlette/httpx deprecation
  warning, using the pinned TShark 4.2.2 toolchain.
- Web lint, Prettier check, production build, and Vitest: passed; **41 web unit
  tests passed**.
- Production Playwright browser suite: **9 passed**.
- Go bridge: `gofmt`, `go test ./...`, `go vet ./...`, and `go build ./...`
  passed.
- Gate 3 validator: 448 schema-record checks; live loopback API, repeat request,
  evidence capture, bridge grant, and deletion checks passed.
- Packaging tests: **18 passed**, including image-archive loading, stale/missing
  image handling, launcher failures, and preservation of case data on stop and
  uninstall.
- Production container acceptance passed against the exact staged image ID and
  verified it remained unchanged through rules-only, persistence, local-provider,
  and cloud-privacy checks.
- `docker compose config`, shell syntax, Python compileall, Ruff check/format,
  and `git diff --check` passed.

The branch has not yet received a GitHub Actions run. The configured GitHub CLI
credential is invalid in this environment, so push, CI status, and draft PR
creation remain outstanding. Gate 8 is not declared complete until those
handoff steps and a final whole-branch security review are recorded.

## Security review

Codex Security diff scan launch failed before inspecting the branch. Its helper
Python could import neither `tomllib` nor fallback `tomli` while loading the
plugin workbench (`deep_scan_config.py`); no scan result was produced.

Manual review covered the full `main...HEAD` diff and checked the Dockerfile,
Compose configuration, `.env` handling, macOS launch/install/uninstall scripts,
PID ownership checks, port validation, host bridge invocation, provider routes,
data-root mounts, image archive loading, and release staging. The review found
no shell evaluation, arbitrary process-name killing, wildcard host publication,
host networking, privileged mode, Docker socket mount, or unbounded executable
path/argument input. Runtime launch uses direct argv; stop verifies the stored
PID's executable path before signaling it; image archive loading checks the
exact image config ID before Compose starts. Compose remains loopback-only, and
cloud privacy checks passed in the container. The Linux host-gateway alias is
created only by the CI acceptance harness when explicitly enabled; it is absent
from the release Compose file.

## Scope and limitations

- V1 is qualified only for **macOS arm64**. Intel macOS, universal macOS,
  Windows, and Linux are unsupported or unqualified. Windows/Linux work remains
  post-V1 portability groundwork.
- Zeek is intentionally unavailable in the release because no V1 capability
  invokes it.
- Gate 9 was not started.
