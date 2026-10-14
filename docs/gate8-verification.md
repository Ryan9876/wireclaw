# Gate 8 Verification

Status: **Complete for V1; merged and closed via PR #11.**

## Release identity

| Field | Validated value |
|---|---|
| Starting `main` SHA | `9ac42f4130708fd145e46bac7545f980d1d804da` |
| Gate 8 code HEAD used for final staging | `63acfe21bed2ba07c4615f5df6dfa98116857e8d` |
| Final validated PR head | `78b78ca5c375c24daa6ee8929a7b195a8b161618` |
| Gate 8 merge commit | `3b8f19a53612caac515be71ce347082cf5bb91d4` |
| Fresh release source SHA | `63acfe21bed2ba07c4615f5df6dfa98116857e8d` |
| Platform | macOS 27.0.1, Apple M3 Pro, `arm64` |
| Docker | 29.8.2 |
| Compose | 5.6.0 |
| Native Wireshark | 4.6.9 |
| Go builder | go1.26.5 darwin/arm64 |
| Core image ID | `sha256:eee9d9478e839cf64f50ee450f7737c2f47084a20d8c1533fa52de5d12c813e8` |
| Core archive SHA-256 | `1f75c0d0b9a44bef35d721c70c0ff923021a0764eedf286c6d2ff74c1315eab2` |
| Base image | `ubuntu:24.04@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60` |
| Web builder | `node:24.15.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6` |
| Python | 3.12.3 (`3.12.3-1ubuntu0.17`) |
| TShark / capinfos / editcap / mergecap | 4.2.2 (`wireshark_deb` `4.2.2-1.1build3`) |
| Zeek | Not packaged; no accepted V1 capability invokes it |
| Compiled web asset SHA-256 | `53c041f45fdf89491697653e222b099beb3ab08c0c30946ed4a4209f56b07faa` |
| Packaged bridge SHA-256 | `8c9c6391450e46141a8b7c02418d988b72f0d0a1685d13ba8ddb1d7fca209110` |

The fresh bundle at `/private/tmp/Wireclaw Final Gate 8 Release/wireclaw-release`
contains the full build context, `core-image.tar`, its exact `core-image-id`,
and the prebuilt bridge. Immediately before its first launch, the local
`wireclaw-core:gate8` tag was removed. The packaged launcher loaded the archive,
verified the exact image ID above, and started the release without rebuilding.

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
| G8.11 real macOS release smoke | Passed from the same fresh archive-loaded candidate | The complete case workflow, both native Wireshark actions, bridge degradation, restart/persistence, stop, and uninstall were exercised from the single bundle identified above. |

## Final archive-loaded macOS release acceptance

The staged release used macOS 27.0.1 on Apple M3 Pro (`arm64`), Docker 29.8.2,
Compose 5.6.0, and native Wireshark 4.6.9. Its data root was
`/private/tmp/Wireclaw Final Gate 8 Data Ω`, which contains both spaces and
Unicode. The release ran with the packaged image and bridge identities listed
above, in `provider_mode=none`.

The UI ingested the known `high_rtt.pcap` fixture and completed deterministic
analysis. Case `d70d56b2251642d2979ea5751026e6f0` remained `COMPLETE`, with
original artifact `88a0d80175a54ff58099a5eeb8897afd`. Finding `finding_001`
(`tcp.rtt`, “High transport RTT observed”) used the backend-approved filter
`tcp.stream == 0`. The two Wireshark actions were visible together; copying the
filter returned the same value, and Show Packet Evidence opened the evidence
drawer.

From this exact archive-loaded release and finding:

- **Full Capture passed.** Native Wireshark showed a `capture` window. Its
  process arguments named this case's immutable
  `.../analyzer/cases/72c8be5c65a54ecc74c53f33d7befb088028e5ced759f50d2341e7233904f22c/original/capture`
  and included `-Y tcp.stream == 0`.
- **Evidence Capture passed.** A separate native Wireshark window showed
  `bf8bf06e6bdb41dcba02d4d5ff0b701f.pcapng` under this case's `evidence`
  directory, with `-Y tcp.stream == 0` in its process arguments. Its registered
  artifact ID is `02cbacb731974d4db20bdf5341fc49d8`; SHA-256 is
  `57d3283c32204a84e9ea212581b09907cbcb512b603238f45230ee9e5cedb7a9`, size is
  600 bytes, and packaged `capinfos` reports five packets. Its provenance names
  the parent SHA, case, finding, cited evidence ID, `tcp_stream` extraction
  mode, and the same display filter.

The fixture source SHA, stored original SHA before and after both opens, and
stored SHA after restart/stop/uninstall all matched:
`72c8be5c65a54ecc74c53f33d7befb088028e5ced759f50d2341e7233904f22c`.
After the packaged stop/start sequence, the API returned the same complete
case/report/evidence, and a read-only SQLite check after final stop/uninstall
still found the case and all registered artifacts. The original, report, and
derived evidence files remained on disk with their expected hashes.

With only the bridge stopped, the same case/report stayed visible, both
Wireshark buttons remained visible but disabled, and Show Packet Evidence still
worked. The packaged launcher restarted the bridge and core. The final
packaged stop and bridge uninstall both reported success and preserved case
data.

Process hygiene: no Wireshark processes were present before this acceptance.
The final GUI check held its test session open and observed exactly two
Wireclaw test-capture processes/windows, one for each action. After confirming
their executable paths, case paths, and filter arguments, each exact test
window was closed through its own native close button. No broad process-name
kill was used. The launcher test session and its temporary browser session were
then stopped; the Wireclaw container and bridge were already stopped/uninstalled.

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

GitHub Actions run [#87](https://github.com/Ryan9876/wireclaw/actions/runs/38506208791)
passed on code HEAD `63acfe21bed2ba07c4615f5df6dfa98116857e8d`, which is the
source SHA in the fresh release metadata above. The Docker release job built
and exercised the production image, verified the locked tool versions, and ran
container acceptance. Linux full validation, production browser validation,
and Ubuntu/macOS/Windows Go portability builds also passed. The bridge
portability jobs do not qualify those platforms as V1 releases.

GitHub Actions run [#89](https://github.com/Ryan9876/wireclaw/actions/runs/38508170175)
passed on the exact final PR head `78b78ca5c375c24daa6ee8929a7b195a8b161618`, including the Docker release, Linux full validation, and all bridge-platform jobs. PR #11 then merged that validated head into `main` as `3b8f19a53612caac515be71ce347082cf5bb91d4`.

The CI launcher tests initially failed because the Linux runner had Docker in
`/usr/bin`, contrary to the test's assumption. The test was corrected to use
an isolated PATH and passed in run #85.

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
