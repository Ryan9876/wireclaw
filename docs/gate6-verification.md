# Gate 6 verification record

Date: 2026-10-13

Branch: `gate6-wireshark-evidence-bridge`

Last CI-validated handoff SHA: `965033512afe5d130090b01980fd6b70a7397012`

Main/base SHA: `29505bb5069be135292d5d6f30ea398552518d0c`

Pull request: [#8](https://github.com/Ryan9876/wireclaw/pull/8) (open, targets `main`)
GitHub Actions: [Gate 6 validation run 38417675722](https://github.com/Ryan9876/wireclaw/actions/runs/38417675722) — all jobs passed on the handoff SHA

Gate 6 implementation and automated proof are recorded separately from native
desktop acceptance. macOS native acceptance is now recorded below. The Gate 6
exit criteria are **not fully demonstrated** until manual Wireshark GUI
acceptance is recorded on Windows and Linux as well.

## Scope and requirements

Gate 6 implements bounded evidence-capture extraction and native Wireshark
integration. It addresses R-F018, R-F019, R-F020, R-D003, R-D004, and R-U003,
while preserving R-S001, R-S003, R-S004, R-S008, R-S009, R-S010, R-N001,
R-N002, R-N005, R-N006, and Constitution C6, C7, C8, C12, C13, and C14.

## G6.1–G6.13 audit disposition

| Task | Implementation and evidence | Result |
| --- | --- | --- |
| G6.1 Evidence extraction service | `services/analyzer/src/wireclaw_analyzer/extraction.py`; API orchestration in `services/api/src/wireclaw_api/gate6_service.py`; parse, bound, and failure tests in `tests/integration/test_gate6.py` | Complete; Python suite and Gate 3 validation passed |
| G6.2 Derived capture provenance | Parent SHA-256, extraction mode/rule, display filter, timestamp, finding IDs, evidence IDs, and tool versions are recorded with the registered artifact; repeat requests reuse only integrity-verified matching artifacts | Complete; integration tests verify parent/finding/evidence/filter, unchanged original hash, valid reuse, and rejection of corrupted provenance |
| G6.3 Go host bridge protocol | `services/host-bridge/{main.go,bridge.go}`; only health and approved-open routes are registered | Complete; Go tests, vet, build passed on Linux, macOS, and Windows runners |
| G6.4 Loopback, auth, origin, bounded requests, replay resistance | Numeric loopback validation; strict administrator-configured Wireclaw UI port allowlist (`--app-port`); strict JSON/body limits; short-lived one-use grants with hashed token material and constant-time comparison | Complete; live origin-handler and bridge security tests passed on all three runners |
| G6.5 Logical IDs and path confinement | API grants resolve case/finding/artifact logical IDs; bridge confines resolved files under the case directory and rejects traversal, symlink escape, unknown IDs, cross-case substitution, and hash mismatch | Complete; API and bridge isolation tests passed |
| G6.6 Wireshark executable selection | Admin configuration or OS-specific discovery; canonical executable path; request schema cannot select executable | Complete; discovery and exact argv tests passed on all three runners |
| G6.7 macOS behavior | macOS application executable discovery; direct native process argument vector | Complete; discovery/selection/argv validated in `macos-14` CI and native GUI accepted locally on macOS 27.0.1 arm64 |
| G6.8 Windows behavior | Program Files discovery; direct process argument vector, including paths with spaces | Complete for discovery/selection/argv validation on `windows-2025`; GUI launch requires manual acceptance |
| G6.9 Linux behavior | Administrator PATH and standard-location discovery; direct process argument vector | Complete for discovery/selection/argv validation on `ubuntu-24.04`; GUI launch requires manual acceptance |
| G6.10 Full Capture action | Visible action requests the backend-approved immutable original artifact with a finding-specific approved display filter (TCP stream or exact DNS transaction frames where available) | Complete; unit, API, and browser tests passed |
| G6.11 Evidence Capture action | Visible beside Full Capture; API creates or integrity-validates/reuses a bounded derived artifact and approves its logical ID before native open | Complete; browser and integration tests passed |
| G6.12 Copy filter and packet evidence | Copy action uses the finding's approved filter; Show Packet Evidence uses persisted evidence; both remain usable when bridge health is unavailable. UI health distinguishes ready, bridge offline, Wireshark missing, and API offline | Complete; unit and production-browser tests verify unavailable state, clipboard, evidence drawer, evidence generation, and action-failure isolation |
| G6.13 Bridge security tests | Tests cover traversal, symlink, case/artifact isolation, altered hash, control filters, unknown fields, oversized body, origin, bad/expired/replayed grant, loopback bind, exact argv, path spaces, discovery, child reaping, configurable app origin, and absence of generic execution | Complete; all Go test jobs passed on three OS families |

## Evidence-capture behavior

Extraction uses the API-generated finding filter, never a browser-authored
filter. Supported extraction modes include TCP stream, DNS transaction set,
explicit frame set, and a bounded frame range when the explicit list exceeds
the filter bound. TShark runs without a shell under configured time, output,
and artifact-size bounds. The generated capture is parsed with capinfos, its
hash and byte count are recorded, and the original hash is checked before and
after extraction. Failed/over-limit extraction removes the unregistered output;
case data, original capture, and previous findings remain intact.

Repeated requests for the same finding reuse an existing artifact only after
the registered derived bytes and paired provenance match the current parent,
finding, related finding/evidence IDs, extraction mode, and approved filter.
Invalid candidates are not reused. Provenance binds the derived artifact to the case, immutable parent SHA-256,
finding, related finding IDs, evidence IDs, extraction rule, display filter,
creation time, and tool versions. Integration tests verify the original SHA
does not change, the derived capture parses, the configured bound is enforced,
and provenance identifies its parent and finding/evidence.

## Bridge protocol and trust boundary

The browser supplies only logical case/finding/artifact IDs to the API and
logical request ID plus one-time token to the bridge. The API verifies the
finding and case-scoped registered artifact, then writes a short-lived grant
manifest containing the token hash. Deleting a case removes its outstanding
grants. The bridge binds only to a numeric loopback address, requires an
approved Wireclaw Origin for health/open requests, parses bounded strict JSON,
consumes grants once, confines canonical paths beneath the case data root,
rejects symlink/path escapes, and verifies artifact kind, size, and SHA-256.
It launches only the canonical configured/discovered Wireshark executable
using direct argv and never invokes a shell. No generic command endpoint exists.
The process launcher starts the native application and reaps its child
asynchronously so the HTTP request does not block on the GUI lifetime. The
approved UI port is configured separately from the bridge's loopback listen
port. The UI reports bridge-offline, Wireshark-not-installed, API-offline, and
ready states separately; evidence-generation errors do not change bridge health.

The API rejects caller-supplied path, display-filter, executable, and argument
fields. Bridge tests verify unknown fields, malformed/oversized requests,
unapproved origins, bad/expired/replayed grants, cross-case substitution,
arbitrary executable/argument injection, control-character and over-limit
filters, exact argv, paths containing spaces, and no generic execution route.
The report remains usable if bridge health is unavailable; both native actions
show an unavailable/disabled state while copy-filter, packet evidence, and
backend evidence generation remain available.

## Validation results

### Automated validation

The following baseline ran in the Ubuntu 24.04 `linux-full` job of [workflow
run 38417675722](https://github.com/Ryan9876/wireclaw/actions/runs/38417675722)
on the handoff SHA:

- Packet tools: `command -v tshark` and `command -v capinfos` both succeeded;
  real-tool checks did not silently skip.
- Python: `python -m pytest -q` — **409 passed, 1 deprecation warning** in
  122.14 seconds.
- `ruff check .` — passed; `ruff format --check services scripts tests` —
  passed, 50 files already formatted.
- `python -m compileall -q services scripts tests` — passed.
- `python scripts/validate_gate3.py` — passed: 447 schema record checks,
  evidence counts `[5, 11]`, live loopback API, repeat request, evidence
  capture, bridge grant, and deletion.
- Go 1.23.12 Linux: gofmt check, `go test ./...` (13 test functions, including
  six table-driven cases), `go vet ./...`, and `go build ./...` — passed.
- Web: `npm ci --prefix apps/web`, lint, format check, production build, and
  `npm test --prefix apps/web` — passed; **40 unit tests passed** on the handoff SHA.
- Production browser: fixture preparation, Chromium installation, and
  `npm run test:e2e --prefix apps/web` with Playwright retries disabled —
  **9 cases passed** (six workflow tests plus three viewport variants).

The same workflow's `bridge-platform` jobs passed `go test ./...`,
`go vet ./...`, and `go build ./...` on `ubuntu-24.04`, `macos-14`, and
`windows-2025`.

The OS matrix validates compilation, platform-specific executable discovery,
logical request handling, and deterministic argv construction. It does not
claim that a native Wireshark GUI was opened in CI.

### Handoff continuation on macOS

On 2026-10-13, the Gate 6 checks were repeated on this macOS ARM64 workstation.
The `api_unavailable` report state was found to offer an impossible “Create
evidence capture without opening Wireshark” action. That action is now hidden
in this state; a focused UI regression test confirms Copy Filter and Show
Packet Evidence remain available.

- Python full suite with real TShark/capinfos 4.6.9: **404 passed, 5 failed,
  1 warning**. The 5 failures were environment/version-sensitive tests outside
  Gate 6: the subprocess pipe-bound test exceeded its 50 ms timeout while
  starting a child, and four Gate 2/4 expectations differed in TShark 4.6.9's
  TCP expert classification for reordered/PMTUD fixtures. Gate 6 integration
  tests passed separately: **5 passed, 1 deprecation warning**.
- `ruff check .`, `ruff format --check services scripts tests`,
  `python -m compileall -q services scripts tests`, and Gate 3 validation —
  passed. Gate 3 reported 447 schema checks, evidence counts `[5, 11]`, and
  successful live loopback API, repeat request, evidence capture, bridge grant,
  and deletion checks.
- Go format, `go test ./...`, `go vet ./...`, and `go build ./...` — passed on
  macOS ARM64 with Go 1.26.5.
- Web lint, Prettier, production build, and unit tests — passed; **41 unit
  tests passed**, including the new API-unavailable regression.
- Production Playwright browser suite — **9 passed** with retries disabled.
- OpenAPI and generated web contracts matched the checked-in files.

The local Python suite's five failures do not occur in the latest Linux CI
baseline. They should be rechecked with the CI TShark version if investigating
those pre-existing cross-version expectations.

### Native desktop acceptance matrix

| Platform | Full | Evidence | Filter | Spaces | Degraded | Result |
| --- | --- | --- | --- | --- | --- | --- |
| macOS 27.0.1 arm64, Wireshark 4.6.9 | Pass | Pass | Pass | Pass | Pass | **Accepted** |
| Windows | Pending manual acceptance | Pending manual acceptance | Pending manual acceptance | Pending manual acceptance | Pending manual acceptance | **PENDING MANUAL ACCEPTANCE** |
| Linux | Pending manual acceptance | Pending manual acceptance | Pending manual acceptance | Pending manual acceptance | Pending manual acceptance | **PENDING MANUAL ACCEPTANCE** |

macOS acceptance record:

```text
OS/version: macOS 27.0.1
Architecture: arm64
Wireshark version: 4.6.9
Wireclaw SHA: 965033512afe5d130090b01980fd6b70a7397012 plus the local UI regression change
Fixture: high_rtt.pcap, uploaded as "trace with spaces.pcap"
Finding ID/category: finding_001 / tcp.rtt
Display filter: tcp.stream == 0
Original SHA before/after: 72c8be5c65a54ecc74c53f33d7befb088028e5ced759f50d2341e7233904f22c (unchanged)
Full Capture result: native Wireshark window opened with the immutable original path and -Y tcp.stream == 0
Evidence Capture result: native Wireshark window opened with the derived PCAPNG path and -Y tcp.stream == 0
Evidence provenance: parent SHA, finding_001, evidence ID, tcp_stream mode, and filter recorded; 5 packets / 584 bytes
Path-with-spaces result: passed; both data root and uploaded filename contained spaces
Degraded-state result: with bridge stopped, API healthy, both Wireshark actions disabled; local evidence generation, packet evidence, and Copy Filter passed
GUI inspection: macOS accessibility returned the Wireshark window title; process argv confirmed original/evidence paths and filter. Screenshot capture was unavailable in this session.
```

## Manual acceptance still required

Before release, run the following on Windows and Linux desktops with Wireshark
installed (macOS is recorded above):

1. Install Python 3.11+, Go, Node.js, and Wireshark with `tshark`/`capinfos`;
   from the repository root run `python -m pip install -e '.[api]'`,
   `npm ci --prefix apps/web`, `npm run build --prefix apps/web`, and
   `python scripts/prepare_web_fixtures.py`.
2. Start the API in one terminal, then the bridge from `services/host-bridge`
   in a second terminal. Use the same data root and an administrator-approved
   Wireshark executable:

   ```sh
   python -m wireclaw_api.cli --data-root "<data root>" --port 8765
   go run . --data-root "<same data root>" --listen 127.0.0.1:8766 --app-port 8765 --wireshark "<approved Wireshark executable>"
   ```

3. Open `http://127.0.0.1:8765`, upload
   `artifacts/web-captures/high_rtt.pcap` under a filename containing spaces,
   and investigate `application is slow`. Record OS/architecture, Wireshark
   version, Wireclaw SHA, finding ID/category, filter, and original SHA-256.
4. Open both capture actions. Inspect the original and derived capture contents,
   filter, evidence provenance, and process argv; verify the original SHA-256
   is unchanged. Repeat with a data-root directory containing spaces.
5. Stop the bridge while leaving the API running. Confirm both open actions are
   disabled and Copy Filter, Show Packet Evidence, and evidence generation
   remain usable. Record each matrix cell and result.

## Not tested / limitations

- Native GUI acceptance remains pending on Windows and Linux. The macOS
  acceptance used a real Wireshark 4.6.9 process and active application window;
  OS-level screenshot capture was unavailable in this session.
- User-specific Wireshark installation layouts outside the supported discovery
  candidates and administrator-configured executable path were not tested.
- No Gate 7 provider/model behavior, Gate 8 packaging, or Gate 9 release
  acceptance was implemented or validated.

Gate 7 and later tasks remain unchecked and untouched.
