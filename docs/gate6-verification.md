# Gate 6 verification record

Date: 2026-10-13  
Branch: `gate6-wireshark-evidence-bridge`  
Validated product commit: `2ad43afa7a88df31215407394c2689ca51eabeee`  
Main/base SHA: `29505bb5069be135292d5d6f30ea398552518d0c`  
Pull request: [#8](https://github.com/Ryan9876/wireclaw/pull/8)  
GitHub Actions: [Gate 6 validation run 38352604990](https://github.com/Ryan9876/wireclaw/actions/runs/38352604990) — success

## Scope and requirements

Gate 6 implements bounded evidence-capture extraction and native Wireshark
integration. It addresses R-F018, R-F019, R-F020, R-D003, R-D004, and R-U003,
while preserving R-S001, R-S003, R-S004, R-S008, R-S009, R-S010, R-N001,
R-N002, R-N005, R-N006, and Constitution C6, C7, C8, C12, C13, and C14.

## G6.1–G6.13 audit disposition

| Task | Implementation and evidence | Result |
| --- | --- | --- |
| G6.1 Evidence extraction service | `services/analyzer/src/wireclaw_analyzer/extraction.py`; API orchestration in `services/api/src/wireclaw_api/gate6_service.py`; parse, bound, and failure tests in `tests/integration/test_gate6.py` | Complete; Python suite and Gate 3 validation passed |
| G6.2 Derived capture provenance | Parent SHA-256, extraction mode/rule, display filter, timestamp, finding IDs, evidence IDs, and tool versions are recorded with the registered artifact | Complete; integration test verifies parent/finding/evidence/filter and unchanged original hash |
| G6.3 Go host bridge protocol | `services/host-bridge/{main.go,bridge.go}`; only health and approved-open routes are registered | Complete; Go tests, vet, build passed on Linux, macOS, and Windows runners |
| G6.4 Loopback, auth, origin, bounded requests, replay resistance | Numeric loopback validation; approved origins required; strict JSON/body limits; short-lived one-use grants with hashed token material and constant-time comparison | Complete; bridge security tests passed on all three runners |
| G6.5 Logical IDs and path confinement | API grants resolve case/finding/artifact logical IDs; bridge confines resolved files under the case directory and rejects traversal, symlink escape, unknown IDs, cross-case substitution, and hash mismatch | Complete; API and bridge isolation tests passed |
| G6.6 Wireshark executable selection | Admin configuration or OS-specific discovery; canonical executable path; request schema cannot select executable | Complete; discovery and exact argv tests passed on all three runners |
| G6.7 macOS behavior | macOS application executable discovery; direct native process argument vector | Complete for discovery/selection/argv validation on `macos-14`; GUI launch requires manual acceptance |
| G6.8 Windows behavior | Program Files discovery; direct process argument vector, including paths with spaces | Complete for discovery/selection/argv validation on `windows-2025`; GUI launch requires manual acceptance |
| G6.9 Linux behavior | Administrator PATH and standard-location discovery; direct process argument vector | Complete for discovery/selection/argv validation on `ubuntu-24.04`; GUI launch requires manual acceptance |
| G6.10 Full Capture action | Visible action requests the backend-approved immutable original artifact with the finding's approved display filter | Complete; browser workflow and bridge-grant tests passed |
| G6.11 Evidence Capture action | Visible beside Full Capture; API creates a bounded derived artifact and approves its logical ID before native open | Complete; browser and integration tests passed |
| G6.12 Copy filter and packet evidence | Copy action uses the finding's approved filter; Show Packet Evidence uses persisted evidence; both remain usable when bridge health is unavailable | Complete; production-browser test verifies unavailable state, clipboard, evidence drawer, and evidence generation |
| G6.13 Bridge security tests | Tests cover traversal, symlink, case/artifact isolation, altered hash, control filters, unknown fields, oversized body, origin, bad/expired/replayed grant, loopback bind, exact argv, path spaces, discovery, and absence of generic execution | Complete; all Go test jobs passed on three OS families |

## Evidence-capture behavior

Extraction uses the API-generated finding filter, never a browser-authored
filter. Supported extraction modes include TCP stream, DNS transaction set,
explicit frame set, and a bounded frame range when the explicit list exceeds
the filter bound. TShark runs without a shell under configured time, output,
and artifact-size bounds. The generated capture is parsed with capinfos, its
hash and byte count are recorded, and the original hash is checked before and
after extraction. Failed/over-limit extraction removes the unregistered output;
case data, original capture, and previous findings remain intact.

Provenance binds the derived artifact to the case, immutable parent SHA-256,
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

The API rejects caller-supplied path, display-filter, executable, and argument
fields. Bridge tests verify unknown fields, malformed/oversized requests,
unapproved origins, bad/expired/replayed grants, cross-case substitution,
arbitrary executable/argument injection, control-character and over-limit
filters, exact argv, paths containing spaces, and no generic execution route.
The report remains usable if bridge health is unavailable; both native actions
show an unavailable/disabled state while copy-filter, packet evidence, and
backend evidence generation remain available.

## Validation results

### Local validation

- Python: `python -m pytest -q` — **408 passed, 1 deprecation warning**, with
  real TShark and capinfos installed; tests did not silently skip the real-tool
  checks.
- `ruff check .` — passed.
- `ruff format --check services scripts tests` — passed; 50 files already
  formatted.
- `python -m compileall -q services scripts tests` — passed.
- `python scripts/validate_gate3.py` — passed: 447 schema record checks,
  evidence counts `[5, 11]`, live loopback API, repeat request, evidence
  capture, bridge grant, and deletion.
- Go 1.23.12 on Linux: `gofmt` check, `go test ./...` (11 top-level tests plus
  subtests), `go vet ./...`, and `go build ./...` — passed.
- Web: `npm ci --prefix apps/web`, lint, format check, production build, and
  `npm test --prefix apps/web` — passed; **38 unit tests passed**.
- Production browser: GitHub Actions ran the production build and Chromium
  suite with Playwright `retries: 0`; **9 cases passed** (six workflow tests
  plus three viewport variants).

### GitHub Actions

Workflow run [38352604990](https://github.com/Ryan9876/wireclaw/actions/runs/38352604990)
completed successfully. The `linux-full` job passed contract regeneration
check, Python validation, Go validation, web validation, and production browser
validation. The `bridge-platform` job passed `go test ./...`, `go vet ./...`,
and `go build ./...` on `ubuntu-24.04`, `macos-14`, and `windows-2025`.

The OS matrix validates compilation, platform-specific executable discovery,
logical request handling, and deterministic argv construction. It does not
claim that a native Wireshark GUI was opened in CI.

## Manual acceptance still required

Before release, run the following on a desktop with Wireshark installed on
macOS, Windows, and Linux:

1. Start Wireclaw and its host bridge; investigate a fixture with an applicable
   packet-level finding.
2. Confirm **Open Full Capture in Wireshark** and **Open Evidence Capture in
   Wireshark** appear together. Open each and verify the expected original or
   derived capture and approved filter.
3. Repeat with the Wireclaw data directory and capture filenames containing
   spaces. Confirm the native application receives a single path argument
   without shell interpretation.
4. Stop the bridge and confirm both open actions visibly report unavailable,
   while **Copy Wireshark Display Filter**, **Show Packet Evidence**, and
   evidence-capture generation still work.

## Not tested / limitations

- A real native GUI launch was not automated or observed on any OS; the manual
  procedure above remains necessary to demonstrate desktop-session behavior.
- User-specific Wireshark installation layouts outside the supported discovery
  candidates and administrator-configured executable path were not tested.
- No Gate 7 provider/model behavior, Gate 8 packaging, or Gate 9 release
  acceptance was implemented or validated.

Gate 7 and later tasks remain unchecked and untouched.
