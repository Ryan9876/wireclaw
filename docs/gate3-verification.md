# Gate 3 verification — local API and case model

Date: 2026-10-08 UTC. Branch: `gate3-local-api-case-model`.
Base: approved Gate 2 merge `059d6b27e8518571d7dbe229d524773d58234e8a`.
Scope: G3.1–G3.11, R-F002/R-F022–R-F026, R-S001–R-S010.

## Authority and Gate 2 closeout

The constitution, requirements, solution, accepted ADRs, security/testing and
architecture/deployment/investigation docs, tasks, AGENTS, PROJECT_INSTRUCTIONS,
Gate 1/Gate 2 records and analyzer README were read before implementation.
The starting tree was clean. Approved PR #3 head was unchanged at
`7795e8ffb8c9df58534b365d940ada2a7bffd342`, mergeable against unchanged main
`3eb988f84bb2ccdf1f193e4be6464d4d0d9c50e5`, with three expected commits and
no Gate 3+ implementation. Its complete 250/96/40 validation record was preserved.
PR #3 merged using the expected head guard; PR #2 closed without merging.
Main was fetched/fast-forwarded and a new Gate 3 branch created. The unchanged
analyzer suite reran: 250 passed, zero skips. All G2 tasks remain complete.

The constitution, requirements, solution, existing accepted ADRs, analyzer Python
implementation/security suites and all forty golden files are unchanged.
ADR-0003 defines per-case analyzer stores, synchronous admission and deletion
recovery without inventing later-gate product behavior. Gate 2 history is appended,
not replaced; its only other documentation change is fenced-example formatting.

## Task mapping

| Task | Implementation | Validation |
| --- | --- | --- |
| G3.1 FastAPI | `app.py`, `cli.py`, pinned optional API dependencies | Live loopback HTTP smoke, startup configuration, OpenAPI snapshot |
| G3.2 State machine | `models.State/TRANSITIONS`, `Service.transition/recover` | All 64 state pairs, real intake/analysis states, interrupted intake and retry |
| G3.3 SQLite | `storage.Database`, explicit schema version 1 | Foreign-key transactions, service recreation, rejected unknown version, injected failures |
| G3.4 Artifact registry | `Files`, `register/artifact/snapshot`, logical IDs | SHA identity, integrity tampering, symlink/traversal rejection, cross-case isolation |
| G3.5 Intake | Streamed request, `begin_ingest/ingest`, existing Gate 1 ingest | Real PCAP validation, malformed/damaged/unsupported, limits, duplicate protection, cleanup/restart |
| G3.6 Baseline orchestration | `investigate`, baseline checkpoint then existing diagnose | Exact direct-analyzer evidence match, quality first, diagnostic failure preserves five baseline items |
| G3.7 Capability API | Strict request, sixteen predefined capabilities, existing DiagnosticRequest | Injection/flag/filter/path rejection, all baseline routes, RTT/health/DNS, unknown stream and association checks |
| G3.8 Resource policy | Policy, body streaming/preparse bounds, admission, run/evidence quotas, existing analyzer bounds | Oversized declared/chunked input, query count, busy rejection, cached repetition, failed-run/history budget, real timeout/output tests |
| G3.9 Retrieval/deletion | Case/evidence/artifact routes, checked-tree rename/journal | Persistence, identical-capture independence, symlink refusal, pending cleanup, precommit rename recovery, repeated deletion 404 |
| G3.10 Safe logging | Static structured run metadata, safe error handlers, no server access/exception logging | Symptom/raw-name/exception secret exclusion; exact safe log fields |
| G3.11 Contracts/integration | `contracts/api.openapi.json`, two API test files, `scripts/validate_gate3.py` | Full corpus, checked-in contract equality, response/schema checks, real HTTP and CLI smoke |

Provider neutrality is a mode enum and Protocol only, supporting cloud-compatible,
local-compatible and none abstractions. Active mode is none. No model adapter,
network call, prompts, reasoning or provider credentials were implemented.

## API, case and artifact boundary

The exact routes, response/error behavior, lifecycle, limits and disk layout are
documented in `services/api/README.md`; OpenAPI is checked in and exposed locally.
Cases use independent generated 32-hex IDs. A case accepts one immutable original,
whose content hash remains the analyzer ID. Separate cases using identical captures
do not share deletable files. Registered artifacts expose IDs/hash/size/provenance,
never host paths. Immutable run snapshots remain independently verifiable evidence.

SQLite stores cases, history, artifacts, runs, evidence/index and deletion journals,
not capture blobs. Parameters, versions, limits and evidence IDs retain reproducible
provenance. Restart preserves registered originals/evidence and explicitly marks
interrupted work failed. Successful repeated requests use hash-checked persisted
snapshots; changed policy/tool versions invalidate the cache. Failures consume a
bounded run budget. Case lifecycle ends at INVESTIGATING in this gate, with no
fake findings, root cause, report or COMPLETE state.

Deletion includes the original and every generated case file. Canonical tree
checks reject symlinks before rename/removal. Metadata deletion and cleanup journaling
share a SQLite transaction; precommit renames restore on restart, committed partial
cleanup retries on restart. Pending cleanup is explicit and blocks new-case disk
admission. Another case's files and paths outside the managed root are untouched.

The launcher defaults to numeric loopback, validates host/port, uses one worker and
limits HTTP concurrency to 32. Host and Origin guards reject nonlocal browser
requests. A lifetime cross-platform file lock enforces one owner per data root.
The API adds no process execution interface; fixed analyzer argv, confinement,
time/pipe/frame/capture limits and shell=False remain unchanged.

## Failure evidence

| Tested condition | Result |
| --- | --- |
| Malformed/damaged/unsupported capture | FAILED; no registered original; owned intake removed; retry permitted |
| Missing packet tool | Safe tool_unavailable; intake failed and cleaned |
| Real subprocess timeout/output overflow | Safe failure; child lifecycle handled by unchanged runner |
| Optional capability timeout/output/unavailable/corrupt output/limit | Failed run recorded; INVESTIGATING and all earlier evidence preserved |
| Diagnostic failure after baseline | FAILED; five baseline items/quality retrievable; restart/retry succeeds |
| Invalid capability/flags/filter/path/stream type | 422 before diagnostic operation |
| Nonexistent real TCP stream | Safe 422; prior evidence/case retained |
| Cross-case artifact ID | 404; no access to another case's artifact |
| Corrupted original identity | Integrity failure, no analysis of changed input |
| SQLite/snapshot persistence failure | Safe 503; transaction rollback and original/prior evidence preserved |
| Interrupted unregistered intake | Restart marks failure and removes owned original/staging |
| Delete cleanup denied | Metadata removed, bytes explicitly pending, journal survives restart |
| Rename before deletion commit | Restart restores original directory/case |
| Symlink/path escape during deletion | Rejected without deleting outside files |
| Oversized JSON/upload/evidence or exhausted budget | Structured 413/429; no unbounded queue or accumulation |
| Sensitive arbitrary exception | Static safe error/log metadata; text absent |

Failure-injection tests deliberately simulate unavailable/optional components and
persistence errors, alongside actual packet-tool execution. Mocked failure tests
are not claimed as observations of real packet-tool timeout/semantics; separate
real-process timeout/output tests and the 96 unchanged analyzer integrations remain.

## Validation

Environment: Linux; Python 3.12.14; analyzer 0.2.0; TShark/capinfos 4.2.2;
pytest 9.1.1; Ruff 0.16.10; FastAPI 0.143.0; Starlette 1.7.0;
Pydantic 2.13.5; Uvicorn 0.54.0; httpx 0.28.1. Zeek optional/unavailable.
Ubuntu packet-tool packages were downloaded/extracted into scratch rather than
installed into the host. Actual commands used:

```sh
export PATH=/tmp/wireclaw-packet-tools/usr/bin:$PATH
export LD_LIBRARY_PATH=/tmp/wireclaw-packet-tools/usr/lib/x86_64-linux-gnu
python -m pip install -e '.[api,test]'
python -m pytest -q
python -m pytest tests/integration -q
python -m pytest tests/unit/test_api_boundary.py -q
python -m ruff check services tests scripts/validate_gate3.py
python -m ruff format --check services tests scripts/validate_gate3.py
python -m compileall -q services tests scripts/validate_gate3.py
python scripts/validate_gate3.py
git diff --check
git diff --exit-code origin/main -- services/analyzer/src tests/golden tests/unit/test_diagnostics.py tests/unit/test_safety.py tests/integration/test_baseline.py tests/integration/test_gate2.py
```

| Check | Result |
| --- | --- |
| Complete pytest | 365 passed: 234 unit + 131 integration; zero skipped |
| Gate 3 tests | 115 passed: 80 unit + 35 API scenarios |
| Unchanged analyzer suite | 250 passed; 154 unit + 96 real integration |
| Separate integration | 131 passed; real packet tools enabled, zero skips |
| Gate 1/Gate 2 semantic goldens | All 40 pass (11/29), files byte-for-byte unchanged |
| Repeatability/immutability | All existing real-tool corpus plus API repeated-request/original tests pass |
| Schema validation | Evidence schema valid; 447 explicit golden/example/CLI/live API record checks; OpenAPI snapshot/schema checks pass |
| Ruff lint/format | Passed; services/tests plus smoke script |
| compileall / diff checks | Passed |
| CLI baseline/diagnostic smoke | Passed; 5/11 schema-valid items |
| Real loopback HTTP smoke | Passed; create/upload/analyze/evidence/capability-repeat/delete |
| SQLite restart/persistence | Passed, including interruptions/deletion journal recovery |
| Security/resource/failure checks | Passed, as mapped above |

One Starlette test-transport deprecation warning is visible; there are no test skips.
The checked-in OpenAPI equality/schema assertion was additionally rerun with the
80-test API unit suite after creating the snapshot. Intermediate formatting/lint
findings were corrected; no analyzer goldens were regenerated.

## Limits and deferred work

Only Linux and real packet tools 4.2.2 were executed; native macOS/Windows,
other tool versions and Docker/release operation remain unvalidated. File/path/
lock/deletion code uses portable branches and relative POSIX registry paths, but
that is not a substitute for native execution. Gate 1 private-root assumptions,
advisory read-only protection, hard-link filesystem requirements and privileged
filesystem races remain explicit. Synchronous admission provides no asynchronous
progress/job queue and no multi-worker support. Direct uvicorn exposure outside
the supplied validated launcher is not a supported deployment.

Gate 4 rules, rankings, fault-domain/root-cause logic and reports; Gate 5 UI;
Gate 6 evidence captures/dual Wireshark launch actions and host bridge; Gate 7
provider adapters/reasoning; Gate 8 Docker and releases are deferred. No work on
these gates began. Existing evidence filters/frame references remain intact.

The nonblocking Gate 2 zero-window interval terminated by FIN/RST without a
positive-window advertisement remains `open_at_capture_end`; no false duration
is generated and Gate 3 does not reinterpret that state. The Starlette/httpx
warning remains dependency maintenance, not a diagnostic or security defect.

Gate 3 is left open for independent review and must not be merged in this session.

## Independent review remediation — 2026-10-08

Independent review of head `cd98d0ab2afd72d4ab18ae1126cbed8dd99b2dc2`
recorded **NOT READY**, with two blocking lifecycle defects:
[PR #4 review](https://github.com/Ryan9876/wireclaw/pull/4#pullrequestreview-5462002679).
The original verification history above is retained; its restart coverage did not
exercise the idle post-upload checkpoint or filesystem preparation failure.
This addendum records remediation evidence, not independent approval.

The constitution, requirements, solution, accepted ADRs, security/privacy, testing,
supporting architecture/deployment/investigation docs, tasks, repository instructions,
Gate 1/2/3 records and review were reread before implementation. The branch was
clean at the reviewed head. No specification conflict was found; authoritative
specifications and task checkboxes were not changed by this remediation.

### Corrections and permanent regressions

1. **False interruption after successful intake.** Recovery inferred execution
   solely from `BASELINE_ANALYSIS`, although that state legitimately rests after
   intake and between completed stages. `Service.recover()` now checks persisted
   `running` run records before failing this checkpoint. Truly transient intake
   states retain interruption recovery; all running records still become failed.
   No successful baseline run is fabricated, and completed/failed records are
   untouched. `test_idle_baseline_checkpoint_survives_restart` covers both upload
   only and an actual completed baseline snapshot: the entire case record,
   history and runs remain identical after recreation, then HTTP investigation
   succeeds and reaches `INVESTIGATING`.
2. **Intake setup stranded metadata.** `begin_ingest()` created a running record
   and entered `INGESTING` before fallible directory setup, outside the HTTP
   handler's cleanup block. It now prepares confined staging before lifecycle
   mutations and owns setup cleanup itself. Partial unregistered analyzer trees
   are removed; if subsequent admission/transition fails, an admitted run is
   failed and cleanup runs before propagation. Filesystem setup errors use only
   static `storage_failure` (HTTP 503 and structured log code).
   `test_intake_preparation_failure_allows_immediate_retry` injects `OSError`
   before directory creation and after partial creation. Both leave the entire
   initial case record unchanged: `NEW`, no runs/artifacts/original, no staging
   tree. Secret, path and command-shaped exception tokens appear in neither
   response nor logs; the log is parsed as structured JSON. A second upload
   succeeds in the same service instance.

`test_active_baseline_checkpoint_recovers_interrupted_run` contrasts the idle
cases with interruption inside `execute()` after admission and before `save()`.
It covers both baseline and diagnostic execution at `BASELINE_ANALYSIS`, retaining
real completed baseline evidence. A process-like `BaseException` injection leaves
a genuinely running row; recreation yields `FAILED` / `service_interrupted` and
fails only that row, preserving completed runs, history, evidence and SHA-verified
original bytes. This is deliberate failure injection, not a real OS process kill.
The completed baseline evidence is generated by actual packet tools.

Adjacent recovery was reviewed: `NEW`, idle `BASELINE_ANALYSIS`, `INVESTIGATING`,
`COMPLETE` and `FAILED` are resting checkpoints; intake and report assembly states
are transient. At the dual-purpose baseline checkpoint, persisted running rows
distinguish interruption. Completed stages between executions can restart without
a false failure. Running optional operations at `INVESTIGATING` are failed without
discarding earlier evidence or changing the resting checkpoint, consistent with
optional-operation failure isolation. Existing interrupted-intake, optional-failure,
failed-investigation retry, restart persistence and deletion-journal regressions
remain intact. No lifecycle redesign or broader implementation was introduced.

### Validation after remediation

Linux / Python 3.12.14; actual TShark and capinfos **4.2.2**, packaged
`4.2.2-1.1build3`. The previous scratch tools/dependencies were absent and restored
with the pinned editable test/API dependencies and extracted Ubuntu packet packages.
Initial provisioning attempts encountered missing pytest and apt sandbox UID/GID
restrictions; installing dependencies and downloading/extracting packages as the
current user resolved these environment failures. No skipped packet tests were
counted as validation. No package, runtime data or generated capture is committed.

Commands use the packet-tool PATH/LD_LIBRARY_PATH recorded above:

| Command | Result |
| --- | --- |
| `python -m pytest -q` | 371 passed; 234 unit + 137 integration; zero skipped |
| `python -m pytest tests/integration -q` | 137 passed; 96 unchanged analyzer + 41 API; zero skipped |
| `python -m pytest tests/unit -q` | 234 passed; zero skipped |
| `python -m pytest tests/unit/test_api_boundary.py -q` | 80 passed; OpenAPI equality/schema included |
| `python -m pytest tests/integration/test_api.py -q -k 'idle_baseline_checkpoint or active_baseline_checkpoint or intake_preparation_failure'` | 6 passed, 35 deselected, zero skipped |
| `python -m pytest tests/unit/test_normalize.py tests/unit/test_safety.py tests/unit/test_diagnostics.py tests/unit/test_ingest_transaction.py tests/unit/test_capture_headers.py tests/integration/test_baseline.py tests/integration/test_gate2.py -q` | 250 unchanged Gate 1/2 regressions; 154 unit + 96 real-tool integration |
| `python -m ruff check services tests scripts/validate_gate3.py` | Clean |
| `python -m ruff format --check services tests scripts/validate_gate3.py` | 37 files formatted |
| `python -m compileall -q services tests scripts/validate_gate3.py` | Exit 0 |
| `python scripts/validate_gate3.py` | 447 schema record checks; CLI baseline/diagnostics 5/11 records; live loopback HTTP, repeat request and deletion succeed |
| `git diff --check` | Clean |
| `git diff --exit-code origin/main -- services/analyzer/src tests/golden tests/unit/test_diagnostics.py tests/unit/test_safety.py tests/integration/test_baseline.py tests/integration/test_gate2.py` | Empty diff; exit 0 |
| `tshark --version`; `capinfos --version` | Both 4.2.2 |

Gate 3 coverage is **121 tests**: 80 boundary unit + 41 API integration, including
six added parameterized lifecycle cases. All **40 semantic goldens** (11 Gate 1,
29 Gate 2) pass unchanged. Before implementation, the six added cases produced
four expected failures (two false idle failures, two setup failures) and two
successful interrupted-run controls. They all succeed after remediation.
The strengthened final regression additionally checks execution interruption and
individual sensitive tokens in structured logs. One existing Starlette/httpx
test-transport deprecation warning remains; no test is skipped.

### Lifecycle evidence and scope

| Scenario | Resulting history and records |
| --- | --- |
| Upload → clean recreation → investigate | `NEW → INGESTING → VALIDATING_CAPTURE → BASELINE_ANALYSIS`; recreation adds nothing and preserves every run; investigation adds `INVESTIGATING`; no `service_interrupted` |
| Setup failure → immediate upload retry | Failure leaves history `[NEW]`, no runs or original, no analyzer staging tree; retry adds `INGESTING → VALIDATING_CAPTURE → BASELINE_ANALYSIS` and one completed ingest |
| Interrupted active baseline/diagnostics → recreation | Prior intake/baseline history and evidence remain; history adds `FAILED`; interrupted row becomes failed with `service_interrupted`; earlier completed rows and immutable input remain unchanged |

Path confinement, case ownership/isolation, immutable inputs/SHA validation,
typed command/filter protections, request/resource limits, single mutation/process
ownership, safe logging and deletion recovery are unchanged and exercised by the
complete regression suite. No Gate 1/2 source or golden changed. No model calls,
findings, reports, ranking, UI, host bridge or packaging were added.

G3.1–G3.11 retain their implementation/validation checkmarks; all Gate 4+ tasks
remain unchecked. PR #4 remains open and unmerged for independent re-review.
Native macOS/Windows, other packet-tool versions, optional Zeek, Docker/release
execution and real OS crash injection remain unvalidated. Existing limits above
continue to apply; no unrelated issue was remediated. The independent reviewer
must make the final gate decision.
