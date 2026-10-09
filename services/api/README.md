# Local API — Gate 3

FastAPI owns case lifecycle, SQLite metadata, artifact registration and bounded
orchestration. The analyzer remains the packet-fact authority. No UI, findings,
reports, model calls, host bridge or release packaging are implemented here.

## Developer startup

Install Python 3.11+ and real TShark/capinfos. From the repository root:

```sh
python -m pip install -e '.[api,test]'
wireclaw-api --data-root data
```

The launcher binds `127.0.0.1:8765`, runs one worker, disables request/access and
exception logs, and caps active HTTP connections at 32. Only numeric loopback
addresses are accepted for `--host`; `--port` is an administrator setting.
One lifetime OS lock permits one service process per data root. Do not bypass
the launcher to expose the service or start multiple workers. Host/Origin checks
reject nonlocal browser requests and DNS rebinding; no wildcard CORS is enabled.
Managed roots must be private to Wireclaw. Privileged filesystem races and
hostile installed packet binaries remain outside the existing Gate 1 boundary.

## Routes and contracts

OpenAPI is served at `/openapi.json`, documentation at `/docs`. Its checked-in
snapshot is `contracts/api.openapi.json`.

| Route | Purpose |
| --- | --- |
| `GET /api/health` | Service health, current gate/provider mode |
| `GET /api/config/capabilities` | Sixteen existing capabilities and public bounds |
| `POST /api/cases` | Create case from JSON `{"symptom":"application is slow"}` |
| `POST /api/cases/{case_id}/capture` | Stream PCAP/PCAPNG body, `application/octet-stream` |
| `POST /api/cases/{case_id}/investigate` | Baseline/quality checkpoint then existing diagnostics |
| `POST /api/cases/{case_id}/capabilities` | Typed capability with registered original artifact ID |
| `GET /api/cases/{case_id}` | Symptom, state/history, quality, artifacts and runs |
| `GET /api/cases/{case_id}/evidence` | Bounded evidence page, `offset`/`limit` |
| `GET /api/cases/{case_id}/evidence/{evidence_id}` | Exact existing record |
| `GET /api/cases/{case_id}/artifacts/{artifact_id}` | Integrity-checked metadata, no filesystem path |
| `DELETE /api/cases/{case_id}` | Explicit deletion of metadata, original and generated files |

Capability request:

```json
{"artifact_id":"<32-hex original_id>","capability":"analyze_rtt","tcp_stream":0}
```

Baseline, DNS, fragmentation and PMTUD capabilities reject stream selectors.
Other Gate 2 capabilities accept optional nonnegative integer TCP stream IDs.
Requests accept no paths, commands, flags, executables or display filters.
Unknown fields fail before execution. Artifact IDs must belong to the case.
Unknown resources return 404; invalid input 422; overflow 413/429; persistence or
storage availability failures 503. Only static error codes are returned; no raw
framework validation values, packet stderr or arbitrary exception text is echoed.

Create -> upload -> investigate -> retrieve evidence is the Gate 3 workflow.
Intake accepts one immutable capture per case and validates content with Gate 1
tools. Uploads are streamed to generated staging names, never caller filenames.
Failed unregistered intake trees are removed. Persistent cleanup denial is explicit
and recovery retries owned cleanup. Registered originals stay read-only and are
SHA-checked before analysis, including cached requests.

## Lifecycle and persistence

All authoritative states/legal transitions are represented and tested. Gate 3
normally reaches NEW -> INGESTING -> VALIDATING_CAPTURE -> BASELINE_ANALYSIS ->
INVESTIGATING. ASSEMBLING_REPORT/COMPLETE are deferred behavior, never simulated.
Active failures may become FAILED while preserving prior evidence. Explicit retries
reuse preserved input. Optional capability failures retain state and earlier evidence.

SQLite schema version 1 stores cases, history, artifacts, runs, evidence/index and
deletion journals. Transactions and foreign keys protect metadata; PCAP blobs never
enter SQLite. Runs retain safe parameters, analyzer/tool versions, configuration,
produced evidence IDs and safe failures. Unknown schema versions fail startup.
Successful repeated requests return snapshots without new execution/rows/logs.
Cache keys include policy and tool versions; changed environments create new
bounded runs. Prior snapshots remain historical reproducibility records.

Restart marks interrupted active stages and runs failed, preserves registered
originals/evidence, removes owned staging/unregistered snapshots, restores precommit
deletion renames, retries committed cleanup and removes orphaned case directories.
`BASELINE_ANALYSIS` also persists as an idle checkpoint after successful intake or
between completed analysis stages. Recovery fails that checkpoint only when a
persisted running run proves interrupted execution; completed/failed runs are retained.
Intake prepares confined staging before creating a run or entering `INGESTING`.
Setup failure removes the unregistered intake tree and returns a static error;
the case remains immediately retryable without restarting the service.

```text
data/
  cases.sqlite3
  service.lock
  cases/<application-case-id>/
    analyzer/cases/<capture-sha>/original/capture
    analyzer/cases/<capture-sha>/normalized/<analyzer summaries>
    analyzer/incoming/<generated staging name>
    analyzer/work/ and analyzer/tool-home/
    normalized/<run-id>.json
  trash/<deleted-case-id>/
```

The isolated analyzer namespace reuses Gate 1 unchanged; identical captures in
different application cases have independent originals and deletion. Registered
relative paths use POSIX representation; callers use logical IDs. Per-run snapshots
are distinct from mutable analyzer summaries. Canonical confinement rejects
traversal, absolute escapes and managed symlinks. See ADR-0003.

Deletion checks the tree, renames it inside the root, then commits case removal
and a cleanup journal. Database failure restores the directory. With
`cleanup_pending: true`, metadata is deleted but bytes may remain;
`original_deleted`/`registered_artifacts_deleted` stay false. Restart retries
cleanup, and new cases are refused while cleanup is pending. Already missing cases
return 404. Deletion accepts no caller filesystem path.

## Resource and privacy policy

Defaults: 100 cases; 64 run attempts per case including failed runs/intake; 4,096
symptom characters; 16 KiB JSON; 60-second upload/body deadline; 5,000 indexed
evidence items; 32 MiB indexed evidence and retained snapshots per case; 100 items
per evidence page. One admitted mutation at a time with busy rejection and no work
queue. All existing Gate 1/Gate 2 frame/time/pipe/capture/value bounds remain.
`Policy` is administrator configuration, never API input. No unbounded retries.

Structured run logs contain only case ID, component, capability, duration, status
and static error code. No payload, DNS raw name, symptoms, secrets, request bodies
or arbitrary exceptions. Console output is not accumulated in application log files.
Symptoms are untrusted stored context and never command/path/capability input.
Provider-neutral cloud/local/none interfaces exist; active mode is none. No model
transport, prompts or credential persistence exist. Raw captures remain local.

## Validation

```sh
python -m pytest -q
python -m pytest tests/integration -q
python -m ruff check services tests
python -m ruff format --check services tests
python -m compileall -q services tests
git diff --check
```

See `docs/gate3-verification.md`. Packet-tool tests must run without skips. Only
Linux with TShark/capinfos 4.2.2 was executed. Native macOS/Windows, Docker/parser
OS isolation and release packaging remain unvalidated/deferred. The test transport
emits a Starlette/httpx deprecation warning; it does not skip/fail tests. Gate 2's
nonblocking FIN/RST-ended zero-window interval remains `open_at_capture_end`.
