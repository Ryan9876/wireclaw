# Phase 2 Task 2 implementation report

## Scope and authority

Base commit: `443b6279a4b82d1531fcce939337faad6f3e3966`.

Implemented the approved two-step capture lifecycle from `task-2-brief.md` and `docs/superpowers/specs/2026-10-22-case-manager-multicapture-design.md`, preserving the existing constitution, requirements, solution, accepted ADRs, case confinement, immutable sources, synchronous admission, safe errors, and upload limits.

The new endpoints are:

- `POST /api/cases/{case_id}/captures` -> 201 `CaptureResponse`.
- `PUT /api/cases/{case_id}/captures/{capture_id}/data` -> `CaptureResponse`.
- `PATCH /api/cases/{case_id}/captures/{capture_id}` -> `CaptureResponse`.
- `DELETE /api/cases/{case_id}/captures/{capture_id}` -> the existing typed deletion result, including truthful cleanup status.

`CaseResponse.captures` lists explicit capture rows in stable creation order. Legacy fields follow the first capture. The singular POST route creates a first capture or uses the sole waiting explicit capture; multiple explicit captures return `capture_selection_required` without mutation. Existing single-capture investigation remains available.

No automatic analysis scheduling, TCP correlation, clock alignment, UI flow, AI behavior, packaging behavior, push, or merge was added.

## Storage and failure behavior

The first source keeps the existing case analyzer location for compatibility. Additional sources use separate capture-owned analyzer stores, so identical bytes still have independent immutable source files. Existing source registry paths resolve promoted captures correctly.

Creation enforces four captures transactionally and refuses admission while deletion cleanup is pending. Metadata edits validate the merged persisted vantage and never invoke extraction. Failed secondary uploads retain primary state, artifacts, and metadata. Restart recovery marks interrupted capture intake explicitly without treating secondary intake as a failed primary analysis.

Capture removal uses the existing deletion journal, confined renames, rollback restoration, and restart cleanup. Primary removal also removes deterministically attributable legacy evidence/reports, updates compatibility fields, and records a resting state for explicit future investigation. It does not start an investigation. A pre-commit interruption restores the still-registered source and report; a committed deletion with failed cleanup reports `cleanup_pending` and retries on restart.

## TDD evidence

All commands below used the repository `.venv`; the bare system `python` initially reported `No module named pytest` and did not run tests. Wireshark tools were enabled with:

```sh
PATH=/Applications/Wireshark.app/Contents/MacOS:$PATH
```

Before production edits, added plural lifecycle and legacy compatibility tests, then ran:

```sh
.venv/bin/python -m pytest -q tests/integration/test_api.py tests/integration/test_gate7.py -k 'plural_capture or legacy_upload'
```

RED: **16 failed, 108 deselected** in 2.33s. Failures were expected missing plural routes (404 rather than 201/422) and missing `CaseResponse.captures` (`KeyError`). Sent the command/failure report to the parent before production changes; parent independently confirmed RED and the test-only diff. Initial GREEN after implementation: **16 passed, 108 deselected** in 6.73s.

Further failures reproduced before their production fixes:

| Regression selection | RED evidence | Cause and correction |
| --- | --- | --- |
| `remove_primary or secondary_interruption` | 2 failed, 73 deselected | Removal retained the primary legacy report/evidence; secondary running ingest was mistaken for interrupted primary baseline work. Cleanup now attributes primary legacy records, and recovery excludes secondary intake from case-fatal interruption. |
| `delete_cleanup_failure or stream_timeout` | 1 failed, 1 passed, 75 deselected | Removal committed metadata then returned 500 on failed cleanup. Added confined rename/journal/retry semantics. The timeout test already passed the shared bounded streaming implementation. |
| `promotes_next or database_failure_restores` | 2 failed, 1 passed, 77 deselected | Removing the primary left NEW/COMPLETE despite an already uploaded next source. Removal now records BASELINE_ANALYSIS for an uploaded promoted source, or NEW without one. The rollback test already passed. |
| `delete_cleanup_failure` after extending disk-admission assertion | 1 failed, 80 deselected | Capture creation admitted another source during pending deletion cleanup. It now uses the existing cleanup admission rule. |

The first primary-removal test initially expected HTTP 404 from an empty case's report endpoint. Inspection of the existing report contract showed NEW cases return `report_not_ready` (409), so the test was corrected to assert that existing code-only readiness result; report behavior was not changed. A later attempted insertion of the cleanup admission guard did not match the formatted source, which the rerun exposed (215 passed, 1 failed in the API/boundary selection). The guard was then inserted at the verified transaction boundary and its focused regression passed.

Additional characterization checks cover cleanup rollback and restart before database commit, source independence with identical bytes, immutable re-upload rejection, metadata-only edits, owner/unknown ID checks, fifth-capture no-side-effect rejection, wrong content type, declared and streamed size bounds, timeout cleanup, and upload above the JSON body limit.

## Broader failures investigated

The first complete API/Gate 7 run produced **120 passed, 4 failed**. Each failure was diagnosed rather than dismissed:

- `tests/integration/test_api.py::test_case_metadata_migration_backfills_existing_cases[1]`
- `tests/integration/test_api.py::test_case_metadata_migration_backfills_existing_cases[2]`

Those tests intentionally reconstruct v1/v2 by dropping the v4 captures table and scoped columns. Comparing newly exposed v4 capture IDs across that destructive fixture reconstruction is incorrect: the old identity was erased, and migration deterministically creates a replacement identity. The revised assertion still compares all original non-display legacy fields, report equality, source artifact ID, source SHA, source byte count, recent-case size, one recreated capture row, and schema version 4. No migration implementation or golden was weakened.

- `tests/integration/test_gate7.py::test_async_capture_executes_embedded_status_probe_off_the_event_loop`
- `tests/integration/test_gate7.py::test_async_capture_cleanup_executes_embedded_status_probe_off_the_event_loop`

The new route selected its capture through presentation `get()`, which invokes embedded status probing; failure bookkeeping also invoked presentation reads on the async event loop. Existing tests captured unawaited-coroutine warnings and an extra probe. Internal lifecycle reads now use deterministic base-service state and failure cleanup runs in the thread pool. The six-case focused rerun (these four plus two removal/recovery regressions) passed.

### OpenAPI and browser consumers

`tests/unit/test_api_boundary.py::test_default_loopback_and_gate6_routes` caught the expected strict mismatch between the new live API and checked-in snapshot. Regenerated the canonical snapshot with:

```sh
PYTHONPATH=services/api/src:services/analyzer/src .venv/bin/python - <<'PY'
import json
from pathlib import Path
from wireclaw_api import create_app
Path('contracts/api.openapi.json').write_text(
    json.dumps(create_app(Path('/tmp/wireclaw-task2-openapi')).openapi(), indent=2) + '\n'
)
PY
npm run contracts --prefix apps/web
```

Resulting generated files: `contracts/api.openapi.json`, `apps/web/src/generated/api.ts`, `apps/web/src/generated/validators.js`. Snapshot equality then passed.

The generated validator correctly rejected browser case fixtures missing the newly required captures field: initial browser run **7 failed, 114 passed**. Added one consistent legacy capture summary to each of the three CaseResponse fixtures, preserving their source, report, and evidence identities. Final browser suite: **121 passed**. Fixture formatting used the existing Prettier tool; there are no UI implementation changes.

### Analyzer baseline control

An integration run produced **230 passed, 4 failed** in 178.40s:

1. `tests/integration/test_gate2.py::test_gate2_golden_reproducibility_schema_traceability[reordered_tcp]`
2. `tests/integration/test_gate2.py::test_gate2_golden_reproducibility_schema_traceability[pmtud_signals]`
3. `tests/integration/test_gate2.py::test_loss_reordering_expert_classes_and_sequence_union`
4. `tests/integration/test_gate4_golden.py::test_gate4_real_capture_golden_rca_cases`

Proved those failures against the pristine starting commit, using an archive (not the modified working tree):

```sh
mkdir -p /tmp/wireclaw-task2-baseline
git archive 443b6279a4b82d1531fcce939337faad6f3e3966 services tests contracts pyproject.toml | tar -x -C /tmp/wireclaw-task2-baseline
```

From that archive, ran the exact four node IDs above with the same repository `.venv/bin/python` and the same Wireshark PATH. Control result: **4 failed in 16.74s**, with the same TCP-health semantic mismatches, reordering `out_of_order.frame_refs=[]` instead of `[5]`, and Gate 4 reordered-traffic finding difference. No analyzer implementation, analyzer fixtures, or analyzer goldens changed. Installed TShark identifies itself as 4.6.9; the release Dockerfile pins 4.2.2. The control proves the failures predate this change; it does not alone prove which tool-version difference causes them.

### Socket restrictions in the first full Python run

The first full run produced **856 passed, 8 failed** in 225.63s: the four baseline analyzer failures, the subsequently fixed OpenAPI snapshot, and three privacy HTTP fixture startup failures:

- `tests/packaging/test_eai14_privacy_qualification.py::test_provider_fixture_fails_when_sentinel_is_in_actual_request`
- `tests/packaging/test_eai14_privacy_qualification.py::test_provider_fixture_passes_when_sentinel_is_absent_and_correlates_case`
- `tests/packaging/test_eai14_privacy_qualification.py::test_provider_fixture_result_never_contains_authorization_or_request_body`

The fixture maps bind errors to `privacy_fixture_bind_failed`. A raw socket control in the same sandbox returned `PermissionError 1 [Errno 1] Operation not permitted` for binding `127.0.0.1:0`. Tool escalation for loopback access was approved; the complete privacy packaging file then passed **31 tests** in 5.32s. No privacy or packaging code was changed.

## Final verification

An already in-flight loopback-enabled run, which had imported the version before the final admission guard, finished with **859 passed, 5 failed** in 207.31s: the four proven baseline analyzer failures plus `test_plural_capture_delete_cleanup_failure_is_journaled_and_retried`. The focused regression passed after inserting the guard. The final full rerun was started after that insertion.

| Verification | Final result |
| --- | --- |
| `PATH=/Applications/Wireshark.app/Contents/MacOS:$PATH .venv/bin/python -m pytest -q` with approved loopback access | **860 passed, 4 failed, 1 warning** in 209.63s. Only the four exact analyzer failures proven on the pristine base remained. All API, Gate 7, boundary, migration, privacy, and packaging tests passed. |
| Isolated API + Gate 7 run before the final added disk-admission assertion | **132 passed** in 74.53s. The added admission regression subsequently passed and all its containing suites passed in the final complete run. |
| Complete privacy packaging file with loopback access | **31 passed** in 5.32s. |
| `npm test --prefix apps/web` | **121 passed**, 2 files. |
| `npm run typecheck --prefix apps/web` | Passed. |
| `npm run lint --prefix apps/web` | Passed. |
| `npm run format:check --prefix apps/web` | Passed after canonical fixture formatting. |
| `npm run build --prefix apps/web` | Passed, including contract generation, TypeScript, and Vite. |
| `go test ./...` from `services/host-bridge` | Passed. |
| `.venv/bin/ruff check .` | Passed. |
| `.venv/bin/ruff format --check services scripts tests` | Passed, 90 files. |
| `.venv/bin/python -m compileall -q services scripts tests` | Passed. |
| `git diff --check` | Passed. |

The Python warning is the existing Starlette TestClient/httpx deprecation warning. Full-suite verification is not reported as globally GREEN: the four proven base-commit analyzer failures remain visible above. This change introduces no remaining test failure under the verified local toolchain.

## Self-review and limits

Reviewed route registration, strict model surfaces, upload bypass matching, owner lookup, transaction/admission limits, path confinement, duplicate-source isolation, removal rollback/journaling, interrupted upload recovery, legacy compatibility, and generated contract changes. Sensitive paths, request bytes, and exception text are not added to responses or logging.

Task 3 remains responsible for plural analysis scheduling and general per-capture evidence scheduling/provenance. This task preserves the existing explicit primary investigation flow and cleans its existing deterministic dependencies on removal. Cross-capture report recomputation and correlation are not claimed here.
