# Gate 1 verification — deterministic analyzer foundation

Date: 2026-10-07. Baseline: `9d8bbdaa599c9278b12a98c4e8ecb42fcb1ac240`.
Implementation branch: `gate1-deterministic-analyzer`. Scope: Gate 1 only.

## Completed

| Task | Implemented and verified by |
| --- | --- |
| G1.1 Python package | `pyproject.toml`, `services/analyzer/src/wireclaw_analyzer`; editable install and CLI smoke |
| G1.2 Safe runner | `runner.py`; fixed enum plans, direct argument arrays, timeout, bounded combined stdout/stderr; mocked and real-process tests |
| G1.3 Tool versions | `Runner.versions()`; records TShark/capinfos versions and explicit optional Zeek unavailability |
| G1.4 Immutable ingest/hash | `storage.py`; bounded byte copy, SHA-256, atomic no-overwrite publication, read-only original, identity manifest and integrity checks |
| G1.5 Metadata | `normalize.metadata`, `Analyzer.get_capture_metadata`; capinfos output plus separately attributed PCAPNG header values |
| G1.6 Quality baseline | `normalize.quality`, `Analyzer.assess_capture_quality`; good/limited/insufficient, structured checks, frame refs, unknowns |
| G1.7 Protocol inventory | `normalize.protocols`, `Analyzer.list_protocols`; per-layer frame counts and explicit counting formula |
| G1.8 Endpoint inventory | `normalize.endpoints`, `Analyzer.list_endpoints`; IPv4/IPv6, directional counts/bytes, transport/ports |
| G1.9 Conversations | `normalize.conversations`, `Analyzer.list_conversations`; directional endpoint pairs, stream IDs, bytes, duration, frame refs and filters |
| G1.10 Evidence contracts | All five capabilities validate each evidence item against the unchanged shared JSON schema; case records include configuration and tool versions |
| G1.11 Fixtures | Standard-library generator: healthy, malformed/damaged/unsupported, truncation, midstream, checksum ambiguity, empty, one-sided, incomplete handshake, timestamp regression, PCAPNG/drops |
| G1.12 Golden tests | Ten complete semantic goldens plus independent fixture assertions; malformed inputs have explicit rejection tests |

## Architecture

`analyzer.py` exposes capture-ID capabilities and assembles/persists the baseline.
`runner.py` owns fixed process plans and discovery. `storage.py` owns bounded intake,
confinement and immutable originals. `normalize.py` contains pure transformations.
`capture_headers.py` reads only bounded PCAPNG interface/statistics metadata.
`errors.py` provides safe structured errors; `cli.py` is a developer entry point.

No FastAPI, UI, LLM, host bridge, diagnostic engine or Docker implementation was added.
Quality precedes inventory in the returned baseline. Inventory methods run that same
quality-aware baseline. No finding or root-cause statement is produced.

## Validation

Final environment: Linux, Python 3.12.14, pytest 9.1.1, Ruff 0.16.10,
TShark 4.2.2 and capinfos 4.2.2. Zeek is absent and is recorded as optional/unavailable.

The environment could not install system packages normally. Real Ubuntu package
binaries/libraries were extracted into a scratch-only directory. Actual packet-tool
commands used this environment prefix, not mocks or checked-in wrappers:

```sh
PATH=/workspace/scratch/59e16347406d/packet-tools/usr/bin:$PATH \
LD_LIBRARY_PATH=/workspace/scratch/59e16347406d/packet-tools/usr/lib/x86_64-linux-gnu
```

| Command (from repository root; packet tools on PATH) | Final result |
| --- | --- |
| `uv pip install --python .venv/bin/python -e .` | Package built and installed successfully |
| `.venv/bin/python tests/fixtures/generate.py data/incoming` | Reproducible fixture corpus generated |
| `.venv/bin/wireclaw-analyze --data-root data incoming/healthy.capture` plus JSON-schema validation | Installed entry point passed; five schema-valid evidence items |
| `.venv/bin/python -m wireclaw_analyzer.cli --data-root data incoming/healthy.capture` | Real capinfos/TShark smoke passed; evidence example saved |
| `.venv/bin/pytest -q` | 66 passed, zero skipped; unit, schema, real-tool golden, malformed, ingestion, safety and process-bound tests |
| `.venv/bin/ruff check services/analyzer/src tests/unit tests/integration/test_baseline.py tests/fixtures/generate.py` | Passed |
| `.venv/bin/ruff format --check services/analyzer/src tests/unit tests/integration/test_baseline.py tests/fixtures/generate.py` | Passed; 13 Python files formatted |
| `.venv/bin/python -m compileall -q services/analyzer/src tests/unit tests/integration/test_baseline.py tests/fixtures/generate.py` | Passed |
| `git diff --check` and staged diff/status inspection | Passed; generated captures, environments, tool binaries and runtime directories excluded |

Development checks also executed real `tshark --version`, `capinfos -h`, and
`capinfos -M` against healthy/empty/drop fixtures, plus direct `Runner.run(PACKETS)`
to inspect the real field format. Pure unit validation initially passed 32 tests;
the first full suite passed 52. Subsequent test expansion caught a persistence
filename regression (10 failures, 54 passes); it was corrected without changing
goldens. The completed suite passes all 66. Interim lint/format findings were fixed.
Final review added empty-version-output and storage-publication failure tests.
No unresolved failures are hidden and no mock integration is represented as a
real packet-tool pass.

To reproduce on another host, install Wireshark's TShark and capinfos, follow
`services/analyzer/README.md`, and run `python -m pytest -q`. If Zeek is installed,
`zeek --version` and the analyzer's `tool_versions` verify its discovery. No
packet-processing Zeek capability is part of this gate.

## Representative normalized evidence

Full schema-valid example: [`gate1-evidence-example.json`](gate1-evidence-example.json).
Healthy fixture capture identity:
`4550e2554f2cb82dcf67b4493581cc9aac9f97fc118305c9ee6dbee721d92f35`.

| Output | Observed/derived result |
| --- | --- |
| Versions | Analyzer 0.1.0; TShark/capinfos 4.2.2; Zeek unavailable |
| Metadata | PCAP; Ethernet; 7 frames; 469 wire bytes; 605 file bytes; 0.6 seconds; snaplen 65535 |
| Quality | good; no baseline defect indicator observed; drops and duplicate-capture cause remain unknown |
| Protocol inventory | TCP 3, UDP 4, DNS 2, IPv4 5, IPv6 2; overlapping layer counts explicitly labeled |
| Endpoints | 192.0.2.1, 192.0.2.2, 192.0.2.53, 2001:db8::1, 2001:db8::2; directional counts and ports retained |
| Conversations | TCP/443, DNS UDP/53, IPv6 UDP/40001; frames [1,2,3], [4,5], [6,7]; filters tcp.stream == 0, udp.stream == 0, udp.stream == 1 |

Each evidence ID embeds the capture identity and capability. Its source records
capability/tool/version; values include reproducible formulas. PCAPNG header
observations retain a separate reader/version provenance object. Quality checks
retain frame references and unknown cause states. This is evidence, not diagnosis.

## Security checks

- No command/filter/flag passthrough; fixed `Operation` plans only, discovered approved binaries,
  direct arguments, `shell=False`, name resolution disabled and isolated user configuration.
- Hash-only logical capture IDs and canonical managed-root paths; traversal, NULs,
  foreign path separators and internal symlinks rejected. Artifact names are allowlisted.
- Original file is never overwritten; source modifications do not alter it; managed
  original tampering is detected; failed intake publishes no original.
- Capture bytes, packet rows, per-process execution time and stdout/stderr are bounded.
  Timeout/output overflow kill and reap processes; real process tests exercise both pipes.
- Raw stderr is discarded; ordinary logs receive no payload, credentials or tool-output text.
  No model/network provider exists. Compressed wrappers are rejected before tool execution.

## Important files changed

`pyproject.toml`, `.gitignore`, the analyzer package and its README; standard-library
fixture generator; ten golden JSON files; unit and integration tests; fixture/golden
READMEs; root README; this record/evidence example; Gate 1 task checkboxes only.
The constitution, requirements, solution, ADRs and shared evidence schema are unchanged.

## Remaining issues and limits

No Gate 1 requirement remains incomplete in this validated environment. Zeek
availability is explicit and optional here. Native Windows/macOS packet-tool smoke
runs were not possible; path/process code is portable, and Windows hard-link deletion
ordering is handled explicitly. Unsupported hard-link filesystems fail rather than
silently weaken original publication. Private managed data roots are required:
read-only mode is advisory against privileged local writers; this gate does not
provide an OS parser sandbox or defend against a privileged filesystem race.

Baseline handshake checks use flags/direction/order and do not establish application
readiness. Offload versus corruption, duplicate-capture cause, and absent drop
counters remain explicitly unknown. Large-capture indexing, advanced diagnosis,
release toolchain pinning, container isolation and packaging remain in their later
gates; none was begun. Both Wireshark actions remain requirements for those gates.

**Gate 1: PASS — ready to begin Gate 2**
