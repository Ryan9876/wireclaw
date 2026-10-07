# Deterministic analyzer — Gate 1

The Python package is in `src/wireclaw_analyzer`. It runs without the future API,
UI, model provider, Docker image, or host bridge. It does not diagnose root cause.

## Developer setup

From the repository root, use Python 3.11 or newer and install TShark and
capinfos through your OS's Wireshark distribution. Ensure both are on PATH.
Zeek is optional in Gate 1; its availability/version is recorded, but no Zeek
packet capability is required or executed yet.

```sh
python -m venv .venv
```

Activate `.venv` using your platform's normal activation command, then:

```sh
python -m pip install -e '.[test]'
python -m pytest -q
python -m ruff check services/analyzer/src tests/unit tests/integration/test_baseline.py tests/fixtures/generate.py
python -m ruff format --check services/analyzer/src tests/unit tests/integration/test_baseline.py tests/fixtures/generate.py
```

Real-tool integration tests explicitly skip if TShark or capinfos is missing.
A skipped integration suite is **not** validation of Gate 1. The unit suite can
still verify parsing, safety boundaries, failures and process bounds.

## Run a synthetic capture

```sh
python tests/fixtures/generate.py data/incoming
python -m wireclaw_analyzer.cli --data-root data incoming/healthy.capture
```

Or invoke `wireclaw-analyze` with the same arguments after installation. For a
non-editable install, provide `--schema /path/to/contracts/evidence.schema.json`.
The default schema path is for source checkouts; contracts remain repository-owned.

Stage a real capture under your private data root first. The CLI accepts only a
path beneath that root, never an external path, executable, filter, or flags.
Supported PCAP/PCAPNG content is checked by capinfos and TShark regardless of
filename extension. Compressed and non-PCAP wrappers are rejected before tool execution. Invalid input fails without publishing an original capture.

## Python capabilities

```python
from pathlib import Path
from wireclaw_analyzer import Analyzer, Limits

analyzer = Analyzer(Path("data"), limits=Limits())
capture_id = analyzer.ingest_capture(Path("incoming/healthy.capture"))
result = analyzer.analyze(capture_id)
metadata = analyzer.get_capture_metadata(capture_id)
quality = analyzer.assess_capture_quality(capture_id)
protocols = analyzer.list_protocols(capture_id)
endpoints = analyzer.list_endpoints(capture_id)
conversations = analyzer.list_conversations(capture_id)
```

Inventory calls currently perform the entire bounded baseline, including quality,
so callers cannot accidentally omit capture quality. Repeated calls are correct
but not optimized; API orchestration/caching remains Gate 3.

## Output and storage

- `cases/<sha256>/original/capture`: immutable byte copy, published without overwrite,
  read-only mode; hash verified before/after baseline execution.
- `cases/<sha256>/normalized/capture-identity.json`: persisted identity and file size.
- `cases/<sha256>/normalized/capture-summary.json`: normalized evidence, analyzer and
  tool versions, configuration. Writes are atomic.

Every evidence item validates against the unchanged shared
`contracts/evidence.schema.json`. IDs include the full capture SHA-256 and
capability. Values include calculations, limitations and nested frame/stream/filter
references where applicable. Endpoints/conversations describe observed IP traffic;
non-IP packets remain in protocol inventory and are explicitly counted as excluded
from the IP endpoint inventory. The first IPv4 fields are preferred when present;
otherwise first IPv6 fields are used. Nested/tunneled endpoint inventory is not
implemented in Gate 1. Protocol-layer counts overlap and must not be summed as a
packet total. Byte totals are wire-frame lengths, not application goodput.

capinfos supplies metadata; TShark supplies selected fields with name resolution
**disabled** and checksum validation **enabled**. A narrow, bounded PCAPNG header
reader records IDB snaplen and last reported ISB ifdrop values with its own
provenance because capinfos 4.2.2 does not print those counters. Totals are unknown
unless every interface reports a count. No packet payload or interface text is
retained by that reader.

## Quality and limits

Quality is `insufficient` for an empty capture, `limited` for observed baseline
quality indicators, and `good` when none is observed. `good` does not certify
complete visibility or fitness for every future diagnostic question.

Checks cover truncation, malformed packets, checksum anomalies, backward timestamps,
reported capture drops, observed one-direction conversations, absent initial SYNs,
and incomplete SYN/SYN-ACK/ACK flag sequences. These are indicators only: direction
asymmetry and offload causes are not proven. Duplicate-capture artifacts remain
`unknown` because repeated transport packets cannot establish the capture cause.
Unavailable drop counters remain `unknown`, never zero. A malformed/unreadable file
returns an analyzer error rather than an apparently valid quality result.

Defaults: 64 MiB capture, 100,000 frames, 16 MiB combined stdout/stderr per process,
30 seconds per process. Limits are configurable positive, finite values; exceeding
one fails explicitly without partial inventory or hidden sampling. Work is bounded
by capture bytes, frame count, process output and time. Large-capture indexing,
worker isolation and release packaging remain later-gate work.

## Safety boundary

The runner accepts only an `Operation` enum and, for packet operations, a confined
capture path. Executables are discovered once from administrator-controlled PATH;
request data cannot select an executable or add flags. Each plan uses direct
argument arrays with `shell=False`, a minimal environment, private tool configuration
and no inherited user Wireshark preferences. Output is drained in bounded chunks;
overflow and timeout kill and reap the child. Stderr is discarded, never logged or
included in errors. `AnalyzerError.as_dict()` gives safe code/capability/tool fields.

Traversal, backslash-based foreign paths, NULs and internal symlinks are rejected.
Managed data directories must be private to Wireclaw: this is not protection against
a privileged local process racing filesystem changes. Read-only mode is advisory
on some filesystems/platforms; integrity checks detect later changes. Atomic original
publication uses same-filesystem hard links; unsupported filesystems must fail rather
than fall back to overwriting. Windows/macOS native execution has not been smoke-tested
in this Linux development environment. Docker packaging is intentionally deferred.
