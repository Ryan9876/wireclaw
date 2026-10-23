"""Gate 7 orchestration, persistence, and safe fallback without a real model."""

import gc
import hashlib
import json
import sqlite3
import warnings
from threading import get_ident

import httpx
import pytest
import wireclaw_api.app as api_module
import wireclaw_api.gate7_service as gate7_module
from fastapi.testclient import TestClient
from wireclaw_analyzer import AnalyzerError
from wireclaw_api import create_app
from wireclaw_api.config import Policy, ProviderMode
from wireclaw_api.gate4_service import Service as Gate4Service
from wireclaw_api.gate6_service import Service as Gate6Service
from wireclaw_api.gate7_service import Service
from wireclaw_api.models import CapabilityRequest, State
from wireclaw_api.providers import openai_compatible
from wireclaw_api.providers.models import ProviderResult
from wireclaw_api.reasoning import loop, persistence
from wireclaw_api.service import Service as Gate3Service
from wireclaw_api.storage import Database, Files

LEGACY_V3_SCHEMA = """
CREATE TABLE cases (
 id TEXT PRIMARY KEY, symptom TEXT NOT NULL, state TEXT NOT NULL,
 created TEXT NOT NULL, updated TEXT NOT NULL, capture_sha TEXT,
 original_id TEXT, quality TEXT, last_error TEXT,
 capture_name TEXT, display_name TEXT);
CREATE TABLE history (
 case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 seq INTEGER NOT NULL, state TEXT NOT NULL, at TEXT NOT NULL,
 PRIMARY KEY(case_id, seq));
CREATE TABLE artifacts (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, relative_path TEXT NOT NULL, sha256 TEXT NOT NULL,
 bytes INTEGER NOT NULL, parent_sha TEXT NOT NULL,
 UNIQUE(case_id, relative_path));
CREATE TABLE runs (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 request_key TEXT NOT NULL, capability TEXT NOT NULL, parameters TEXT NOT NULL,
 status TEXT NOT NULL, error TEXT, versions TEXT, configuration TEXT,
 evidence_ids TEXT, created TEXT NOT NULL);
CREATE INDEX run_requests ON runs(case_id, request_key, status);
CREATE TABLE evidence (
 case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 id TEXT NOT NULL, record TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(id),
 PRIMARY KEY(case_id, id));
CREATE TABLE deletions (case_id TEXT PRIMARY KEY, trash_path TEXT NOT NULL);
CREATE TABLE reasoning_steps (
 case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 step_id TEXT NOT NULL, sequence INTEGER NOT NULL, at TEXT NOT NULL, metadata TEXT NOT NULL,
 PRIMARY KEY(case_id, step_id), UNIQUE(case_id, sequence));
PRAGMA user_version = 3;
"""


def test_v3_capture_migration_preserves_source_and_safe_provenance(tmp_path):
    files = Files(tmp_path / "legacy")
    case_id, original_id, report_id, normalized_id = "a" * 32, "b" * 32, "c" * 32, "3" * 32
    evidence_capture_id, provenance_id = "7" * 32, "8" * 32
    failed_ingest_id, successful_ingest_id = "5" * 32, "6" * 32
    original_bytes = b"legacy source capture bytes"
    capture_sha = hashlib.sha256(original_bytes).hexdigest()
    report_sha = "e" * 64
    source_path = files.path(f"cases/{case_id}/source.pcap")
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(original_bytes)
    with sqlite3.connect(files.path("cases.sqlite3")) as conn:
        conn.executescript(LEGACY_V3_SCHEMA)
        conn.execute(
            "INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                case_id,
                "slow",
                "COMPLETE",
                "2026-01-01",
                "2026-01-02",
                capture_sha,
                original_id,
                "good",
                None,
                "trace.pcap",
                "Edge capture",
            ),
        )
        conn.execute(
            "INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "9" * 32,
                "waiting",
                "NEW",
                "2026-01-01",
                "2026-01-01",
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )
        conn.execute(
            "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?)",
            (
                original_id,
                case_id,
                "original",
                f"cases/{case_id}/source.pcap",
                capture_sha,
                len(original_bytes),
                capture_sha,
            ),
        )
        conn.execute(
            "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?)",
            (report_id, case_id, "report", "cases/report.json", report_sha, 50, capture_sha),
        )
        conn.execute(
            "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?)",
            (
                normalized_id,
                case_id,
                "normalized",
                "cases/normalized.json",
                "4" * 64,
                30,
                capture_sha,
            ),
        )
        for artifact_id, kind in (
            (evidence_capture_id, "evidence_capture"),
            (provenance_id, "evidence_provenance"),
        ):
            conn.execute(
                "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?)",
                (artifact_id, case_id, kind, f"cases/{kind}", "4" * 64, 30, capture_sha),
            )
        for run_id, status, error in (
            (failed_ingest_id, "failed", "invalid_capture"),
            (successful_ingest_id, "complete", None),
        ):
            conn.execute(
                "INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    case_id,
                    f"ingest-{status}",
                    "ingest",
                    "{}",
                    status,
                    error,
                    None,
                    None,
                    None,
                    "2026-01-01",
                ),
            )
        conn.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "f" * 32,
                case_id,
                "r1",
                "baseline",
                "{}",
                "complete",
                None,
                None,
                None,
                None,
                "2026-01-02",
            ),
        )
        conn.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "1" * 32,
                case_id,
                "r2",
                "assemble_report",
                "{}",
                "complete",
                None,
                None,
                None,
                None,
                "2026-01-02",
            ),
        )
        conn.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "2" * 32,
                case_id,
                "r3",
                "diagnostics",
                "{}",
                "complete",
                None,
                None,
                None,
                None,
                "2026-01-02",
            ),
        )
        conn.execute(
            "INSERT INTO evidence VALUES(?,?,?,?)",
            (case_id, "ev_capture", "{}", "f" * 32),
        )
        conn.execute(
            "INSERT INTO evidence VALUES(?,?,?,?)",
            (case_id, "ev_report", "{}", "1" * 32),
        )
        conn.execute(
            "INSERT INTO evidence VALUES(?,?,?,?)",
            (case_id, "ev_diagnostics", "{}", "2" * 32),
        )
        conn.execute(
            "INSERT INTO evidence VALUES(?,?,?,?)",
            (case_id, "ev_failed_ingest", "{}", failed_ingest_id),
        )
    db = Database(files)
    with db.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
        captures = [dict(row) for row in conn.execute("SELECT * FROM captures")]
        assert len(captures) == 1
        assert (
            conn.execute("SELECT count(*) FROM captures WHERE case_id=?", ("9" * 32,)).fetchone()[0]
            == 0
        )
        uncaptured = conn.execute(
            "SELECT original_id,state FROM cases WHERE id=?", ("9" * 32,)
        ).fetchone()
        assert (uncaptured["original_id"], uncaptured["state"]) == (None, "NEW")
        capture = captures[0]
        assert {
            key: capture[key]
            for key in (
                "case_id",
                "capture_name",
                "display_name",
                "original_artifact_id",
                "sha256",
                "bytes",
            )
        } == {
            "case_id": case_id,
            "capture_name": "trace.pcap",
            "display_name": "Edge capture",
            "original_artifact_id": original_id,
            "sha256": capture_sha,
            "bytes": len(original_bytes),
        }
        assert capture["vantage_type"] == "unknown"
        assert capture["status"] == "analyzed"
        assert (
            conn.execute("SELECT capture_id FROM runs WHERE id=?", (failed_ingest_id,)).fetchone()[
                0
            ]
            is None
        )
        assert (
            conn.execute(
                "SELECT capture_id FROM runs WHERE id=?", (successful_ingest_id,)
            ).fetchone()[0]
            == capture["id"]
        )
        assert (
            conn.execute("SELECT capture_id FROM artifacts WHERE id=?", (original_id,)).fetchone()[
                0
            ]
            == capture["id"]
        )
        assert (
            conn.execute(
                "SELECT capture_id FROM artifacts WHERE id=?", (normalized_id,)
            ).fetchone()[0]
            == capture["id"]
        )
        for artifact_id in (evidence_capture_id, provenance_id):
            assert (
                conn.execute(
                    "SELECT capture_id FROM artifacts WHERE id=?", (artifact_id,)
                ).fetchone()[0]
                == capture["id"]
            )
        assert (
            conn.execute("SELECT capture_id FROM artifacts WHERE id=?", (report_id,)).fetchone()[0]
            is None
        )
        assert (
            conn.execute("SELECT capture_id FROM runs WHERE id=?", ("f" * 32,)).fetchone()[0]
            == capture["id"]
        )
        assert (
            conn.execute("SELECT capture_id FROM runs WHERE id=?", ("2" * 32,)).fetchone()[0]
            == capture["id"]
        )
        assert (
            conn.execute("SELECT capture_id FROM runs WHERE id=?", ("1" * 32,)).fetchone()[0]
            is None
        )
        assert (
            conn.execute("SELECT capture_id FROM evidence WHERE id='ev_capture'").fetchone()[0]
            == capture["id"]
        )
        assert (
            conn.execute("SELECT capture_id FROM evidence WHERE id='ev_diagnostics'").fetchone()[0]
            == capture["id"]
        )
        assert (
            conn.execute("SELECT capture_id FROM evidence WHERE id='ev_report'").fetchone()[0]
            is None
        )
        assert (
            conn.execute("SELECT capture_id FROM evidence WHERE id='ev_failed_ingest'").fetchone()[
                0
            ]
            is None
        )
    Database(files)
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM captures").fetchone()[0] == 1
    assert source_path.read_bytes() == original_bytes
    service = Gate3Service(files.root, Policy())
    try:
        assert service.artifact(case_id, original_id)[1].read_bytes() == original_bytes
        assert service.get(case_id)["original_id"] == original_id
    finally:
        service.close()


def test_v4_evidence_migration_allows_same_evidence_id_per_capture(tmp_path):
    files = Files(tmp_path / "v4")
    case_id, capture_a, capture_b, run_id = "a" * 32, "b" * 32, "c" * 32, "d" * 32
    with sqlite3.connect(files.path("cases.sqlite3")) as conn:
        conn.executescript(LEGACY_V3_SCHEMA)
        conn.execute(
            "INSERT INTO cases(id,symptom,state,created,updated) VALUES(?,?,?,?,?)",
            (case_id, "slow", "NEW", "2026-01-01", "2026-01-01"),
        )
        conn.commit()
    Database(files)
    with sqlite3.connect(files.path("cases.sqlite3")) as conn:
        conn.execute(
            "INSERT INTO captures(id,case_id,capture_name,vantage_type,status,created,updated) "
            "VALUES(?,?,?,?,?,?,?)",
            (capture_a, case_id, "first.pcap", "client", "waiting", "2026-01-01", "2026-01-01"),
        )
        conn.execute(
            "INSERT INTO captures(id,case_id,capture_name,vantage_type,status,created,updated) "
            "VALUES(?,?,?,?,?,?,?)",
            (capture_b, case_id, "second.pcap", "server", "waiting", "2026-01-02", "2026-01-02"),
        )
        conn.execute(
            "INSERT INTO runs(id,case_id,request_key,capability,parameters,status,created,capture_id) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (run_id, case_id, "key", "baseline", "{}", "complete", "2026-01-02", capture_a),
        )
        conn.execute(
            "INSERT INTO evidence(case_id,id,record,run_id,capture_id) VALUES(?,?,?,?,?)",
            (case_id, "ev_same", "{}", run_id, capture_a),
        )
        conn.commit()
    db = Database(files)
    with db.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
        conn.execute(
            "INSERT INTO evidence(case_id,id,record,run_id,capture_id) VALUES(?,?,?,?,?)",
            (case_id, "ev_same", "{}", run_id, capture_b),
        )
        assert (
            conn.execute(
                "SELECT count(*) FROM evidence WHERE case_id=? AND id='ev_same'", (case_id,)
            ).fetchone()[0]
            == 2
        )


def test_capture_models_bound_names_vantage_and_subtype():
    from pydantic import ValidationError
    from wireclaw_api.models import (
        CaptureResponse,
        CaptureStatus,
        CaptureVantage,
        CreateCapture,
        UpdateCapture,
    )

    for value in ("unknown", "client", "network", "server", "other"):
        assert CreateCapture(
            capture_name="trace.pcap", vantage_type=value
        ).vantage_type == CaptureVantage(value)
    for value in (
        "Firewall",
        "Router",
        "Switch",
        "Load balancer",
        "Proxy",
        "Wireless",
        "Other network device",
    ):
        assert (
            CreateCapture(
                capture_name="trace.pcap", vantage_type="network", vantage_subtype=value
            ).vantage_subtype
            == value
        )
    assert CreateCapture(capture_name="trace.pcap").vantage_type == CaptureVantage.UNKNOWN
    assert UpdateCapture(display_name="  Edge  ").display_name == "Edge"
    assert UpdateCapture(vantage_type="network", vantage_subtype="Proxy").vantage_subtype == "Proxy"
    assert {status.value for status in CaptureStatus} == {
        "waiting",
        "preparing",
        "analyzing",
        "analyzed",
        "correlating",
        "needs_attention",
    }
    response = {
        "id": "a" * 32,
        "case_id": "b" * 32,
        "capture_name": "trace.pcap",
        "display_name": None,
        "original_artifact_id": "c" * 32,
        "sha256": "d" * 64,
        "bytes": 123,
        "vantage_type": "network",
        "vantage_subtype": "Router",
        "status": "analyzed",
        "last_error": None,
        "created": "2026-01-01",
        "updated": "2026-01-02",
    }
    assert CaptureResponse.model_validate(response).status == CaptureStatus.ANALYZED
    for kwargs in (
        {"capture_name": " "},
        {"capture_name": "x" * 256},
        {"capture_name": "trace.pcap", "vantage_type": 12},
        {"capture_name": "trace.pcap", "vantage_type": True},
        {"capture_name": "trace.pcap", "vantage_type": "device"},
        {"capture_name": "trace.pcap", "vantage_type": "client", "vantage_subtype": "Router"},
        {"capture_name": "trace.pcap", "vantage_type": "network", "vantage_subtype": "Unknown box"},
        {"capture_name": "trace.pcap", "extra": "bad"},
    ):
        with pytest.raises(ValidationError):
            CreateCapture(**kwargs)
    for kwargs in (
        {"display_name": " "},
        {"display_name": "x" * 121},
        {"display_name": 12},
        {"vantage_type": "outside"},
        {"vantage_type": "client", "vantage_subtype": "Router"},
        {"extra": "bad"},
    ):
        with pytest.raises(ValidationError):
            UpdateCapture(**kwargs)
    for change in (
        {"status": "ready"},
        {"vantage_type": "outside"},
        {"bytes": "123"},
        {"bytes": -1},
        {"sha256": "not-a-sha"},
        {"capture_name": "a\n"},
        {"display_name": "x" * 121},
        {"last_error": "x" * 257},
        {"vantage_type": "client"},
        {"extra": "bad"},
    ):
        with pytest.raises(ValidationError):
            CaptureResponse.model_validate(response | change)


def test_existing_single_capture_inserts_remain_compatible(tmp_path):
    service, case_id = prepared_service(tmp_path / "data", Policy())
    artifact_path = service.files.case(case_id) / "legacy.bin"
    artifact_path.write_bytes(b"legacy")
    with service.db.connect() as conn:
        artifact_id = service.register(conn, case_id, artifact_path, "normalized", "a" * 64)
        assert (
            conn.execute("SELECT capture_id FROM artifacts WHERE id=?", (artifact_id,)).fetchone()[
                0
            ]
            is None
        )
        assert (
            conn.execute("SELECT count(*) FROM runs WHERE case_id=?", (case_id,)).fetchone()[0] == 1
        )
        assert (
            conn.execute("SELECT count(*) FROM evidence WHERE case_id=?", (case_id,)).fetchone()[0]
            == 2
        )


def test_capture_provenance_rejects_cross_case_ids(tmp_path):
    db = Database(Files(tmp_path / "data"))
    owner_id, other_id, capture_id = "a" * 32, "b" * 32, "c" * 32
    with db.connect() as conn:
        for case_id in (owner_id, other_id):
            conn.execute(
                "INSERT INTO cases(id,symptom,state,created,updated) VALUES(?,?,?,?,?)",
                (case_id, "slow", "NEW", "2026-01-01", "2026-01-01"),
            )
        conn.execute(
            "INSERT INTO captures(id,case_id,capture_name,vantage_type,status,created,updated) "
            "VALUES(?,?,?,?,?,?,?)",
            (capture_id, owner_id, "trace.pcap", "unknown", "waiting", "2026-01-01", "2026-01-01"),
        )
        conn.execute(
            "INSERT INTO artifacts(id,case_id,kind,relative_path,sha256,bytes,parent_sha) "
            "VALUES(?,?,?,?,?,?,?)",
            ("d" * 32, other_id, "normalized", "cases/snapshot", "e" * 64, 1, "f" * 64),
        )
        conn.execute(
            "INSERT INTO runs(id,case_id,request_key,capability,parameters,status,created) "
            "VALUES(?,?,?,?,?,?,?)",
            ("1" * 32, other_id, "key", "baseline", "{}", "complete", "2026-01-01"),
        )
        conn.execute(
            "INSERT INTO evidence(case_id,id,record,run_id) VALUES(?,?,?,?)",
            (other_id, "ev", "{}", "1" * 32),
        )
        for table, row_id in (
            ("artifacts", "d" * 32),
            ("runs", "1" * 32),
            ("evidence", "ev"),
        ):
            with pytest.raises(sqlite3.IntegrityError, match="capture_case_mismatch"):
                conn.execute(f"UPDATE {table} SET capture_id=? WHERE id=?", (capture_id, row_id))
        with pytest.raises(sqlite3.IntegrityError, match="capture_case_mismatch"):
            conn.execute(
                "INSERT INTO artifacts(id,case_id,kind,relative_path,sha256,bytes,parent_sha,"
                "capture_id) VALUES(?,?,?,?,?,?,?,?)",
                (
                    "2" * 32,
                    other_id,
                    "normalized",
                    "cases/other",
                    "e" * 64,
                    1,
                    "f" * 64,
                    capture_id,
                ),
            )


def prepared_service(tmp_path, policy):
    service = Service(tmp_path, policy)
    case = service.create("A slow HTTP transaction")
    case_id = case["id"]
    capture_sha = "a" * 64
    artifact_id = "b" * 32
    with service.db.connect() as conn:
        conn.execute(
            "UPDATE cases SET capture_sha=?,original_id=? WHERE id=?",
            (capture_sha, artifact_id, case_id),
        )
    run_id, _ = service.start(case_id, "seed", {})
    evidence = [
        {
            "schema_version": "1.0",
            "id": f"ev_{capture_sha}_assess_capture_quality",
            "category": "assess_capture_quality",
            "epistemic_class": "derived",
            "source": {"capability": "assess_capture_quality", "tool": "tshark", "version": "test"},
            "scope": {"capture": True},
            "value": {"capture_sha256": capture_sha, "state": "good", "limitations": []},
            "summary": "capture quality",
            "limitations": [],
        },
        {
            "schema_version": "1.0",
            "id": f"ev_{capture_sha}_list_conversations",
            "category": "list_conversations",
            "epistemic_class": "derived",
            "source": {"capability": "list_conversations", "tool": "tshark", "version": "test"},
            "scope": {"capture": True},
            "value": {"capture_sha256": capture_sha, "conversations": []},
            "summary": "conversation inventory",
            "limitations": [],
        },
    ]
    service.save(
        case_id,
        run_id,
        {
            "schema_version": "1.0",
            "capture_sha256": capture_sha,
            "analyzer_version": "test",
            "tool_versions": {},
            "configuration": {},
            "evidence": evidence,
        },
    )
    for state in (
        State.INGESTING,
        State.VALIDATING_CAPTURE,
        State.BASELINE_ANALYSIS,
        State.INVESTIGATING,
    ):
        service.transition(case_id, state)
    return service, case_id


class ScriptedCycleProvider:
    def __init__(self, actions):
        self.actions = iter(actions)
        self.requests = []

    def propose(self, request):
        self.requests.append(request)
        return ProviderResult(content=json.dumps(next(self.actions)))


def capability_action(name="analyze_dns"):
    return {"action": "request_capability", "capability": name, "parameters": {}}


def finalize_action():
    return {"action": "finalize", "hypotheses": [], "remaining_hypotheses": []}


def test_async_capture_executes_embedded_status_probe_off_the_event_loop(tmp_path, monkeypatch):
    model_id = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    token = "ASYNC_CAPTURE_STATUS_TOKEN_SENTINEL_" + "x" * 32
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model=model_id,
        provider_api_key=token,
    )
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")

    requests = []
    probe_threads = []
    real_client = httpx.AsyncClient

    async def healthy_model_server(request):
        requests.append(request)
        return httpx.Response(200, json={"data": [{"id": model_id}]})

    transport = httpx.MockTransport(healthy_model_server)

    def client_factory(*args, **kwargs):
        return real_client(*args, transport=transport, **kwargs)

    real_probe = openai_compatible.embedded_runtime_available

    def observed_probe(current_policy):
        probe_threads.append(get_ident())
        return real_probe(current_policy)

    monkeypatch.setattr(openai_compatible.httpx, "AsyncClient", client_factory)
    monkeypatch.setattr(gate7_module, "embedded_runtime_available", observed_probe)

    app = create_app(tmp_path / "async-capture", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        service = client.app.state.service

        def complete_fake_ingest(case_id, run_id, path):
            capture_sha = hashlib.sha256(path.read_bytes()).hexdigest()
            service.transition(case_id, State.VALIDATING_CAPTURE)
            with service.db.connect() as conn:
                conn.execute(
                    "UPDATE cases SET capture_sha=?,original_id=? WHERE id=?",
                    (capture_sha, "c" * 32, case_id),
                )
                conn.execute("UPDATE runs SET status='complete' WHERE id=?", (run_id,))
            service.transition(case_id, State.BASELINE_ANALYSIS)
            return service.get(case_id)

        service.ingest = complete_fake_ingest
        created = client.post("/api/cases", json={"symptom": "A slow connection"})
        assert created.status_code == 201
        requests.clear()
        probe_threads.clear()

        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always", RuntimeWarning)
            uploaded = client.post(
                f"/api/cases/{created.json()['id']}/capture",
                content=b"synthetic capture bytes",
                headers={"content-type": "application/octet-stream"},
            )
            gc.collect()

    unawaited_warnings = [
        str(item.message) for item in caught_warnings if "was never awaited" in str(item.message)
    ]
    assert len(requests) == 2, (
        "expected embedded model probes in begin_ingest and threaded ingest; "
        f"observed {len(requests)} requests and warnings {unawaited_warnings}"
    )
    assert not unawaited_warnings
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["state"] == State.BASELINE_ANALYSIS
    assert len(probe_threads) == 2
    assert all(request.headers["authorization"] == f"Bearer {token}" for request in requests)


def test_async_capture_cleanup_executes_embedded_status_probe_off_the_event_loop(
    tmp_path, monkeypatch
):
    model_id = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model=model_id,
        provider_api_key="ASYNC_CAPTURE_CLEANUP_TOKEN_SENTINEL_" + "x" * 32,
    )
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")

    requests = []
    real_client = httpx.AsyncClient

    async def healthy_model_server(request):
        requests.append(request)
        return httpx.Response(200, json={"data": [{"id": model_id}]})

    transport = httpx.MockTransport(healthy_model_server)
    monkeypatch.setattr(
        openai_compatible.httpx,
        "AsyncClient",
        lambda *args, **kwargs: real_client(*args, transport=transport, **kwargs),
    )
    monkeypatch.setattr(
        gate7_module, "embedded_runtime_available", openai_compatible.embedded_runtime_available
    )

    app = create_app(tmp_path / "async-capture-cleanup", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        service = client.app.state.service

        def fail_ingest(_case_id, _run_id, _path):
            raise AnalyzerError("synthetic_ingest_failure")

        service.ingest = fail_ingest
        created = client.post("/api/cases", json={"symptom": "A slow connection"})
        assert created.status_code == 201
        case_id = created.json()["id"]
        requests.clear()

        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always", RuntimeWarning)
            uploaded = client.post(
                f"/api/cases/{case_id}/capture",
                content=b"synthetic capture bytes",
                headers={"content-type": "application/octet-stream"},
            )
            gc.collect()
        with service.db.connect() as conn:
            failed_state = conn.execute(
                "SELECT state FROM cases WHERE id=?", (case_id,)
            ).fetchone()["state"]

    unawaited_warnings = [
        str(item.message) for item in caught_warnings if "was never awaited" in str(item.message)
    ]
    assert len(requests) == 2, (
        "expected embedded model probes in begin_ingest and cleanup_ingest; "
        f"observed {len(requests)} requests and warnings {unawaited_warnings}"
    )
    assert not unawaited_warnings
    assert uploaded.status_code == 422
    assert failed_state == State.FAILED


def install_cycle_runner(monkeypatch, providers, capability_calls):
    provider_iter = iter(providers)
    monkeypatch.setattr(loop, "make_provider", lambda _policy: next(provider_iter))

    def run_capability(_case_id, request):
        capability_calls.append(request.capability)
        return {"evidence": []}

    def investigate(self, case_id):
        if self.get(case_id)["state"] in (State.COMPLETE, State.FAILED):
            self.transition(case_id, State.BASELINE_ANALYSIS)
            self.transition(case_id, State.INVESTIGATING)
        return self._assemble_report(case_id)

    monkeypatch.setattr(Gate4Service, "investigate", investigate)
    return run_capability


def test_first_model_assisted_investigation_persists_reconstructable_step_audit(
    tmp_path, monkeypatch
):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
        provider_api_key="API_KEY_SENTINEL",
        max_reasoning_steps=2,
    )
    service, case_id = prepared_service(tmp_path, policy)
    final_with_response_sentinel = {
        **finalize_action(),
        "hypotheses": [
            {
                "category": "unsupported.category",
                "evidence_ids": [],
                "fault_domains": [],
                "summary": "RAW_RESPONSE_SENTINEL",
            }
        ],
    }
    provider = ScriptedCycleProvider([capability_action(), final_with_response_sentinel])
    calls = []
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], calls)
    with service.db.connect() as conn:
        conn.execute(
            "UPDATE cases SET symptom=? WHERE id=?",
            ("RAW_PROMPT_SENTINEL /private/case.pcap", case_id),
        )
    try:
        service.investigate(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)
        assert report["reasoning"]["mode"] == "model_assisted"
        assert report["reasoning"]["steps"] == 2
        assert len(records) == 2
        first = records[0]
        assert first["case_id"] == case_id
        assert first["step_id"]
        assert first["sequence"] == 1
        assert first["at"]
        assert first["provider_mode"] == ProviderMode.LOCAL.value
        assert first["model"] == "cycle-model"
        assert first["endpoint_class"] == "local"
        assert len(first["context_digest"]) == 64
        assert first["action_type"] == "request_capability"
        assert first["capability"] == "analyze_dns"
        assert first["parameters"] == {}
        assert first["request_fingerprint"]
        assert first["resulting_evidence_ids"] == []
        assert first["status"] == "complete"
        assert first["failure_code"] is None
        assert isinstance(first["duration_ms"], int)
        assert first["reasoning_session_id"] == records[1]["reasoning_session_id"]
        serialized_history = json.dumps(records)
        for sentinel in (
            "API_KEY_SENTINEL",
            "RAW_PROMPT_SENTINEL",
            "/private/case.pcap",
            "Authorization",
            "RAW_RESPONSE_SENTINEL",
        ):
            assert sentinel not in serialized_history
    finally:
        service.close()


def test_finalize_recommendations_cannot_outgrow_deterministic_hypotheses(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    evidence = service.evidence_records(case_id)
    deterministic = service.build_investigation_result(
        case_id=case_id,
        symptom=service.get(case_id)["symptom"],
        evidence=evidence,
        analyzer_versions=service.analyzer_versions(case_id),
        max_display_filter_chars=policy.max_display_filter_chars,
    )
    prose_sentinel = "ATTACKER_NEXT_EVIDENCE_SENTINEL: assert an unrelated breach"
    action = {
        "action": "finalize",
        "hypotheses": [],
        "remaining_hypotheses": [
            {
                "category": "server.application_wait",
                "evidence_ids": [],
                "fault_domains": ["server_application"],
                "next_evidence": [prose_sentinel, "browser_har"],
            }
        ],
    }
    provider = ScriptedCycleProvider([action])
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)

        assert report["remaining_hypotheses"] == deterministic["remaining_hypotheses"]
        assert prose_sentinel not in json.dumps(report)
        assert prose_sentinel not in json.dumps(records)
        assert (
            "Capture a browser HAR for the same user-visible transaction."
            not in report["recommended_next_evidence"]
        )
        assert records[-1]["next_evidence_codes"] == []

        monkeypatch.setattr(api_module, "Service", lambda *_args: service)
        app = create_app(tmp_path / "recommendation-api", policy)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            api_report = client.get(f"/api/cases/{case_id}/report")
            assert api_report.status_code == 200
            assert prose_sentinel not in api_report.text
            assert "Capture a browser HAR for the same user-visible transaction." not in (
                api_report.text
            )
    finally:
        service.close()


def test_model_omission_cannot_remove_deterministic_finding(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    deterministic_finding = {
        "id": "finding_deterministic_rtt",
        "title": "Measured RTT",
        "category": "tcp.rtt",
        "confidence": "medium",
        "statement": "The deterministic baseline measured elevated RTT.",
        "epistemic_class": "inferred",
        "fault_domains": ["network_path"],
        "affected_scope": {},
        "evidence_ids": [service.evidence_records(case_id)[0]["id"]],
        "alternate_explanations": [],
        "limitations": [],
        "recommended_validation": [],
        "wireshark": {
            "applicable": False,
            "full_capture": False,
            "evidence_capture": False,
            "copy_filter": False,
            "show_packet_evidence": False,
            "display_filter": None,
        },
    }

    def build_with_deterministic_finding(**kwargs):
        report = build_investigation_result(**kwargs)
        report["findings"] = [deterministic_finding]
        return report

    from wireclaw_api import gate4_service, gate7_service
    from wireclaw_api.investigation import build_investigation_result

    monkeypatch.setattr(
        gate7_service, "build_investigation_result", build_with_deterministic_finding
    )
    monkeypatch.setattr(
        gate4_service, "build_investigation_result", build_with_deterministic_finding
    )
    provider = ScriptedCycleProvider([finalize_action()])
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)

        assert report["reasoning"]["mode"] == "model_assisted"
        assert report["reasoning"]["accepted_categories"] == []
        assert report["findings"] == [deterministic_finding]
    finally:
        service.close()


def test_remaining_recommendation_rejects_evidence_from_another_finding(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    evidence = service.evidence_records(case_id)
    unrelated_evidence_id = evidence[0]["id"]
    related_evidence_id = evidence[1]["id"]
    assert evidence[0]["epistemic_class"] in {"observed", "derived"}
    assert evidence[1]["epistemic_class"] in {"observed", "derived"}

    def report_with_unrelated_finding_evidence(**kwargs):
        report = build_investigation_result(**kwargs)
        report["findings"] = [
            {
                "id": "finding_review_other",
                "title": "Unrelated deterministic finding",
                "category": "tcp.rtt",
                "confidence": "medium",
                "statement": "This finding owns the cited evidence.",
                "epistemic_class": "inferred",
                "fault_domains": ["server_application"],
                "affected_scope": {},
                "evidence_ids": [unrelated_evidence_id],
                "alternate_explanations": [],
                "limitations": [],
                "recommended_validation": [],
                "wireshark": {
                    "applicable": False,
                    "full_capture": False,
                    "evidence_capture": False,
                    "copy_filter": False,
                    "show_packet_evidence": False,
                    "display_filter": None,
                },
            }
        ]
        report["remaining_hypotheses"] = [
            {
                "statement": "A deterministic server wait remains unresolved.",
                "fault_domains": ["server_application"],
                "evidence_ids": [related_evidence_id],
                "next_evidence": [],
            }
        ]
        return report

    from wireclaw_api import gate7_service
    from wireclaw_api.investigation import build_investigation_result

    monkeypatch.setattr(
        gate7_service, "build_investigation_result", report_with_unrelated_finding_evidence
    )
    prose_sentinel = "MODEL_RECOMMENDATION_PROSE_SENTINEL"
    provider = ScriptedCycleProvider(
        [
            {
                "action": "finalize",
                "hypotheses": [],
                "remaining_hypotheses": [
                    {
                        "category": "server.application_wait",
                        "evidence_ids": [unrelated_evidence_id],
                        "fault_domains": ["server_application"],
                        "next_evidence": ["server_side_capture", prose_sentinel],
                    }
                ],
            }
        ]
    )
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)
        deterministic = report_with_unrelated_finding_evidence(
            case_id=case_id,
            symptom=service.get(case_id)["symptom"],
            evidence=evidence,
            analyzer_versions=service.analyzer_versions(case_id),
            max_display_filter_chars=policy.max_display_filter_chars,
        )
        assert unrelated_evidence_id in evidence[0]["id"]
        assert unrelated_evidence_id in deterministic["findings"][0]["evidence_ids"]
        assert unrelated_evidence_id not in deterministic["remaining_hypotheses"][0]["evidence_ids"]
        assert report["reasoning"]["mode"] == "model_assisted"
        assert records[-1]["next_evidence_codes"] == []
        assert prose_sentinel not in json.dumps(report)
        assert (
            "Collect a synchronized server-side capture for the same transaction."
            not in (report["recommended_next_evidence"])
        )
    finally:
        service.close()


def test_valid_hypothesis_summary_sentinel_is_not_persisted_or_exposed(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="review-model",
        provider_api_key="x" * 32,
    )
    service, case_id = prepared_service(tmp_path, policy)
    evidence = service.evidence_records(case_id)
    evidence_id = evidence[0]["id"]
    sentinel = "MODEL_SUMMARY_SENTINEL: claim a fabricated packet fact"

    def report_with_supported_test_finding(**kwargs):
        report = build_investigation_result(**kwargs)
        report["findings"] = [
            {
                "id": "finding_review_test",
                "title": "Review test finding",
                "category": "tcp.rtt",
                "confidence": "medium",
                "statement": "The test evidence supports a bounded finding.",
                "epistemic_class": "inferred",
                "fault_domains": ["network_path"],
                "affected_scope": {},
                "evidence_ids": [evidence_id],
                "alternate_explanations": [],
                "limitations": [],
                "recommended_validation": [],
                "wireshark": {
                    "applicable": False,
                    "full_capture": False,
                    "evidence_capture": False,
                    "copy_filter": False,
                    "show_packet_evidence": False,
                    "display_filter": None,
                },
            }
        ]
        return report

    from wireclaw_api import gate4_service, gate7_service
    from wireclaw_api.investigation import build_investigation_result

    monkeypatch.setattr(
        gate7_service, "build_investigation_result", report_with_supported_test_finding
    )
    monkeypatch.setattr(
        gate4_service, "build_investigation_result", report_with_supported_test_finding
    )
    provider = ScriptedCycleProvider(
        [
            {
                "action": "finalize",
                "hypotheses": [
                    {
                        "category": "tcp.rtt",
                        "evidence_ids": [evidence_id],
                        "fault_domains": ["network_path"],
                        "summary": sentinel,
                    }
                ],
                "remaining_hypotheses": [],
            }
        ]
    )
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])

    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        records = persistence.steps(service, case_id)
        _, report_path = service.artifact(case_id, service._report_row(case_id)["id"])

        assert report["reasoning"]["accepted_categories"] == ["tcp.rtt"]
        assert sentinel not in json.dumps(records)
        assert sentinel not in json.dumps(service.get(case_id))
        assert sentinel not in json.dumps(report)
        assert sentinel.encode() not in report_path.read_bytes()

        monkeypatch.setattr(api_module, "Service", lambda *_args: service)
        app = create_app(tmp_path / "review-api", policy)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            api_report = client.get(f"/api/cases/{case_id}/report")
            assert api_report.status_code == 200
            assert sentinel not in api_report.text
            api_case = client.get(f"/api/cases/{case_id}")
            assert api_case.status_code == 200
            assert sentinel not in api_case.text
    finally:
        service.close()


def test_reinvestigation_uses_fresh_cycle_and_preserves_previous_audit(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
        max_reasoning_steps=2,
    )
    service, case_id = prepared_service(tmp_path, policy)
    repeated_capability = capability_action()
    first_provider = ScriptedCycleProvider([repeated_capability, finalize_action()])
    second_provider = ScriptedCycleProvider([repeated_capability, finalize_action()])
    calls = []
    service.run_reasoning_capability = install_cycle_runner(
        monkeypatch, [first_provider, second_provider], calls
    )
    try:
        service.investigate(case_id)
        first_records = persistence.steps(service, case_id)
        first_session = first_records[0]["reasoning_session_id"]
        assert len(first_records) == 2

        service.investigate(case_id)
        all_records = persistence.steps(service, case_id)
        second_records = [
            row for row in all_records if row["reasoning_session_id"] != first_session
        ]
        assert len(all_records) == 4
        assert len(second_records) == 2
        assert calls == ["analyze_dns", "analyze_dns"]
        assert first_records[0]["request_fingerprint"] == second_records[0]["request_fingerprint"]
        assert first_session != second_records[0]["reasoning_session_id"]
        assert service.report(case_id)["reasoning"]["steps"] == 2
        assert service.report(case_id)["reasoning"]["mode"] == "model_assisted"
    finally:
        service.close()


def test_step_limit_is_applied_independently_to_each_reasoning_cycle(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
        max_reasoning_steps=2,
    )
    service, case_id = prepared_service(tmp_path, policy)
    first_provider = ScriptedCycleProvider([capability_action(), finalize_action()])
    second_provider = ScriptedCycleProvider(
        [capability_action(), capability_action("analyze_tls_handshakes")]
    )
    calls = []
    service.run_reasoning_capability = install_cycle_runner(
        monkeypatch, [first_provider, second_provider], calls
    )
    try:
        service.investigate(case_id)
        service.investigate(case_id)
        records = persistence.steps(service, case_id)
        sessions = {record["reasoning_session_id"] for record in records}
        assert len(sessions) == 2
        assert [
            sum(row["reasoning_session_id"] == session for row in records) for session in sessions
        ] == [2, 2]
        assert calls == ["analyze_dns", "analyze_dns", "analyze_tls_handshakes"]
        assert service.report(case_id)["reasoning"]["mode"] == "model_fallback"
        assert service.report(case_id)["reasoning"]["steps"] == 2
        assert service.report(case_id)["reasoning"]["failure_code"] == "reasoning_step_limit"
    finally:
        service.close()


def test_completed_case_capability_rebuild_preserves_reasoning_history(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
    )
    service, case_id = prepared_service(tmp_path, policy)
    providers = [
        ScriptedCycleProvider([finalize_action()]),
        ScriptedCycleProvider([finalize_action()]),
    ]
    calls = []
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, providers, calls)
    external_capability_calls = []

    def complete_capability(self, case, request):
        external_capability_calls.append(request.capability)
        self.transition(case, State.BASELINE_ANALYSIS)
        self.transition(case, State.INVESTIGATING)
        self._assemble_report(case)
        return {"ok": True}

    monkeypatch.setattr(Gate6Service, "capability", complete_capability)
    try:
        service.investigate(case_id)
        prior = persistence.steps(service, case_id)
        assert len(prior) == 1
        service.capability(
            case_id,
            CapabilityRequest(artifact_id="b" * 32, capability="analyze_dns"),
        )
        history = persistence.steps(service, case_id)
        assert len(history) == 2
        assert history[0]["reasoning_session_id"] != history[1]["reasoning_session_id"]
        assert service.report(case_id)["reasoning"]["steps"] == 1
        assert external_capability_calls == ["analyze_dns"]
        assert len(calls) == 0
    finally:
        service.close()


def test_case_deletion_cascades_all_reasoning_cycles(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.LOCAL,
        provider_base_url="http://127.0.0.1:1234/v1",
        provider_model="cycle-model",
    )
    service, case_id = prepared_service(tmp_path, policy)
    providers = [
        ScriptedCycleProvider([finalize_action()]),
        ScriptedCycleProvider([finalize_action()]),
    ]
    calls = []
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, providers, calls)
    try:
        # Two report cycles exercise the same cascade regardless of case state.
        service._assemble_report(case_id)
        service.transition(case_id, State.BASELINE_ANALYSIS)
        service.transition(case_id, State.INVESTIGATING)
        service._assemble_report(case_id)
        assert len(persistence.steps(service, case_id)) == 2
        service.delete(case_id)
        with service.db.connect() as conn:
            assert (
                conn.execute(
                    "SELECT count(*) FROM reasoning_steps WHERE case_id=?", (case_id,)
                ).fetchone()[0]
                == 0
            )
    finally:
        service.close()


def test_rules_only_report_exposes_mode_and_keeps_database_reasoning_table(tmp_path):
    service, case_id = prepared_service(tmp_path, Policy())
    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        assert report["reasoning"] == {
            "mode": "rules_only",
            "status": "complete",
            "steps": 0,
            "provider_mode": "none",
            "model": None,
            "embedded_availability": "not_applicable",
            "embedded_failure_code": None,
        }
        with service.db.connect() as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
            assert conn.execute("SELECT count(*) FROM reasoning_steps").fetchone()[0] == 0
    finally:
        service.close()


def test_embedded_health_and_capabilities_expose_safe_ready_status(tmp_path, monkeypatch):
    token = "API_KEY_SENTINEL_" + "x" * 40
    path_sentinel = "/private/model/path/SECRET.gguf"
    from wireclaw_api import gate7_service

    monkeypatch.setattr(gate7_service, "embedded_runtime_available", lambda _policy: True)
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key=token,
    )
    app = create_app(tmp_path / "api", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        health = client.get("/api/health").json()
        capabilities = client.get("/api/config/capabilities").json()
    for value in (health, capabilities):
        encoded = json.dumps(value)
        assert token not in encoded
        assert path_sentinel not in encoded
        assert "Authorization" not in encoded
        assert value["ai"] == {
            "effective_provider_mode": "embedded_local",
            "embedded_availability": "ready",
            "model": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
            "failure_code": None,
        }


def test_embedded_health_tracks_runtime_loss_and_recovery_without_investigation(
    tmp_path, monkeypatch
):
    token = "RUNTIME_STATUS_TOKEN_SENTINEL_" + "x" * 40
    model_id = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    reachability = {"ready": True, "calls": 0}

    def runtime_probe(_policy):
        reachability["calls"] += 1
        return reachability["ready"]

    from wireclaw_api import gate7_service

    monkeypatch.setattr(gate7_service, "embedded_runtime_available", runtime_probe, raising=False)
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model=model_id,
        provider_api_key=token,
    )
    app = create_app(tmp_path / "runtime-status", policy)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        ready_health = client.get("/api/health").json()
        ready_capabilities = client.get("/api/config/capabilities").json()
        assert ready_health["ai"]["embedded_availability"] == "ready"
        assert ready_capabilities["ai"]["embedded_availability"] == "ready"

        # Model-server process loss is injected after startup readiness. No case
        # investigation or provider completion is performed before these checks.
        reachability["ready"] = False
        unavailable_health_response = client.get("/api/health")
        unavailable_health = unavailable_health_response.json()
        unavailable_capabilities_response = client.get("/api/config/capabilities")
        unavailable_capabilities = unavailable_capabilities_response.json()

        assert unavailable_health_response.status_code == 200
        assert unavailable_health["status"] == "ok"
        assert unavailable_health["ai"]["embedded_availability"] == "unavailable"
        assert unavailable_health["ai"]["effective_provider_mode"] == "none"
        assert unavailable_capabilities["ai"] == unavailable_health["ai"]
        assert token not in unavailable_health_response.text
        assert token not in unavailable_capabilities_response.text
        assert "host.docker.internal" not in unavailable_health_response.text
        assert reachability["calls"] == 4

        created = client.post("/api/cases", json={"symptom": "A slow transaction"})
        assert created.status_code == 201
        case_status = client.get(f"/api/cases/{created.json()['id']}")
        assert case_status.status_code == 200
        assert case_status.json()["ai_status"] == unavailable_health["ai"]
        assert token not in case_status.text

        reachability["ready"] = True
        recovered_health = client.get("/api/health").json()
        assert recovered_health["ai"]["embedded_availability"] == "ready"


def test_launcher_unavailable_status_does_not_change_core_health(tmp_path, monkeypatch):
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "unavailable:docker-connectivity")
    app = create_app(tmp_path / "api", Policy())
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        health_response = client.get("/api/health")
        health = health_response.json()
    assert health_response.status_code == 200
    assert health["status"] == "ok"
    assert health["ai"] == {
        "effective_provider_mode": "none",
        "embedded_availability": "unavailable",
        "model": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        "failure_code": "docker-connectivity",
    }


def test_embedded_reasoning_audit_records_model_and_launcher_fallback_without_secrets(
    tmp_path, monkeypatch
):
    token = "API_KEY_SENTINEL_" + "x" * 40
    from wireclaw_api import gate7_service

    monkeypatch.setattr(gate7_service, "embedded_runtime_available", lambda _policy: True)
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key=token,
        max_reasoning_steps=1,
    )
    service, case_id = prepared_service(tmp_path / "embedded", policy)
    provider = ScriptedCycleProvider([finalize_action()])
    service.run_reasoning_capability = install_cycle_runner(monkeypatch, [provider], [])
    service._assemble_report(case_id)
    assisted = service.report(case_id)
    assert assisted["reasoning"]["provider_mode"] == "embedded_local"
    assert assisted["reasoning"]["model"] == "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
    assert assisted["reasoning"]["embedded_availability"] == "ready"
    assert token not in json.dumps(assisted)

    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "unavailable:docker-connectivity")
    rules_service, rules_case = prepared_service(tmp_path / "rules", Policy())
    rules_service._assemble_report(rules_case)
    fallback = rules_service.report(rules_case)
    assert fallback["reasoning"]["mode"] == "rules_only"
    assert fallback["reasoning"]["embedded_availability"] == "unavailable"
    assert fallback["reasoning"]["embedded_failure_code"] == "docker-connectivity"


def test_embedded_runtime_failure_state_is_initialized_before_recovery(tmp_path, monkeypatch):
    original_recover = Gate3Service.recover

    def recover_during_parent_init(self):
        assert self._embedded_runtime_failure_code is None
        return original_recover(self)

    monkeypatch.setattr(Gate3Service, "recover", recover_during_parent_init)
    service = Service(tmp_path, Policy())
    service.close()


def test_embedded_provider_failure_degrades_health_and_case_ai_status(tmp_path, monkeypatch):
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    policy = Policy(
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key="ephemeral-test-token-" + "x" * 40,
        max_reasoning_steps=1,
    )
    service, case_id = prepared_service(tmp_path / "embedded-crash", policy)

    class FailedProvider:
        def propose(self, _request):
            return ProviderResult(failure_code="provider_unavailable")

    monkeypatch.setattr(loop, "make_provider", lambda _policy: FailedProvider())
    service._assemble_report(case_id)

    expected = {
        "effective_provider_mode": "none",
        "embedded_availability": "unavailable",
        "model": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        "failure_code": "runtime-unhealthy",
    }
    assert service.ai_status() == expected
    assert service.get(case_id)["ai_status"] == expected
    assert service.report(case_id)["reasoning"]["embedded_availability"] == "unavailable"
    monkeypatch.setattr(api_module, "Service", lambda *_args: service)
    app = create_app(tmp_path / "embedded-crash-api", policy)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        assert client.get("/api/health").json()["ai"] == expected
        assert client.get("/api/config/capabilities").json()["ai"] == expected


def test_provider_timeout_persists_bounded_audit_and_keeps_report_usable(tmp_path, monkeypatch):
    policy = Policy(
        provider_mode=ProviderMode.CLOUD,
        provider_base_url="https://provider.example/v1",
        provider_model="fake-model",
        provider_api_key="API_KEY_SENTINEL",
    )
    service, case_id = prepared_service(tmp_path, policy)

    class TimeoutProvider:
        def propose(self, request):
            return ProviderResult(failure_code="provider_timeout")

    monkeypatch.setattr(loop, "make_provider", lambda _policy: TimeoutProvider())
    try:
        service._assemble_report(case_id)
        report = service.report(case_id)
        assert report["reasoning"]["mode"] == "model_fallback"
        assert report["reasoning"]["failure_code"] == "provider_timeout"
        assert any("provider_timeout" in item for item in report["limitations"])
        with service.db.connect() as conn:
            metadata = conn.execute(
                "SELECT metadata FROM reasoning_steps WHERE case_id=?", (case_id,)
            ).fetchone()[0]
            runs = json.dumps(
                [
                    dict(row)
                    for row in conn.execute("SELECT * FROM runs WHERE case_id=?", (case_id,))
                ]
            )
        assert "API_KEY_SENTINEL" not in metadata
        assert "API_KEY_SENTINEL" not in runs
        assert "API_KEY_SENTINEL" not in json.dumps(report)
        assert service.evidence_records(case_id)
    finally:
        service.close()


# Follow-up turns are explanatory, stateless, and never part of persisted reasoning.
def followup_client(tmp_path, monkeypatch, result=None, *, mode=ProviderMode.LOCAL):
    policy = Policy(
        provider_mode=mode,
        provider_base_url="http://127.0.0.1:1234/v1" if mode is not ProviderMode.NONE else None,
        provider_model="followup-model" if mode is not ProviderMode.NONE else None,
    )
    service, case_id = prepared_service(tmp_path, policy)
    # Seed a completed deterministic report without making any provider request.
    Gate6Service._assemble_report(service, case_id)
    requests = []

    class Provider:
        def propose(self, request):
            requests.append(request)
            if isinstance(result, Exception):
                raise result
            return result or ProviderResult(
                content=json.dumps(
                    {
                        "answer": "The available evidence cannot answer this question.",
                        "evidence_ids": [],
                    }
                )
            )

    monkeypatch.setattr(loop, "make_provider", lambda _policy: Provider())
    monkeypatch.setattr(api_module, "Service", lambda *_args: service)
    return (
        TestClient(create_app(tmp_path, policy), base_url="http://127.0.0.1:8765"),
        service,
        case_id,
        requests,
    )


def test_followup_provider_receives_timeout_configured_from_environment(tmp_path, monkeypatch):
    for key in (
        "WIRECLAW_PUBLIC_PORT",
        "WIRECLAW_BRIDGE_PORT",
        "WIRECLAW_PROVIDER_MODE",
        "WIRECLAW_PROVIDER_BASE_URL",
        "WIRECLAW_PROVIDER_MODEL",
        "WIRECLAW_PROVIDER_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WIRECLAW_PROVIDER_MODE", "openai_compatible_local")
    monkeypatch.setenv("WIRECLAW_PROVIDER_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("WIRECLAW_PROVIDER_MODEL", "followup-model")
    monkeypatch.setenv("WIRECLAW_PROVIDER_TIMEOUT_SECONDS", "120")
    policy = Policy.from_environment()
    service, case_id = prepared_service(tmp_path, policy)
    Gate6Service._assemble_report(service, case_id)
    configured_timeouts = []
    original_make_provider = loop.make_provider

    class Provider:
        def propose(self, _request):
            return ProviderResult(
                content=json.dumps(
                    {
                        "answer": "The available evidence cannot answer this question.",
                        "evidence_ids": [],
                    }
                )
            )

    def make_provider(configured_policy):
        configured_provider = original_make_provider(configured_policy)
        configured_timeouts.append(configured_provider.timeout_seconds)
        return Provider()

    monkeypatch.setattr(loop, "make_provider", make_provider)
    monkeypatch.setattr(api_module, "Service", lambda *_args: service)
    client = TestClient(create_app(tmp_path, policy), base_url="http://127.0.0.1:8765")
    with client:
        response = client.post(
            f"/api/cases/{case_id}/followups", json={"question": "Why was this slow?"}
        )

    assert response.status_code == 200, response.text
    assert configured_timeouts == [120]


def assert_followup_error(client, case_id, status, code, body=None):
    response = client.post(f"/api/cases/{case_id}/followups", json=body or {"question": "Why?"})
    assert response.status_code == status, response.text
    assert response.json() == {"error": {"code": code}}


def test_followup_unknown_case_returns_404_case_not_found(tmp_path, monkeypatch):
    client, _, _, _ = followup_client(tmp_path, monkeypatch)
    with client:
        assert_followup_error(client, "f" * 32, 404, "case_not_found")


def test_followup_incomplete_report_returns_409_report_not_ready(tmp_path, monkeypatch):
    client, service, case_id, _ = followup_client(tmp_path, monkeypatch)
    with client:
        service.transition(case_id, State.BASELINE_ANALYSIS)
        assert_followup_error(client, case_id, 409, "report_not_ready")


def test_followup_missing_report_returns_404_report_not_found(tmp_path, monkeypatch):
    client, service, case_id, _ = followup_client(tmp_path, monkeypatch)
    with client:
        with service.db.connect() as conn:
            conn.execute("DELETE FROM artifacts WHERE case_id=? AND kind='report'", (case_id,))
        assert_followup_error(client, case_id, 404, "report_not_found")


def test_followup_rules_only_returns_409_followup_unavailable(tmp_path, monkeypatch):
    client, _, case_id, requests = followup_client(tmp_path, monkeypatch, mode=ProviderMode.NONE)
    with client:
        assert_followup_error(client, case_id, 409, "followup_unavailable")
        assert requests == []


def test_followup_provider_unavailable_returns_503_without_details(tmp_path, monkeypatch):
    client, _, case_id, _ = followup_client(tmp_path, monkeypatch, RuntimeError("PRIVATE_SECRET"))
    with client:
        assert_followup_error(client, case_id, 503, "provider_unavailable")


def test_followup_provider_timeout_returns_504_provider_timeout(tmp_path, monkeypatch):
    client, _, case_id, _ = followup_client(
        tmp_path, monkeypatch, ProviderResult(failure_code="provider_timeout")
    )
    with client:
        assert_followup_error(client, case_id, 504, "provider_timeout")


def test_followup_malformed_provider_response_returns_502_followup_response_invalid(
    tmp_path, monkeypatch
):
    client, _, case_id, _ = followup_client(
        tmp_path, monkeypatch, ProviderResult(content="SECRET_NOT_JSON")
    )
    with client:
        assert_followup_error(client, case_id, 502, "followup_response_invalid")


def test_followup_invalid_citations_return_502_followup_response_invalid(tmp_path, monkeypatch):
    client, _, case_id, _ = followup_client(
        tmp_path,
        monkeypatch,
        ProviderResult(content=json.dumps({"answer": "Claim", "evidence_ids": ["other-case-id"]})),
    )
    with client:
        assert_followup_error(client, case_id, 502, "followup_response_invalid")


def test_followup_rejects_cited_evidence_ids_in_answer_prose(tmp_path, monkeypatch):
    client, service, case_id, _ = followup_client(tmp_path, monkeypatch)
    evidence_id = service.evidence_records(case_id)[0]["id"]

    class Provider:
        def propose(self, _request):
            return ProviderResult(
                content=json.dumps(
                    {
                        "answer": f"This record supports the observation: {evidence_id}.",
                        "evidence_ids": [evidence_id],
                    }
                )
            )

    monkeypatch.setattr(loop, "make_provider", lambda _policy: Provider())
    with client:
        assert_followup_error(client, case_id, 502, "followup_response_invalid")


def test_followup_invalid_question_returns_422_invalid_request(tmp_path, monkeypatch):
    client, _, case_id, requests = followup_client(tmp_path, monkeypatch)
    with client:
        for body in (
            {},
            {"question": " "},
            {"question": "q" * 2001},
            {"question": 1},
            {"question": "Why", "history": []},
        ):
            response = client.post(f"/api/cases/{case_id}/followups", json=body)
            assert response.status_code == 422
            assert response.json() == {"error": {"code": "invalid_request"}}
        assert not requests


def test_followup_uses_only_normalized_active_case_context(tmp_path, monkeypatch):
    client, service, case_id, requests = followup_client(tmp_path, monkeypatch)
    with client:
        other = service.create("OTHER_CASE_PRIVATE_SYMPTOM")
        with service.db.connect() as conn:
            conn.execute(
                "UPDATE cases SET symptom=? WHERE id=?",
                ("slow token=SECRET /private/capture.pcap", case_id),
            )
            record = service.evidence_records(case_id)[0]
            record["payload"] = "RAW_PAYLOAD_SENTINEL"
            record["value"]["payload"] = "RAW_PAYLOAD_SENTINEL"
            conn.execute(
                "UPDATE evidence SET record=? WHERE case_id=? AND id=?",
                (json.dumps(record), case_id, record["id"]),
            )
        response = client.post(f"/api/cases/{case_id}/followups", json={"question": "Why?"})
        assert response.status_code == 200, response.text
        context = json.loads(requests[0].context_json)
        assert set(context) == {"case_id", "symptom", "report", "evidence", "question"}
        assert context["case_id"] == case_id
        assert context["question"] == "Why?"
        assert context["report"]["capture_quality"]
        for sentinel in (
            other["id"],
            "OTHER_CASE_PRIVATE_SYMPTOM",
            "RAW_PAYLOAD_SENTINEL",
            "SECRET",
            "/private/capture.pcap",
        ):
            assert sentinel not in requests[0].context_json


def test_followup_context_contains_report_cited_evidence_only(tmp_path, monkeypatch):
    client, service, case_id, requests = followup_client(tmp_path, monkeypatch)
    with client:
        existing = service.evidence_records(case_id)[0]
        with service.db.connect() as conn:
            row = conn.execute(
                "SELECT run_id,capture_id FROM evidence WHERE case_id=? AND id=?",
                (case_id, existing["id"]),
            ).fetchone()
            uncited_ids = []
            for index in range(12):
                record = dict(existing)
                record["id"] = f"ev_uncited_followup_{index}"
                record["summary"] = "unrelated qualification evidence " + ("x" * 1200)
                uncited_ids.append(record["id"])
                conn.execute(
                    "INSERT INTO evidence(case_id,id,record,run_id,capture_id) VALUES(?,?,?,?,?)",
                    (
                        case_id,
                        record["id"],
                        json.dumps(record),
                        row["run_id"],
                        row["capture_id"],
                    ),
                )

        report = service.report(case_id)
        report_citations = set()

        def collect_citations(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "evidence_ids" and isinstance(item, list):
                        report_citations.update(item)
                    elif key == "capture_evidence_ids" and isinstance(item, dict):
                        for ids in item.values():
                            if isinstance(ids, list):
                                report_citations.update(ids)
                    else:
                        collect_citations(item)
            elif isinstance(value, list):
                for item in value:
                    collect_citations(item)

        collect_citations(report)
        assert report_citations
        response = client.post(
            f"/api/cases/{case_id}/followups", json={"question": "What is concluded?"}
        )
        assert response.status_code == 200, response.text
        supplied_ids = {item["id"] for item in json.loads(requests[0].context_json)["evidence"]}
        assert report_citations <= supplied_ids
        assert not (set(uncited_ids) & supplied_ids)


def test_followup_request_excludes_previous_turns(tmp_path, monkeypatch):
    client, _, case_id, requests = followup_client(tmp_path, monkeypatch)
    with client:
        for question in ("FIRST_QUESTION_SENTINEL", "SECOND_QUESTION_SENTINEL"):
            assert (
                client.post(
                    f"/api/cases/{case_id}/followups", json={"question": question}
                ).status_code
                == 200
            )
        assert "FIRST_QUESTION_SENTINEL" not in requests[1].context_json
        assert "cannot answer" not in requests[1].context_json
        assert "history" not in json.loads(requests[1].context_json)


def test_followup_does_not_mutate_report_or_evidence(tmp_path, monkeypatch):
    client, service, case_id, _ = followup_client(tmp_path, monkeypatch)
    with client:
        report = service.report(case_id)
        evidence = service.evidence_records(case_id)
        with service.db.connect() as conn:
            before = "\n".join(conn.iterdump())
        assert (
            client.post(
                f"/api/cases/{case_id}/followups", json={"question": "UNPERSISTED_QUESTION"}
            ).status_code
            == 200
        )
        assert service.report(case_id) == report
        assert service.evidence_records(case_id) == evidence
        with service.db.connect() as conn:
            assert "\n".join(conn.iterdump()) == before


def test_followup_bounds_question_and_answer(tmp_path, monkeypatch):
    client, _, case_id, requests = followup_client(
        tmp_path,
        monkeypatch,
        ProviderResult(content=json.dumps({"answer": "x" * 4001, "evidence_ids": []})),
    )
    with client:
        assert_followup_error(
            client, case_id, 502, "followup_response_invalid", {"question": " " + "q" * 2000 + " "}
        )
        assert len(json.loads(requests[0].context_json)["question"]) == 2000


def test_followup_reports_provider_failure_without_logging_content(tmp_path, monkeypatch, caplog):
    client, _, case_id, _ = followup_client(
        tmp_path, monkeypatch, RuntimeError("ANSWER_SECRET API_KEY_SECRET")
    )
    with client:
        assert_followup_error(
            client, case_id, 503, "provider_unavailable", {"question": "QUESTION_SECRET"}
        )
    for sentinel in ("QUESTION_SECRET", "ANSWER_SECRET", "API_KEY_SECRET"):
        assert sentinel not in caplog.text


def test_followup_rejects_unknown_and_cross_case_evidence_ids(tmp_path, monkeypatch):
    client, service, case_id, _ = followup_client(tmp_path, monkeypatch)
    with client:
        other_case = service.create("Other case")
        own_id = service.evidence_records(case_id)[0]["id"]
        other_id = "ev_other_case"
        run_id, _ = service.start(other_case["id"], "seed", {})
        with service.db.connect() as conn:
            conn.execute(
                "INSERT INTO evidence(case_id,id,run_id,record) VALUES(?,?,?,?)",
                (other_case["id"], other_id, run_id, json.dumps({"id": other_id})),
            )

        class Provider:
            citation = own_id

            def propose(self, _request):
                return ProviderResult(
                    content=json.dumps(
                        {
                            "answer": "Capture quality is derived from deterministic evidence.",
                            "evidence_ids": [self.citation, self.citation],
                        }
                    )
                )

        provider = Provider()
        monkeypatch.setattr(loop, "make_provider", lambda _policy: provider)
        response = client.post(
            f"/api/cases/{case_id}/followups", json={"question": "Capture quality?"}
        )
        assert response.status_code == 200
        assert response.json()["evidence_ids"] == [own_id]
        for citation in ("ev_invented", other_id):
            provider.citation = citation
            assert_followup_error(client, case_id, 502, "followup_response_invalid")


def test_followup_context_contains_completed_conclusion_and_uncertainty(tmp_path, monkeypatch):
    client, service, case_id, requests = followup_client(tmp_path, monkeypatch)
    with client:
        assert (
            client.post(
                f"/api/cases/{case_id}/followups", json={"question": "What is concluded?"}
            ).status_code
            == 200
        )
        report = service.report(case_id)
        projected = json.loads(requests[0].context_json)["report"]
        assert projected["conclusion"] == report["conclusion"]
        assert (
            projected["remaining_hypotheses"][0]["statement"]
            == report["remaining_hypotheses"][0]["statement"]
        )


def test_followup_rejects_uncited_assertions_and_tool_responses(tmp_path, monkeypatch):
    client, _, case_id, _ = followup_client(tmp_path, monkeypatch)
    with client:

        class Provider:
            content = None

            def propose(self, _request):
                return ProviderResult(content=json.dumps(self.content))

        provider = Provider()
        monkeypatch.setattr(loop, "make_provider", lambda _policy: provider)
        for output in (
            {"answer": "The server caused the delay.", "evidence_ids": []},
            {"answer": " ", "evidence_ids": []},
            {"action": "request_capability", "capability": "analyze_dns", "parameters": {}},
            {
                "answer": "The available evidence cannot answer.",
                "evidence_ids": [],
                "command": "sh",
            },
        ):
            provider.content = output
            assert_followup_error(client, case_id, 502, "followup_response_invalid")


def test_followup_enforces_http_and_provider_byte_bounds(tmp_path, monkeypatch):
    from dataclasses import replace

    client, service, case_id, requests = followup_client(tmp_path, monkeypatch)
    with client:
        response = client.post(
            f"/api/cases/{case_id}/followups", content=b"x" * (service.policy.max_json_bytes + 1)
        )
        assert response.status_code == 413
        assert response.json() == {"error": {"code": "request_size_limit"}}
        service.policy = replace(service.policy, max_provider_request_bytes=64)
        assert_followup_error(client, case_id, 503, "provider_unavailable")
        assert not requests


def test_followup_provider_failure_codes_are_safe_and_exact(tmp_path, monkeypatch, caplog):
    client, _, case_id, _ = followup_client(tmp_path, monkeypatch)
    with client:

        class Provider:
            code = None

            def propose(self, _request):
                return ProviderResult(failure_code=self.code)

        provider = Provider()
        monkeypatch.setattr(loop, "make_provider", lambda _policy: provider)
        for code, status, expected in (
            ("provider_invalid_response", 502, "followup_response_invalid"),
            ("provider_response_too_large", 502, "followup_response_invalid"),
            ("provider_auth_failed", 503, "provider_unavailable"),
            ("provider_protocol_error", 503, "provider_unavailable"),
            ("PRIVATE_SENTINEL_API_KEY", 503, "provider_unavailable"),
        ):
            provider.code = code
            assert_followup_error(client, case_id, status, expected)
        assert "PRIVATE_SENTINEL_API_KEY" not in caplog.text


def test_followup_embedded_unavailable_does_not_call_provider(tmp_path, monkeypatch):
    from dataclasses import replace

    client, service, case_id, requests = followup_client(tmp_path, monkeypatch)
    service.policy = replace(
        service.policy,
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key="x" * 40,
    )
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "unavailable:runtime-unhealthy")
    with client:
        assert_followup_error(client, case_id, 503, "provider_unavailable")
        assert not requests


def test_followup_embedded_provider_uses_answer_schema(tmp_path, monkeypatch):
    from dataclasses import replace

    client, service, case_id, _ = followup_client(tmp_path, monkeypatch)
    service.policy = replace(
        service.policy,
        provider_mode=ProviderMode.EMBEDDED,
        provider_base_url="http://host.docker.internal:8767/v1",
        provider_model="wireclaw-qwen3-4b-instruct-2507-q4_k_m",
        provider_api_key="x" * 40,
    )
    monkeypatch.setenv("WIRECLAW_EMBEDDED_AI_STATUS", "ready")
    monkeypatch.setattr(gate7_module, "embedded_runtime_available", lambda _policy: True)
    monkeypatch.setattr(
        loop,
        "make_provider",
        lambda policy: openai_compatible.OpenAICompatibleProvider(
            mode=policy.provider_mode,
            base_url=policy.provider_base_url,
            model=policy.provider_model,
            timeout_seconds=policy.provider_timeout_seconds,
            api_key=policy.provider_api_key,
        ),
    )
    wire_requests = []
    original = httpx.AsyncClient

    def handler(request):
        wire_requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "answer": "The available evidence cannot answer this question.",
                                    "evidence_ids": [],
                                }
                            )
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    with client:
        response = client.post(f"/api/cases/{case_id}/followups", json={"question": "Why?"})
        assert response.status_code == 200
        body = json.loads(wire_requests[0].content)
        schema = body["response_format"]["json_schema"]["schema"]
        assert set(schema["properties"]) == {"answer", "evidence_ids"}
        assert schema["additionalProperties"] is False
        assert len(body["messages"]) == 2
        assert "action" not in schema["properties"]


def test_followup_requests_bounded_tokens_and_accepts_a_concise_case_cited_answer(
    tmp_path, monkeypatch
):
    client, service, case_id, requests = followup_client(tmp_path, monkeypatch)
    evidence_id = service.evidence_records(case_id)[0]["id"]
    answer = (
        "The available evidence cannot identify where the delay occurred. "
        "A capture at both endpoints would show whether the server received the connection promptly."
    )

    class Provider:
        def propose(self, request):
            requests.append(request)
            return ProviderResult(
                content=json.dumps({"answer": answer, "evidence_ids": [evidence_id]})
            )

    monkeypatch.setattr(loop, "make_provider", lambda _policy: Provider())
    with client:
        response = client.post(
            f"/api/cases/{case_id}/followups", json={"question": "Where did the delay occur?"}
        )

    assert response.status_code == 200, response.text
    assert response.json() == {"answer": answer, "evidence_ids": [evidence_id]}
    assert requests[0].max_output_tokens == 640


def test_followup_accepts_maximum_answer_and_caps_provider_response_bytes(
    tmp_path, monkeypatch, caplog
):
    from dataclasses import replace

    client, service, case_id, _ = followup_client(tmp_path, monkeypatch)
    with client:
        evidence_id = service.evidence_records(case_id)[0]["id"]

        class Provider:
            content = json.dumps({"answer": "x" * 4000, "evidence_ids": [evidence_id]})

            def propose(self, _request):
                return ProviderResult(content=self.content)

        provider = Provider()
        monkeypatch.setattr(loop, "make_provider", lambda _policy: provider)
        response = client.post(f"/api/cases/{case_id}/followups", json={"question": "Why?"})
        assert response.status_code == 200
        assert len(response.json()["answer"]) == 4000
        service.policy = replace(service.policy, max_provider_response_bytes=256)
        provider.content = "PRIVATE_RESPONSE_SENTINEL" * 300
        assert_followup_error(client, case_id, 502, "followup_response_invalid")
        assert "PRIVATE_RESPONSE_SENTINEL" not in caplog.text


def test_followup_openapi_documents_code_only_error_matrix(tmp_path):
    from jsonschema import Draft202012Validator

    responses = create_app(tmp_path).openapi()["paths"]["/api/cases/{case_id}/followups"]["post"][
        "responses"
    ]
    expected = {
        "404": {"case_not_found", "report_not_found"},
        "409": {"report_not_ready", "followup_unavailable"},
        "413": {"request_size_limit"},
        "422": {"invalid_request"},
        "502": {"followup_response_invalid"},
        "503": {"provider_unavailable"},
        "504": {"provider_timeout"},
    }
    for status, codes in expected.items():
        assert status in responses
        schema = responses[status]["content"]["application/json"]["schema"]
        assert schema["additionalProperties"] is False
        assert schema["required"] == ["error"]
        error_schema = schema["properties"]["error"]
        assert error_schema["additionalProperties"] is False
        assert error_schema["required"] == ["code"]
        assert set(error_schema["properties"]["code"]["enum"]) == codes
        validator = Draft202012Validator(schema)
        for code in codes:
            validator.validate({"error": {"code": code}})
        assert not validator.is_valid({"detail": "PRIVATE_PROVIDER_OUTPUT"})
        assert not validator.is_valid(
            {"error": {"code": next(iter(codes)), "message": "PRIVATE_PROVIDER_OUTPUT"}}
        )
    assert "HTTPValidationError" not in json.dumps(responses)
    shared_schema = responses["default"]["content"]["application/json"]["schema"]
    Draft202012Validator(shared_schema).validate({"error": {"code": "service_busy"}})


def test_legacy_upload_creates_explicit_primary_and_completes(tmp_path):
    from generate import generate

    captures = generate(tmp_path / "fixtures")
    with TestClient(create_app(tmp_path / "data"), base_url="http://127.0.0.1:8765") as client:
        case_id = client.post(
            "/api/cases", json={"symptom": "slow", "capture_name": "legacy.pcap"}
        ).json()["id"]
        response = client.post(
            f"/api/cases/{case_id}/capture",
            content=captures["healthy"],
            headers={"content-type": "application/octet-stream"},
        )
        assert response.status_code == 200, response.text
        record = response.json()
        assert len(record["captures"]) == 1
        primary = record["captures"][0]
        assert primary["capture_name"] == "legacy.pcap"
        assert primary["original_artifact_id"] == record["original_id"]
        assert primary["sha256"] == record["capture_sha"]
        assert client.post(f"/api/cases/{case_id}/investigate").json()["state"] == "COMPLETE"


def test_legacy_upload_uses_single_waiting_explicit_capture_and_rejects_ambiguity(tmp_path):
    from generate import generate

    captures = generate(tmp_path / "fixtures")
    with TestClient(create_app(tmp_path / "data"), base_url="http://127.0.0.1:8765") as client:
        case_id = client.post("/api/cases", json={"symptom": "slow"}).json()["id"]
        created = client.post(
            f"/api/cases/{case_id}/captures", json={"capture_name": "explicit.pcap"}
        )
        assert created.status_code == 201, created.text
        primary = created.json()
        response = client.post(
            f"/api/cases/{case_id}/capture",
            content=captures["healthy"],
            headers={"content-type": "application/octet-stream"},
        )
        assert response.status_code == 200, response.text
        assert [item["id"] for item in response.json()["captures"]] == [primary["id"]]
        assert client.post(f"/api/cases/{case_id}/investigate").json()["state"] == "COMPLETE"
        other = client.post("/api/cases", json={"symptom": "ambiguous"}).json()["id"]
        for name in ("one.pcap", "two.pcap"):
            assert (
                client.post(f"/api/cases/{other}/captures", json={"capture_name": name}).status_code
                == 201
            )
        before = client.get(f"/api/cases/{other}").json()
        response = client.post(
            f"/api/cases/{other}/capture",
            content=captures["healthy"],
            headers={"content-type": "application/octet-stream"},
        )
        assert response.status_code == 409
        assert response.json() == {"error": {"code": "capture_selection_required"}}
        assert client.get(f"/api/cases/{other}").json() == before
