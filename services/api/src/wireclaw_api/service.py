"""Case lifecycle and transactional orchestration of existing deterministic capabilities."""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator
from wireclaw_analyzer import Analyzer, Capability, DiagnosticRequest

from .models import BASELINE, TRANSITIONS, State
from .storage import ApiError, Database, Files, OwnerLock, encode, logical_id

LOGGER = logging.getLogger("wireclaw.api")


def now():
    return datetime.now(UTC).isoformat()


def identifier():
    return uuid4().hex


class Service:
    def __init__(self, root, policy):
        self.policy = policy
        self.files = Files(root)
        self.owner = OwnerLock(self.files)
        self.lock = threading.Lock()
        try:
            self.db = Database(self.files)
            schema = Path(__file__).resolve().parents[4] / "contracts/evidence.schema.json"
            self.validator = Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))
            self.recover()
        except BaseException:
            self.owner.close()
            raise

    def close(self):
        self.owner.close()

    @contextmanager
    def admission(self):
        if not self.lock.acquire(blocking=False):
            raise ApiError("service_busy", 429)
        try:
            yield
        finally:
            self.lock.release()

    def analyzer(self, case_id):
        return Analyzer(
            self.files.store.confined(self.files.case(case_id) / "analyzer", exists=False),
            limits=self.policy.analyzer,
            diagnostic_limits=self.policy.diagnostics,
        )

    def create(self, symptom):
        if len(symptom) > self.policy.max_symptom_chars:
            raise ApiError("symptom_size_limit", 413)
        case_id = identifier()
        with self.db.connect() as conn:
            if conn.execute("SELECT count(*) FROM cases").fetchone()[0] >= self.policy.max_cases:
                raise ApiError("case_count_limit", 429)
            # Pending deletion cleanup continues to count against disk admission.
            if conn.execute("SELECT count(*) FROM deletions").fetchone()[0]:
                raise ApiError("cleanup_pending", 503)
            directory = self.files.case(case_id)
            directory.mkdir(parents=True, exist_ok=False)
            try:
                conn.execute(
                    "INSERT INTO cases VALUES(?,?,?,?,?,NULL,NULL,NULL,NULL)",
                    (case_id, symptom, State.NEW, now(), now()),
                )
                conn.execute("INSERT INTO history VALUES(?,?,?,?)", (case_id, 0, State.NEW, now()))
                conn.commit()
            except BaseException:
                directory.rmdir()
                raise
        return self.get(case_id)

    def get(self, case_id):
        with self.db.connect() as conn:
            case = self.db.case(conn, case_id)
            case["history"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT seq,state,at FROM history WHERE case_id=? ORDER BY seq", (case_id,)
                )
            ]
            case["runs"] = [
                {
                    **dict(r),
                    "parameters": json.loads(r["parameters"]),
                    "versions": json.loads(r["versions"]) if r["versions"] else None,
                    "configuration": json.loads(r["configuration"]) if r["configuration"] else None,
                    "evidence_ids": json.loads(r["evidence_ids"]) if r["evidence_ids"] else [],
                }
                for r in conn.execute(
                    "SELECT * FROM runs WHERE case_id=? ORDER BY created", (case_id,)
                )
            ]
            case["artifacts"] = self._artifacts(conn, case_id)
            case["evidence_count"] = conn.execute(
                "SELECT count(*) FROM evidence WHERE case_id=?", (case_id,)
            ).fetchone()[0]
        case["gate_boundary"] = "Gate 3: deterministic evidence; findings/report deferred to Gate 4"
        case["provider_mode"] = "none"
        return case

    @staticmethod
    def _artifacts(conn, case_id):
        return [
            {k: r[k] for k in ("id", "kind", "sha256", "bytes", "parent_sha")}
            for r in conn.execute("SELECT * FROM artifacts WHERE case_id=? ORDER BY id", (case_id,))
        ]

    def transition(self, case_id, state, *, error=None):
        with self.db.connect() as conn:
            case = self.db.case(conn, case_id)
            if state not in TRANSITIONS[State(case["state"])]:
                raise ApiError("invalid_state_transition")
            seq = conn.execute(
                "SELECT max(seq)+1 FROM history WHERE case_id=?", (case_id,)
            ).fetchone()[0]
            conn.execute(
                "UPDATE cases SET state=?,updated=?,last_error=? WHERE id=?",
                (state, now(), error, case_id),
            )
            conn.execute("INSERT INTO history VALUES(?,?,?,?)", (case_id, seq, state, now()))

    def start(self, case_id, capability, parameters):
        key = hashlib.sha256(
            encode({"capability": capability, "policy": asdict(self.policy), **parameters}).encode()
        ).hexdigest()
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            # Successful duplicate returns a snapshot and costs no additional rows or execution.
            previous = conn.execute(
                "SELECT id FROM runs WHERE case_id=? AND request_key=? AND status='complete'",
                (case_id, key),
            ).fetchone()
            if previous:
                return previous["id"], True
            count = conn.execute(
                "SELECT count(*) FROM runs WHERE case_id=?", (case_id,)
            ).fetchone()[0]
            if count >= self.policy.max_runs:
                raise ApiError("run_count_limit", 429)
            run_id = identifier()
            conn.execute(
                "INSERT INTO runs VALUES(?,?,?,?,?,'running',NULL,NULL,NULL,NULL,?)",
                (run_id, case_id, key, capability, encode(parameters), now()),
            )
            return run_id, False

    def fail(self, case_id, run_id, code, *, fatal=False):
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE runs SET status='failed',error=? WHERE id=? AND case_id=?",
                (code, run_id, case_id),
            )
        if fatal:
            with self.db.connect() as conn:
                state = self.db.case(conn, case_id)["state"]
            if State.FAILED in TRANSITIONS[State(state)]:
                self.transition(case_id, State.FAILED, error=code)

    def artifact(self, case_id, artifact_id):
        logical_id(artifact_id)
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            row = conn.execute(
                "SELECT * FROM artifacts WHERE id=? AND case_id=?", (artifact_id, case_id)
            ).fetchone()
            if row is None:
                raise ApiError("artifact_not_found", 404)
        path = self.files.path(row["relative_path"], exists=True)
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > max(
                    self.policy.analyzer.max_capture_bytes, self.policy.max_evidence_bytes
                ):
                    raise ApiError("artifact_size_limit", 413)
                digest.update(chunk)
        if total != row["bytes"] or digest.hexdigest() != row["sha256"]:
            raise ApiError("artifact_integrity_failure")
        return dict(row), path

    def register(self, conn, case_id, path, kind, parent_sha):
        path = self.files.store.confined(path)
        total = path.stat().st_size
        if total > max(self.policy.analyzer.max_capture_bytes, self.policy.max_evidence_bytes):
            raise ApiError("artifact_size_limit", 413)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        artifact_id = identifier()
        conn.execute(
            "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?)",
            (
                artifact_id,
                case_id,
                kind,
                path.relative_to(self.files.root).as_posix(),
                digest.hexdigest(),
                total,
                parent_sha,
            ),
        )
        return artifact_id

    def begin_ingest(self, case_id):
        case = self.get(case_id)
        if case["original_id"] or case["state"] not in (State.NEW, State.FAILED):
            raise ApiError("capture_already_registered")
        run_id, _ = self.start(case_id, "ingest", {})
        self.transition(case_id, State.INGESTING)
        path = self.files.case(case_id) / "analyzer" / "incoming"
        self.files.store.confined(path, exists=False).mkdir(parents=True, exist_ok=True)
        return run_id, path / identifier()

    def ingest(self, case_id, run_id, path):
        self.transition(case_id, State.VALIDATING_CAPTURE)
        analyzer = self.analyzer(case_id)
        capture_sha = analyzer.ingest_capture(path.relative_to(analyzer.store.root))
        original = analyzer.store.verify(capture_sha)
        with self.db.connect() as conn:
            artifact_id = self.register(conn, case_id, original, "original", capture_sha)
            conn.execute(
                "UPDATE cases SET capture_sha=?,original_id=?,updated=? WHERE id=?",
                (capture_sha, artifact_id, now(), case_id),
            )
            conn.execute(
                "UPDATE runs SET status='complete',versions=? WHERE id=?",
                (encode(analyzer.versions), run_id),
            )
        self.transition(case_id, State.BASELINE_ANALYSIS)
        return self.get(case_id)

    def cleanup_ingest(self, case_id):
        # Only an unregistered intake tree is owned by this failed upload.
        case = self.get(case_id)
        if not case["original_id"]:
            directory = self.files.case(case_id) / "analyzer"
            self.remove_tree(directory)

    def snapshot(self, case_id, run_id):
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT id FROM artifacts WHERE case_id=? AND relative_path=?",
                (case_id, f"cases/{case_id}/normalized/{run_id}.json"),
            ).fetchone()
        if row is None:
            raise ApiError("snapshot_unavailable", 500)
        _, path = self.artifact(case_id, row["id"])
        return json.loads(path.read_text(encoding="utf-8"))

    def save(self, case_id, run_id, result):
        serialized = encode(result).encode()
        if len(serialized) > self.policy.max_evidence_bytes:
            raise ApiError("evidence_size_limit", 413)
        records = result["evidence"]
        for item in records:
            self.validator.validate(item)
        path = self.files.case(case_id) / "normalized" / f"{run_id}.json"
        self.files.store.confined(path, exists=False)
        path.parent.mkdir(exist_ok=True)
        try:
            with self.db.connect() as conn:
                previous = {
                    r["id"]: r["record"]
                    for r in conn.execute(
                        "SELECT id,record FROM evidence WHERE case_id=?", (case_id,)
                    )
                }
                previous.update({item["id"]: encode(item) for item in records})
                if len(previous) > self.policy.max_evidence_items:
                    raise ApiError("evidence_item_limit", 413)
                # Bound both indexed evidence and retained reproducibility snapshots.
                snapshots = conn.execute(
                    "SELECT coalesce(sum(bytes),0) FROM artifacts WHERE case_id=? AND kind='normalized'",
                    (case_id,),
                ).fetchone()[0]
                if (
                    max(
                        sum(len(v.encode()) for v in previous.values()), snapshots + len(serialized)
                    )
                    > self.policy.max_evidence_bytes
                ):
                    raise ApiError("evidence_size_limit", 413)
                with path.open("xb") as stream:
                    stream.write(serialized)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.register(conn, case_id, path, "normalized", result["capture_sha256"])
                for item in records:
                    conn.execute(
                        "INSERT INTO evidence VALUES(?,?,?,?) ON CONFLICT(case_id,id) "
                        "DO UPDATE SET record=excluded.record,run_id=excluded.run_id",
                        (case_id, item["id"], encode(item), run_id),
                    )
                conn.execute(
                    "UPDATE runs SET status='complete',versions=?,configuration=?,evidence_ids=? WHERE id=?",
                    (
                        encode({"analyzer": result["analyzer_version"], **result["tool_versions"]}),
                        encode(result["configuration"]),
                        encode([e["id"] for e in records]),
                        run_id,
                    ),
                )
                quality = next(
                    (
                        e["value"]["state"]
                        for e in records
                        if e["category"] == "assess_capture_quality"
                    ),
                    None,
                )
                if quality:
                    conn.execute(
                        "UPDATE cases SET quality=?,updated=? WHERE id=?", (quality, now(), case_id)
                    )
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def execute(self, case_id, capability, parameters, operation, *, fatal=False, versions=None):
        parameters = {**parameters, "tool_versions": versions}
        run_id, cached = self.start(case_id, capability, parameters)
        if cached:
            return self.snapshot(case_id, run_id)
        started = time.monotonic()
        try:
            result = operation()
            self.save(case_id, run_id, result)
        except Exception as error:
            from wireclaw_analyzer import AnalyzerError

            code = (
                error.code if isinstance(error, (ApiError, AnalyzerError)) else "operation_failed"
            )
            if isinstance(error, sqlite3.Error):
                code = "persistence_failure"
            elif isinstance(error, OSError):
                code = "storage_failure"
            self.fail(case_id, run_id, code, fatal=fatal)
            self.log(case_id, capability, started, "failed", code)
            status = (
                error.status
                if isinstance(error, ApiError)
                else (503 if isinstance(error, (sqlite3.Error, OSError)) else 422)
            )
            raise ApiError(code, status) from None
        self.log(case_id, capability, started, "complete")
        return result

    def investigate(self, case_id):
        case = self.get(case_id)
        if not case["original_id"]:
            raise ApiError("capture_required")
        self.artifact(case_id, case["original_id"])
        if case["state"] in (State.FAILED, State.COMPLETE):
            with self.db.connect() as conn:
                count = conn.execute(
                    "SELECT count(*) FROM runs WHERE case_id=?", (case_id,)
                ).fetchone()[0]
                if count >= self.policy.max_runs:
                    raise ApiError("run_count_limit", 429)
            self.transition(case_id, State.BASELINE_ANALYSIS)
        elif case["state"] not in (State.BASELINE_ANALYSIS, State.INVESTIGATING):
            raise ApiError("invalid_state_transition")
        analyzer = self.analyzer(case_id)
        self.execute(
            case_id,
            "baseline",
            {},
            lambda: analyzer.analyze(case["capture_sha"]),
            fatal=True,
            versions=analyzer.versions,
        )
        self.execute(
            case_id,
            "diagnostics",
            {},
            lambda: analyzer.diagnose(case["capture_sha"]),
            fatal=True,
            versions=analyzer.versions,
        )
        if self.get(case_id)["state"] == State.BASELINE_ANALYSIS:
            self.transition(case_id, State.INVESTIGATING)
        return self.get(case_id)

    def capability(self, case_id, request):
        case = self.get(case_id)
        if case["state"] not in (State.INVESTIGATING, State.FAILED, State.COMPLETE):
            raise ApiError("baseline_required")
        artifact, _ = self.artifact(case_id, request.artifact_id)
        if artifact["kind"] != "original" or request.artifact_id != case["original_id"]:
            raise ApiError("original_artifact_required")
        # Capture quality must already exist, including when prior diagnostics failed.
        if case["quality"] is None:
            raise ApiError("baseline_required")
        analyzer = self.analyzer(case_id)
        parameters = {"artifact_id": request.artifact_id, "tcp_stream": request.tcp_stream}
        if request.capability in BASELINE:

            def operation():
                result = analyzer.analyze(case["capture_sha"])
                return {
                    **result,
                    "evidence": [
                        e
                        for e in result["evidence"]
                        if e["source"]["capability"] == request.capability
                    ],
                }
        else:

            def operation():
                return analyzer.run_diagnostic(
                    DiagnosticRequest(
                        case["capture_sha"], Capability(request.capability), request.tcp_stream
                    )
                )

        return self.execute(
            case_id, request.capability, parameters, operation, versions=analyzer.versions
        )

    def evidence(self, case_id, *, offset=0, limit=100, evidence_id=None):
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            if evidence_id:
                row = conn.execute(
                    "SELECT record FROM evidence WHERE case_id=? AND id=?", (case_id, evidence_id)
                ).fetchone()
                if row is None:
                    raise ApiError("evidence_not_found", 404)
                return json.loads(row["record"])
            return [
                json.loads(r["record"])
                for r in conn.execute(
                    "SELECT record FROM evidence WHERE case_id=? ORDER BY id LIMIT ? OFFSET ?",
                    (case_id, limit, offset),
                )
            ]

    def remove_tree(self, directory):
        self.files.checked_tree(directory)
        if not directory.exists():
            return

        def readonly(function, path, error_info):
            error = error_info[1]
            if not isinstance(error, PermissionError):
                raise error
            os.chmod(path, 0o600)
            function(path)

        shutil.rmtree(directory, onerror=readonly)

    def delete(self, case_id):
        directory = self.files.case(case_id)
        trash = self.files.path(Path("trash") / case_id)
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
        self.files.checked_tree(directory)
        trash.parent.mkdir(exist_ok=True)
        if trash.exists():
            raise ApiError("cleanup_pending", 503)
        moved = directory.exists()
        if moved:
            directory.rename(trash)
        try:
            with self.db.connect() as conn:
                conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
                conn.execute(
                    "INSERT INTO deletions VALUES(?,?)",
                    (case_id, trash.relative_to(self.files.root).as_posix()),
                )
        except BaseException:
            if moved:
                trash.rename(directory)
            raise
        pending = not self.cleanup_deleted(case_id, trash)
        return {
            "deleted": True,
            "original_deleted": not pending,
            "registered_artifacts_deleted": not pending,
            "cleanup_pending": pending,
        }

    def cleanup_deleted(self, case_id, trash):
        try:
            self.remove_tree(trash)
        except OSError:
            return False
        with self.db.connect() as conn:
            conn.execute("DELETE FROM deletions WHERE case_id=?", (case_id,))
        return True

    def recover(self):
        with self.db.connect() as conn:
            cases = [dict(r) for r in conn.execute("SELECT * FROM cases")]
            deleted = [dict(r) for r in conn.execute("SELECT * FROM deletions")]
        for item in deleted:
            self.cleanup_deleted(item["case_id"], self.files.path(item["trash_path"]))
        case_root = self.files.path("cases")
        if case_root.exists():
            self.files.checked_tree(case_root)
            known_cases = {case["id"] for case in cases}
            for directory in case_root.iterdir():
                logical_id(directory.name)
                if directory.name not in known_cases:
                    self.remove_tree(directory)
        for case in cases:
            case_id = case["id"]
            directory = self.files.case(case_id)
            trash = self.files.path(Path("trash") / case_id)
            if trash.exists() and not directory.exists():
                self.files.checked_tree(trash)
                trash.rename(directory)
            if case["state"] in (
                State.INGESTING,
                State.VALIDATING_CAPTURE,
                State.BASELINE_ANALYSIS,
                State.ASSEMBLING_REPORT,
            ):
                self.transition(case_id, State.FAILED, error="service_interrupted")
                self.cleanup_ingest(case_id)
            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE runs SET status='failed',error='service_interrupted' WHERE case_id=? AND status='running'",
                    (case_id,),
                )
                # Remove unregistered snapshots left by a crash before SQLite commit.
                known = {
                    r[0]
                    for r in conn.execute(
                        "SELECT relative_path FROM artifacts WHERE case_id=?", (case_id,)
                    )
                }
            normalized = directory / "normalized"
            if normalized.exists():
                self.files.checked_tree(normalized)
                for path in normalized.iterdir():
                    if path.relative_to(self.files.root).as_posix() not in known:
                        path.unlink()
            incoming = directory / "analyzer" / "incoming"
            if incoming.exists():
                self.remove_tree(incoming)

    @staticmethod
    def log(case_id, capability, started, status, code=None):
        LOGGER.info(
            encode(
                {
                    "case_id": case_id,
                    "component": "api",
                    "capability": capability,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "status": status,
                    "error_code": code,
                }
            )
        )
