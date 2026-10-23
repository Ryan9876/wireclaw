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

from .models import BASELINE, TRANSITIONS, CreateCapture, State, UpdateCapture
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
            schema_root = Path(
                os.environ.get(
                    "WIRECLAW_CONTRACTS_DIR",
                    str(Path(__file__).resolve().parents[4] / "contracts"),
                )
            )
            schema = schema_root / "evidence.schema.json"
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

    def capture_analyzer_root(self, case_id, capture_id):
        with self.db.connect() as conn:
            capture = self.db.capture(conn, case_id, capture_id)
            if capture["original_artifact_id"]:
                row = conn.execute(
                    "SELECT relative_path FROM artifacts WHERE case_id=? AND id=?",
                    (case_id, capture["original_artifact_id"]),
                ).fetchone()
                if row:
                    return self.files.path(row["relative_path"], exists=False).parents[3]
            primary = conn.execute(
                "SELECT id FROM captures WHERE case_id=? ORDER BY created,rowid LIMIT 1", (case_id,)
            ).fetchone()["id"]
        directory = self.files.case(case_id)
        if capture_id != primary:
            directory = directory / "captures" / capture_id
        return self.files.store.confined(directory / "analyzer", exists=False)

    def analyzer(self, case_id, capture_id=None):
        if capture_id is None:
            with self.db.connect() as conn:
                self.db.case(conn, case_id)
                row = conn.execute(
                    "SELECT id FROM captures WHERE case_id=? ORDER BY created,rowid LIMIT 1",
                    (case_id,),
                ).fetchone()
            capture_id = row["id"] if row else None
        root = (
            self.capture_analyzer_root(case_id, capture_id)
            if capture_id
            else self.files.case(case_id) / "analyzer"
        )
        return Analyzer(
            self.files.store.confined(root, exists=False),
            limits=self.policy.analyzer,
            diagnostic_limits=self.policy.diagnostics,
        )

    def create(self, symptom, capture_name=None):
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
                    "INSERT INTO cases(id,symptom,state,created,updated,capture_name) "
                    "VALUES(?,?,?,?,?,?)",
                    (case_id, symptom, State.NEW, now(), now(), capture_name),
                )
                conn.execute("INSERT INTO history VALUES(?,?,?,?)", (case_id, 0, State.NEW, now()))
                conn.commit()
            except BaseException:
                directory.rmdir()
                raise
        return self.get(case_id)

    def recent(self, limit=10):
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ApiError("invalid_request", 422)
        with self.db.connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT c.id,coalesce(c.display_name,c.capture_name,'Capture ' || substr(c.id,1,8)) "
                    "AS name,a.bytes AS capture_bytes,c.created,c.updated,c.state FROM cases c "
                    "LEFT JOIN artifacts a ON a.id=c.original_id AND a.case_id=c.id AND a.kind='original' "
                    "ORDER BY c.updated DESC,c.id DESC LIMIT ?",
                    (limit,),
                )
            ]

    def rename(self, case_id, display_name):
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            conn.execute(
                "UPDATE cases SET display_name=?,updated=? WHERE id=?",
                (display_name, now(), case_id),
            )
        return self.get(case_id)

    def get(self, case_id):
        with self.db.connect() as conn:
            case = self.db.case(conn, case_id)
            case["name"] = case["display_name"] or case["capture_name"] or f"Capture {case_id[:8]}"
            case["captures"] = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM captures WHERE case_id=? ORDER BY created,rowid", (case_id,)
                )
            ]
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
                    "SELECT id,case_id,request_key,capability,parameters,status,error,"
                    "versions,configuration,evidence_ids,created "
                    "FROM runs WHERE case_id=? ORDER BY created",
                    (case_id,),
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
            if state == State.COMPLETE:
                # Only the primary source participated in the legacy report.
                conn.execute(
                    "UPDATE captures SET status='analyzed',last_error=NULL,updated=? "
                    "WHERE case_id=? AND original_artifact_id=?",
                    (now(), case_id, case["original_id"]),
                )

    def start(self, case_id, capability, parameters, *, capture_id=None):
        policy_fingerprint = asdict(self.policy)
        policy_fingerprint.pop("provider_api_key", None)
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            if capture_id is not None:
                self.db.capture(conn, case_id, capture_id)
            key = hashlib.sha256(
                encode(
                    {
                        "capability": capability,
                        "policy": policy_fingerprint,
                        **parameters,
                        "capture_id": capture_id,
                    }
                ).encode()
            ).hexdigest()
            # Successful duplicate returns a snapshot and costs no additional rows or execution.
            previous = conn.execute(
                "SELECT id FROM runs WHERE case_id=? AND request_key=? AND status='complete' "
                "AND capture_id IS ?",
                (case_id, key, capture_id),
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
                "INSERT INTO runs(id,case_id,request_key,capability,parameters,status,created,capture_id) "
                "VALUES(?,?,?,?,?,'running',?,?)",
                (run_id, case_id, key, capability, encode(parameters), now(), capture_id),
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
            "INSERT INTO artifacts(id,case_id,kind,relative_path,sha256,bytes,parent_sha) "
            "VALUES(?,?,?,?,?,?,?)",
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

    def create_capture(self, case_id, capture_name, vantage_type="unknown", vantage_subtype=None):
        # Validate direct service callers under the same strict metadata contract.
        from pydantic import ValidationError

        try:
            metadata = CreateCapture.model_validate(
                {
                    "capture_name": capture_name,
                    "vantage_type": vantage_type,
                    "vantage_subtype": vantage_subtype,
                }
            )
        except ValidationError:
            raise ApiError("invalid_request", 422) from None
        capture_id = identifier()
        timestamp = now()
        with self.db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self.db.case(conn, case_id)
            if conn.execute("SELECT count(*) FROM deletions").fetchone()[0]:
                raise ApiError("cleanup_pending", 503)
            if (
                conn.execute(
                    "SELECT count(*) FROM captures WHERE case_id=?", (case_id,)
                ).fetchone()[0]
                >= 4
            ):
                raise ApiError("capture_count_limit")
            conn.execute(
                "INSERT INTO captures(id,case_id,capture_name,vantage_type,vantage_subtype,created,updated) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    capture_id,
                    case_id,
                    metadata.capture_name,
                    metadata.vantage_type,
                    metadata.vantage_subtype,
                    timestamp,
                    timestamp,
                ),
            )
            self.sync_primary_capture(conn, case_id)
        return self.get_capture(case_id, capture_id)

    def get_capture(self, case_id, capture_id):
        with self.db.connect() as conn:
            return self.db.capture(conn, case_id, capture_id)

    @staticmethod
    def sync_primary_capture(conn, case_id):
        primary = conn.execute(
            "SELECT * FROM captures WHERE case_id=? ORDER BY created,rowid LIMIT 1", (case_id,)
        ).fetchone()
        conn.execute(
            "UPDATE cases SET capture_name=?,capture_sha=?,original_id=?,updated=? WHERE id=?",
            (
                primary["capture_name"] if primary else None,
                primary["sha256"] if primary else None,
                primary["original_artifact_id"] if primary else None,
                now(),
                case_id,
            ),
        )

    def update_capture(self, case_id, capture_id, **changes):
        from pydantic import ValidationError

        with self.db.connect() as conn:
            capture = self.db.capture(conn, case_id, capture_id)
            try:
                changes = UpdateCapture.model_validate(changes).model_dump(exclude_unset=True)
                merged = {**capture, **changes}
                if "vantage_type" in changes and changes["vantage_type"] != "network":
                    merged["vantage_subtype"] = None
                CreateCapture.model_validate(
                    {
                        key: merged[key]
                        for key in ("capture_name", "vantage_type", "vantage_subtype")
                    }
                )
                if merged["vantage_type"] is None:
                    raise ValueError
            except (ValidationError, ValueError):
                raise ApiError("invalid_request", 422) from None
            conn.execute(
                "UPDATE captures SET display_name=?,vantage_type=?,vantage_subtype=?,updated=? "
                "WHERE case_id=? AND id=?",
                (
                    merged["display_name"],
                    merged["vantage_type"],
                    merged["vantage_subtype"],
                    now(),
                    case_id,
                    capture_id,
                ),
            )
            conn.execute("UPDATE cases SET updated=? WHERE id=?", (now(), case_id))
        return self.get_capture(case_id, capture_id)

    def begin_ingest(self, case_id):
        case = self.get(case_id)
        captures = case["captures"]
        waiting = [capture for capture in captures if capture["original_artifact_id"] is None]
        if len(waiting) > 1:
            raise ApiError("capture_selection_required")
        if captures and not waiting:
            raise ApiError("capture_already_registered")
        if not captures:
            if case["original_id"] or case["state"] not in (State.NEW, State.FAILED):
                raise ApiError("capture_already_registered")
            # Prepare before creating metadata, preserving the legacy resting
            # checkpoint if the filesystem cannot accept an upload.
            started = time.monotonic()
            directory = self.files.case(case_id) / "analyzer"
            try:
                self.files.store.confined(directory / "incoming", exists=False).mkdir(
                    parents=True, exist_ok=True
                )
            except OSError:
                self.remove_tree(directory)
                self.log(case_id, "ingest", started, "failed", "storage_failure")
                raise ApiError("storage_failure", 503) from None
            capture = self.create_capture(case_id, case["capture_name"] or f"Capture {case_id[:8]}")
        else:
            capture = waiting[0]
        return self.begin_capture_ingest(case_id, capture["id"])

    def begin_capture_ingest(self, case_id, capture_id):
        capture = self.get_capture(case_id, capture_id)
        if capture["original_artifact_id"]:
            raise ApiError("capture_already_registered")
        path = self.capture_analyzer_root(case_id, capture_id) / "incoming"
        run_id = None
        started = time.monotonic()
        try:
            self.files.store.confined(path, exists=False).mkdir(parents=True, exist_ok=True)
            run_id, _ = self.start(case_id, "ingest", {"capture_id": capture_id})
            with self.db.connect() as conn:
                conn.execute("UPDATE runs SET capture_id=? WHERE id=?", (capture_id, run_id))
                conn.execute(
                    "UPDATE captures SET status='preparing',last_error=NULL,updated=? WHERE id=?",
                    (now(), capture_id),
                )
            case = Service.get(self, case_id)
            if case["captures"][0]["id"] == capture_id and case["state"] in (
                State.NEW,
                State.FAILED,
            ):
                self.transition(case_id, State.INGESTING)
        except Exception as error:
            code = "storage_failure" if isinstance(error, OSError) else "capture_intake_failed"
            if run_id is not None:
                self.fail_capture_ingest(case_id, capture_id, run_id, code)
            self.cleanup_capture_ingest(case_id, capture_id)
            if isinstance(error, OSError):
                self.log(case_id, "ingest", started, "failed", code)
                raise ApiError(code, 503) from None
            raise
        return run_id, path / identifier()

    def ingest_capture_id(self, case_id, run_id):
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT capture_id FROM runs WHERE id=? AND case_id=?", (run_id, case_id)
            ).fetchone()
            if row is None or row["capture_id"] is None:
                raise ApiError("run_not_found", 404)
            return row["capture_id"]

    def ingest(self, case_id, run_id, path):
        capture_id = self.ingest_capture_id(case_id, run_id)
        self.ingest_capture(case_id, capture_id, run_id, path)
        return self.get(case_id)

    def ingest_capture(self, case_id, capture_id, run_id, path):
        self.get_capture(case_id, capture_id)
        case = Service.get(self, case_id)
        primary = case["captures"][0]["id"] == capture_id
        if primary and case["state"] == State.INGESTING:
            self.transition(case_id, State.VALIDATING_CAPTURE)
        analyzer = self.analyzer(case_id, capture_id)
        capture_sha = analyzer.ingest_capture(path.relative_to(analyzer.store.root))
        original = analyzer.store.verify(capture_sha)
        with self.db.connect() as conn:
            artifact_id = self.register(conn, case_id, original, "original", capture_sha)
            conn.execute("UPDATE artifacts SET capture_id=? WHERE id=?", (capture_id, artifact_id))
            conn.execute(
                "UPDATE captures SET sha256=?,original_artifact_id=?,bytes=?,status='analyzing',"
                "last_error=NULL,updated=? WHERE id=? AND case_id=?",
                (capture_sha, artifact_id, original.stat().st_size, now(), capture_id, case_id),
            )
            self.sync_primary_capture(conn, case_id)
            conn.execute(
                "UPDATE runs SET status='complete',versions=? WHERE id=? AND case_id=? AND capture_id=?",
                (encode(analyzer.versions), run_id, case_id, capture_id),
            )
        if primary and Service.get(self, case_id)["state"] == State.VALIDATING_CAPTURE:
            self.transition(case_id, State.BASELINE_ANALYSIS)
        return self.get_capture(case_id, capture_id)

    def fail_capture_ingest(self, case_id, capture_id, run_id, code):
        case = Service.get(self, case_id)
        primary = case["captures"][0]["id"] == capture_id
        self.fail(case_id, run_id, code, fatal=primary)
        with self.db.connect() as conn:
            self.db.capture(conn, case_id, capture_id)
            conn.execute(
                "UPDATE captures SET status='needs_attention',last_error=?,updated=? WHERE id=?",
                (code, now(), capture_id),
            )

    def cleanup_capture_ingest(self, case_id, capture_id):
        capture = self.get_capture(case_id, capture_id)
        if not capture["original_artifact_id"]:
            self.remove_tree(self.capture_analyzer_root(case_id, capture_id))

    def cleanup_ingest(self, case_id):
        for capture in self.get(case_id)["captures"]:
            if not capture["original_artifact_id"]:
                self.cleanup_capture_ingest(case_id, capture["id"])

    def remove_capture(self, case_id, capture_id):
        capture = self.get_capture(case_id, capture_id)
        root = self.capture_analyzer_root(case_id, capture_id)
        self.files.checked_tree(root)
        trash = self.files.path(Path("trash") / capture_id)
        self.files.checked_tree(trash)
        if trash.exists():
            raise ApiError("cleanup_pending", 503)
        moved = []
        try:
            with self.db.connect() as conn:
                primary = (
                    conn.execute(
                        "SELECT id FROM captures WHERE case_id=? ORDER BY created,rowid LIMIT 1",
                        (case_id,),
                    ).fetchone()["id"]
                    == capture_id
                )
                if primary:
                    # Legacy analysis still operates on the primary capture until
                    # per-capture scheduling is introduced. Attribute only its
                    # existing deterministic artifacts/runs before removing them.
                    conn.execute(
                        "UPDATE artifacts SET capture_id=? WHERE case_id=? AND capture_id IS NULL "
                        "AND parent_sha=? AND kind IN ('normalized','report','evidence_capture',"
                        "'evidence_provenance')",
                        (capture_id, case_id, capture["sha256"]),
                    )
                    conn.execute(
                        "UPDATE runs SET capture_id=? WHERE case_id=? AND capture_id IS NULL "
                        "AND (capability IN ('baseline','diagnostics','get_capture_metadata',"
                        "'assess_capture_quality','list_protocols','list_endpoints','list_conversations') "
                        "OR capability LIKE 'analyze_%')",
                        (capture_id, case_id),
                    )
                    conn.execute(
                        "UPDATE evidence SET capture_id=? WHERE case_id=? AND run_id IN "
                        "(SELECT id FROM runs WHERE case_id=? AND capture_id=?)",
                        (capture_id, case_id, case_id, capture_id),
                    )
                    conn.execute("DELETE FROM reasoning_steps WHERE case_id=?", (case_id,))
                    conn.execute(
                        "UPDATE cases SET quality=NULL,last_error=NULL WHERE id=?", (case_id,)
                    )
                # Only capture-owned artifacts are eligible for removal.
                artifacts = [
                    dict(row)
                    for row in conn.execute(
                        "SELECT id,relative_path FROM artifacts WHERE case_id=? AND capture_id=?",
                        (case_id, capture_id),
                    )
                ]
                paths = [(self.files.path(row["relative_path"]), row["id"]) for row in artifacts]
                trash.mkdir(parents=True, exist_ok=False)
                if root.exists():
                    root.rename(trash / "analyzer")
                    moved.append((root, trash / "analyzer"))
                for path, artifact_id in paths:
                    if path.is_relative_to(root) or not path.exists():
                        continue
                    destination = trash / artifact_id
                    path.rename(destination)
                    moved.append((path, destination))
                conn.execute(
                    "DELETE FROM evidence WHERE case_id=? AND capture_id=?", (case_id, capture_id)
                )
                conn.execute(
                    "DELETE FROM runs WHERE case_id=? AND capture_id=?", (case_id, capture_id)
                )
                conn.execute(
                    "DELETE FROM artifacts WHERE case_id=? AND capture_id=?", (case_id, capture_id)
                )
                conn.execute("DELETE FROM captures WHERE case_id=? AND id=?", (case_id, capture_id))
                self.sync_primary_capture(conn, case_id)
                if primary:
                    promoted = self.db.case(conn, case_id)
                    resting_state = (
                        State.BASELINE_ANALYSIS if promoted["original_id"] else State.NEW
                    )
                    if promoted["state"] != resting_state:
                        conn.execute(
                            "UPDATE cases SET state=?,quality=NULL,last_error=NULL WHERE id=?",
                            (resting_state, case_id),
                        )
                        seq = conn.execute(
                            "SELECT max(seq)+1 FROM history WHERE case_id=?", (case_id,)
                        ).fetchone()[0]
                        conn.execute(
                            "INSERT INTO history VALUES(?,?,?,?)",
                            (case_id, seq, resting_state, now()),
                        )
                conn.execute(
                    "INSERT INTO deletions VALUES(?,?)",
                    (capture_id, trash.relative_to(self.files.root).as_posix()),
                )
        except BaseException:
            for original, destination in reversed(moved):
                destination.rename(original)
            if trash.exists():
                trash.rmdir()
            raise
        pending = not self.cleanup_deleted(capture_id, trash)
        return {
            "deleted": True,
            "original_deleted": not pending,
            "registered_artifacts_deleted": not pending,
            "cleanup_pending": pending,
        }

    def restore_capture_removal(self, case_id, capture_id):
        # A pre-commit interruption leaves the capture row and registry intact.
        # Restore only those registered paths from this capture's fixed trash ID.
        trash = self.files.path(Path("trash") / capture_id)
        if not trash.exists():
            return
        self.files.checked_tree(trash)
        root = self.capture_analyzer_root(case_id, capture_id)
        if (trash / "analyzer").exists() and not root.exists():
            root.parent.mkdir(parents=True, exist_ok=True)
            (trash / "analyzer").rename(root)
        with self.db.connect() as conn:
            artifacts = [
                dict(row)
                for row in conn.execute(
                    "SELECT id,relative_path FROM artifacts WHERE case_id=?", (case_id,)
                )
            ]
        for artifact in artifacts:
            source = trash / artifact["id"]
            if source.exists():
                target = self.files.path(artifact["relative_path"])
                if target.exists():
                    raise ApiError("cleanup_pending", 503)
                target.parent.mkdir(parents=True, exist_ok=True)
                source.rename(target)
        trash.rmdir()

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
                run = conn.execute(
                    "SELECT capture_id FROM runs WHERE id=? AND case_id=?", (run_id, case_id)
                ).fetchone()
                if run is None:
                    raise ApiError("run_not_found", 404)
                artifact_id = self.register(
                    conn, case_id, path, "normalized", result["capture_sha256"]
                )
                if run["capture_id"] is not None:
                    conn.execute(
                        "UPDATE artifacts SET capture_id=? WHERE id=?",
                        (run["capture_id"], artifact_id),
                    )
                for item in records:
                    if run["capture_id"] is None:
                        conn.execute(
                            "INSERT INTO evidence(case_id,id,record,run_id,capture_id) VALUES(?,?,?,?,NULL) "
                            "ON CONFLICT(case_id,id) WHERE capture_id IS NULL "
                            "DO UPDATE SET record=excluded.record,run_id=excluded.run_id",
                            (case_id, item["id"], encode(item), run_id),
                        )
                    else:
                        conn.execute(
                            "INSERT INTO evidence(case_id,id,record,run_id,capture_id) VALUES(?,?,?,?,?) "
                            "ON CONFLICT(case_id,id,capture_id) "
                            "DO UPDATE SET record=excluded.record,run_id=excluded.run_id",
                            (case_id, item["id"], encode(item), run_id, run["capture_id"]),
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

    def execute(
        self,
        case_id,
        capability,
        parameters,
        operation,
        *,
        fatal=False,
        versions=None,
        capture_id=None,
    ):
        parameters = {**parameters, "tool_versions": versions}
        run_id, cached = self.start(case_id, capability, parameters, capture_id=capture_id)
        if cached:
            return self.snapshot(case_id, run_id)
        started = time.monotonic()
        try:
            result = operation()
            capture_ids = [capture["id"] for capture in Service.get(self, case_id)["captures"]]
            if capture_id is not None and capture_ids and capture_id != capture_ids[0]:
                result = {
                    **result,
                    "evidence": [
                        {**item, "id": f"{item['id']}:{capture_id}"} for item in result["evidence"]
                    ],
                }
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

    def execute_capture_analysis(self, case_id, capture_id):
        capture = self.get_capture(case_id, capture_id)
        if capture["original_artifact_id"] is None or capture["sha256"] is None:
            raise ApiError("capture_required")
        analyzer = self.analyzer(case_id, capture_id)
        artifact_id = capture["original_artifact_id"]
        return self.execute(
            case_id,
            "baseline",
            {"artifact_id": artifact_id},
            lambda: analyzer.analyze(capture["sha256"]),
            versions=analyzer.versions,
            capture_id=capture_id,
        )

    def investigate(self, case_id):
        case = self.get(case_id)
        if not case["original_id"]:
            raise ApiError("capture_required")
        capture_id = case["captures"][0]["id"] if case["captures"] else None
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
            capture_id=capture_id,
        )
        self.execute(
            case_id,
            "diagnostics",
            {},
            lambda: analyzer.diagnose(case["capture_sha"], include_http_timing=True),
            fatal=True,
            versions=analyzer.versions,
            capture_id=capture_id,
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
        capture_id = artifact.get("capture_id")
        analyzer = self.analyzer(case_id, capture_id)
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
                if request.capability == "analyze_http_timing":
                    return analyzer.run_http_timing(case["capture_sha"], request.tcp_stream)
                return analyzer.run_diagnostic(
                    DiagnosticRequest(
                        case["capture_sha"], Capability(request.capability), request.tcp_stream
                    )
                )

        return self.execute(
            case_id,
            request.capability,
            parameters,
            operation,
            versions=analyzer.versions,
            capture_id=capture_id,
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
            for capture in Service.get(self, case_id)["captures"]:
                self.restore_capture_removal(case_id, capture["id"])
            with self.db.connect() as conn:
                running = conn.execute(
                    "SELECT 1 FROM runs WHERE case_id=? AND status='running' "
                    "AND (capability!='ingest' OR capture_id IS NULL OR capture_id=("
                    "SELECT id FROM captures WHERE case_id=? ORDER BY created,rowid LIMIT 1)) LIMIT 1",
                    (case_id, case_id),
                ).fetchone()
            # BASELINE_ANALYSIS also rests between intake and investigation (or
            # between completed stages). Only an admitted running run proves
            # interrupted execution at that checkpoint.
            if case["state"] in (
                State.INGESTING,
                State.VALIDATING_CAPTURE,
                State.ASSEMBLING_REPORT,
            ) or (case["state"] == State.BASELINE_ANALYSIS and running):
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
            for capture in Service.get(self, case_id)["captures"]:
                if capture["status"] == "preparing":
                    with self.db.connect() as conn:
                        conn.execute(
                            "UPDATE captures SET status='needs_attention',"
                            "last_error='service_interrupted',updated=? WHERE id=?",
                            (now(), capture["id"]),
                        )
                # Failure persistence may precede a crash before route cleanup.
                # Artifact registration, not status, determines intake ownership.
                if capture["original_artifact_id"] is None:
                    self.cleanup_capture_ingest(case_id, capture["id"])
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
