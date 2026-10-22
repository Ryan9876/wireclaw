"""Confined application paths, explicit schema and single-process ownership."""

import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from wireclaw_analyzer.storage import Limits, Store


class ApiError(Exception):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


def logical_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ApiError("invalid_id", 422)
    return value


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Files:
    def __init__(self, root):
        root = Path(root).absolute()
        if any(p.is_symlink() for p in (root, *root.parents)):
            raise ApiError("symlink_rejected", 500)
        self.store = Store(root, Limits())
        self.root = self.store.root
        self.root.chmod(0o700)

    def path(self, relative, *, exists=False):
        if Path(relative).is_absolute():
            raise ApiError("invalid_path", 422)
        return self.store.confined(Path(relative), exists=exists)

    def case(self, case_id):
        return self.path(Path("cases") / logical_id(case_id))

    def checked_tree(self, directory):
        self.store.confined(directory, exists=False)
        if directory.exists():
            for current, directories, files in os.walk(directory, followlinks=False):
                for name in (*directories, *files):
                    self.store.confined(Path(current) / name, exists=False)


class OwnerLock:
    def __init__(self, files):
        lock_path = files.path("service.lock")
        self.stream = lock_path.open("r+b" if lock_path.exists() else "w+b")
        try:
            if os.name == "nt":
                import msvcrt

                self.stream.write(b"0")
                self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise ApiError("data_root_in_use", 503) from None

    def close(self):
        self.stream.close()


SCHEMA_V3 = """
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


class Database:
    def __init__(self, files):
        self.path = files.path("cases.sqlite3")
        # SQLite sidecars also must never follow an injected symlink.
        for suffix in ("-journal", "-wal", "-shm"):
            files.path("cases.sqlite3" + suffix)
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                conn.executescript("BEGIN IMMEDIATE;" + SCHEMA_V3 + "COMMIT;")
                version = 3
            if version == 1:
                conn.executescript(
                    "BEGIN IMMEDIATE;"
                    "CREATE TABLE reasoning_steps ("
                    "case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,"
                    "step_id TEXT NOT NULL, sequence INTEGER NOT NULL, at TEXT NOT NULL,"
                    "metadata TEXT NOT NULL, PRIMARY KEY(case_id,step_id),"
                    "UNIQUE(case_id,sequence)); PRAGMA user_version=2; COMMIT;"
                )
                version = 2
            if version == 2:
                conn.executescript(
                    "BEGIN IMMEDIATE;"
                    "ALTER TABLE cases ADD COLUMN capture_name TEXT;"
                    "ALTER TABLE cases ADD COLUMN display_name TEXT;"
                    "UPDATE cases SET capture_name='Capture ' || substr(id,1,8);"
                    "PRAGMA user_version=3; COMMIT;"
                )
                version = 3
            if version == 3:
                self._migrate_v4(conn)
                version = 4
            if version != 4:
                raise ApiError("unsupported_schema_version", 500)

    @staticmethod
    def _migrate_v4(conn):
        # Upgrade the schema and provenance together so an interrupted upgrade
        # leaves the v3 database intact for the next startup.
        try:
            conn.executescript(
                "BEGIN IMMEDIATE;"
                "CREATE TABLE captures ("
                "id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,"
                "capture_name TEXT NOT NULL, display_name TEXT, original_artifact_id TEXT,"
                "sha256 TEXT, bytes INTEGER, vantage_type TEXT NOT NULL DEFAULT 'unknown',"
                "vantage_subtype TEXT, status TEXT NOT NULL DEFAULT 'waiting', last_error TEXT,"
                "created TEXT NOT NULL, updated TEXT NOT NULL);"
                "CREATE INDEX captures_case ON captures(case_id);"
                "CREATE UNIQUE INDEX captures_original ON captures(case_id,original_artifact_id);"
                "ALTER TABLE artifacts ADD COLUMN capture_id TEXT REFERENCES captures(id);"
                "ALTER TABLE runs ADD COLUMN capture_id TEXT REFERENCES captures(id);"
                "ALTER TABLE evidence ADD COLUMN capture_id TEXT REFERENCES captures(id);"
                "CREATE INDEX artifacts_capture ON artifacts(case_id,capture_id);"
                "CREATE INDEX runs_capture ON runs(case_id,capture_id);"
                "CREATE INDEX evidence_capture ON evidence(case_id,capture_id);"
            )
            for table in ("artifacts", "runs", "evidence"):
                for action in ("INSERT", "UPDATE"):
                    conn.execute(
                        f"CREATE TRIGGER {table}_capture_owner_{action.lower()} "
                        f"BEFORE {action} ON {table} "
                        "WHEN NEW.capture_id IS NOT NULL AND NOT EXISTS ("
                        "SELECT 1 FROM captures WHERE id=NEW.capture_id AND case_id=NEW.case_id) "
                        "BEGIN SELECT RAISE(ABORT, 'capture_case_mismatch'); END"
                    )
            cases = conn.execute(
                "SELECT id,state,capture_name,display_name,original_id,capture_sha,created,updated "
                "FROM cases WHERE original_id IS NOT NULL"
            ).fetchall()
            for case in cases:
                source = conn.execute(
                    "SELECT sha256,bytes FROM artifacts WHERE id=? AND case_id=? AND kind='original'",
                    (case["original_id"], case["id"]),
                ).fetchone()
                capture_id = hashlib.sha256(
                    f"capture:{case['id']}:{case['original_id']}".encode()
                ).hexdigest()[:32]
                status = {
                    "INGESTING": "preparing",
                    "VALIDATING_CAPTURE": "preparing",
                    "BASELINE_ANALYSIS": "analyzing",
                    "INVESTIGATING": "analyzing",
                    "FAILED": "needs_attention",
                }.get(case["state"], "analyzed" if source else "needs_attention")
                if source is None:
                    status = "needs_attention"
                conn.execute(
                    "INSERT INTO captures(id,case_id,capture_name,display_name,"
                    "original_artifact_id,sha256,bytes,vantage_type,status,created,updated) "
                    "VALUES(?,?,?,?,?,?,?,'unknown',?,?,?)",
                    (
                        capture_id,
                        case["id"],
                        case["capture_name"] or f"Capture {case['id'][:8]}",
                        case["display_name"],
                        case["original_id"],
                        case["capture_sha"] or (source["sha256"] if source else None),
                        source["bytes"] if source else None,
                        status,
                        case["created"],
                        case["updated"],
                    ),
                )
                if source is None:
                    continue
                conn.execute(
                    "UPDATE artifacts SET capture_id=? WHERE case_id=? AND "
                    "((id=? AND kind='original') OR (kind='normalized' AND parent_sha=?))",
                    (capture_id, case["id"], case["original_id"], source["sha256"]),
                )
                conn.execute(
                    "UPDATE runs SET capture_id=? WHERE case_id=? AND "
                    "(capability IN ('ingest','baseline','diagnostics','get_capture_metadata',"
                    "'assess_capture_quality','list_protocols','list_endpoints','list_conversations') "
                    "OR capability LIKE 'analyze_%')",
                    (capture_id, case["id"]),
                )
                conn.execute(
                    "UPDATE evidence SET capture_id=? WHERE case_id=? AND run_id IN "
                    "(SELECT id FROM runs WHERE case_id=? AND capture_id=?)",
                    (capture_id, case["id"], case["id"], capture_id),
                )
            conn.execute("PRAGMA user_version=4")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=2)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def case(conn, case_id):
        logical_id(case_id)
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise ApiError("case_not_found", 404)
        return dict(row)
