"""Confined application paths, explicit schema and single-process ownership."""

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


SCHEMA = """
CREATE TABLE cases (
 id TEXT PRIMARY KEY, symptom TEXT NOT NULL, state TEXT NOT NULL,
 created TEXT NOT NULL, updated TEXT NOT NULL, capture_sha TEXT,
 original_id TEXT, quality TEXT, last_error TEXT);
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
PRAGMA user_version = 1;
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
                conn.executescript("BEGIN IMMEDIATE;" + SCHEMA + "COMMIT;")
            elif version != 1:
                raise ApiError("unsupported_schema_version", 500)

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
