#!/usr/bin/env python3
"""Trusted-host AI lifecycle primitives. Only the macOS launcher invokes this file.

There is a numeric-PID TOCTOU interval after each identity check and before
os.kill. These checks reduce accidental/reused-PID targeting; they are not an
atomic PID-bound signaling primitive.
"""
import ctypes
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path

MAX_RECEIPT = 1024
FIELDS = {"pid", "process_start", "executable", "executable_sha256"}
START_RE = re.compile(r"[0-9]{1,20}:[0-9]{1,6}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class LifecycleError(Exception):
    pass


def _fixed_helper(path):
    value = Path(path)
    if (not value.is_absolute() or str(value) != os.path.normpath(path)
            or value.name != "llama-server" or value.parent.name != "MacOS"
            or value.parent.parent.name != "Contents" or value.parent.parent.parent.name != "WireclawAI.app"):
        raise LifecycleError("invalid fixed helper")
    current = Path(value.anchor)
    for part in value.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise LifecycleError("symlinked helper")
    if not value.is_file():
        raise LifecycleError("missing helper")
    return str(value)


def _digest(path):
    if os.stat(path).st_size > 512 * 1024 * 1024:
        raise LifecycleError("helper oversized")
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate(identity, fixed_helper):
    if not isinstance(identity, dict) or set(identity) != FIELDS:
        raise LifecycleError("invalid receipt fields")
    pid, start, executable, digest = (identity[key] for key in
                                       ("pid", "process_start", "executable", "executable_sha256"))
    if type(pid) is not int or not 0 < pid <= 999999:
        raise LifecycleError("invalid PID")
    if not isinstance(start, str) or not START_RE.fullmatch(start):
        raise LifecycleError("invalid process start")
    if not isinstance(executable, str) or len(executable) > 512 or executable != _fixed_helper(fixed_helper):
        raise LifecycleError("invalid executable")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest) or digest != _digest(executable):
        raise LifecycleError("invalid helper digest")
    return identity


def _parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LifecycleError("duplicate receipt field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _safe_receipt_path(path):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise LifecycleError("invalid receipt path")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        if current.is_symlink():
            raise LifecycleError("symlinked receipt ancestor")
    if path.is_symlink():
        raise LifecycleError("symlinked receipt")
    return path


def write_receipt(path, identity, fixed_helper, *, replace_stale=False):
    path = _safe_receipt_path(path)
    _validate(identity, fixed_helper)
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077:
        raise LifecycleError("unsafe receipt directory")
    if path.exists():
        if replace_stale:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o600:
                raise LifecycleError("unsafe existing receipt")
        else:
            read_receipt(path, fixed_helper)
    data = (json.dumps(identity, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    if len(data) > MAX_RECEIPT:
        raise LifecycleError("receipt oversized")
    fd, temporary = tempfile.mkstemp(prefix=".ai-receipt-", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_receipt_with_file_id(path, fixed_helper):
    path = _safe_receipt_path(path)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o600 or info.st_size > MAX_RECEIPT:
            raise LifecycleError("unsafe receipt")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                    or opened.st_mode & 0o777 != 0o600
                    or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                raise LifecycleError("receipt replaced")
            raw = stream.read(MAX_RECEIPT + 1)
        if len(raw) > MAX_RECEIPT:
            raise LifecycleError("oversized receipt")
        identity = _parse_json(raw)
        return _validate(identity, fixed_helper), (opened.st_dev, opened.st_ino)
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        raise LifecycleError("invalid receipt") from exc


def read_receipt(path, fixed_helper):
    identity, _ = _read_receipt_with_file_id(path, fixed_helper)
    return identity


class _ProcBSDInfo(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint32), ("status", ctypes.c_uint32),
                ("xstatus", ctypes.c_uint32), ("pid", ctypes.c_uint32),
                ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
                ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
                ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
                ("svgid", ctypes.c_uint32), ("rfu", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
                ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
                ("pjobc", ctypes.c_uint32), ("tdev", ctypes.c_uint32),
                ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
                ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


def inspect_process(pid):
    if sys.platform != "darwin":
        raise LifecycleError("macOS process inspection required")
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    info = _ProcBSDInfo()
    count = libproc.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if count != ctypes.sizeof(info):
        # libproc may leave errno unset for a vanished PID. The complete PID
        # list provides a second read-only absence check; truncation fails.
        size = libproc.proc_listpids(1, 0, None, 0)
        if size <= 0 or size > 1048576:
            raise LifecycleError("process list unavailable")
        capacity = size + 4096
        entries = (ctypes.c_int * (capacity // ctypes.sizeof(ctypes.c_int)))()
        used = libproc.proc_listpids(1, 0, entries, ctypes.sizeof(entries))
        if used <= 0 or used >= ctypes.sizeof(entries):
            raise LifecycleError("process list incomplete")
        if pid not in entries[:used // ctypes.sizeof(ctypes.c_int)]:
            return None
        raise LifecycleError("process identity unavailable")
    path = ctypes.create_string_buffer(4096)
    count = libproc.proc_pidpath(pid, path, len(path))
    if count <= 0 or count >= len(path):
        raise LifecycleError("process path unavailable")
    executable = os.fsdecode(path.value)
    return {"pid": pid, "process_start": f"{info.start_sec}:{info.start_usec}",
            "executable": executable, "executable_sha256": _digest(executable)}


def _verified(identity, fixed_helper, inspect):
    _validate(identity, fixed_helper)
    current = inspect(identity["pid"])
    if current is None:
        return False
    if current != identity:
        raise LifecycleError("process identity mismatch")
    return True


def recover_receipt(path, status, fixed_helper, inspect=inspect_process):
    if not isinstance(status, dict) or status.get("state") != "running" or set(status) != FIELDS | {"state"}:
        raise LifecycleError("invalid status receipt")
    identity = {key: status[key] for key in FIELDS}
    if not _verified(identity, fixed_helper, inspect):
        raise LifecycleError("process missing")
    write_receipt(path, identity, fixed_helper, replace_stale=True)


def stop_verified(path, fixed_helper, inspect=inspect_process, signal=None, wait=time.sleep, attempts=10):
    if signal is None:
        signal = lambda pid, name: os.kill(pid, getattr(__import__("signal"), "SIG" + name))
    if type(attempts) is not int or not 0 <= attempts <= 10:
        raise LifecycleError("invalid wait bound")
    identity, receipt_file_id = _read_receipt_with_file_id(path, fixed_helper)
    if not _verified(identity, fixed_helper, inspect):
        return
    signal(identity["pid"], "TERM")
    for _ in range(attempts):
        wait(1)
        if inspect(identity["pid"]) is None:
            return
    # Read authoritative state again and reverify every field immediately
    # before KILL. Any replacement or partial observation fails closed.
    fresh, fresh_file_id = _read_receipt_with_file_id(path, fixed_helper)
    if fresh_file_id != receipt_file_id or fresh != identity or not _verified(fresh, fixed_helper, inspect):
        raise LifecycleError("identity changed before KILL")
    signal(identity["pid"], "KILL")
    for _ in range(attempts):
        wait(1)
        if inspect(identity["pid"]) is None:
            return
    raise LifecycleError("helper exit unconfirmed")


def remove_receipt(path, fixed_helper):
    identity = read_receipt(path, fixed_helper)
    if inspect_process(identity["pid"]) is not None:
        raise LifecycleError("helper exit unconfirmed")
    Path(path).unlink()


def _status_stdin():
    raw = sys.stdin.buffer.read(MAX_RECEIPT + 1)
    if len(raw) > MAX_RECEIPT:
        raise LifecycleError("oversized status receipt")
    try:
        return _parse_json(raw)
    except (ValueError, UnicodeError) as exc:
        raise LifecycleError("invalid status receipt") from exc


def main(argv):
    if len(argv) != 3 or argv[0] not in {"create", "recover", "stop", "remove"}:
        return 2
    operation, receipt, fixed_helper = argv
    try:
        if operation in {"create", "recover"}:
            status = _status_stdin()
            if operation == "create" and Path(receipt).exists():
                raise LifecycleError("receipt already exists")
            recover_receipt(receipt, status, fixed_helper)
        elif operation == "stop":
            stop_verified(receipt, fixed_helper)
        else:
            remove_receipt(receipt, fixed_helper)
        return 0
    except LifecycleError:
        print("Wireclaw: AI lifecycle identity unavailable; no unverified process signaled.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
