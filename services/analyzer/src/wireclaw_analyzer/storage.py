"""Managed-root paths and immutable, content-addressed capture intake."""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import AnalyzerError


@dataclass(frozen=True)
class Limits:
    max_capture_bytes: int = 64 * 1024 * 1024
    max_output_bytes: int = 16 * 1024 * 1024
    max_packets: int = 100_000
    timeout_seconds: float = 30

    def __post_init__(self):
        for value in vars(self).values():
            if (
                isinstance(value, bool)
                or not isinstance(value, (float, int))
                or not 0 < value < float("inf")
            ):
                raise AnalyzerError("invalid_limits")
        for value in (self.max_capture_bytes, self.max_output_bytes, self.max_packets):
            if not isinstance(value, int):
                raise AnalyzerError("invalid_limits")


class Store:
    def __init__(self, root: Path, limits: Limits):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.limits = limits

    def confined(self, path: Path, *, exists: bool = True) -> Path:
        path = Path(path)
        if ".." in path.parts or "\x00" in str(path) or (os.name != "nt" and "\\" in str(path)):
            raise AnalyzerError("invalid_path")
        candidate = path if path.is_absolute() else self.root / path
        # Reject internal symlinks, including ones that still resolve within root.
        try:
            relative = candidate.relative_to(self.root)
        except ValueError:
            raise AnalyzerError("path_escape") from None
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise AnalyzerError("symlink_rejected")
        result = candidate.resolve()
        if not result.is_relative_to(self.root):
            raise AnalyzerError("path_escape")
        if exists and not result.is_file():
            raise AnalyzerError("file_unavailable")
        return result

    def capture_path(self, capture_id: str) -> Path:
        if not isinstance(capture_id, str) or not re.fullmatch(r"[a-f0-9]{64}", capture_id):
            raise AnalyzerError("invalid_capture_id")
        return self.confined(Path("cases") / capture_id / "original" / "capture")

    def ingest(self, source: Path, validate) -> str:
        source = self.confined(source)
        destination = self.confined(Path("work"), exists=False)
        destination.mkdir(exist_ok=True)
        import tempfile

        fd, temporary = tempfile.mkstemp(dir=destination)
        temporary = Path(temporary)
        digest = hashlib.sha256()
        try:
            total = 0
            with os.fdopen(fd, "wb") as outgoing, source.open("rb") as incoming:
                while chunk := incoming.read(1024 * 1024):
                    total += len(chunk)
                    if total > self.limits.max_capture_bytes:
                        raise AnalyzerError("capture_size_limit")
                    digest.update(chunk)
                    outgoing.write(chunk)
            validate(temporary)
            capture_id = digest.hexdigest()
            directory = self.confined(Path("cases") / capture_id / "original", exists=False)
            directory.mkdir(parents=True, exist_ok=True)
            target = directory / "capture"
            if target.exists():
                self.verify(capture_id)
            else:
                # Hard-link publication is atomic and never overwrites an existing original.
                try:
                    os.link(temporary, target)
                    # Windows cannot unlink a read-only hard link. Remove the staging
                    # name first, then protect the managed original.
                    temporary.unlink()
                    target.chmod(0o444)
                except FileExistsError:
                    self.verify(capture_id)
            self.persist(
                capture_id,
                {"capture_sha256": capture_id, "file_bytes": total},
                name="capture-identity.json",
            )
            return capture_id
        except OSError:
            raise AnalyzerError("capture_storage_failure") from None
        finally:
            temporary.unlink(missing_ok=True)

    def verify(self, capture_id: str) -> Path:
        path = self.capture_path(capture_id)
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > self.limits.max_capture_bytes:
                    raise AnalyzerError("capture_size_limit")
                digest.update(chunk)
        if digest.hexdigest() != capture_id:
            raise AnalyzerError("capture_integrity_failure")
        return path

    def persist(self, capture_id: str, value: dict, *, name="capture-summary.json") -> Path:
        if name not in ("capture-summary.json", "capture-identity.json"):
            raise AnalyzerError("invalid_artifact_name")
        path = self.confined(Path("cases") / capture_id / "normalized", exists=False)
        path.mkdir(exist_ok=True)
        import tempfile

        fd, temporary_name = tempfile.mkstemp(dir=path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
                stream.write("\n")
            target = self.confined(path / name, exists=False)
            os.replace(temporary_name, target)
            return target
        finally:
            Path(temporary_name).unlink(missing_ok=True)
