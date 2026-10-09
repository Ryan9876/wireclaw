"""Bounded derived-capture creation for Gate 6 evidence review."""

import hashlib
from pathlib import Path

from .errors import AnalyzerError
from .runner import Operation, Runner
from .storage import Limits, Store


class EvidenceExtractor:
    """Create a derived capture beneath one managed case root."""

    def __init__(self, root: Path, limits: Limits):
        self.store = Store(root, limits)
        self.runner = Runner(self.store)

    @staticmethod
    def _digest(path: Path, limit: int) -> tuple[str, int]:
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise AnalyzerError("capture_size_limit")
                digest.update(chunk)
        return digest.hexdigest(), total

    def extract(
        self,
        source: Path,
        destination: Path,
        display_filter: str,
        *,
        max_bytes: int,
    ) -> dict:
        source = self.store.confined(source)
        before, _ = self._digest(source, self.store.limits.max_capture_bytes)
        output = self.runner.extract(source, destination, display_filter, max_bytes=max_bytes)
        try:
            # capinfos validates that the generated artifact is a readable capture.
            self.runner.run(Operation.METADATA, output)
            after, _ = self._digest(source, self.store.limits.max_capture_bytes)
            if before != after:
                raise AnalyzerError("capture_integrity_failure")
            output_sha, output_bytes = self._digest(output, max_bytes)
            return {
                "path": output,
                "sha256": output_sha,
                "bytes": output_bytes,
                "parent_sha256": before,
            }
        except BaseException:
            try:
                output.chmod(0o600)
            except OSError:
                pass
            output.unlink(missing_ok=True)
            raise
