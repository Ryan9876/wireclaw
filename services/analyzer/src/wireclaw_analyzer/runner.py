"""Fixed operation plans only: no caller flags, filters or executable paths."""

import os
import shutil
import subprocess
import threading
import time
from enum import Enum
from pathlib import Path

from .diagnostic_fields import EXTRA_FIELDS
from .errors import AnalyzerError
from .storage import Store

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "udp.stream",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.checksum.status",
    "udp.checksum.status",
    "ip.checksum.status",
    "_ws.malformed",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "ip.proto",
    "ipv6.nxt",
)


class Operation(Enum):
    TSHARK_VERSION = "tshark_version"
    CAPINFOS_VERSION = "capinfos_version"
    ZEEK_VERSION = "zeek_version"
    METADATA = "get_capture_metadata"
    PACKETS = "baseline_packet_fields"
    DIAGNOSTICS = "diagnostic_packet_fields"


class Runner:
    def __init__(self, store: Store):
        self.store = store
        # PATH is administrator environment, never request data. Discovery occurs once.
        self._tools = {tool: shutil.which(tool) for tool in ("tshark", "capinfos", "zeek")}

    def run(self, operation: Operation, capture: Path | None = None) -> str:
        if not isinstance(operation, Operation):
            raise AnalyzerError("invalid_operation")
        tool = {
            Operation.METADATA: "capinfos",
            Operation.PACKETS: "tshark",
            Operation.DIAGNOSTICS: "tshark",
        }.get(operation, operation.value.split("_")[0])
        executable = self._tools[tool]
        if executable is None:
            raise AnalyzerError("tool_unavailable", operation.value, tool)
        if operation in (Operation.METADATA, Operation.PACKETS, Operation.DIAGNOSTICS):
            if capture is None:
                raise AnalyzerError("capture_required")
            capture = self.store.confined(capture)
            if capture.stat().st_size > self.store.limits.max_capture_bytes:
                raise AnalyzerError("capture_size_limit")
        elif capture is not None:
            raise AnalyzerError("unexpected_parameter")
        if operation is Operation.METADATA:
            args = [executable, "-M", "-t", "-E", "-c", "-s", "-d", "-l", "-u", "-I", str(capture)]
        elif operation in (Operation.PACKETS, Operation.DIAGNOSTICS):
            args = [
                executable,
                "-n",
                "-r",
                str(capture),
                "-o",
                "tcp.check_checksum:TRUE",
                "-o",
                "udp.check_checksum:TRUE",
                "-o",
                "ip.check_checksum:TRUE",
                "-T",
                "fields",
                "-E",
                "separator=/t",
                "-E",
                "occurrence=f",
            ]
            fields = FIELDS
            if operation is Operation.DIAGNOSTICS:
                # Two passes permit forward DNS references; numeric repeated fields are retained.
                args[args.index("occurrence=f")] = "occurrence=a"
                args.extend(
                    [
                        "-2",
                        "-o",
                        "tcp.analyze_sequence_numbers:TRUE",
                        "-o",
                        "tcp.relative_sequence_numbers:FALSE",
                        "-o",
                        "tcp.desegment_tcp_streams:TRUE",
                        "-o",
                        "tls.keylog_file:",
                    ]
                )
                fields = FIELDS + EXTRA_FIELDS
            for field in fields:
                args.extend(["-e", field])
        else:
            args = [executable, "--version"]
        environment = {
            key: value
            for key, value in os.environ.items()
            if key
            in (
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "TEMP",
                "TMP",
                "LD_LIBRARY_PATH",
                "WIRESHARK_DATA_DIR",
            )
        }
        environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
        # Isolate user Wireshark preferences/plugins and prevent arbitrary working-directory files.
        home = self.store.confined(Path("tool-home"), exists=False)
        home.mkdir(exist_ok=True)
        environment.update(
            {
                "HOME": str(home),
                "USERPROFILE": str(home),
                "XDG_CONFIG_HOME": str(home),
                "APPDATA": str(home),
                "WIRESHARK_CONFIG_DIR": str(home),
            }
        )
        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                shell=False,
                env=environment,
                cwd=home,
            )
        except OSError:
            raise AnalyzerError("tool_start_failure", operation.value, tool) from None
        limit = self.store.limits.max_output_bytes
        output = bytearray()
        exceeded = threading.Event()
        total = [0]
        lock = threading.Lock()

        def drain(pipe, keep):
            try:
                while chunk := pipe.read(8192):
                    with lock:
                        total[0] += len(chunk)
                        if total[0] > limit:
                            exceeded.set()
                            process.kill()
                        elif keep:
                            output.extend(chunk)
            finally:
                pipe.close()

        readers = [
            threading.Thread(target=drain, args=(process.stdout, True)),
            threading.Thread(target=drain, args=(process.stderr, False)),
        ]
        for reader in readers:
            reader.start()
        timeout = False
        try:
            process.wait(timeout=self.store.limits.timeout_seconds)
        except subprocess.TimeoutExpired:
            timeout = True
            process.kill()
            process.wait()
        finally:
            for reader in readers:
                reader.join()
        if timeout:
            raise AnalyzerError("tool_timeout", operation.value, tool)
        if exceeded.is_set():
            raise AnalyzerError("tool_output_limit", operation.value, tool)
        if process.returncode:
            raise AnalyzerError("tool_failed", operation.value, tool)
        try:
            return output.decode("utf-8", errors="strict")
        except UnicodeError:
            raise AnalyzerError("invalid_tool_output", operation.value, tool) from None

    def extract(
        self,
        capture: Path,
        destination: Path,
        display_filter: str,
        *,
        max_bytes: int,
    ) -> Path:
        """Create one bounded capture using only an internally approved display filter."""
        if not isinstance(display_filter, str) or len(display_filter) > 2048:
            raise AnalyzerError("invalid_display_filter")
        if any(ord(char) < 32 or ord(char) == 127 for char in display_filter):
            raise AnalyzerError("invalid_display_filter")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise AnalyzerError("invalid_limits")
        capture = self.store.confined(capture)
        destination = self.store.confined(destination, exists=False)
        if destination.exists():
            raise AnalyzerError("artifact_exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        executable = self._tools["tshark"]
        if executable is None:
            raise AnalyzerError("tool_unavailable", "evidence_capture", "tshark")
        args = [executable, "-n", "-r", str(capture)]
        if display_filter:
            args.extend(["-Y", display_filter])
        args.extend(["-w", str(destination)])
        environment = {
            key: value
            for key, value in os.environ.items()
            if key
            in (
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "TEMP",
                "TMP",
                "LD_LIBRARY_PATH",
                "WIRESHARK_DATA_DIR",
            )
        }
        environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
        home = self.store.confined(Path("tool-home"), exists=False)
        home.mkdir(exist_ok=True)
        environment.update(
            {
                "HOME": str(home),
                "USERPROFILE": str(home),
                "XDG_CONFIG_HOME": str(home),
                "APPDATA": str(home),
                "WIRESHARK_CONFIG_DIR": str(home),
            }
        )
        process = None
        readers = []
        exceeded = threading.Event()
        diagnostic_bytes = [0]
        lock = threading.Lock()
        try:
            try:
                process = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    shell=False,
                    env=environment,
                    cwd=home,
                )
            except OSError:
                raise AnalyzerError("tool_start_failure", "evidence_capture", "tshark") from None

            def drain(pipe):
                try:
                    while chunk := pipe.read(8192):
                        with lock:
                            diagnostic_bytes[0] += len(chunk)
                            if diagnostic_bytes[0] > self.store.limits.max_output_bytes:
                                exceeded.set()
                                process.kill()
                finally:
                    pipe.close()

            readers = [
                threading.Thread(target=drain, args=(process.stdout,)),
                threading.Thread(target=drain, args=(process.stderr,)),
            ]
            for reader in readers:
                reader.start()
            deadline = time.monotonic() + self.store.limits.timeout_seconds
            timed_out = False
            evidence_too_large = False
            while process.poll() is None:
                if destination.exists() and destination.stat().st_size > max_bytes:
                    evidence_too_large = True
                    process.kill()
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    process.kill()
                    break
                time.sleep(0.02)
            process.wait()
            for reader in readers:
                reader.join()
            readers = []
            if timed_out:
                raise AnalyzerError("tool_timeout", "evidence_capture", "tshark")
            if evidence_too_large:
                raise AnalyzerError("evidence_capture_size_limit")
            if exceeded.is_set():
                raise AnalyzerError("tool_output_limit", "evidence_capture", "tshark")
            if process.returncode:
                raise AnalyzerError("tool_failed", "evidence_capture", "tshark")
            if not destination.is_file():
                raise AnalyzerError("evidence_capture_unavailable")
            if destination.stat().st_size > max_bytes:
                raise AnalyzerError("evidence_capture_size_limit")
            destination.chmod(0o400)
            return destination
        except BaseException:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            for reader in readers:
                reader.join()
            if destination.exists():
                try:
                    destination.chmod(0o600)
                except OSError:
                    pass
                destination.unlink(missing_ok=True)
            raise

    def versions(self) -> dict:
        result = {}
        for tool, operation in zip(
            ("tshark", "capinfos", "zeek"),
            (Operation.TSHARK_VERSION, Operation.CAPINFOS_VERSION, Operation.ZEEK_VERSION),
            strict=True,
        ):
            try:
                lines = self.run(operation).splitlines()
                if not lines:
                    raise AnalyzerError("invalid_tool_version", operation.value, tool)
                first = lines[0]
                import re

                match = re.search(r"\b\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?", first)
                if match is None:
                    raise AnalyzerError("invalid_tool_version", operation.value, tool)
                result[tool] = {"available": True, "version": match.group()}
            except AnalyzerError as error:
                result[tool] = {"available": False, "version": None, "error": error.as_dict()}
        return result
