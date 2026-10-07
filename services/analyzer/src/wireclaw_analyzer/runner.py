"""Fixed operation plans only: no caller flags, filters or executable paths."""

import os
import shutil
import subprocess
import threading
from enum import Enum
from pathlib import Path

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
)


class Operation(Enum):
    TSHARK_VERSION = "tshark_version"
    CAPINFOS_VERSION = "capinfos_version"
    ZEEK_VERSION = "zeek_version"
    METADATA = "get_capture_metadata"
    PACKETS = "baseline_packet_fields"


class Runner:
    def __init__(self, store: Store):
        self.store = store
        # PATH is administrator environment, never request data. Discovery occurs once.
        self._tools = {tool: shutil.which(tool) for tool in ("tshark", "capinfos", "zeek")}

    def run(self, operation: Operation, capture: Path | None = None) -> str:
        if not isinstance(operation, Operation):
            raise AnalyzerError("invalid_operation")
        tool = {Operation.METADATA: "capinfos", Operation.PACKETS: "tshark"}.get(
            operation, operation.value.split("_")[0]
        )
        executable = self._tools[tool]
        if executable is None:
            raise AnalyzerError("tool_unavailable", operation.value, tool)
        if operation in (Operation.METADATA, Operation.PACKETS):
            if capture is None:
                raise AnalyzerError("capture_required")
            capture = self.store.confined(capture)
            if capture.stat().st_size > self.store.limits.max_capture_bytes:
                raise AnalyzerError("capture_size_limit")
        elif capture is not None:
            raise AnalyzerError("unexpected_parameter")
        if operation is Operation.METADATA:
            args = [executable, "-M", "-t", "-E", "-c", "-s", "-d", "-l", "-u", "-I", str(capture)]
        elif operation is Operation.PACKETS:
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
            for field in FIELDS:
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
