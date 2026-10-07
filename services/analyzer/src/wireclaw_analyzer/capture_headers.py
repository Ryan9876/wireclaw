"""Narrow PCAPNG metadata reader for snaplen and ISB ifdrop; no payload parsing.

capinfos 4.2 does not print ISB drop counters. These observed header values retain
separate provenance, rather than falsely attributing them to capinfos.
"""

import struct
from pathlib import Path

from .errors import AnalyzerError


def pcapng_metadata(path: Path) -> dict:
    interfaces = []
    section = -1
    section_interfaces = []
    endian = "<"
    size = path.stat().st_size
    with path.open("rb") as stream:
        while stream.tell() < size:
            start = stream.tell()
            header = stream.read(8)
            if len(header) != 8:
                raise AnalyzerError("invalid_capture_header")
            if header[:4] == b"\x0a\x0d\x0d\x0a":
                marker = stream.read(4)
                if marker == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif marker == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise AnalyzerError("invalid_capture_header")
                section += 1
                section_interfaces = []
                stream.seek(start + 8)
            kind, length = struct.unpack(endian + "II", header)
            if length < 12 or length % 4 or start + length > size or section < 0:
                raise AnalyzerError("invalid_capture_header")
            stream.seek(start + length - 4)
            if struct.unpack(endian + "I", stream.read(4))[0] != length:
                raise AnalyzerError("invalid_capture_header")
            stream.seek(start + 8)
            if kind == 1:
                if length < 20:
                    raise AnalyzerError("invalid_capture_header")
                _, _, snaplen = struct.unpack(endian + "HHI", stream.read(8))
                interface = {
                    "section": section,
                    "interface": len(section_interfaces),
                    "snaplen": snaplen,
                    "reported_drops": None,
                }
                section_interfaces.append(interface)
                interfaces.append(interface)
            elif kind == 5:
                if length < 24 or length > 65536:
                    raise AnalyzerError("invalid_capture_header")
                interface_id, _, _ = struct.unpack(endian + "III", stream.read(12))
                if interface_id >= len(section_interfaces):
                    raise AnalyzerError("invalid_capture_header")
                end = start + length - 4
                while stream.tell() < end:
                    if end - stream.tell() < 4:
                        raise AnalyzerError("invalid_capture_header")
                    code, count = struct.unpack(endian + "HH", stream.read(4))
                    if stream.tell() + count + (-count % 4) > end:
                        raise AnalyzerError("invalid_capture_header")
                    if code == 0:
                        if count != 0:
                            raise AnalyzerError("invalid_capture_header")
                        break
                    if code == 5:
                        if count != 8:
                            raise AnalyzerError("invalid_capture_header")
                        value = struct.unpack(endian + "Q", stream.read(8))[0]
                        section_interfaces[interface_id]["reported_drops"] = value
                    else:
                        stream.seek(count, 1)
                    stream.seek(-count % 4, 1)
            stream.seek(start + length)
    counts = [interface["reported_drops"] for interface in interfaces]
    snaplens = sorted({interface["snaplen"] for interface in interfaces})
    return {
        "interfaces": interfaces,
        "snaplen": snaplens[0] if len(snaplens) == 1 else None,
        "capture_drops": sum(counts) if counts and all(c is not None for c in counts) else None,
        "header_provenance": {
            "tool": "wireclaw-pcapng-metadata",
            "version": "0.1.0",
            "scope": "IDB snaplen / last reported ISB ifdrop per interface; sum only when all interfaces report",
        },
    }
