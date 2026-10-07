import struct

import pytest
from generate import block, frames, pcapng
from wireclaw_analyzer import AnalyzerError
from wireclaw_analyzer.capture_headers import pcapng_metadata


def test_reported_drops_and_missing_drops(tmp_path):
    path = tmp_path / "capture"
    path.write_bytes(pcapng(frames(), drops=True))
    result = pcapng_metadata(path)
    assert result["capture_drops"] == 3
    assert result["snaplen"] == 65535
    assert result["header_provenance"]["version"] == "0.1.0"
    path.write_bytes(pcapng(frames()))
    assert pcapng_metadata(path)["capture_drops"] is None


def test_partial_interfaces_are_unknown(tmp_path):
    path = tmp_path / "capture"
    path.write_bytes(pcapng(frames(), drops=True) + block(1, struct.pack("<HHI", 1, 0, 128)))
    result = pcapng_metadata(path)
    assert result["capture_drops"] is None
    assert result["snaplen"] is None
    assert len(result["interfaces"]) == 2


def test_multiple_sections_and_big_endian(tmp_path):
    def big_block(kind, body):
        size = len(body) + 12
        return struct.pack(">II", kind, size) + body + struct.pack(">I", size)

    big = big_block(0x0A0D0D0A, struct.pack(">IHHq", 0x1A2B3C4D, 1, 0, -1))
    big += big_block(1, struct.pack(">HHI", 1, 0, 65535))
    big += big_block(5, struct.pack(">IIIHHQHH", 0, 0, 0, 5, 8, 5, 0, 0))
    path = tmp_path / "capture"
    path.write_bytes(pcapng(frames(), drops=True) + big)
    result = pcapng_metadata(path)
    assert result["capture_drops"] == 8
    assert [i["section"] for i in result["interfaces"]] == [0, 1]


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"a",
        b"\x0a\x0d\x0d\x0a" + b"\0" * 12,
        pcapng(frames())[:-1],
        pcapng(frames()) + block(5, struct.pack("<III", 77, 0, 0)),
    ],
)
def test_invalid_headers_fail_safely(tmp_path, content):
    path = tmp_path / "capture"
    path.write_bytes(content)
    if not content:
        assert pcapng_metadata(path)["interfaces"] == []
    else:
        with pytest.raises(AnalyzerError, match="invalid_capture_header"):
            pcapng_metadata(path)
