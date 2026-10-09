from pathlib import Path

path = Path("tests/unit/test_investigation.py")
text = path.read_text()
old = '''    assert result["findings"][0]["category"] == "dns.timing"\n    assert result["conclusion"]["confidence"] == "medium"\n    assert "does not by itself prove" in result["findings"][0]["alternate_explanations"][0]\n'''
new = '''    assert result["findings"][0]["category"] == "dns.timing"\n    assert result["findings"][0]["confidence"] == "low"\n    assert result["conclusion"]["type"] == "insufficient_evidence"\n    assert result["conclusion"]["confidence"] == "low"\n    assert "does not by itself prove" in result["findings"][0]["alternate_explanations"][0]\n'''
if old not in text:
    raise SystemExit("expected DNS regression assertion block not found")
path.write_text(text.replace(old, new, 1))
