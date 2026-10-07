import io
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from wireclaw_analyzer import AnalyzerError, Limits
from wireclaw_analyzer.runner import Operation, Runner
from wireclaw_analyzer.storage import Store


@pytest.mark.parametrize(
    "path",
    ["../secret", "incoming/../../secret", "/etc/passwd", r"C:\Windows\system.ini", "bad\x00name"],
)
def test_path_escape(tmp_path, path):
    store = Store(tmp_path, Limits())
    with pytest.raises(AnalyzerError):
        store.confined(Path(path))


def test_symlink_escape_and_symlink_within_root(tmp_path):
    store = Store(tmp_path, Limits())
    (tmp_path / "target").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "target")
    with pytest.raises(AnalyzerError, match="symlink_rejected"):
        store.confined(Path("link"))
    (tmp_path / "outside").symlink_to(tmp_path.parent)
    with pytest.raises(AnalyzerError, match="symlink_rejected"):
        store.confined(Path("outside/file"))


@pytest.mark.parametrize("capture_id", ["../", "--help", "A" * 64, "0" * 63, None, "$(id)"])
def test_capture_id_validation(tmp_path, capture_id):
    with pytest.raises(AnalyzerError, match="invalid_capture_id"):
        Store(tmp_path, Limits()).capture_path(capture_id)


@pytest.mark.parametrize("value", [0, -1, True, float("nan"), float("inf"), "20"])
def test_invalid_limits(value):
    with pytest.raises(AnalyzerError, match="invalid_limits"):
        Limits(timeout_seconds=value)


def test_only_operations_and_no_caller_command_parameters(tmp_path):
    runner = Runner(Store(tmp_path, Limits()))
    for operation in ("bash", ["tshark", "--help"], "get_capture_metadata", None):
        with pytest.raises(AnalyzerError, match="invalid_operation"):
            runner.run(operation)
    with pytest.raises(TypeError):
        runner.run(Operation.PACKETS, flags=["-X", "lua_script:malicious"])


def fake_process(stdout=b"", stderr=b"", *, timeout=False, returncode=0):
    class Fake:
        def __init__(self):
            self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(stderr)
            self.returncode, self.killed = returncode, False

        def wait(self, timeout=None):
            if timeout is not None and globals_timeout:
                raise subprocess.TimeoutExpired("controlled", timeout)
            return self.returncode

        def kill(self):
            self.killed = True

    globals_timeout = timeout
    return Fake()


def setup_runner(tmp_path, limits=None):
    with patch("wireclaw_analyzer.runner.shutil.which", return_value="/trusted/tshark"):
        return Runner(Store(tmp_path, limits or Limits()))


def test_fixed_direct_args_and_no_payload_logs(tmp_path, caplog):
    runner = setup_runner(tmp_path)
    capture = tmp_path / "$(touch owned); --help"
    capture.write_bytes(b"x")
    process = fake_process(stdout=b"safe", stderr=b"secret payload")
    with patch("wireclaw_analyzer.runner.subprocess.Popen", return_value=process) as spawn:
        assert runner.run(Operation.PACKETS, capture) == "safe"
    arguments, options = spawn.call_args
    assert isinstance(arguments[0], list)
    assert str(capture) in arguments[0]
    assert options["shell"] is False
    assert "-n" in arguments[0]
    assert "secret payload" not in caplog.text


@pytest.mark.parametrize("stdout,stderr", [(b"x" * 1000, b""), (b"", b"SECRET" * 1000)])
def test_bounded_stdout_and_stderr(tmp_path, stdout, stderr):
    runner = setup_runner(tmp_path, Limits(max_output_bytes=100))
    process = fake_process(stdout, stderr)
    with (
        patch("wireclaw_analyzer.runner.subprocess.Popen", return_value=process),
        pytest.raises(AnalyzerError, match="tool_output_limit"),
    ):
        runner.run(Operation.TSHARK_VERSION)
    assert process.killed


def test_timeout_kills_and_reaps(tmp_path):
    runner = setup_runner(tmp_path, Limits(timeout_seconds=0.01))
    process = fake_process(timeout=True)
    with (
        patch("wireclaw_analyzer.runner.subprocess.Popen", return_value=process),
        pytest.raises(AnalyzerError, match="tool_timeout"),
    ):
        runner.run(Operation.TSHARK_VERSION)
    assert process.killed


def test_tool_failure_redacts_stderr(tmp_path):
    runner = setup_runner(tmp_path)
    with (
        patch(
            "wireclaw_analyzer.runner.subprocess.Popen",
            return_value=fake_process(stderr=b"credential=secret", returncode=1),
        ),
        pytest.raises(AnalyzerError) as failure,
    ):
        runner.run(Operation.TSHARK_VERSION)
    assert failure.value.as_dict() == {
        "code": "tool_failed",
        "capability": "tshark_version",
        "tool": "tshark",
    }
    assert "secret" not in str(failure.value)


def test_missing_tools_are_explicit(tmp_path):
    with patch("wireclaw_analyzer.runner.shutil.which", return_value=None):
        runner = Runner(Store(tmp_path, Limits()))
    versions = runner.versions()
    assert all(
        not state["available"] and state["error"]["code"] == "tool_unavailable"
        for state in versions.values()
    )


def test_failed_ingest_cleanup(tmp_path):
    store = Store(tmp_path, Limits())
    source = tmp_path / "source"
    source.write_bytes(b"untrusted")

    def reject(path):
        raise AnalyzerError("malformed_capture")

    with pytest.raises(AnalyzerError):
        store.ingest(source, reject)
    assert not list((tmp_path / "work").iterdir())
    assert not (tmp_path / "cases").exists()


def test_real_subprocess_timeout_and_pipe_bounds(tmp_path):
    import sys

    spawn = subprocess.Popen
    runner = setup_runner(tmp_path, Limits(timeout_seconds=0.05, max_output_bytes=1024))
    for program, expected in (
        ("import time; time.sleep(5)", "tool_timeout"),
        ("import sys; sys.stdout.write('x'*1000000)", "tool_output_limit"),
        ("import sys; sys.stderr.write('x'*1000000)", "tool_output_limit"),
    ):
        children = []

        def execute(*args, program=program, children=children, **kwargs):
            child = spawn([sys.executable, "-c", program], **kwargs)
            children.append(child)
            return child

        with (
            patch("wireclaw_analyzer.runner.subprocess.Popen", side_effect=execute),
            pytest.raises(AnalyzerError, match=expected),
        ):
            runner.run(Operation.TSHARK_VERSION)
        assert children[0].poll() is not None


def test_missing_required_tool_does_not_create_original(tmp_path):
    from wireclaw_analyzer import Analyzer

    (tmp_path / "source").write_bytes(b"\xd4\xc3\xb2\xa1")
    with patch("wireclaw_analyzer.runner.shutil.which", return_value=None):
        analyzer = Analyzer(tmp_path)
    with pytest.raises(AnalyzerError, match="tool_unavailable"):
        analyzer.ingest_capture(Path("source"))
    assert not list(tmp_path.glob("cases/*/original/capture"))


def test_no_arbitrary_artifact_write(tmp_path):
    store = Store(tmp_path, Limits())
    with pytest.raises(AnalyzerError, match="invalid_artifact_name"):
        store.persist("0" * 64, {}, name="../../outside")


def test_empty_version_output_is_structured(tmp_path):
    runner = setup_runner(tmp_path)
    with patch.object(runner, "run", return_value=""):
        versions = runner.versions()
    assert all(state["error"]["code"] == "invalid_tool_version" for state in versions.values())


def test_storage_publication_failure_is_structured_and_cleans_staging(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"synthetic")
    store = Store(tmp_path, Limits())
    with (
        patch("wireclaw_analyzer.storage.os.link", side_effect=OSError("filesystem limitation")),
        pytest.raises(AnalyzerError, match="capture_storage_failure"),
    ):
        store.ingest(source, lambda path: None)
    assert not list((tmp_path / "work").iterdir())
    assert not list(tmp_path.glob("cases/*/original/capture"))
