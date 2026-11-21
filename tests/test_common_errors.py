import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (
    STATUS_INFO,
    STATUS_PASS,
    STATUS_SKIPPED,
    is_root,
    make_check,
    read_text,
    run_cmd,
    skipped_check,
)


class TestCmdResult:
    def test_not_found(self):
        result = run_cmd(["nonexistent-binary-xyz"])
        assert result.not_found is True
        assert result.timed_out is False
        assert result.returncode == 127
        assert "not found" in result.stderr
        assert not result.ok()

    def test_timeout(self):
        result = run_cmd(["sleep", "10"], timeout=0.1)
        assert result.timed_out is True
        assert result.not_found is False
        assert result.returncode == 124
        assert "timeout" in result.stderr
        assert not result.ok()

    def test_success(self):
        result = run_cmd(["echo", "hello"])
        assert result.returncode == 0
        assert result.stdout.strip() == "hello"
        assert result.not_found is False
        assert result.timed_out is False
        assert result.ok()

    def test_nonzero_exit(self):
        result = run_cmd(["false"])
        assert result.returncode != 0
        assert result.not_found is False
        assert result.timed_out is False
        assert not result.ok()

    def test_unexpected_exception_logged(self, caplog, monkeypatch, tmp_path):
        import subprocess

        def fake_run(*args, **kwargs):
            raise OSError("fake os error")

        monkeypatch.setattr(subprocess, "run", fake_run)
        with caplog.at_level(logging.ERROR, logger="securitywizard"):
            result = run_cmd(["some", "args"])
        assert result.returncode == 1
        assert result.not_found is False
        assert result.timed_out is False
        assert not result.ok()
        assert "fake os error" in result.stderr
        assert any("Unexpected error" in r.message for r in caplog.records)

    def test_argument_list_only(self):
        result = run_cmd(["echo", "a b c"])
        assert result.stdout.strip() == "a b c"


class TestSkippedCheck:
    def test_skipped_reason_in_details(self):
        c = skipped_check(
            id="T-1",
            category="ssh",
            title="Test",
            what_it_checks="w",
            risk="r",
            command="cmd",
            reason="FileNotFoundError: [Errno 2] /etc/ssh/sshd_config",
        )
        assert c["status"] == STATUS_SKIPPED
        assert "FileNotFoundError" in c["current_value"]
        assert "FileNotFoundError" in c["details"][0]


class TestScannerExceptionHandling:
    def test_check_raising_becomes_skipped(self, monkeypatch):
        import scanner

        def run_checks_raises():
            raise ValueError("boom happened")

        mod = type("mod", (), {"run_checks": staticmethod(run_checks_raises)})()
        importlib_stub = type("m", (), {"import_module": staticmethod(lambda name: mod)})()

        monkeypatch.setattr(scanner, "importlib", importlib_stub)

        result = scanner._run_module("ssh", "checks_ssh")
        assert len(result) == 1
        assert result[0]["status"] == STATUS_SKIPPED
        assert "ValueError" in result[0]["current_value"]
        assert "boom happened" in result[0]["current_value"]


class TestMakeCheck:
    def test_invalid_status_defaults_to_info(self, caplog):
        with caplog.at_level(logging.WARNING, logger="securitywizard"):
            c = make_check(
                id="T-2",
                category="network",
                title="Test",
                status="BOGUS",
                what_it_checks="w",
                risk="r",
                command="cmd",
            )
        assert c["status"] == STATUS_INFO
        assert any("Unknown status" in r.message for r in caplog.records)

    def test_valid_status_preserved(self):
        c = make_check(
            id="T-3",
            category="network",
            title="Test",
            status=STATUS_PASS,
            what_it_checks="w",
            risk="r",
            command="cmd",
        )
        assert c["status"] == STATUS_PASS


class TestReadText:
    def test_read_existing_file(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("hello world")
        assert read_text(str(f)) == "hello world"

    def test_read_missing_file_returns_default(self, caplog):
        with caplog.at_level(logging.WARNING, logger="securitywizard"):
            result = read_text("/nonexistent/file/path", default="DEFAULT")
        assert result == "DEFAULT"
        assert any("Failed to read" in r.message for r in caplog.records)


class TestIsRoot:
    def test_is_root_returns_bool(self):
        assert isinstance(is_root(), bool)


def test_cmd_result_supports_tuple_unpacking_and_attributes():
    """Many checks unpack `rc, out, err = run_cmd(...)`; the result object must support both styles."""
    import sys

    from common import run_cmd

    result = run_cmd([sys.executable, "-c", "import sys; print('hello'); sys.stderr.write('oops'); sys.exit(3)"])
    rc, out, err = result
    assert (rc, out.strip(), err) == (3, "hello", "oops")
    assert result.returncode == 3 and result.stdout.strip() == "hello"
    rc, out, err = run_cmd(["definitely-not-a-real-command-xyz"])
    assert rc == 127 and out == ""
