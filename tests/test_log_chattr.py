"""Tests that chattr +a remediations have been removed from LOG-001/LOG-002."""
import pathlib
import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKS_LOGS = REPO_ROOT / "checks_logs.py"
ACTIONS_SYSTEM = REPO_ROOT / "actions_system.py"


def test_no_chattr_in_checks_logs():
    """chattr must not appear anywhere in checks_logs.py."""
    text = CHECKS_LOGS.read_text(encoding="utf-8")
    assert "chattr" not in text, "chattr still present in checks_logs.py"


def test_no_chattr_in_actions_system():
    """chattr must not appear anywhere in actions_system.py."""
    text = ACTIONS_SYSTEM.read_text(encoding="utf-8")
    assert "chattr" not in text, "chattr still present in actions_system.py"


def test_old_remediation_ids_not_registered():
    """The old chattr-based remediation ids must no longer be in the ACTIONS registry."""
    import actions_system
    for old_id in ("log_append_only_auth", "log_append_only_syslog"):
        assert old_id not in actions_system.ACTIONS, (
            f"{old_id} is still registered in ACTIONS"
        )


def test_preview_old_id_returns_error():
    """Previewing an old chattr remediation id must not succeed."""
    import actions_system
    import remediator

    for old_id in ("log_append_only_auth", "log_append_only_syslog"):
        result = remediator.preview(old_id)
        assert result is not None, "preview returned None"
        assert result.get("blocked") is True, (
            f"preview({old_id}) was not blocked: {result}"
        )
        assert "Unknown remediation" in result.get("blocked_reason", ""), (
            f"preview({old_id}) blocked_reason does not mention Unknown remediation: {result.get('blocked_reason')}"
        )


def test_check_log_attr_no_chattr(tmp_path):
    """Call _check_log_attr with a mocked file path and verify no chattr in output."""
    import checks_logs

    # Create a mock log file
    mock_log = tmp_path / "auth.log"
    mock_log.write_text("test log content")

    result = checks_logs._check_log_attr(str(mock_log), "LOG-001", None, "/var/log/auth.log")

    # Verify no chattr in any string field (excluding the path itself)
    assert result["status"] == "INFO"
    assert "chattr" not in result["current_value"]
    assert "chattr" not in result["recommended_value"]
    assert "chattr" not in str(result["details"])
    assert "chattr" not in result["manual_command"]
