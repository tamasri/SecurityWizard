"""Tests for sudoers_parse module."""

import os
import sys
from unittest.mock import MagicMock

import pytest

# Ensure repo root is on sys.path (conftest.py does this, but be safe)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import STATUS_CRITICAL, STATUS_INFO, STATUS_WARNING
from sudoers_parse import (
    SudoRule,
    _command_base_name,
    _has_wildcard,
    _is_risky_command,
    _is_shell_or_interpreter,
    _join_continuations,
    _parse_aliases,
    _parse_rule_line,
    classify_rule,
    parse_all_sudoers,
    parse_sudoers_file,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sudoers_content_simple():
    """Simple sudoers content with a narrow rule."""
    return """# This is a comment
deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app
"""


@pytest.fixture
def sudoers_content_critical():
    """Sudoers content with NOPASSWD: ALL."""
    return """bob ALL=(ALL) NOPASSWD: ALL
"""


@pytest.fixture
def sudoers_content_wildcard_vim():
    """Sudoers content with wildcard on vim."""
    return """x ALL=(root) NOPASSWD: /usr/bin/vim *
"""


@pytest.fixture
def sudoers_content_aliases():
    """Sudoers content with aliases."""
    return """User_Alias ADMINS = alice, bob
Cmnd_Alias RESTART = /usr/local/bin/restart-app, /usr/local/bin/stop-app
ADMINS ALL=(root) NOPASSWD: RESTART
"""


@pytest.fixture
def sudoers_content_negation():
    """Sudoers content with negation."""
    return """!deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app
"""


@pytest.fixture
def sudoers_content_continuation():
    """Sudoers content with line continuation."""
    return """deploy ALL=(root) NOPASSWD: \\
    /usr/local/bin/restart-app, \\
    /usr/local/bin/stop-app
"""


@pytest.fixture
def sudoers_content_defaults():
    """Sudoers content with Defaults lines."""
    return """Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app
"""


# ---------------------------------------------------------------------------
# Tests for _parse_aliases
# ---------------------------------------------------------------------------


def test_parse_aliases():
    content = """User_Alias ADMINS = alice, bob
Cmnd_Alias RESTART = /usr/local/bin/restart-app, /usr/local/bin/stop-app
Runas_Alias ROOT = root
Host_Alias ALL = ALL
"""
    aliases = _parse_aliases(content)
    assert aliases["ADMINS"] == ["alice", "bob"]
    assert aliases["RESTART"] == ["/usr/local/bin/restart-app", "/usr/local/bin/stop-app"]
    assert aliases["ROOT"] == ["root"]
    assert aliases["ALL"] == ["ALL"]


def test_parse_aliases_empty():
    content = "# comment\n"
    aliases = _parse_aliases(content)
    assert aliases == {}


# ---------------------------------------------------------------------------
# Tests for _join_continuations
# ---------------------------------------------------------------------------


def test_join_continuations_simple():
    lines = ["a", "b", "c"]
    result = _join_continuations(lines)
    assert result == [("a", 1), ("b", 2), ("c", 3)]


def test_join_continuations_with_backslash():
    lines = ["a \\", "b", "c"]
    result = _join_continuations(lines)
    assert result == [("a b", 1), ("c", 3)]


def test_join_continuations_multiple_backslashes():
    lines = ["a \\", "b \\", "c"]
    result = _join_continuations(lines)
    assert result == [("a b c", 1)]


# ---------------------------------------------------------------------------
# Tests for _parse_rule_line
# ---------------------------------------------------------------------------


def test_parse_rule_line_narrow():
    line = "deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.user == "deploy"
    assert rule.hosts == ["ALL"]
    assert rule.runas == ["root"]
    assert rule.tags == ["NOPASSWD"]
    assert rule.commands == ["/usr/local/bin/restart-app"]
    assert rule.source_file == "/etc/sudoers"
    assert rule.line == 1
    assert rule.negated is False


def test_parse_rule_line_critical():
    line = "bob ALL=(ALL) NOPASSWD: ALL"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.user == "bob"
    assert rule.hosts == ["ALL"]
    assert rule.runas == ["ALL"]
    assert rule.tags == ["NOPASSWD"]
    assert rule.commands == ["ALL"]


def test_parse_rule_line_wildcard_vim():
    line = "x ALL=(root) NOPASSWD: /usr/bin/vim *"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.user == "x"
    assert rule.hosts == ["ALL"]
    assert rule.runas == ["root"]
    assert rule.tags == ["NOPASSWD"]
    assert rule.commands == ["/usr/bin/vim *"]


def test_parse_rule_line_negated():
    line = "!deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.user == "deploy"
    assert rule.negated is True


def test_parse_rule_line_defaults():
    line = "Defaults env_reset"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is None


def test_parse_rule_line_comment():
    line = "# This is a comment"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is None


def test_parse_rule_line_blank():
    line = ""
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is None


def test_parse_rule_line_alias_definition():
    line = "User_Alias ADMINS = alice, bob"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is None


def test_parse_rule_line_include():
    line = "#include /etc/sudoers.d/users"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is None


def test_parse_rule_line_includedir():
    line = "#includedir /etc/sudoers.d"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is None


def test_parse_rule_line_multiple_commands():
    line = "deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app, /usr/local/bin/stop-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.commands == ["/usr/local/bin/restart-app", "/usr/local/bin/stop-app"]


def test_parse_rule_line_no_nopasswd():
    line = "deploy ALL=(root) /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.tags == []
    assert rule.commands == ["/usr/local/bin/restart-app"]


def test_parse_rule_line_passwd_tag():
    line = "deploy ALL=(root) PASSWD: /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.tags == ["PASSWD"]


def test_parse_rule_line_setenv_tag():
    line = "deploy ALL=(root) SETENV: /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.tags == ["SETENV"]


def test_parse_rule_line_noexec_tag():
    line = "deploy ALL=(root) NOEXEC: /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.tags == ["NOEXEC"]


def test_parse_rule_line_multiple_tags():
    line = "deploy ALL=(root) NOPASSWD: NOEXEC: /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.tags == ["NOPASSWD", "NOEXEC"]


def test_parse_rule_line_group():
    line = "%sudo ALL=(root) NOPASSWD: /usr/local/bin/restart-app"
    rule = _parse_rule_line(line, "/etc/sudoers", 1, {})
    assert rule is not None
    assert rule.user == "%sudo"


def test_parse_rule_line_alias_user():
    line = "ADMINS ALL=(root) NOPASSWD: /usr/local/bin/restart-app"
    aliases = {"ADMINS": ["alice", "bob"]}
    rule = _parse_rule_line(line, "/etc/sudoers", 1, aliases)
    assert rule is not None
    assert rule.user == "alice,bob"


def test_parse_rule_line_alias_command():
    line = "deploy ALL=(root) NOPASSWD: RESTART"
    aliases = {"RESTART": ["/usr/local/bin/restart-app", "/usr/local/bin/stop-app"]}
    rule = _parse_rule_line(line, "/etc/sudoers", 1, aliases)
    assert rule is not None
    assert rule.commands == ["/usr/local/bin/restart-app", "/usr/local/bin/stop-app"]


# ---------------------------------------------------------------------------
# Tests for _has_wildcard
# ---------------------------------------------------------------------------


def test_has_wildcard_true():
    assert _has_wildcard("/usr/bin/vim *") is True
    assert _has_wildcard("ALL") is False
    assert _has_wildcard("/usr/local/bin/restart-app") is False


# ---------------------------------------------------------------------------
# Tests for _command_base_name
# ---------------------------------------------------------------------------


def test_command_base_name():
    assert _command_base_name("/usr/bin/vim *") == "vim"
    assert _command_base_name("/usr/local/bin/restart-app") == "restart-app"
    assert _command_base_name("ALL") == "ALL"
    assert _command_base_name("bash -c 'echo hi'") == "bash"


# ---------------------------------------------------------------------------
# Tests for _is_risky_command
# ---------------------------------------------------------------------------


def test_is_risky_command():
    assert _is_risky_command("bash") is True
    assert _is_risky_command("sh") is True
    assert _is_risky_command("python3") is True
    assert _is_risky_command("vim") is True
    assert _is_risky_command("find") is True
    assert _is_risky_command("docker") is True
    assert _is_risky_command("systemctl") is True
    assert _is_risky_command("/usr/local/bin/restart-app") is False
    assert _is_risky_command("ls") is False


# ---------------------------------------------------------------------------
# Tests for _is_shell_or_interpreter
# ---------------------------------------------------------------------------


def test_is_shell_or_interpreter():
    assert _is_shell_or_interpreter("bash") is True
    assert _is_shell_or_interpreter("sh") is True
    assert _is_shell_or_interpreter("python3") is True
    assert _is_shell_or_interpreter("perl") is True
    assert _is_shell_or_interpreter("vim") is False
    assert _is_shell_or_interpreter("ls") is False


# ---------------------------------------------------------------------------
# Tests for parse_sudoers_file
# ---------------------------------------------------------------------------


def test_parse_sudoers_file_simple(tmp_path, sudoers_content_simple):
    sudoers_file = tmp_path / "sudoers"
    sudoers_file.write_text(sudoers_content_simple)
    rules = parse_sudoers_file(str(sudoers_file))
    assert len(rules) == 1
    assert rules[0].user == "deploy"
    assert rules[0].commands == ["/usr/local/bin/restart-app"]


def test_parse_sudoers_file_critical(tmp_path, sudoers_content_critical):
    sudoers_file = tmp_path / "sudoers"
    sudoers_file.write_text(sudoers_content_critical)
    rules = parse_sudoers_file(str(sudoers_file))
    assert len(rules) == 1
    assert rules[0].user == "bob"
    assert rules[0].commands == ["ALL"]


def test_parse_sudoers_file_wildcard_vim(tmp_path, sudoers_content_wildcard_vim):
    sudoers_file = tmp_path / "sudoers"
    sudoers_file.write_text(sudoers_content_wildcard_vim)
    rules = parse_sudoers_file(str(sudoers_file))
    assert len(rules) == 1
    assert rules[0].user == "x"
    assert rules[0].commands == ["/usr/bin/vim *"]


def test_parse_sudoers_file_aliases(tmp_path, sudoers_content_aliases):
    sudoers_file = tmp_path / "sudoers"
    sudoers_file.write_text(sudoers_content_aliases)
    rules = parse_sudoers_file(str(sudoers_file))
    assert len(rules) == 1
    assert rules[0].user == "alice,bob"
    assert rules[0].commands == ["/usr/local/bin/restart-app", "/usr/local/bin/stop-app"]


def test_parse_sudoers_file_negation(tmp_path, sudoers_content_negation):
    sudoers_file = tmp_path / "sudoers"
    sudoers_file.write_text(sudoers_content_negation)
    rules = parse_sudoers_file(str(sudoers_file))
    assert len(rules) == 1
    assert rules[0].user == "deploy"
    assert rules[0].negated is True


def test_parse_sudoers_file_continuation(tmp_path, sudoers_content_continuation):
    sudoers_file = tmp_path / "sudoers"
    sudoers_file.write_text(sudoers_content_continuation)
    rules = parse_sudoers_file(str(sudoers_file))
    assert len(rules) == 1
    assert rules[0].user == "deploy"
    assert rules[0].commands == ["/usr/local/bin/restart-app", "/usr/local/bin/stop-app"]


def test_parse_sudoers_file_defaults(tmp_path, sudoers_content_defaults):
    sudoers_file = tmp_path / "sudoers"
    sudoers_file.write_text(sudoers_content_defaults)
    rules = parse_sudoers_file(str(sudoers_file))
    assert len(rules) == 1
    assert rules[0].user == "deploy"
    assert rules[0].commands == ["/usr/local/bin/restart-app"]


# ---------------------------------------------------------------------------
# Tests for classify_rule
# ---------------------------------------------------------------------------


def test_classify_rule_narrow():
    rule = SudoRule(
        user="deploy",
        hosts=["ALL"],
        runas=["root"],
        tags=["NOPASSWD"],
        commands=["/usr/local/bin/restart-app"],
        source_file="/etc/sudoers",
        line=1,
    )
    severity, reason = classify_rule(rule)
    assert severity == STATUS_INFO
    assert "narrow" in reason.lower() or "Narrow" in reason


def test_classify_rule_critical_nopasswd_all():
    rule = SudoRule(
        user="bob",
        hosts=["ALL"],
        runas=["ALL"],
        tags=["NOPASSWD"],
        commands=["ALL"],
        source_file="/etc/sudoers",
        line=1,
    )
    severity, reason = classify_rule(rule)
    assert severity == STATUS_CRITICAL
    assert "NOPASSWD: ALL" in reason


def test_classify_rule_wildcard_vim():
    rule = SudoRule(
        user="x",
        hosts=["ALL"],
        runas=["root"],
        tags=["NOPASSWD"],
        commands=["/usr/bin/vim *"],
        source_file="/etc/sudoers",
        line=1,
    )
    severity, reason = classify_rule(rule)
    assert severity == STATUS_CRITICAL
    assert "wildcard" in reason.lower() or "Wildcard" in reason


def test_classify_rule_negated():
    rule = SudoRule(
        user="deploy",
        hosts=["ALL"],
        runas=["root"],
        tags=["NOPASSWD"],
        commands=["/usr/local/bin/restart-app"],
        source_file="/etc/sudoers",
        line=1,
        negated=True,
    )
    severity, reason = classify_rule(rule)
    assert severity == STATUS_INFO
    assert "Negated" in reason


def test_classify_rule_risky_command():
    rule = SudoRule(
        user="bob",
        hosts=["ALL"],
        runas=["root"],
        tags=[],
        commands=["/usr/bin/vim"],
        source_file="/etc/sudoers",
        line=1,
    )
    severity, reason = classify_rule(rule)
    assert severity == STATUS_WARNING
    assert "risky" in reason.lower() or "Risky" in reason


def test_classify_rule_nopasswd_risky_command():
    rule = SudoRule(
        user="bob",
        hosts=["ALL"],
        runas=["root"],
        tags=["NOPASSWD"],
        commands=["/usr/bin/vim"],
        source_file="/etc/sudoers",
        line=1,
    )
    severity, reason = classify_rule(rule)
    assert severity == STATUS_CRITICAL
    assert "NOPASSWD" in reason


def test_classify_rule_allowed_by_config():
    rule = SudoRule(
        user="deploy",
        hosts=["ALL"],
        runas=["root"],
        tags=["NOPASSWD"],
        commands=["/usr/local/bin/restart-app"],
        source_file="/etc/sudoers",
        line=1,
    )
    mock_config = MagicMock()
    mock_config.allowed_sudo_rule.return_value = MagicMock()
    severity, reason = classify_rule(rule, config=mock_config)
    assert severity == STATUS_INFO
    assert "Allowed by config" in reason


def test_classify_rule_not_allowed_by_config():
    rule = SudoRule(
        user="deploy",
        hosts=["ALL"],
        runas=["root"],
        tags=["NOPASSWD"],
        commands=["/usr/local/bin/restart-app"],
        source_file="/etc/sudoers",
        line=1,
    )
    mock_config = MagicMock()
    mock_config.allowed_sudo_rule.return_value = None
    severity, reason = classify_rule(rule, config=mock_config)
    assert severity == STATUS_INFO
    assert "narrow" in reason.lower() or "Narrow" in reason


# ---------------------------------------------------------------------------
# Tests for parse_all_sudoers (with mocked files)
# ---------------------------------------------------------------------------


def test_parse_all_sudoers(tmp_path, monkeypatch):
    # Create /etc/sudoers
    etc_sudoers = tmp_path / "sudoers"
    etc_sudoers.write_text("deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app\n")

    # Create /etc/sudoers.d/
    sudoers_d = tmp_path / "sudoers.d"
    sudoers_d.mkdir()
    extra = sudoers_d / "extra"
    extra.write_text("bob ALL=(ALL) NOPASSWD: ALL\n")

    # Mock os.path.isfile and glob.glob
    monkeypatch.setattr(os.path, "isfile", lambda p: p == "/etc/sudoers" or p == str(etc_sudoers) or p == str(extra))
    monkeypatch.setattr(
        "sudoers_parse.glob.glob", lambda pattern: [str(extra)] if pattern == "/etc/sudoers.d/*" else []
    )

    # Mock open to read from tmp_path
    def mock_open(path, *args, **kwargs):
        if path == "/etc/sudoers":
            return open(str(etc_sudoers), *args, **kwargs)
        elif path == str(extra):
            return open(path, *args, **kwargs)
        else:
            return open(path, *args, **kwargs)

    monkeypatch.setattr("sudoers_parse.builtins_open", mock_open)

    rules = parse_all_sudoers()
    assert len(rules) == 2
    users = [r.user for r in rules]
    assert "deploy" in users
    assert "bob" in users
