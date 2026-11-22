"""checks_privilege: SUID/SGID hunter, file permission checks, cron inventory and sudoers analysis (mocked system)."""

import os
import stat
from types import SimpleNamespace

import pytest

import checks_privilege
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING, CmdResult


class FakeFS:
    """Files and their (mode, uid, gid), plus glob patterns, for the functions of checks_privilege."""

    def __init__(self, monkeypatch, files=None, globs=None, dirs=(), dir_modes=None, symlinks=()):
        self.files = dict(files or {})
        self.globs = dict(globs or {})
        self.dirs = set(dirs) | set(dir_modes or {})
        self.dir_modes = dict(dir_modes or {})
        self.symlinks = set(symlinks)
        real_stat = os.stat

        def isfile(path):
            return path in self.files

        def isdir(path):
            return path in self.dirs

        def islink(path):
            return path in self.symlinks

        def fake_stat(path, *args, **kwargs):
            if path in self.dir_modes:
                return SimpleNamespace(st_mode=stat.S_IFDIR | self.dir_modes[path], st_uid=0, st_gid=0)
            if path in self.files:
                mode, uid, gid = self.files[path]
                return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid)
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(checks_privilege.os.path, "isfile", isfile)
        monkeypatch.setattr(checks_privilege.os.path, "isdir", isdir)
        monkeypatch.setattr(checks_privilege.os.path, "islink", islink)
        monkeypatch.setattr(checks_privilege.os, "stat", fake_stat)
        monkeypatch.setattr(checks_privilege.glob, "glob", lambda pattern: list(self.globs.get(pattern, [])))


# ---- ownership and permission checks ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "function, path, check_id, good, bad_list",
    [
        (
            "_check_passwd",
            "/etc/passwd",
            "PRV-002",
            (0o644, 0, 0),
            [(0o666, 0, 0), (0o644, 1000, 0), (0o644, 0, 1000), (0o600, 0, 0)],
        ),
        ("_check_group", "/etc/group", "PRV-004", (0o644, 0, 0), [(0o666, 0, 0), (0o644, 1, 0), (0o640, 0, 0)]),
        ("_check_sudoers", "/etc/sudoers", "PRV-005", (0o440, 0, 0), [(0o644, 0, 0), (0o440, 1000, 0), (0o440, 0, 5)]),
        (
            "_check_shadow",
            "/etc/shadow",
            "PRV-003",
            (0o640, 0, 42),
            [(0o644, 0, 42), (0o640, 1000, 42), (0o640, 0, 1000)],
        ),
    ],
)
def test_file_permission_checks(monkeypatch, function, path, check_id, good, bad_list):
    fn = getattr(checks_privilege, function)
    FakeFS(monkeypatch, files={path: good})
    result = fn()
    assert result["status"] == STATUS_PASS and result["id"] == check_id
    for bad in bad_list:
        FakeFS(monkeypatch, files={path: bad})
        assert fn()["status"] == STATUS_CRITICAL, bad
    FakeFS(monkeypatch)  # the file is missing
    missing = fn()
    assert missing["status"] == STATUS_SKIPPED and missing["current_value"] == "File not found"


def test_shadow_accepts_mode_000_for_root_and_reports_owner_and_group(monkeypatch):
    FakeFS(monkeypatch, files={"/etc/shadow": (0o000, 0, 0)})
    result = checks_privilege._check_shadow()
    assert result["status"] == STATUS_PASS and result["current_value"] == "0000 root:root"
    FakeFS(monkeypatch, files={"/etc/shadow": (0o640, 0, 42)})
    assert checks_privilege._check_shadow()["current_value"] == "0640 root:shadow"


def test_current_value_shows_mode_owner_and_group(monkeypatch):
    FakeFS(monkeypatch, files={"/etc/passwd": (0o646, 1000, 7)})
    assert checks_privilege._check_passwd()["current_value"] == "0646 1000:7"


# ---- sshd_config -------------------------------------------------------------------------------------------------


def test_sshd_config_permission_evaluation(monkeypatch):
    FakeFS(monkeypatch, files={"/etc/ssh/sshd_config": (0o644, 0, 0)})
    monkeypatch.setattr(checks_privilege, "read_text", lambda path: "Port 22\n")
    evaluate = checks_privilege._evaluate_sshd_config_permissions
    assert evaluate(0o644, 0) == STATUS_INFO
    assert evaluate(0o640, 0) == STATUS_PASS and evaluate(0o600, 0) == STATUS_PASS and evaluate(0o400, 0) == STATUS_PASS
    assert evaluate(0o664, 0) == STATUS_CRITICAL and evaluate(0o646, 0) == STATUS_CRITICAL
    assert evaluate(0o644, 1000) == STATUS_CRITICAL
    for secret in ("-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"):
        monkeypatch.setattr(checks_privilege, "read_text", lambda path, s=secret: s)
        assert evaluate(0o644, 0) == STATUS_CRITICAL


def test_sshd_config_check_reports_value_and_remediation(monkeypatch):
    FakeFS(monkeypatch, files={"/etc/ssh/sshd_config": (0o644, 0, 0)})
    monkeypatch.setattr(checks_privilege, "read_text", lambda path: "Port 22\n")
    result = checks_privilege._check_sshd_config()
    assert result["status"] == STATUS_INFO and result["current_value"] == "0644 root:root"
    assert result["remediation_id"] == "fix_perm_sshd_config"
    FakeFS(monkeypatch)
    assert checks_privilege._check_sshd_config()["status"] == STATUS_SKIPPED


# ---- cron ------------------------------------------------------------------------------------------------------------


def test_cron_without_any_jobs(monkeypatch):
    FakeFS(monkeypatch)
    result = checks_privilege._check_cron()
    assert result["status"] == STATUS_INFO and result["current_value"] == "No cron jobs found"


def test_cron_inventory_lists_every_source(monkeypatch):
    FakeFS(
        monkeypatch,
        files={
            "/etc/crontab": (0o644, 0, 0),
            "/etc/cron.d/backup": (0o644, 0, 0),
            "/var/spool/cron/crontabs/root": (0o600, 0, 0),
        },
        globs={
            "/etc/cron.d/*": ["/etc/cron.d/backup", "/etc/cron.d/dir"],
            "/var/spool/cron/crontabs/*": ["/var/spool/cron/crontabs/root"],
        },
    )
    result = checks_privilege._check_cron()
    assert result["status"] == STATUS_INFO and result["current_value"] == "3 cron entries found"
    assert any("/etc/cron.d/backup (0644)" in line for line in result["details"])


@pytest.mark.parametrize(
    "files, globs, writable",
    [
        ({"/etc/crontab": (0o666, 0, 0)}, {}, "/etc/crontab"),
        ({"/etc/cron.d/x": (0o662, 0, 0)}, {"/etc/cron.d/*": ["/etc/cron.d/x"]}, "/etc/cron.d/x"),
        (
            {"/var/spool/cron/crontabs/u": (0o602, 0, 0)},
            {"/var/spool/cron/crontabs/*": ["/var/spool/cron/crontabs/u"]},
            "/var/spool/cron/crontabs/u",
        ),
    ],
)
def test_world_writable_cron_files_are_warned_about(monkeypatch, files, globs, writable):
    FakeFS(monkeypatch, files=files, globs=globs)
    result = checks_privilege._check_cron()
    assert result["status"] == STATUS_WARNING and writable in result["current_value"]


# ---- SUID/SGID hunter -------------------------------------------------------------------------------------------------


def test_find_command_has_paths_first_and_prunes_pseudo_filesystems():
    cmd = checks_privilege.build_find_cmd(["/usr/bin", "/opt"])
    assert cmd[:3] == ["find", "/usr/bin", "/opt"] and cmd[3] == "-xdev"
    for excluded in ("/proc", "/sys", "/var/lib/docker", "/var/lib/containerd", "/snap"):
        assert excluded in cmd
    assert cmd[-6:] == ["-perm", "/6000", "-type", "f"] or cmd[-4:] == ["-perm", "/6000", "-type", "f"]


def _suid(monkeypatch, output, dpkg=(), allowed=(), rc=0, err=""):
    FakeFS(
        monkeypatch,
        dirs={"/usr/bin", "/opt"},
        globs={"/var/lib/dpkg/info/*.list": ["/var/lib/dpkg/info/pkg.list"]} if dpkg else {},
    )
    monkeypatch.setattr(checks_privilege, "run_cmd", lambda args, timeout=None: CmdResult(rc, output, err))
    monkeypatch.setattr(checks_privilege, "read_text", lambda path: "\n".join(dpkg))
    monkeypatch.setattr(
        checks_privilege, "get_config", lambda: SimpleNamespace(allowed_suid=lambda path: path in allowed)
    )
    return checks_privilege._check_suid_sgid()


def test_suid_all_known_binaries_pass(monkeypatch):
    result = _suid(
        monkeypatch, "/usr/bin/sudo\n/usr/bin/passwd\n/usr/lib/custom/helper\n", dpkg=["/usr/lib/custom/helper"]
    )
    assert result["status"] == STATUS_PASS and "All 3" in result["current_value"]
    assert any(line.startswith("SAFE (dpkg)") for line in result["details"])


def test_suid_unknown_binary_is_a_warning(monkeypatch):
    result = _suid(monkeypatch, "/usr/bin/sudo\n/opt/odd/tool\n")
    assert result["status"] == STATUS_WARNING and "/opt/odd/tool" in result["current_value"]
    assert "UNKNOWN: /opt/odd/tool" in result["details"]


def test_suid_shell_or_interpreter_is_critical(monkeypatch):
    result = _suid(monkeypatch, "/usr/bin/sudo\n/usr/bin/python3\n/usr/bin/vim\n")
    assert result["status"] == STATUS_CRITICAL and "2 risky" in result["current_value"]


def test_suid_allowlisted_binary_is_accepted(monkeypatch):
    result = _suid(monkeypatch, "/opt/odd/tool\n", allowed={"/opt/odd/tool"})
    assert result["status"] == STATUS_PASS and "ALLOWED: /opt/odd/tool" in result["details"]


def test_suid_reports_why_find_failed(monkeypatch):
    failed = _suid(monkeypatch, "", rc=1, err="find: Permission denied\n")
    assert failed["status"] == STATUS_SKIPPED and "Permission denied" in failed["current_value"]
    quiet = _suid(monkeypatch, "", rc=2)
    assert quiet["status"] == STATUS_SKIPPED and "rc=2" in quiet["current_value"]


def test_suid_skipped_when_no_scan_path_exists(monkeypatch):
    FakeFS(monkeypatch)
    result = checks_privilege._check_suid_sgid()
    assert result["status"] == STATUS_SKIPPED and result["current_value"] == "No scan paths found"


# ---- sudoers analysis -------------------------------------------------------------------------------------------------


def _sudoers(monkeypatch, classified):
    import sudoers_parse

    rules = [
        SimpleNamespace(source_file="/etc/sudoers", line=i + 1, raw=raw) for i, (raw, _sev) in enumerate(classified)
    ]
    severities = {raw: sev for raw, sev in classified}
    monkeypatch.setattr(sudoers_parse, "parse_all_sudoers", lambda: rules)
    monkeypatch.setattr(sudoers_parse, "classify_rule", lambda rule, config=None: (severities[rule.raw], "because"))
    monkeypatch.setattr(checks_privilege, "get_config", lambda: None)
    return checks_privilege._check_nopasswd()


def test_sudoers_without_rules_passes(monkeypatch):
    assert _sudoers(monkeypatch, [])["status"] == STATUS_PASS


@pytest.mark.parametrize(
    "classified, expected, text",
    [
        (
            [("a ALL=(ALL) NOPASSWD: ALL", STATUS_CRITICAL), ("b ALL=(root) /bin/ls", STATUS_INFO)],
            STATUS_CRITICAL,
            "1 critical",
        ),
        ([("a ALL=(root) /usr/bin/vim *", STATUS_WARNING)], STATUS_WARNING, "1 warning-level"),
        (
            [("a ALL=(root) /usr/bin/ls", STATUS_INFO), ("b ALL=(root) /usr/bin/id", STATUS_INFO)],
            STATUS_INFO,
            "2 narrow",
        ),
        ([("a ALL=(root) /usr/bin/ls", STATUS_PASS)], STATUS_PASS, "No sudoers rules"),
    ],
)
def test_sudoers_status_is_the_worst_rule(monkeypatch, classified, expected, text):
    result = _sudoers(monkeypatch, classified)
    assert result["status"] == expected and text in result["current_value"]
    assert len(result["details"]) == len(classified)


# ---- run_checks --------------------------------------------------------------------------------------------------------------


def test_run_checks_returns_ten_results(monkeypatch):
    FakeFS(monkeypatch)
    import sudoers_parse

    monkeypatch.setattr(sudoers_parse, "parse_all_sudoers", lambda: [])
    monkeypatch.setattr(checks_privilege, "get_config", lambda: None)
    results = checks_privilege.run_checks()
    assert [r["id"] for r in results][:6] == ["PRV-001", "PRV-002", "PRV-003", "PRV-004", "PRV-005", "PRV-006"]
    assert [r["id"] for r in results][-2:] == ["PRV-009", "PRV-010"]
    assert len(results) == 10


def test_run_checks_turns_an_exception_into_a_skipped_result(monkeypatch):
    def boom():
        raise RuntimeError("boom")

    for name in (
        "_check_suid_sgid",
        "_check_passwd",
        "_check_shadow",
        "_check_group",
        "_check_sudoers",
        "_check_sshd_config",
        "_check_cron",
        "_check_nopasswd",
        "_check_writable_systemd_units",
        "_check_path_hijack",
    ):
        monkeypatch.setattr(checks_privilege, name, boom)
    boom.__doc__ = None
    results = checks_privilege.run_checks()
    assert len(results) == 10 and all(r["status"] == STATUS_SKIPPED for r in results)


# ---- PRV-009: writable systemd unit files --------------------------------------------------------------------


def test_writable_systemd_units_missing_dir(monkeypatch):
    FakeFS(monkeypatch)
    result = checks_privilege._check_writable_systemd_units()
    assert result["id"] == "PRV-009" and result["status"] == STATUS_SKIPPED


def test_writable_systemd_units_no_local_units(monkeypatch):
    FakeFS(monkeypatch, dirs={"/etc/systemd/system"}, globs={"/etc/systemd/system/*.service": []})
    result = checks_privilege._check_writable_systemd_units()
    assert result["status"] == STATUS_INFO and "No local" in result["current_value"]


def test_writable_systemd_units_all_clean(monkeypatch):
    FakeFS(
        monkeypatch,
        dirs={"/etc/systemd/system"},
        files={"/etc/systemd/system/app.service": (0o644, 0, 0)},
        globs={"/etc/systemd/system/*.service": ["/etc/systemd/system/app.service"]},
    )
    result = checks_privilege._check_writable_systemd_units()
    assert result["status"] == STATUS_PASS and "All 1" in result["current_value"]


def test_writable_systemd_unit_is_flagged(monkeypatch):
    FakeFS(
        monkeypatch,
        dirs={"/etc/systemd/system"},
        files={"/etc/systemd/system/bad.service": (0o664, 0, 0)},
        globs={"/etc/systemd/system/*.service": ["/etc/systemd/system/bad.service"]},
    )
    result = checks_privilege._check_writable_systemd_units()
    assert result["status"] == STATUS_CRITICAL and "bad.service" in result["current_value"]


def test_vendor_symlinked_units_are_not_flagged(monkeypatch):
    FakeFS(
        monkeypatch,
        dirs={"/etc/systemd/system"},
        files={"/etc/systemd/system/vendor.service": (0o666, 0, 0)},
        globs={"/etc/systemd/system/*.service": ["/etc/systemd/system/vendor.service"]},
        symlinks={"/etc/systemd/system/vendor.service"},
    )
    result = checks_privilege._check_writable_systemd_units()
    assert result["status"] == STATUS_INFO  # the only unit was a symlink, so nothing local was scanned


def test_writable_systemd_units_skips_a_file_that_vanished_between_glob_and_stat(monkeypatch):
    FakeFS(
        monkeypatch,
        dirs={"/etc/systemd/system"},
        files={"/etc/systemd/system/ok.service": (0o644, 0, 0)},
        globs={"/etc/systemd/system/*.service": ["/etc/systemd/system/ok.service", "/etc/systemd/system/gone.service"]},
    )
    result = checks_privilege._check_writable_systemd_units()
    assert result["status"] == STATUS_PASS and "All 1" in result["current_value"]


def test_writable_systemd_units_survives_a_glob_error(monkeypatch):
    FakeFS(monkeypatch, dirs={"/etc/systemd/system"})

    def boom(pattern):
        raise OSError("denied")

    monkeypatch.setattr(checks_privilege.glob, "glob", boom)
    assert checks_privilege._check_writable_systemd_units()["status"] == STATUS_SKIPPED


# ---- PRV-010: PATH hijack opportunities ------------------------------------------------------------------------


def test_path_hijack_clean_path(monkeypatch):
    monkeypatch.setattr(checks_privilege, "read_text", lambda path, default="": default)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    FakeFS(monkeypatch, dir_modes={"/usr/bin": 0o755, "/bin": 0o755})
    result = checks_privilege._check_path_hijack()
    assert result["id"] == "PRV-010" and result["status"] == STATUS_PASS
    assert "/usr/bin:/bin" in result["current_value"]


def test_path_hijack_flags_writable_directory(monkeypatch):
    monkeypatch.setattr(checks_privilege, "read_text", lambda path, default="": default)
    monkeypatch.setenv("PATH", "/usr/bin:/opt/evil")
    FakeFS(monkeypatch, dir_modes={"/usr/bin": 0o755, "/opt/evil": 0o777})
    result = checks_privilege._check_path_hijack()
    assert result["status"] == STATUS_CRITICAL and "/opt/evil" in result["current_value"]


def test_path_hijack_flags_relative_entry(monkeypatch):
    monkeypatch.setattr(checks_privilege, "read_text", lambda path, default="": default)
    monkeypatch.setenv("PATH", "/usr/bin::/bin")
    FakeFS(monkeypatch, dir_modes={"/usr/bin": 0o755, "/bin": 0o755})
    result = checks_privilege._check_path_hijack()
    assert result["status"] == STATUS_CRITICAL and "relative/current-directory" in result["current_value"]


def test_path_hijack_prefers_etc_environment(monkeypatch):
    monkeypatch.setattr(
        checks_privilege, "read_text", lambda path, default="": 'PATH="/custom/bin:/usr/bin"\nFOO=bar\n'
    )
    monkeypatch.setenv("PATH", "/should/not/be/used")
    FakeFS(monkeypatch, dir_modes={"/custom/bin": 0o755, "/usr/bin": 0o755})
    result = checks_privilege._check_path_hijack()
    assert "/custom/bin:/usr/bin" in result["current_value"] and "/should/not/be/used" not in result["current_value"]


def test_path_hijack_falls_back_to_default_when_nothing_is_set(monkeypatch):
    monkeypatch.setattr(checks_privilege, "read_text", lambda path, default="": default)
    monkeypatch.delenv("PATH", raising=False)
    FakeFS(monkeypatch)
    result = checks_privilege._check_path_hijack()
    assert "/usr/bin" in result["current_value"]


def test_path_hijack_ignores_nonexistent_entries(monkeypatch):
    monkeypatch.setattr(checks_privilege, "read_text", lambda path, default="": default)
    monkeypatch.setenv("PATH", "/does/not/exist:/usr/bin")
    FakeFS(monkeypatch, dir_modes={"/usr/bin": 0o755})
    result = checks_privilege._check_path_hijack()
    assert result["status"] == STATUS_PASS
