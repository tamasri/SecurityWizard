"""checks_resilience: Traefik/Nginx/Stalwart rate-limit and timeout config review, and fail2ban jail scoping.

This module never sends traffic anywhere; every test here only ever reads from tmp_path (or injected
patterns), never a real system path, and never opens a socket.
"""

from types import SimpleNamespace

import checks_resilience
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


# ---- RES-001: Traefik ------------------------------------------------------------------------------------------


def test_traefik_missing_configuration_is_skipped(tmp_path):
    result = checks_resilience.check_traefik_limits(patterns=[str(tmp_path / "nope.yaml")])
    assert result["id"] == "RES-001" and result["status"] == STATUS_SKIPPED


def test_traefik_all_limits_present_is_pass(tmp_path):
    path = _write(
        tmp_path,
        "dynamic.yaml",
        "http:\n  middlewares:\n    limit:\n      rateLimit:\n        average: 100\n"
        "  routers:\n    app:\n      middlewares: [limit]\nserversTransport:\n  maxRequestBodyBytes: 1048576\n"
        "transport:\n  respondingTimeouts:\n    idleTimeout: 60s\n",
    )
    result = checks_resilience.check_traefik_limits(patterns=[path])
    assert result["status"] == STATUS_PASS


def test_traefik_missing_everything_is_critical(tmp_path):
    path = _write(tmp_path, "dynamic.yaml", "http:\n  routers:\n    app:\n      rule: Host(`x`)\n")
    result = checks_resilience.check_traefik_limits(patterns=[path])
    assert result["status"] == STATUS_CRITICAL
    assert "rateLimit middleware" in result["current_value"]
    assert "maxRequestBodyBytes" in result["current_value"]
    assert "timeouts" in result["current_value"]


def test_traefik_missing_one_item_is_a_warning(tmp_path):
    path = _write(
        tmp_path,
        "dynamic.yaml",
        "http:\n  middlewares:\n    limit:\n      rateLimit:\n        average: 100\n"
        "serversTransport:\n  maxRequestBodyBytes: 1048576\n",
    )
    result = checks_resilience.check_traefik_limits(patterns=[path])
    assert result["status"] == STATUS_WARNING and "timeouts" in result["current_value"]


def test_traefik_matches_multiple_files_via_glob(tmp_path):
    (tmp_path / "a.yaml").write_text("rateLimit:\n  average: 1\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text(
        "maxRequestBodyBytes: 1\nrespondingTimeouts:\n  idleTimeout: 1s\n", encoding="utf-8"
    )
    result = checks_resilience.check_traefik_limits(patterns=[str(tmp_path / "*.yaml")])
    assert result["status"] == STATUS_PASS and len(result["details"]) == 2


# ---- RES-002: Nginx --------------------------------------------------------------------------------------------


def test_nginx_missing_configuration_is_skipped(tmp_path):
    result = checks_resilience.check_nginx_limits(patterns=[str(tmp_path / "nope.conf")])
    assert result["status"] == STATUS_SKIPPED


def test_nginx_all_limits_present_is_pass(tmp_path):
    path = _write(
        tmp_path,
        "nginx.conf",
        "http {\n  limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;\n"
        "  limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "  client_max_body_size 10m;\n  keepalive_timeout 65;\n}\n",
    )
    result = checks_resilience.check_nginx_limits(patterns=[path])
    assert result["status"] == STATUS_PASS


def test_nginx_missing_everything_is_critical(tmp_path):
    path = _write(tmp_path, "nginx.conf", "http {\n  server_name example.com;\n}\n")
    result = checks_resilience.check_nginx_limits(patterns=[path])
    assert result["status"] == STATUS_CRITICAL


def test_nginx_missing_two_items_is_still_a_warning(tmp_path):
    path = _write(
        tmp_path,
        "nginx.conf",
        "http {\n  limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;\n"
        "  limit_conn_zone $binary_remote_addr zone=addr:10m;\n}\n",
    )
    result = checks_resilience.check_nginx_limits(patterns=[path])
    assert result["status"] == STATUS_WARNING


# ---- RES-003: Stalwart (best effort) ----------------------------------------------------------------------------


def test_stalwart_missing_configuration_is_skipped(tmp_path):
    result = checks_resilience.check_stalwart_limits(patterns=[str(tmp_path / "nope.toml")])
    assert result["status"] == STATUS_SKIPPED


def test_stalwart_with_limit_keys_is_informational_not_pass(tmp_path):
    path = _write(tmp_path, "config.toml", '[server]\ntimeout = "30s"\nmax-connections = 100\n')
    result = checks_resilience.check_stalwart_limits(patterns=[path])
    assert result["status"] == STATUS_INFO
    assert "timeout" in result["current_value"] and "verify" in result["current_value"].lower()


def test_stalwart_without_limit_keys_is_a_warning(tmp_path):
    path = _write(tmp_path, "config.toml", '[server]\nhostname = "mail.example.com"\n')
    result = checks_resilience.check_stalwart_limits(patterns=[path])
    assert result["status"] == STATUS_WARNING


# ---- RES-004: fail2ban/CrowdSec jail scoping --------------------------------------------------------------------


def test_fail2ban_no_file_and_not_active_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(
        checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=False, crowdsec=False)
    )
    result = checks_resilience.check_fail2ban_scoping(patterns=[str(tmp_path / "nope.local")])
    assert result["status"] == STATUS_SKIPPED and "does not appear to be active" in result["current_value"]


def test_fail2ban_active_but_no_file_is_skipped_with_a_different_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[str(tmp_path / "nope.local")])
    assert result["status"] == STATUS_SKIPPED and "no jail configuration file was found" in result["current_value"]


def test_fail2ban_all_expected_jails_scoped_is_pass(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        "jail.local",
        "[sshd]\nenabled = true\nmaxretry = 5\nbantime = 3600\n\n"
        "[postfix-sasl]\nenabled = true\nmaxretry = 3\n\n"
        "[nginx-http-auth]\nenabled = true\nmaxretry = 5\n",
    )
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[path])
    assert result["status"] == STATUS_PASS
    assert "ssh" in result["current_value"] and "sshd" in result["current_value"]


def test_fail2ban_disabled_jail_does_not_count_as_scoped(tmp_path, monkeypatch):
    path = _write(tmp_path, "jail.local", "[sshd]\nenabled = false\n")
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[path])
    assert result["status"] == STATUS_CRITICAL and "ssh" in result["current_value"]


def test_fail2ban_missing_services_is_warning_when_some_are_covered(tmp_path, monkeypatch):
    path = _write(tmp_path, "jail.local", "[sshd]\nenabled = true\nmaxretry = 5\n")
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[path])
    assert result["status"] == STATUS_WARNING
    assert "mail" in result["current_value"] and "web auth" in result["current_value"]


def test_fail2ban_too_permissive_maxretry_is_a_warning(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        "jail.local",
        "[sshd]\nenabled = true\nmaxretry = 50\n\n[postfix]\nenabled = true\n\n[traefik-auth]\nenabled = true\n",
    )
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[path])
    assert result["status"] == STATUS_WARNING and "maxretry=50" in result["current_value"]


def test_fail2ban_very_short_bantime_is_flagged(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        "jail.local",
        "[sshd]\nenabled = true\nmaxretry = 5\nbantime = 30\n\n[postfix]\nenabled = true\n\n[traefik-auth]\nenabled = true\n",
    )
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[path])
    assert result["status"] == STATUS_WARNING and "bantime=30" in result["current_value"]


def test_fail2ban_permanent_bantime_is_not_flagged_as_too_short(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        "jail.local",
        "[sshd]\nenabled = true\nmaxretry = 5\nbantime = -1\n\n[postfix]\nenabled = true\n\n[traefik-auth]\nenabled = true\n",
    )
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[path])
    assert result["status"] == STATUS_PASS


def test_fail2ban_malformed_maxretry_is_not_treated_as_a_crash(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        "jail.local",
        "[sshd]\nenabled = true\nmaxretry = not-a-number\n\n[postfix]\nenabled = true\n\n[traefik-auth]\nenabled = true\n",
    )
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[path])
    assert result["status"] == STATUS_PASS  # an unparsable maxretry is simply not flagged, not a crash


def test_traefik_a_path_matched_by_two_patterns_is_only_read_once(tmp_path):
    path = _write(tmp_path, "dynamic.yaml", "rateLimit:\n  average: 1\nmaxRequestBodyBytes: 1\nidleTimeout: 1s\n")
    result = checks_resilience.check_traefik_limits(patterns=[path, path])
    assert result["status"] == STATUS_PASS and len(result["details"]) == 1


def test_fail2ban_reads_multiple_files_via_glob(tmp_path, monkeypatch):
    _write(tmp_path, "10-sshd.conf", "[sshd]\nenabled = true\nmaxretry = 5\n")
    _write(tmp_path, "20-mail.conf", "[postfix]\nenabled = true\n")
    _write(tmp_path, "30-web.conf", "[nginx-http-auth]\nenabled = true\n")
    monkeypatch.setattr(checks_resilience, "detect_environment", lambda: SimpleNamespace(fail2ban=True, crowdsec=False))
    result = checks_resilience.check_fail2ban_scoping(patterns=[str(tmp_path / "*.conf")])
    assert result["status"] == STATUS_PASS


# ---- run_checks -----------------------------------------------------------------------------------------------------


def test_run_checks_returns_all_four_in_order(monkeypatch):
    monkeypatch.setattr(checks_resilience, "check_traefik_limits", lambda: {"id": "RES-001"})
    monkeypatch.setattr(checks_resilience, "check_nginx_limits", lambda: {"id": "RES-002"})
    monkeypatch.setattr(checks_resilience, "check_stalwart_limits", lambda: {"id": "RES-003"})
    monkeypatch.setattr(checks_resilience, "check_fail2ban_scoping", lambda: {"id": "RES-004"})
    assert [r["id"] for r in checks_resilience.run_checks()] == ["RES-001", "RES-002", "RES-003", "RES-004"]


def test_run_checks_turns_an_exception_into_a_skipped_result(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(checks_resilience, "check_traefik_limits", boom)
    monkeypatch.setattr(checks_resilience, "check_nginx_limits", lambda: {"id": "RES-002", "status": STATUS_PASS})
    monkeypatch.setattr(checks_resilience, "check_stalwart_limits", lambda: {"id": "RES-003", "status": STATUS_PASS})
    monkeypatch.setattr(checks_resilience, "check_fail2ban_scoping", lambda: {"id": "RES-004", "status": STATUS_PASS})
    results = checks_resilience.run_checks()
    assert results[0]["id"] == "RES-001" and results[0]["status"] == STATUS_SKIPPED
    assert "kaboom" in results[0]["current_value"]
