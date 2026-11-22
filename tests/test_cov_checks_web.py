"""checks_web: HTTP security response headers and HSTS max-age (every HTTPS GET mocked, no network touched)."""

import pytest

import checks_web
from common import STATUS_CRITICAL, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING
from config import reset_config

FULL_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def _allow(tmp_path, monkeypatch, *hosts):
    entries = ", ".join(f'{{host = "{h}", reason = "test"}}' for h in hosts)
    path = tmp_path / "securitywizard.toml"
    path.write_text(f"[pentest]\ntargets = [{entries}]\n", encoding="utf-8")
    monkeypatch.setenv("SECURITYWIZARD_CONFIG", str(path))
    reset_config()  # force the next get_config() call to reload this file


@pytest.fixture(autouse=True)
def allow_example_com(tmp_path, monkeypatch):
    """Most tests here only care about header logic, so allowlist example.com by default; a test that
    cares about the allowlist itself calls _allow() again with different hosts."""
    reset_config()
    _allow(tmp_path, monkeypatch, "example.com")
    yield
    reset_config()


# ---- configured_domains ---------------------------------------------------------------------------------------


def test_configured_domains_empty_without_config(monkeypatch):
    monkeypatch.delenv("SECURITYWIZARD_CONFIG", raising=False)
    reset_config()
    assert checks_web.configured_domains() == []


# ---- WEB-001: header presence -----------------------------------------------------------------------------------


def test_all_headers_present_is_pass():
    [web001, web002] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: dict(FULL_HEADERS))
    assert web001["id"] == "WEB-001" and web001["status"] == STATUS_PASS
    assert "none" in web001["current_value"].lower().split("missing:")[1]
    assert web002["id"] == "WEB-002" and web002["status"] == STATUS_PASS


def test_missing_referrer_policy_only_is_still_pass():
    headers = {k: v for k, v in FULL_HEADERS.items() if k != "referrer-policy"}
    [web001, _web002] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: headers)
    assert web001["status"] == STATUS_PASS  # Referrer-Policy is informational only


def test_one_core_header_missing_is_a_warning():
    headers = {k: v for k, v in FULL_HEADERS.items() if k != "x-frame-options"}
    [web001, _web002] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: headers)
    assert web001["status"] == STATUS_WARNING and "X-Frame-Options" in web001["current_value"]


def test_three_or_more_core_headers_missing_is_critical():
    headers = {"referrer-policy": "no-referrer"}
    [web001] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: headers)
    assert web001["status"] == STATUS_CRITICAL


def test_no_headers_at_all_is_critical_and_lists_everything_missing():
    [web001] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: {})
    assert web001["status"] == STATUS_CRITICAL
    for label in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"):
        assert label in web001["current_value"]


def test_headers_are_matched_case_insensitively():
    headers = {k.upper(): v for k, v in FULL_HEADERS.items()}
    [web001, _web002] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: headers)
    assert web001["status"] == STATUS_PASS


def test_request_failure_is_skipped():
    def fetch(host, port, timeout):
        raise OSError("connection refused")

    [result] = checks_web.check_security_headers("example.com", fetch=fetch)
    assert result["status"] == STATUS_SKIPPED and "Request failed" in result["current_value"]


def test_host_outside_the_allowlist_is_refused(tmp_path, monkeypatch):
    _allow(tmp_path, monkeypatch, "other.example.com")
    [result] = checks_web.check_security_headers("example.com")
    assert result["status"] == STATUS_SKIPPED and "not in the [pentest] target allowlist" in result["current_value"]


# ---- WEB-002: HSTS max-age -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "max_age, expected",
    [(31536000, STATUS_PASS), (checks_web.MIN_HSTS_MAX_AGE, STATUS_PASS), (3600, STATUS_WARNING), (0, STATUS_WARNING)],
)
def test_hsts_max_age_thresholds(max_age, expected):
    headers = dict(FULL_HEADERS, **{"strict-transport-security": f"max-age={max_age}"})
    [_web001, web002] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: headers)
    assert web002["status"] == expected and f"max-age={max_age}" in web002["current_value"]


def test_hsts_header_without_a_parseable_max_age_is_a_warning():
    headers = dict(FULL_HEADERS, **{"strict-transport-security": "includeSubDomains"})
    [_web001, web002] = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: headers)
    assert web002["status"] == STATUS_WARNING and "Could not parse" in web002["current_value"]


def test_no_hsts_header_means_no_web_002_check():
    headers = {k: v for k, v in FULL_HEADERS.items() if k != "strict-transport-security"}
    results = checks_web.check_security_headers("example.com", fetch=lambda h, p, t: headers)
    assert [r["id"] for r in results] == ["WEB-001"]


def test_parse_hsts_max_age_handles_malformed_values():
    assert checks_web._parse_hsts_max_age("max-age=not-a-number") is None
    assert checks_web._parse_hsts_max_age("includeSubDomains") is None
    assert checks_web._parse_hsts_max_age("max-age=100; includeSubDomains") == 100


# ---- run_checks -----------------------------------------------------------------------------------------------------


def test_run_checks_without_any_domain_configured(monkeypatch):
    monkeypatch.delenv("SECURITYWIZARD_CONFIG", raising=False)
    reset_config()
    [result] = checks_web.run_checks()
    assert result["id"] == "WEB-001" and result["status"] == STATUS_SKIPPED


def test_run_checks_covers_every_configured_domain(tmp_path, monkeypatch):
    _allow(tmp_path, monkeypatch, "a.example.com", "b.example.com")
    monkeypatch.setattr(checks_web, "_fetch_headers", lambda host, port=443, timeout=5.0: dict(FULL_HEADERS))
    results = checks_web.run_checks()
    ids_by_host = {}
    for r in results:
        host = r["title"].split(":")[0]
        ids_by_host.setdefault(host, []).append(r["id"])
    assert ids_by_host == {"a.example.com": ["WEB-001", "WEB-002"], "b.example.com": ["WEB-001", "WEB-002"]}


def test_run_checks_turns_an_unexpected_error_into_a_skipped_result(tmp_path, monkeypatch):
    _allow(tmp_path, monkeypatch, "example.com")

    def boom(host, fetch=None):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(checks_web, "check_security_headers", boom)
    [result] = checks_web.run_checks()
    assert result["status"] == STATUS_SKIPPED and "kaboom" in result["current_value"]
