"""Accepted risks from the configuration file are applied to scan results."""

from datetime import date, timedelta

import pytest

import config
import scanner
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_WARNING, make_check


def _check(check_id, status, current="PasswordAuthentication yes"):
    return make_check(
        id=check_id,
        category="ssh",
        title="t",
        status=status,
        what_it_checks="w",
        risk="r",
        command="c",
        current_value=current,
    )


@pytest.fixture
def use_config(tmp_path, monkeypatch):
    def _use(text):
        path = tmp_path / "securitywizard.toml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setenv("SECURITYWIZARD_CONFIG", str(path))
        config.reset_config()

    yield _use
    config.reset_config()


def test_accepted_risk_downgrades_the_check_and_improves_the_score(use_config):
    use_config('[[accepted_risk]]\ncheck_id = "SSH-001"\nreason = "Match block handles this"\n')
    checks = [_check("SSH-001", STATUS_CRITICAL), _check("SSH-002", STATUS_PASS)]
    result = scanner._build_result("now", checks)
    first = result["checks"][0]
    assert first["status"] == STATUS_INFO
    assert first["accepted_risk"] == {
        "reason": "Match block handles this",
        "expires": None,
        "original_status": STATUS_CRITICAL,
    }
    assert result["score"] == 100  # INFO is not scored, so only the PASS counts
    assert result["counts"][STATUS_CRITICAL] == 0


def test_expired_accepted_risk_is_ignored(use_config):
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    use_config(f'[[accepted_risk]]\ncheck_id = "SSH-001"\nreason = "temporary"\nexpires = "{yesterday}"\n')
    result = scanner._build_result("now", [_check("SSH-001", STATUS_WARNING)])
    assert result["checks"][0]["status"] == STATUS_WARNING
    assert "accepted_risk" not in result["checks"][0]


def test_unexpired_accepted_risk_is_applied(use_config):
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    use_config(f'[[accepted_risk]]\ncheck_id = "SSH-001"\nreason = "temporary"\nexpires = "{tomorrow}"\n')
    result = scanner._build_result("now", [_check("SSH-001", STATUS_WARNING)])
    assert result["checks"][0]["status"] == STATUS_INFO


def test_match_filter_must_appear_in_the_evidence(use_config):
    use_config('[[accepted_risk]]\ncheck_id = "KRN-001"\nreason = "needed"\nmatch = "ip_forward"\n')
    other = scanner._build_result("now", [_check("KRN-001", STATUS_WARNING, "net.ipv4.conf.all.rp_filter = 0")])
    same = scanner._build_result("now", [_check("KRN-001", STATUS_WARNING, "net.ipv4.ip_forward = 1")])
    assert other["checks"][0]["status"] == STATUS_WARNING
    assert same["checks"][0]["status"] == STATUS_INFO


def test_only_warnings_and_criticals_are_accepted(use_config):
    use_config('[[accepted_risk]]\ncheck_id = "SSH-001"\nreason = "x"\n')
    result = scanner._build_result("now", [_check("SSH-001", STATUS_PASS)])
    assert result["checks"][0]["status"] == STATUS_PASS


def test_a_broken_configuration_never_stops_the_scan(use_config):
    use_config("this is not = [valid toml")
    result = scanner._build_result("now", [_check("SSH-001", STATUS_WARNING)])
    assert result["checks"][0]["status"] == STATUS_WARNING
