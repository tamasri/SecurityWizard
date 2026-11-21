import pytest
from scanner import compute_score
from common import STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED


def _check(status, id="CHK-1"):
    return {"id": id, "status": status, "category": "test", "title": "Test", "remediation_id": None}


def test_empty_results_score_none():
    result = compute_score([])
    assert result["score"] is None
    assert result["counts"] == {
        STATUS_PASS: 0, STATUS_WARNING: 0, STATUS_CRITICAL: 0,
        STATUS_INFO: 0, STATUS_SKIPPED: 0
    }
    assert result["excluded"] == 0
    assert "No scored checks" in result["formula"]
    assert "not_scanned" in result


def test_all_pass_score_100():
    checks = [_check(STATUS_PASS, "P1"), _check(STATUS_PASS, "P2"), _check(STATUS_PASS, "P3")]
    result = compute_score(checks)
    assert result["score"] == 100
    assert result["counts"][STATUS_PASS] == 3
    assert result["excluded"] == 0
    assert "not_scanned" not in result


def test_all_warning_score_50():
    checks = [_check(STATUS_WARNING, "W1"), _check(STATUS_WARNING, "W2")]
    result = compute_score(checks)
    assert result["score"] == 50
    assert result["counts"][STATUS_WARNING] == 2


def test_all_critical_score_0():
    checks = [_check(STATUS_CRITICAL, "C1"), _check(STATUS_CRITICAL, "C2")]
    result = compute_score(checks)
    assert result["score"] == 0
    assert result["counts"][STATUS_CRITICAL] == 2


def test_mixed_pass_warning_critical():
    checks = [
        _check(STATUS_PASS, "P1"),
        _check(STATUS_PASS, "P2"),
        _check(STATUS_WARNING, "W1"),
        _check(STATUS_CRITICAL, "C1"),
    ]
    result = compute_score(checks)
    # numerator = 2*1.0 + 1*0.5 + 1*0.0 = 2.5
    # denominator = 2 + 1 + 1 = 4
    # score = round(100 * 2.5 / 4) = round(62.5) = 62
    assert result["score"] == 62
    assert result["counts"][STATUS_PASS] == 2
    assert result["counts"][STATUS_WARNING] == 1
    assert result["counts"][STATUS_CRITICAL] == 1
    assert result["excluded"] == 0


def test_skipped_excluded_from_denominator():
    checks = [
        _check(STATUS_PASS, "P1"),
        _check(STATUS_SKIPPED, "S1"),
        _check(STATUS_SKIPPED, "S2"),
    ]
    result = compute_score(checks)
    # Only PASS counts: numerator=1, denom=1, score=100
    assert result["score"] == 100
    assert result["excluded"] == 2  # 2 SKIPPED
    assert result["counts"][STATUS_SKIPPED] == 2


def test_info_excluded_from_denominator():
    checks = [
        _check(STATUS_PASS, "P1"),
        _check(STATUS_INFO, "I1"),
        _check(STATUS_INFO, "I2"),
    ]
    result = compute_score(checks)
    # Only PASS counts: numerator=1, denom=1, score=100
    assert result["score"] == 100
    assert result["excluded"] == 2  # 2 INFO


def test_all_skipped_score_none():
    checks = [_check(STATUS_SKIPPED, "S1"), _check(STATUS_SKIPPED, "S2")]
    result = compute_score(checks)
    assert result["score"] is None
    assert result["excluded"] == 2
    assert "not_scanned" in result


def test_all_info_score_none():
    checks = [_check(STATUS_INFO, "I1"), _check(STATUS_INFO, "I2")]
    result = compute_score(checks)
    assert result["score"] is None
    assert result["excluded"] == 2
    assert "not_scanned" in result


def test_skipped_and_info_score_none():
    checks = [_check(STATUS_SKIPPED, "S1"), _check(STATUS_INFO, "I1")]
    result = compute_score(checks)
    assert result["score"] is None
    assert result["excluded"] == 2
    assert "not_scanned" in result


def test_weights_included_in_result():
    checks = [_check(STATUS_PASS, "P1")]
    result = compute_score(checks)
    assert result["weights"]["PASS"] == 1.0
    assert result["weights"]["WARNING"] == 0.5
    assert result["weights"]["CRITICAL"] == 0.0
    assert result["weights"]["INFO"] == "excluded"
    assert result["weights"]["SKIPPED"] == "excluded"


def test_formula_string_present():
    checks = [_check(STATUS_PASS, "P1"), _check(STATUS_WARNING, "W1")]
    result = compute_score(checks)
    assert "100" in result["formula"]
    assert "PASS" in result["formula"]
    assert "WARNING" in result["formula"]
