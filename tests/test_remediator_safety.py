"""Safety nets of the remediation engine that real actions rely on.

Regression: the dead-man switch only looked at the registry entry while every real SSH/firewall action sets
`risky_remote` in its plan, so the automatic revert was never armed; and the anti-lockout `precondition`
stored in a plan was never called.
"""

import pytest

import remediator


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    monkeypatch.setenv("SECURITYWIZARD_ALLOW_NONROOT", "1")
    monkeypatch.setattr(remediator, "_is_root", lambda: False)
    monkeypatch.setattr(remediator, "ACTIONS", {})
    return tmp_path


def _register(monkeypatch, rid, plan, **info):
    entry = {"title": rid, "description": "", "build_plan": lambda: dict(plan)}
    entry.update(info)
    monkeypatch.setitem(remediator.ACTIONS, rid, entry)


def _runner(cmd):
    return 0, "", ""


# ---- the plan's own anti-lockout check ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "check, expected",
    [
        (None, []),
        (lambda: [], []),
        (lambda: None, []),
        (lambda: ["would close your SSH port"], ["would close your SSH port"]),
        (lambda: ["a", "b"], ["a", "b"]),
        (lambda: "single reason", ["single reason"]),
    ],
)
def test_plan_precondition_results(check, expected):
    plan = {} if check is None else {"precondition": check}
    assert remediator._plan_precondition(plan) == expected


def test_a_failing_precondition_check_refuses_the_change():
    def broken():
        raise RuntimeError("cannot tell")

    [reason] = remediator._plan_precondition({"precondition": broken})
    assert "precondition check failed" in reason and "cannot tell" in reason


def test_apply_refuses_when_the_plan_precondition_says_so(env, monkeypatch):
    ran = []
    _register(
        monkeypatch,
        "ssh_risky",
        {"commands": [["touch", "x"]], "risky_remote": True, "precondition": lambda: ["no key for the current user"]},
    )
    result = remediator.apply("ssh_risky", confirm=True, runner=lambda cmd: ran.append(cmd) or (0, "", ""))
    assert result["ok"] is False and result["message"] == "precondition: no key for the current user"
    assert ran == [] and not (env / "backups").exists()  # nothing ran and no snapshot was taken


def test_preview_shows_the_precondition_as_the_reason_it_is_blocked(env, monkeypatch):
    _register(monkeypatch, "ufw_like", {"commands": [["ufw", "enable"]], "precondition": lambda: ["SSH port unknown"]})
    result = remediator.preview("ufw_like")
    assert result["blocked"] is True and result["blocked_reason"] == "SSH port unknown"


def test_blockers_and_preconditions_are_both_reported(env, monkeypatch):
    plan = {"blockers": ["ufw missing"], "precondition": lambda: ["SSH port unknown"]}
    _register(monkeypatch, "both", plan)
    assert remediator.preview("both")["blocked_reason"] == "ufw missing; SSH port unknown"


# ---- the dead-man switch --------------------------------------------------------------------------------------------


def _arm_spy(monkeypatch):
    armed = []
    monkeypatch.setattr(
        remediator.deadman, "arm", lambda token, revert, minutes, bdir, info=None: armed.append((token, minutes, info))
    )
    return armed


def test_dead_man_is_armed_when_only_the_plan_marks_the_change_risky(env, monkeypatch):
    armed = _arm_spy(monkeypatch)
    _register(monkeypatch, "ssh_plan_flag", {"commands": [["true"]], "risky_remote": True})
    result = remediator.apply("ssh_plan_flag", confirm=True, runner=_runner)
    assert result["ok"] is True and result["deadman_token"] == "DM-ssh_plan_flag" and result["deadline"] > 0
    assert armed and armed[0][0] == "DM-ssh_plan_flag" and armed[0][1] == 5
    assert armed[0][2]["snapshot_id"] == result["snapshot_id"]


def test_dead_man_minutes_can_come_from_the_plan(env, monkeypatch):
    armed = _arm_spy(monkeypatch)
    _register(monkeypatch, "slow_change", {"commands": [["true"]], "risky_remote": True, "deadman_minutes": 12})
    remediator.apply("slow_change", confirm=True, runner=_runner)
    assert armed[0][1] == 12


def test_the_registry_flag_still_works(env, monkeypatch):
    armed = _arm_spy(monkeypatch)
    _register(monkeypatch, "legacy_flag", {"commands": [["true"]]}, risky_remote=True, deadman_minutes=3)
    assert remediator.apply("legacy_flag", confirm=True, runner=_runner)["deadman_token"] == "DM-legacy_flag"
    assert armed[0][1] == 3


def test_ordinary_changes_do_not_arm_the_dead_man(env, monkeypatch):
    armed = _arm_spy(monkeypatch)
    _register(monkeypatch, "plain_change", {"commands": [["true"]]})
    result = remediator.apply("plain_change", confirm=True, runner=_runner)
    assert result["ok"] is True and "deadman_token" not in result and armed == []


def test_every_real_ssh_and_firewall_action_is_protected():
    """The shipped actions that can cut the connection must declare it in their plan and have an anti-lockout check."""
    import importlib

    real = importlib.reload(remediator).ACTIONS
    risky = [rid for rid in real if rid.startswith(("ssh_", "ufw_", "docker_user"))]
    assert len(risky) >= 8
    for rid in risky:
        plan = real[rid]["build_plan"]()
        assert plan.get("risky_remote") is True, rid
        assert callable(plan.get("precondition")), rid
