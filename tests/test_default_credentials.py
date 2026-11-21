"""The dashboard is locked by default with generated credentials that the user may (but need not) change."""
import json
import os
import re

import pytest
from fastapi.testclient import TestClient

import auth
import main
import security

CSRF = {"X-Requested-With": "SecurityWizard"}


@pytest.fixture
def locked(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "1")
    for name in ("SECURITYWIZARD_PASSWORD_HASH", "SECURITYWIZARD_PASSWORD_FILE", "SECURITYWIZARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    auth.reset_for_tests()
    for bucket in security._rate_limits.values():
        bucket.clear()
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as client:
        yield client
    auth.reset_for_tests()


def _initial(tmp_path):
    text = (tmp_path / "data" / auth.INITIAL_CREDENTIALS_FILE).read_text(encoding="utf-8")
    user = re.search(r"username: (\S+)", text).group(1)
    password = re.search(r"password: (\S+)", text).group(1)
    return user, password


def _login(client, user, password):
    return client.post("/api/login", json={"username": user, "password": password}, headers=CSRF)


def test_first_start_generates_simple_random_credentials(locked, tmp_path):
    user, password = _initial(tmp_path)
    assert re.fullmatch(r"wizard\d{4}", user)
    assert re.fullmatch(r"[a-z]+-[a-z]+-\d{3}", password)
    store = tmp_path / "data" / auth.CREDENTIALS_FILE
    data = json.loads(store.read_text(encoding="utf-8"))
    assert data["is_default"] is True and data["username"] == user
    assert password not in store.read_text(encoding="utf-8")  # only a hash is stored
    if os.name != "nt":
        assert (store.stat().st_mode & 0o777) == 0o600
        assert ((tmp_path / "data" / auth.INITIAL_CREDENTIALS_FILE).stat().st_mode & 0o777) == 0o600


def test_credentials_are_not_regenerated_on_restart(locked, tmp_path):
    first = _initial(tmp_path)
    auth.reset_for_tests()
    auth.init("127.0.0.1")
    assert auth.get_username() == first[0]
    assert auth.verify_login(*first)


def test_api_is_locked_but_page_and_version_are_public(locked):
    assert locked.get("/").status_code == 200
    assert locked.get("/api/version").json()["version"] == main.__version__
    assert locked.get("/api/status").status_code == 401
    assert locked.get("/api/history").status_code == 401
    assert locked.post("/api/scan", json={}, headers=CSRF).status_code == 401


def test_login_success_and_failure(locked, tmp_path):
    user, password = _initial(tmp_path)
    assert _login(locked, user, "wrong-password-1").status_code == 401
    assert _login(locked, "someone-else", password).status_code == 401
    ok = _login(locked, user, password)
    assert ok.status_code == 200
    assert locked.get("/api/status").status_code == 200


def test_state_reports_default_credentials_only_after_login(locked, tmp_path):
    state = locked.get("/api/auth/state").json()
    assert state["auth_required"] is True and state["authenticated"] is False
    assert state["using_default_credentials"] is False
    user, password = _initial(tmp_path)
    _login(locked, user, password)
    state = locked.get("/api/auth/state").json()
    assert state["authenticated"] is True and state["using_default_credentials"] is True


def test_changing_credentials_is_optional_and_works(locked, tmp_path):
    user, password = _initial(tmp_path)
    _login(locked, user, password)
    # everything keeps working while the defaults are still in place
    assert locked.get("/api/status").json()["using_default_credentials"] is True
    done = locked.post("/api/account/change", headers=CSRF,
                       json={"current_password": password, "new_password": "a-better-pass-1", "new_username": "alice"})
    assert done.status_code == 200
    assert not (tmp_path / "data" / auth.INITIAL_CREDENTIALS_FILE).exists()
    assert locked.get("/api/auth/state").json()["using_default_credentials"] is False
    locked.post("/api/logout", headers=CSRF)
    locked.cookies.clear()
    assert _login(locked, user, password).status_code == 401
    assert _login(locked, "alice", "a-better-pass-1").status_code == 200


@pytest.mark.parametrize("new_password, expected", [("short", 400), ("a-better-pass-1", 400)])
def test_change_validation(locked, tmp_path, new_password, expected):
    user, password = _initial(tmp_path)
    _login(locked, user, password)
    current = password if new_password == "short" else "not-the-current-one"
    resp = locked.post("/api/account/change", headers=CSRF, json={"current_password": current, "new_password": new_password})
    assert resp.status_code == expected


def test_change_rejects_same_password(locked, tmp_path):
    user, password = _initial(tmp_path)
    _login(locked, user, password)
    resp = locked.post("/api/account/change", headers=CSRF, json={"current_password": password, "new_password": password})
    assert resp.status_code == 400


def test_old_sessions_are_invalidated_after_a_change(locked, tmp_path):
    user, password = _initial(tmp_path)
    _login(locked, user, password)
    old_cookie = locked.cookies.get(auth.SESSION_COOKIE)
    locked.post("/api/account/change", headers=CSRF, json={"current_password": password, "new_password": "another-pass-22"})
    assert auth._verify_session_token(old_cookie) is None


def test_login_is_rate_limited(locked):
    codes = [_login(locked, "x", "y").status_code for _ in range(7)]
    assert 429 in codes


def test_tampered_cookie_is_rejected(locked):
    locked.cookies.set(auth.SESSION_COOKIE, "bogus.token")
    assert locked.get("/api/status").status_code == 401


def test_auth_can_be_disabled_explicitly(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "0")
    auth.reset_for_tests()
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as client:
        assert client.get("/api/status").status_code == 200
        assert client.get("/api/auth/state").json()["auth_required"] is False
    auth.reset_for_tests()


def test_environment_credentials_cannot_be_changed_in_the_ui(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "1")
    monkeypatch.setenv("SECURITYWIZARD_PASSWORD_HASH", auth.hash_password("env-password-1"))
    monkeypatch.setenv("SECURITYWIZARD_USERNAME", "ops")
    auth.reset_for_tests()
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as client:
        assert _login(client, "ops", "env-password-1").status_code == 200
        assert client.get("/api/auth/state").json()["using_default_credentials"] is False
        resp = client.post("/api/account/change", headers=CSRF,
                           json={"current_password": "env-password-1", "new_password": "something-else-9"})
        assert resp.status_code == 400
    auth.reset_for_tests()
