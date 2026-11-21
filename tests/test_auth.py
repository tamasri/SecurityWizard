import os
import sys
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import auth

@pytest.fixture(autouse=True)
def cleanup():
    auth.reset_for_tests()
    yield
    auth.reset_for_tests()

@pytest.fixture
def loopback_env(monkeypatch):
    monkeypatch.delenv("SECURITYWIZARD_AUTH", raising=False)
    monkeypatch.delenv("SECURITYWIZARD_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("SECURITYWIZARD_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("SECURITYWIZARD_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("SECURITYWIZARD_TOKEN", raising=False)
    yield

@pytest.fixture
def auth_enabled_env(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "1")
    monkeypatch.delenv("SECURITYWIZARD_ALLOWED_HOSTS", raising=False)
    yield

@pytest.fixture
def password_env(monkeypatch):
    pw_hash = auth.hash_password("secret123")
    monkeypatch.setenv("SECURITYWIZARD_PASSWORD_HASH", pw_hash)
    yield

@pytest.fixture
def token_env(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_TOKEN", "my-test-token")
    yield

def test_loopback_no_auth(loopback_env):
    auth.init("127.0.0.1")
    assert auth.is_auth_enabled() == False

def test_non_loopback_auth_enabled(loopback_env, monkeypatch):
    auth.init("0.0.0.0")
    assert auth.is_auth_enabled() == True

def test_auth_env_on(loopback_env, monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "1")
    auth.init("127.0.0.1")
    assert auth.is_auth_enabled() == True

def test_auth_env_off(loopback_env, monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "0")
    auth.init("0.0.0.0")
    assert auth.is_auth_enabled() == False

def test_hash_password_roundtrip(loopback_env):
    h = auth.hash_password("mypassword")
    assert auth.verify_password("mypassword", h) == True
    assert auth.verify_password("wrongpassword", h) == False

def test_hash_password_argon2(loopback_env):
    h = auth.hash_password("mypassword")
    assert h.startswith("$argon2") or h.startswith("pbkdf2_sha256$")

def test_check_host_allowed(loopback_env):
    auth.init("127.0.0.1")
    assert auth.check_host_allowed("127.0.0.1") == True
    assert auth.check_host_allowed("localhost") == True
    assert auth.check_host_allowed("example.com") == False

def test_custom_allowed_hosts(loopback_env, monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_ALLOWED_HOSTS", "myhost,otherhost")
    auth.init("127.0.0.1")
    assert auth.check_host_allowed("myhost") == True
    assert auth.check_host_allowed("otherhost") == True
    assert auth.check_host_allowed("localhost") == False

def test_token_generation(loopback_env, auth_enabled_env):
    auth.init("0.0.0.0")
    token = auth.get_generated_token()
    assert token is not None
    assert len(token) >= 32

def test_password_file(loopback_env, auth_enabled_env, monkeypatch, tmp_path):
    pw_hash = auth.hash_password("filepass")
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text(pw_hash)
    monkeypatch.setenv("SECURITYWIZARD_PASSWORD_FILE", str(pw_file))
    auth.init("0.0.0.0")
    assert auth.verify_password("filepass", auth._password_hash) == True

def test_session_token_creation(loopback_env, auth_enabled_env):
    auth.init("0.0.0.0")
    token = auth._create_session_token("user1")
    assert token is not None
    assert auth._verify_session_token(token) == "user1"
    assert auth._verify_session_token("invalid") is None

def test_session_token_tamper(loopback_env, auth_enabled_env):
    auth.init("0.0.0.0")
    token = auth._create_session_token("user1")
    tampered = token[:-2] + "aa"
    assert auth._verify_session_token(tampered) is None

def test_app_auth_disabled(loopback_env):
    auth.init("127.0.0.1")
    app = FastAPI()
    
    @app.get("/api/test")
    async def test():
        return {"ok": True}
    
    client = TestClient(app)
    resp = client.get("/api/test")
    assert resp.status_code == 200

def test_app_auth_enabled_password(loopback_env, auth_enabled_env, password_env):
    auth.init("0.0.0.0")
    app = FastAPI()
    
    @app.get("/api/test")
    async def test():
        return {"ok": True}
    
    @app.middleware("http")
    async def auth_middleware(request, call_next):
        if auth.is_auth_enabled():
            cookie_token = request.cookies.get("sw_session", "")
            if not cookie_token:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=401, content={"detail": "Authentication required"})
            username = auth._verify_session_token(cookie_token)
            if not username:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        return await call_next(request)
    
    client = TestClient(app)
    resp = client.get("/api/test")
    assert resp.status_code == 401

def test_login_logout(loopback_env, auth_enabled_env, password_env):
    auth.init("0.0.0.0")
    app = FastAPI()
    
    @app.post("/api/login")
    async def login(request: Request):
        body = await request.json()
        password = body.get("password", "")
        if auth.verify_password(password, auth._password_hash):
            token = auth._create_session_token("user")
            response = JSONResponse(content={"token": token})
            response.set_cookie("sw_session", token, httponly=True, samesite="strict")
            return response
        return JSONResponse(status_code=401, content={"detail": "Invalid password"})
    
    @app.get("/api/protected")
    async def protected():
        return {"data": "secret"}
    
    client = TestClient(app)
    resp = client.post("/api/login", json={"password": "secret123"})
    assert resp.status_code == 200
    token = resp.json()["token"]
    
    client.cookies.set("sw_session", token)
    resp = client.get("/api/protected")
    assert resp.status_code == 200

def test_host_header_middleware(loopback_env, monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_ALLOWED_HOSTS", "allowed.example.com")
    auth.init("0.0.0.0")
    app = FastAPI()
    
    @app.middleware("http")
    async def host_middleware(request, call_next):
        host = request.headers.get("host", "")
        if not auth.check_host_allowed(host):
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=403, content={"detail": "Forbidden Host"})
        return await call_next(request)
    
    @app.get("/test")
    async def test():
        return {"ok": True}
    
    client = TestClient(app)
    resp = client.get("/test", headers={"host": "allowed.example.com"})
    assert resp.status_code == 200
    
    resp = client.get("/test", headers={"host": "bad.example.com"})
    assert resp.status_code == 403
