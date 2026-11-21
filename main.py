import json
import logging
import os
import re
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

import auth
import deadman
import export
import history
import remediator
import scanner
import security
from common import __version__

logger = logging.getLogger("securitywizard")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
CSRF_HEADER_VALUE = "SecurityWizard"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    auth.init(os.environ.get("SECURITYWIZARD_BIND", "127.0.0.1"))
    security.init()
    yield


app = FastAPI(title="SecurityWizard", version=__version__, lifespan=lifespan)

# --- scan state ----------------------------------------------------------------------------------
_scan_lock = threading.Lock()
_scan_state: Dict[str, Any] = {
    "status": "idle",  # idle | running | finished
    "job_id": None,
    "scan_id": None,
    "started": None,
    "finished": None,
    "duration": None,
    "progress": {"done": 0, "total": 0, "current": ""},
    "result": None,
    "error": None,
}
jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()


# --- request models -------------------------------------------------------------------------------
class ScanRequest(BaseModel):
    category: Optional[str] = None


class DryRunRequest(BaseModel):
    remediation_id: str


class RemediateRequest(BaseModel):
    remediation_id: str
    confirm: bool


class RollbackRequest(BaseModel):
    snapshot_id: str


class DeadmanRequest(BaseModel):
    token: str


class LoginRequest(BaseModel):
    username: Optional[str] = None
    password: str = ""


class ChangeCredentialsRequest(BaseModel):
    current_password: str
    new_password: str
    new_username: Optional[str] = None


# --- helpers --------------------------------------------------------------------------------------
PUBLIC_PATHS = {"/", "/api/auth/state", "/api/login", "/api/logout", "/api/version", "/api/health"}


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _with_headers(request: Request, response):
    for header, value in security.get_security_headers().items():
        response.headers[header] = value
    if request.url.path.startswith("/api/"):
        for header, value in security.get_cache_headers().items():
            response.headers[header] = value
    return response


def _session_response(content: Dict[str, Any], username: str) -> JSONResponse:
    token = auth._create_session_token(username)
    response = JSONResponse(content=content)
    response.set_cookie(
        auth.SESSION_COOKIE, token, httponly=True, samesite="strict", secure=False, max_age=auth.SESSION_MAX_AGE
    )
    return response


# --- middleware -----------------------------------------------------------------------------------
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    host = request.headers.get("host", "")
    if host and not auth.check_host_allowed(host):
        return _with_headers(request, JSONResponse(status_code=403, content={"detail": "Forbidden Host"}))

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get("x-requested-with", "") != CSRF_HEADER_VALUE:
            return _with_headers(request, JSONResponse(status_code=403, content={"detail": "Forbidden Origin"}))
        if not security.check_origin_allowed(request):
            return _with_headers(request, JSONResponse(status_code=403, content={"detail": "Origin not allowed"}))

    if auth.is_auth_enabled():
        path = request.url.path
        is_public = path in PUBLIC_PATHS or path.startswith("/static/")
        if not is_public and auth.request_user(request) is None:
            return _with_headers(request, JSONResponse(status_code=401, content={"detail": "Authentication required"}))

    return _with_headers(request, await call_next(request))


# --- public routes --------------------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(os.path.join(BASE_DIR, "templates", "index.html"))


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/version")
async def version():
    return {"version": __version__}


@app.get("/api/auth/state")
async def auth_state(request: Request):
    required = auth.is_auth_enabled()
    user = auth.request_user(request) if required else None
    authenticated = (user is not None) or not required
    return {
        "auth_required": required,
        "authenticated": authenticated,
        "username": user,
        "using_default_credentials": bool(authenticated and auth.using_default_credentials()),
        "can_change_credentials": auth.get_auth_mode() == "credentials",
    }


@app.post("/api/login")
async def login(request: Request, body: LoginRequest):
    client = _client(request)
    if not security.check_rate_limit("login", client):
        security.audit_log("login", client, result="rate_limited")
        return JSONResponse(status_code=429, content={"detail": "Too many login attempts"})
    if not auth.is_auth_enabled():
        return {"ok": True, "auth_required": False}
    mode = auth.get_auth_mode()
    if mode == "token":
        header = request.headers.get("authorization", "")
        if auth.request_user(request) and header.startswith("Bearer "):
            security.audit_log("login", client, result="success")
            return _session_response({"ok": True}, "token-user")
    elif mode in ("credentials", "password"):
        username = body.username if body.username else (auth.get_username() if mode == "password" else "")
        if auth.verify_login(username or "", body.password):
            security.audit_log("login", client, result="success")
            return _session_response(
                {"ok": True, "using_default_credentials": auth.using_default_credentials()}, username
            )
    else:
        security.audit_log("login", client, result="error")
        return JSONResponse(status_code=400, content={"detail": "Authentication is not configured"})
    security.audit_log("login", client, result="failed")
    return JSONResponse(status_code=401, content={"detail": "Invalid username or password"})


@app.post("/api/logout")
async def logout():
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(auth.SESSION_COOKIE)
    return response


# --- authenticated routes -------------------------------------------------------------------------
@app.post("/api/account/change")
async def change_account(request: Request, body: ChangeCredentialsRequest):
    client = _client(request)
    if not security.check_rate_limit("login", client):
        security.audit_log("account_change", client, result="rate_limited")
        return JSONResponse(status_code=429, content={"detail": "Too many attempts"})
    ok, message = await run_in_threadpool(
        auth.change_credentials, body.current_password, body.new_password, body.new_username
    )
    security.audit_log("account_change", client, result="success" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"detail": message})
    # The change invalidates all older sessions: give this browser a fresh one.
    return _session_response({"ok": True, "detail": message}, auth.get_username() or "user")


@app.get("/api/status")
async def get_status():
    from common import is_root

    return {
        "version": __version__,
        "dry_run_only": os.environ.get("SECURITYWIZARD_DRY_RUN_ONLY", "0") == "1",
        "is_root": is_root(),
        "readonly": security.is_readonly(),
        "auth_enabled": auth.is_auth_enabled(),
        "using_default_credentials": auth.using_default_credentials(),
    }


def _finish_scan(job_id: str, started: str, result: Optional[dict], error: Optional[str]) -> None:
    finished = datetime.now(timezone.utc)
    duration = (finished - datetime.fromisoformat(started)).total_seconds()
    scan_id = None
    if result is not None:
        try:
            result["scan_id"] = str(uuid.uuid4())
            scan_id = history.save_scan(result)
        except Exception:  # history is best effort: never lose the scan itself
            logger.exception("Could not save the scan to the history")
            scan_id = None
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id].update(status="error" if error else "done", result=result, error=error)
    with _scan_lock:
        _scan_state.update(
            status="finished",
            finished=finished.isoformat(),
            duration=duration,
            result=result,
            error=error,
            scan_id=scan_id,
        )


def _run_scan_job(job_id: str, started: str, category: Optional[str]) -> None:
    try:

        def progress_cb(done, total, current):
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]["progress"] = {"done": done, "total": total, "current": current}
            with _scan_lock:
                _scan_state["progress"] = {"done": done, "total": total, "current": current}

        if category:
            result = scanner.run_category_scan(category)
            progress_cb(1, 1, category)
        else:
            result = scanner.run_full_scan(progress_cb)
        _finish_scan(job_id, started, result, None)
    except Exception as exc:
        logger.exception("Scan failed")
        _finish_scan(job_id, started, None, "%s: %s" % (type(exc).__name__, exc))


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    """Start a scan in the background and return immediately (poll /api/scan/status)."""
    with _scan_lock:
        if _scan_state["status"] == "running":
            return {"job_id": _scan_state["job_id"], "already_running": True}
        job_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc).isoformat()
        total = len(scanner.MODULES) if not req.category else 1
        _scan_state.update(
            status="running",
            job_id=job_id,
            scan_id=None,
            started=started,
            finished=None,
            duration=None,
            progress={"done": 0, "total": total, "current": ""},
            result=None,
            error=None,
        )
    with jobs_lock:
        jobs[job_id] = {
            "status": "running",
            "progress": {"done": 0, "total": total, "current": ""},
            "result": None,
            "error": None,
        }
    threading.Thread(target=_run_scan_job, args=(job_id, started, req.category), daemon=True, name="scan").start()
    return {"job_id": job_id}


# NOTE: declared before /api/scan/{job_id}, otherwise "status" would be treated as a job id.
@app.get("/api/scan/status")
async def get_scan_global_status():
    with _scan_lock:
        return dict(_scan_state)


@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    with jobs_lock:
        if job_id not in jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        return dict(jobs[job_id])


@app.post("/api/dry-run")
async def dry_run(request: Request, req: DryRunRequest):
    if not security.validate_remediation_id(req.remediation_id):
        raise HTTPException(status_code=422, detail="Invalid remediation_id format")
    result = await run_in_threadpool(remediator.preview, req.remediation_id)
    security.audit_log("dry-run", _client(request), remediation_id=req.remediation_id, result="success")
    return result


@app.post("/api/remediate")
async def remediate(request: Request, req: RemediateRequest):
    if security.is_readonly():
        return JSONResponse(status_code=403, content={"detail": "Read-only mode: apply disabled"})
    if not security.validate_remediation_id(req.remediation_id):
        raise HTTPException(status_code=422, detail="Invalid remediation_id format")
    client = _client(request)
    if not security.check_rate_limit("apply", client):
        security.audit_log("apply", client, remediation_id=req.remediation_id, result="rate_limited")
        return JSONResponse(status_code=429, content={"detail": "Too many apply operations"})
    result = await run_in_threadpool(remediator.apply, req.remediation_id, req.confirm)
    security.audit_log("apply", client, remediation_id=req.remediation_id, result="success")
    return result


DEADMAN_TOKEN_RE = re.compile(r"^DM-[a-z][a-z0-9_]{2,63}$")


@app.get("/api/deadman")
async def get_deadman():
    """Tokens of risky changes that will be reverted automatically unless confirmed."""
    return {"pending": deadman.pending(remediator._bdir())}


@app.post("/api/deadman/confirm")
async def confirm_deadman(request: Request, req: DeadmanRequest):
    """Keep a risky change (SSH/firewall): cancels the automatic revert."""
    if security.is_readonly():
        return JSONResponse(status_code=403, content={"detail": "Read-only mode"})
    if not DEADMAN_TOKEN_RE.match(req.token):
        raise HTTPException(status_code=422, detail="Invalid token format")
    ok = await run_in_threadpool(deadman.confirm, req.token, remediator._bdir())
    security.audit_log("deadman_confirm", _client(request), result="success" if ok else "unknown_token")
    return {"ok": ok}


@app.get("/api/backups")
async def get_backups():
    return {"backups": await run_in_threadpool(remediator.list_backups)}


@app.post("/api/rollback")
async def rollback(request: Request, req: RollbackRequest):
    if security.is_readonly():
        return JSONResponse(status_code=403, content={"detail": "Read-only mode: rollback disabled"})
    if not security.validate_snapshot_id(req.snapshot_id):
        raise HTTPException(status_code=422, detail="Invalid snapshot_id format")
    client = _client(request)
    if not security.check_rate_limit("rollback", client):
        security.audit_log("rollback", client, result="rate_limited")
        return JSONResponse(status_code=429, content={"detail": "Too many rollback operations"})
    result = await run_in_threadpool(remediator.rollback, req.snapshot_id)
    security.audit_log("rollback", client, result="success")
    return result


@app.get("/api/history")
async def get_history():
    return {"scans": await run_in_threadpool(history.list_scans)}


@app.get("/api/history/diff")
async def get_history_diff(old: str, new: str):
    if not history.SCAN_ID_RE.match(old) or not history.SCAN_ID_RE.match(new):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    old_scan = await run_in_threadpool(history.load_scan, old)
    new_scan = await run_in_threadpool(history.load_scan, new)
    if old_scan is None or new_scan is None:
        missing = [sid for sid, scan in ((old, old_scan), (new, new_scan)) if scan is None]
        raise HTTPException(status_code=404, detail="Scan not found: " + ", ".join(missing))
    return await run_in_threadpool(history.diff_scans, old_scan, new_scan)


@app.get("/api/history/{scan_id}")
async def get_history_scan(scan_id: str):
    if not history.SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    scan = await run_in_threadpool(history.load_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/export")
async def get_export(fmt: str, scan_id: Optional[str] = None):
    if fmt not in ("json", "markdown", "sarif", "html"):
        raise HTTPException(status_code=400, detail="format must be json, markdown, sarif, or html")
    if scan_id is not None and not history.SCAN_ID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    if scan_id:
        scan = await run_in_threadpool(history.load_scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        with _scan_lock:
            scan = _scan_state["result"]
        if scan is None:
            raise HTTPException(status_code=404, detail="No scan result available")
    if fmt == "json":
        return JSONResponse(content=json.loads(export.to_json(scan)))
    if fmt == "markdown":
        return JSONResponse(content={"markdown": export.to_markdown(scan)})
    if fmt == "sarif":
        return JSONResponse(content=json.loads(export.to_sarif(scan)))
    return JSONResponse(content={"html": export.to_html(scan)})


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    bind = os.environ.get("SECURITYWIZARD_BIND", "127.0.0.1")
    uvicorn.run(app, host=bind, port=int(os.environ.get("SECURITYWIZARD_PORT", "8443")))
