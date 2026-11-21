import os
import json
import uuid
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel
import uvicorn

import scanner
import remediator
import auth
import history
import export
import security

app = FastAPI(title="SecurityWizard", version="1.0.0")

# --- Scan state ---
_scan_lock = threading.Lock()
_scan_state: Dict[str, Any] = {
    "status": "idle",       # idle | running | finished
    "job_id": None,
    "started": None,
    "finished": None,
    "duration": None,
    "progress": {"done": 0, "total": 0, "current": ""},
    "result": None,
    "error": None,
}

# --- Pydantic Models ---
class ScanRequest(BaseModel):
    category: Optional[str] = None

class DryRunRequest(BaseModel):
    remediation_id: str

class RemediateRequest(BaseModel):
    remediation_id: str
    confirm: bool

class RollbackRequest(BaseModel):
    snapshot_id: str

# --- Job Store ---
jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()

# --- Middleware ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Check Host header
    host = request.headers.get("host", "")
    if host and not auth.check_host_allowed(host):
        return JSONResponse(status_code=403, content={"detail": "Forbidden Host"})
    
    # Check X-Requested-With for POST requests
    if request.method == "POST":
        xrw = request.headers.get("x-requested-with", "")
        if xrw != "SecurityWizard":
            return JSONResponse(status_code=403, content={"detail": "Forbidden Origin"})
        
        # Check Origin/Referer for state-changing requests
        if not security.check_origin_allowed(request):
            return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
    
    # Auth check for /api/* and /
    if auth.is_auth_enabled():
        path = request.url.path
        if path.startswith("/api/") or path == "/":
            cookie_token = request.cookies.get("sw_session", "")
            if cookie_token:
                username = auth._verify_session_token(cookie_token)
                if username:
                    return await call_next(request)
            
            if path == "/api/login" or path == "/api/logout":
                return await call_next(request)
            
            if auth.get_auth_mode() == "token" and auth.get_generated_token():
                auth_header = request.headers.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    if token == auth.get_generated_token():
                        return await call_next(request)
            
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    
    response = await call_next(request)
    
    # Add security headers to every response
    for header, value in security.get_security_headers().items():
        response.headers[header] = value
    
    # Add cache headers for API responses
    if request.url.path.startswith("/api/"):
        for header, value in security.get_cache_headers().items():
            response.headers[header] = value
    
    return response

# --- Routes ---
@app.get("/")
async def index():
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    return FileResponse(template_path)

@app.post("/api/login")
async def login(request: Request):
    # Rate limit login attempts
    client_ip = request.client.host if request.client else "unknown"
    if not security.check_rate_limit("login", client_ip):
        security.audit_log("login", client_ip, result="rate_limited")
        return JSONResponse(status_code=429, content={"detail": "Too many login attempts"})
    
    body = await request.json()
    password = body.get("password", "")
    if auth.get_auth_mode() == "password":
        if auth.verify_password(password, auth.get_password_hash()):
            token = auth._create_session_token("user")
            security.audit_log("login", client_ip, result="success")
            response = JSONResponse(content={"token": token})
            response.set_cookie("sw_session", token, httponly=True, samesite="strict", secure=False)
            return response
        security.audit_log("login", client_ip, result="failed")
        return JSONResponse(status_code=401, content={"detail": "Invalid password"})
    elif auth.get_auth_mode() == "token":
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token == auth.get_generated_token():
                session_token = auth._create_session_token("token-user")
                security.audit_log("login", client_ip, result="success")
                response = JSONResponse(content={"token": session_token})
                response.set_cookie("sw_session", session_token, httponly=True, samesite="strict", secure=False)
                return response
        security.audit_log("login", client_ip, result="failed")
        return JSONResponse(status_code=401, content={"detail": "Invalid token"})
    security.audit_log("login", client_ip, result="error")
    return JSONResponse(status_code=400, content={"detail": "Auth not configured"})

@app.post("/api/logout")
async def logout():
    response = JSONResponse(content={"ok": True})
    response.delete_cookie("sw_session")
    return response

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.get("/api/status")
async def get_status():
    from common import is_root
    dry_run_only = os.environ.get("SECURITYWIZARD_DRY_RUN_ONLY", "0") == "1"
    readonly = security.is_readonly()
    return {"dry_run_only": dry_run_only, "is_root": is_root(), "readonly": readonly}

@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    with _scan_lock:
        if _scan_state["status"] == "running":
            return {"job_id": _scan_state["job_id"], "already_running": True}

        job_id = str(uuid.uuid4())
        _scan_state["status"] = "running"
        _scan_state["job_id"] = job_id
        _scan_state["started"] = datetime.now(timezone.utc).isoformat()
        _scan_state["finished"] = None
        _scan_state["duration"] = None
        _scan_state["progress"] = {"done": 0, "total": 7 if not req.category else 1, "current": ""}
        _scan_state["result"] = None
        _scan_state["error"] = None

        with jobs_lock:
            jobs[job_id] = {
                "status": "running",
                "progress": {"done": 0, "total": 7 if not req.category else 1, "current": ""},
                "result": None,
                "error": None,
            }

    def run_job():
        try:
            def progress_cb(done, total, current):
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["progress"] = {"done": done, "total": total, "current": current}
                with _scan_lock:
                    _scan_state["progress"] = {"done": done, "total": total, "current": current}

            if req.category:
                result = scanner.run_category_scan(req.category)
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["progress"] = {"done": 1, "total": 1, "current": req.category}
                with _scan_lock:
                    _scan_state["progress"] = {"done": 1, "total": 1, "current": req.category}
            else:
                result = scanner.run_full_scan(progress_cb)

            now_iso = datetime.now(timezone.utc).isoformat()
            duration = (datetime.fromisoformat(now_iso) - datetime.fromisoformat(_scan_state["started"])).total_seconds()
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]["status"] = "done"
                    jobs[job_id]["result"] = result
            with _scan_lock:
                _scan_state["status"] = "finished"
                _scan_state["finished"] = now_iso
                _scan_state["duration"] = duration
                _scan_state["result"] = result
        except Exception as exc:
            now_iso = datetime.now(timezone.utc).isoformat()
            duration = (datetime.fromisoformat(now_iso) - datetime.fromisoformat(_scan_state["started"])).total_seconds()
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]["status"] = "error"
                    jobs[job_id]["error"] = str(exc)
            with _scan_lock:
                _scan_state["status"] = "finished"
                _scan_state["finished"] = now_iso
                _scan_state["duration"] = duration
                _scan_state["error"] = str(exc)

    await run_in_threadpool(run_job)
    return {"job_id": job_id}

@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    with jobs_lock:
        if job_id not in jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        job = jobs[job_id].copy()
    return job


@app.get("/api/scan/status")
async def get_scan_global_status():
    with _scan_lock:
        return dict(_scan_state)

@app.post("/api/dry-run")
async def dry_run(req: DryRunRequest):
    # Validate remediation ID
    if not security.validate_remediation_id(req.remediation_id):
        raise HTTPException(status_code=422, detail="Invalid remediation_id format")
    
    client_ip = req.client.host if req.client else "unknown"
    result = await run_in_threadpool(remediator.preview, req.remediation_id)
    security.audit_log("dry-run", client_ip, remediation_id=req.remediation_id, result="success")
    return result

@app.post("/api/remediate")
async def remediate(req: RemediateRequest):
    # Check read-only mode
    if security.is_readonly():
        return JSONResponse(status_code=403, content={"detail": "Read-only mode: apply disabled"})
    
    # Validate remediation ID
    if not security.validate_remediation_id(req.remediation_id):
        raise HTTPException(status_code=422, detail="Invalid remediation_id format")
    
    # Rate limit apply operations
    client_ip = req.client.host if req.client else "unknown"
    if not security.check_rate_limit("apply", client_ip):
        security.audit_log("apply", client_ip, remediation_id=req.remediation_id, result="rate_limited")
        return JSONResponse(status_code=429, content={"detail": "Too many apply operations"})
    
    result = await run_in_threadpool(remediator.apply, req.remediation_id, req.confirm)
    security.audit_log("apply", client_ip, remediation_id=req.remediation_id, result="success")
    return result

@app.get("/api/backups")
async def get_backups():
    backups = await run_in_threadpool(remediator.list_backups)
    return {"backups": backups}

@app.post("/api/rollback")
async def rollback(req: RollbackRequest):
    # Check read-only mode
    if security.is_readonly():
        return JSONResponse(status_code=403, content={"detail": "Read-only mode: rollback disabled"})
    
    # Validate snapshot ID
    if not security.validate_snapshot_id(req.snapshot_id):
        raise HTTPException(status_code=422, detail="Invalid snapshot_id format")
    
    # Rate limit rollback operations
    client_ip = req.client.host if req.client else "unknown"
    if not security.check_rate_limit("rollback", client_ip):
        security.audit_log("rollback", client_ip, result="rate_limited")
        return JSONResponse(status_code=429, content={"detail": "Too many rollback operations"})
    
    result = await run_in_threadpool(remediator.rollback, req.snapshot_id)
    security.audit_log("rollback", client_ip, result="success")
    return result

@app.get("/api/history")
async def get_history():
    scans = await run_in_threadpool(history.list_scans)
    return {"scans": scans}

@app.get("/api/history/diff")
async def get_history_diff(old: str, new: str):
    if not history.SCAN_ID_RE.match(old) or not history.SCAN_ID_RE.match(new):
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    old_scan = await run_in_threadpool(history.load_scan, old)
    new_scan = await run_in_threadpool(history.load_scan, new)
    if old_scan is None or new_scan is None:
        missing = []
        if old_scan is None:
            missing.append(old)
        if new_scan is None:
            missing.append(new)
        raise HTTPException(status_code=404, detail=f"Scan not found: {', '.join(missing)}")
    diff = await run_in_threadpool(history.diff_scans, old_scan, new_scan)
    return diff

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
    elif fmt == "markdown":
        return JSONResponse(content={"markdown": export.to_markdown(scan)})
    elif fmt == "sarif":
        return JSONResponse(content=json.loads(export.to_sarif(scan)))
    else:
        return JSONResponse(content={"html": export.to_html(scan)})

if __name__ == "__main__":
    bind = os.environ.get("SECURITYWIZARD_BIND", "127.0.0.1")
    auth.init(bind)
    security.init()
    if auth.is_auth_enabled() and auth.get_generated_token():
        print(f"SecurityWizard auth token: {auth.get_generated_token()}")
    uvicorn.run(app, host=bind, port=int(os.environ.get("SECURITYWIZARD_PORT", "8443")))
