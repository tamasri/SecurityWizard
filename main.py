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

app = FastAPI(title="SecurityWizard", version="1.0.0")

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
    
    return await call_next(request)

# --- Routes ---
@app.get("/")
async def index():
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    return FileResponse(template_path)

@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    password = body.get("password", "")
    if auth.get_auth_mode() == "password":
        if auth.verify_password(password, auth.get_password_hash()):
            token = auth._create_session_token("user")
            response = JSONResponse(content={"token": token})
            response.set_cookie("sw_session", token, httponly=True, samesite="strict", secure=False)
            return response
        return JSONResponse(status_code=401, content={"detail": "Invalid password"})
    elif auth.get_auth_mode() == "token":
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token == auth.get_generated_token():
                session_token = auth._create_session_token("token-user")
                response = JSONResponse(content={"token": session_token})
                response.set_cookie("sw_session", session_token, httponly=True, samesite="strict", secure=False)
                return response
        return JSONResponse(status_code=401, content={"detail": "Invalid token"})
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
    return {"dry_run_only": dry_run_only, "is_root": is_root()}

@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    job_id = str(uuid.uuid4())
    
    with jobs_lock:
        jobs[job_id] = {
            "status": "running",
            "progress": {"done": 0, "total": 6 if not req.category else 1, "current": ""},
            "result": None,
            "error": None
        }
    
    def run_job():
        try:
            def progress_cb(done, total, current):
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["progress"] = {"done": done, "total": total, "current": current}
            
            if req.category:
                result = scanner.run_category_scan(req.category)
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]["progress"] = {"done": 1, "total": 1, "current": req.category}
            else:
                result = scanner.run_full_scan(progress_cb)
            
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]["status"] = "done"
                    jobs[job_id]["result"] = result
        except Exception as e:
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]["status"] = "error"
                    jobs[job_id]["error"] = str(e)
    
    thread = threading.Thread(target=run_job)
    thread.start()
    
    return {"job_id": job_id}

@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    with jobs_lock:
        if job_id not in jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        job = jobs[job_id].copy()
    return job

@app.post("/api/dry-run")
async def dry_run(req: DryRunRequest):
    result = await run_in_threadpool(remediator.preview, req.remediation_id)
    return result

@app.post("/api/remediate")
async def remediate(req: RemediateRequest):
    result = await run_in_threadpool(remediator.apply, req.remediation_id, req.confirm)
    return result

@app.get("/api/backups")
async def get_backups():
    backups = await run_in_threadpool(remediator.list_backups)
    return {"backups": backups}

@app.post("/api/rollback")
async def rollback(req: RollbackRequest):
    result = await run_in_threadpool(remediator.rollback, req.snapshot_id)
    return result

if __name__ == "__main__":
    bind = os.environ.get("SECURITYWIZARD_BIND", "127.0.0.1")
    auth.init(bind)
    if auth.is_auth_enabled() and auth.get_generated_token():
        print(f"SecurityWizard auth token: {auth.get_generated_token()}")
    uvicorn.run(app, host=bind, port=int(os.environ.get("SECURITYWIZARD_PORT", "8443")))
