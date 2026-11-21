import os
import json
import uuid
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.wsgi import WSGIMiddleware
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel
import uvicorn

import scanner
import remediator

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
    if host:
        host_part = host.split(":")[0]
        if host_part not in ("127.0.0.1", "localhost"):
            return JSONResponse(status_code=403, content={"detail": "Forbidden Host"})
    
    # Check X-Requested-With for POST requests
    if request.method == "POST":
        xrw = request.headers.get("x-requested-with", "")
        if xrw != "SecurityWizard":
            return JSONResponse(status_code=403, content={"detail": "Forbidden Origin"})
    
    return await call_next(request)

# --- Routes ---
@app.get("/")
async def index():
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    return FileResponse(template_path)

@app.get("/api/health")
async def health():
    return {"status": "ok"}

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
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("SECURITYWIZARD_PORT", "8443")))
