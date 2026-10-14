from __future__ import annotations
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from dataclasses import asdict
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .scanner import ScanCancelled, scan_target
from .scope import ScopeError, find_scope_entry, load_scope, mutate_scope
from .storage import Store
from .paths import resource_root, data_directory
from .reports import csv_report, pdf_report, compare_reports

APP_ROOT = resource_root()
MIN_REPEAT_INTERVAL = 60.0
_store = None
_lock = threading.Lock()
_active: dict[str, threading.Event] = {}
_last: dict[str, float] = {}

@asynccontextmanager
async def lifespan(app):
    global _store
    _store = Store(data_directory() / 'auditor.db')
    yield
    with _lock:
        for event in _active.values():
            event.set()

app = FastAPI(title='External Surface Auditor', version='1.1.0', docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost'])

@app.middleware('http')
async def local_origin(request, call_next):
    origin = request.headers.get('origin')
    if origin and origin not in {'http://127.0.0.1:8765', 'http://localhost:8765'}:
        return JSONResponse(status_code=403, content={'detail': 'Only the local application origin is accepted.'})
    if request.headers.get('sec-fetch-site') == 'cross-site':
        return JSONResponse(status_code=403, content={'detail': 'Cross-site requests are blocked.'})
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response

class TargetRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    host: str = Field(min_length=1, max_length=253)
    environment: str
    paths: list[str] = Field(default_factory=list, max_length=10)
    allow_private: bool = False
    authorization_confirmed: bool = False

class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=253)
    authorization_confirmed: bool

@app.get('/', include_in_schema=False)
def index():
    return FileResponse(APP_ROOT / 'static/index.html')

@app.get('/static/{name}')
def asset(name: str):
    if name not in {'app.js', 'style.css'}:
        raise HTTPException(404, 'Asset not found.')
    return FileResponse(APP_ROOT / 'static' / name)

@app.get('/mobile', include_in_schema=False)
@app.get('/mobile/', include_in_schema=False)
def mobile_viewer():
    return FileResponse(APP_ROOT / 'mobile' / 'index.html')

@app.get('/mobile/{name}', include_in_schema=False)
def mobile_asset(name: str):
    if name not in {'app.js', 'style.css', 'manifest.webmanifest', 'sw.js', 'icon.svg'}:
        raise HTTPException(404, 'Mobile asset not found.')
    return FileResponse(APP_ROOT / 'mobile' / name)

@app.get('/api/health')
def health():
    return {'status': 'ok', 'mode': 'local-staging-only', 'version': '1.1.0'}

@app.get('/api/scope')
def scope():
    try:
        return {'targets': [asdict(e) for e in load_scope()]}
    except ScopeError as exc:
        raise HTTPException(500, str(exc)) from exc

@app.put('/api/scope/{host}')
def save_target(host: str, request: TargetRequest):
    if not request.authorization_confirmed:
        raise HTTPException(400, 'Confirm authorization for the staging or lab target.')
    try:
        mutate_scope(host, request.model_dump(exclude={'authorization_confirmed'}))
    except ScopeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return scope()

@app.delete('/api/scope/{host}')
def delete_target(host: str):
    try:
        mutate_scope(host, None)
    except ScopeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return scope()


def require_job(job_id):
    job = _store.get(job_id)
    if job is None:
        raise HTTPException(404, 'Scan not found.')
    return job


def worker(job_id, entry, cancellation):
    try:
        _store.update(job_id, 'running', 'Starting checks')
        def progress(message):
            _store.update(job_id, 'running', message)
        report = scan_target(entry, progress, cancellation.is_set)
        if cancellation.is_set():
            raise ScanCancelled()
        report['scope_snapshot'] = {**asdict(entry), 'paths': list(entry.paths)}
        report['scanner_version'] = '1.1.0'
        report['job_id'] = job_id
        previous = _store.previous(entry.host, job_id)
        if previous and previous['report'].get('scope_snapshot') == report['scope_snapshot']:
            report['comparison'] = compare_reports(report, previous['report'])
            report['comparison']['previous_job_id'] = previous['id']
        _store.update(job_id, 'completed', 'Report ready', report)
    except ScanCancelled:
        _store.update(job_id, 'cancelled', 'Cancelled; partial results were discarded')
    except ScopeError as exc:
        _store.update(job_id, 'failed', 'Scope validation failed', error=str(exc))
    except Exception:
        _store.update(job_id, 'failed', 'Scan failed', error='Unexpected runner error. Check local configuration and retry.')
    finally:
        with _lock:
            _active.pop(job_id, None)

@app.post('/api/scans', status_code=202)
def create_scan(request: ScanRequest):
    if not request.authorization_confirmed:
        raise HTTPException(400, 'Confirm target authorization.')
    try:
        entry = find_scope_entry(request.target, load_scope())
    except ScopeError as exc:
        raise HTTPException(403, str(exc)) from exc
    with _lock:
        if _active:
            raise HTTPException(409, 'A scan is already running.')
        elapsed = time.monotonic() - _last.get(entry.host, float('-inf'))
        if elapsed < MIN_REPEAT_INTERVAL:
            raise HTTPException(429, f'Wait {int(MIN_REPEAT_INTERVAL - elapsed) + 1} seconds before repeating this target.')
        job_id = str(uuid.uuid4())
        cancellation = threading.Event()
        _store.create(job_id, entry.host)
        _active[job_id] = cancellation
        _last[entry.host] = time.monotonic()
        threading.Thread(target=worker, args=(job_id, entry, cancellation), daemon=True).start()
    return {'id': job_id, 'state': 'queued'}

@app.get('/api/scans')
def list_scans():
    return {'scans': _store.list()}

@app.get('/api/scans/{job_id}')
def get_scan(job_id: str):
    return require_job(job_id)

@app.post('/api/scans/{job_id}/cancel')
def cancel_scan(job_id: str):
    require_job(job_id)
    with _lock:
        event = _active.get(job_id)
        if event is None:
            raise HTTPException(409, 'The scan is no longer running.')
        event.set()
    return {'id': job_id, 'state': 'cancelling', 'note': 'Cancellation takes effect between bounded network operations.'}

@app.delete('/api/scans/{job_id}')
def delete_scan(job_id: str):
    require_job(job_id)
    with _lock:
        if job_id in _active:
            raise HTTPException(409, 'Cancel and wait for this scan before deleting it.')
        _store.delete(job_id)
    return {'deleted': job_id}

@app.get('/api/scans/{job_id}/report/{format}')
def export_report(job_id: str, format: str):
    job = require_job(job_id)
    if job['state'] != 'completed':
        raise HTTPException(409, 'A completed report is required.')
    report = job['report']
    if format == 'json':
        import json
        payload, media = json.dumps(report, indent=2).encode(), 'application/json'
    elif format == 'csv':
        payload, media = csv_report(report), 'text/csv; charset=utf-8'
    elif format == 'pdf':
        payload, media = pdf_report(report), 'application/pdf'
    else:
        raise HTTPException(400, 'Supported formats: json, csv, pdf.')
    return Response(payload, media_type=media, headers={'Content-Disposition': f'attachment; filename="report-{job_id}.{format}"'})

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('app.main:app', host='127.0.0.1', port=8765, reload=False)
