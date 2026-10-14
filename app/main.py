from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .scanner import scan_target
from .scope import ScopeError, find_scope_entry, load_scope

APP_ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = APP_ROOT / "static"
MIN_REPEAT_INTERVAL = 60.0

app = FastAPI(
    title="External Surface Security Auditor",
    version="0.1.0",
    description="A local, scope-bound scanner for approved staging and lab targets.",
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

_scan_lock = threading.Lock()
_rate_lock = threading.Lock()
_last_scan_by_target: dict[str, float] = {}


@app.middleware("http")
async def restrict_browser_origin(request, call_next):
    origin = request.headers.get("origin")
    if origin and origin not in {"http://127.0.0.1:8765", "http://localhost:8765"}:
        return JSONResponse(status_code=403, content={"detail": "This local prototype accepts requests only from its own browser origin."})
    return await call_next(request)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=253)
    authorization_confirmed: bool


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_ROOT / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-staging-only"}


@app.get("/api/scope")
def scope_summary() -> dict[str, Any]:
    try:
        entries = load_scope()
    except ScopeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "targets": [
            {
                "host": item.host,
                "environment": item.environment,
                "paths": list(item.paths),
                "allow_private": item.allow_private,
            }
            for item in entries
        ]
    }


@app.post("/api/scan")
def run_scan(request: ScanRequest) -> dict[str, Any]:
    if not request.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Confirm that this target is authorized for testing.")
    try:
        entry = find_scope_entry(request.target, load_scope())
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    now = time.monotonic()
    with _rate_lock:
        previous = _last_scan_by_target.get(entry.host)
        if previous is not None and now - previous < MIN_REPEAT_INTERVAL:
            remaining = int(MIN_REPEAT_INTERVAL - (now - previous)) + 1
            raise HTTPException(status_code=429, detail=f"Wait {remaining} seconds before scanning this target again.")
        if not _scan_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="Another scan is already running. Try again when it finishes.")
        _last_scan_by_target[entry.host] = now

    try:
        return scan_target(entry)
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    finally:
        _scan_lock.release()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8765, reload=False)
