"""Local SQLite persistence. No customer data is uploaded."""
from __future__ import annotations
import json
from contextlib import contextmanager
import os
import sqlite3
from pathlib import Path
from datetime import UTC, datetime


def now():
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != 'nt':
            path.parent.chmod(0o700)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, target TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, progress TEXT NOT NULL, report TEXT, error TEXT)')
            db.execute("UPDATE jobs SET state='interrupted', error='Runner stopped before completion.', updated_at=? WHERE state IN ('queued','running','cancelling')", (now(),))
        if os.name != 'nt':
            path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, job_id, target):
        with self.connect() as db:
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?)', (job_id, target, 'queued', now(), now(), 'Queued', None, None))

    def update(self, job_id, state, progress, report=None, error=None):
        with self.connect() as db:
            db.execute('UPDATE jobs SET state=?,updated_at=?,progress=?,report=?,error=? WHERE id=?', (state, now(), progress, json.dumps(report) if report is not None else None, error, job_id))

    @staticmethod
    def decode(row):
        if row is None:
            return None
        result = dict(row)
        result['report'] = json.loads(result['report']) if result['report'] else None
        return result

    def get(self, job_id):
        with self.connect() as db:
            return self.decode(db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone())

    def list(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute('SELECT id,target,state,created_at,updated_at,progress,error FROM jobs ORDER BY created_at DESC LIMIT 100')]

    def delete(self, job_id):
        with self.connect() as db:
            db.execute('DELETE FROM jobs WHERE id=?', (job_id,))

    def previous(self, target, exclude):
        with self.connect() as db:
            return self.decode(db.execute("SELECT * FROM jobs WHERE target=? AND id!=? AND state='completed' ORDER BY created_at DESC LIMIT 1", (target, exclude)).fetchone())
