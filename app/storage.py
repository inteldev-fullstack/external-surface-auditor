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
            db.execute('CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, created_at TEXT NOT NULL)')
            db.execute("INSERT OR IGNORE INTO workspaces(id,name,created_at) VALUES ('default','My Workspace',?)", (now(),))
            db.execute('CREATE TABLE IF NOT EXISTS targets (workspace_id TEXT NOT NULL, host TEXT NOT NULL, environment TEXT NOT NULL, paths TEXT NOT NULL, allow_private INTEGER NOT NULL, PRIMARY KEY(workspace_id,host), FOREIGN KEY(workspace_id) REFERENCES workspaces(id))')
            db.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, target TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, progress TEXT NOT NULL, report TEXT, error TEXT, workspace_id TEXT NOT NULL DEFAULT 'default')")
            cols = {row['name'] for row in db.execute('PRAGMA table_info(jobs)')}
            if 'workspace_id' not in cols:
                db.execute("ALTER TABLE jobs ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default'")
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

    def workspaces(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute('SELECT id,name,created_at FROM workspaces ORDER BY name COLLATE NOCASE')]

    def create_workspace(self, name):
        import uuid
        name = ' '.join(name.split())
        if not 2 <= len(name) <= 80:
            raise ValueError('Workspace name must contain 2 to 80 characters.')
        workspace_id = str(uuid.uuid4())
        with self.connect() as db:
            if db.execute('SELECT 1 FROM workspaces WHERE name=? COLLATE NOCASE', (name,)).fetchone():
                raise ValueError('A workspace with this name already exists.')
            db.execute('INSERT INTO workspaces VALUES (?,?,?)', (workspace_id,name,now()))
        return {'id':workspace_id,'name':name,'created_at':now()}

    def workspace_exists(self, workspace_id):
        with self.connect() as db:
            return db.execute('SELECT 1 FROM workspaces WHERE id=?', (workspace_id,)).fetchone() is not None

    def scope(self, workspace_id='default'):
        from .scope import ScopeEntry
        with self.connect() as db:
            rows = db.execute('SELECT * FROM targets WHERE workspace_id=? ORDER BY host', (workspace_id,)).fetchall()
        return [ScopeEntry(row['host'], row['environment'], tuple(json.loads(row['paths'])), bool(row['allow_private'])) for row in rows]

    def save_scope(self, workspace_id, entries):
        from .scope import parse_scope
        validated = parse_scope({'targets':entries})
        with self.connect() as db:
            if not db.execute('SELECT 1 FROM workspaces WHERE id=?', (workspace_id,)).fetchone():
                raise ValueError('Workspace not found.')
            db.execute('DELETE FROM targets WHERE workspace_id=?', (workspace_id,))
            db.executemany('INSERT INTO targets VALUES (?,?,?,?,?)', [(workspace_id,e.host,e.environment,json.dumps(e.paths),int(e.allow_private)) for e in validated])
        return validated

    def migrate_legacy_scope(self, entries):
        with self.connect() as db:
            if db.execute("SELECT 1 FROM settings WHERE key='legacy_scope_migrated'").fetchone(): return
            db.executemany('INSERT INTO targets VALUES (?,?,?,?,?)', [('default',e.host,e.environment,json.dumps(e.paths),int(e.allow_private)) for e in entries])
            db.execute("INSERT INTO settings(key,value) VALUES ('legacy_scope_migrated','1')")

    def create(self, job_id, target, workspace_id='default'):
        with self.connect() as db:
            db.execute('INSERT INTO jobs (id,target,state,created_at,updated_at,progress,report,error,workspace_id) VALUES (?,?,?,?,?,?,?,?,?)', (job_id, target, 'queued', now(), now(), 'Queued', None, None, workspace_id))

    def update(self, job_id, state, progress, report=None, error=None, workspace_id=None):
        with self.connect() as db:
            if workspace_id is None:
                db.execute('UPDATE jobs SET state=?,updated_at=?,progress=?,report=?,error=? WHERE id=?', (state, now(), progress, json.dumps(report) if report is not None else None, error, job_id))
            else:
                db.execute('UPDATE jobs SET state=?,updated_at=?,progress=?,report=?,error=? WHERE id=? AND workspace_id=?', (state, now(), progress, json.dumps(report) if report is not None else None, error, job_id, workspace_id))

    @staticmethod
    def decode(row):
        if row is None:
            return None
        result = dict(row)
        result['report'] = json.loads(result['report']) if result['report'] else None
        return result

    def get(self, job_id, workspace_id=None):
        with self.connect() as db:
            if workspace_id is None:
                row=db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            else:
                row=db.execute('SELECT * FROM jobs WHERE id=? AND workspace_id=?', (job_id,workspace_id)).fetchone()
            return self.decode(row)

    def list(self, workspace_id='default'):
        with self.connect() as db:
            return [dict(row) for row in db.execute('SELECT id,target,state,created_at,updated_at,progress,error FROM jobs WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100', (workspace_id,))]

    def delete(self, job_id, workspace_id=None):
        with self.connect() as db:
            if workspace_id is None:
                db.execute('DELETE FROM jobs WHERE id=?', (job_id,))
            else:
                db.execute('DELETE FROM jobs WHERE id=? AND workspace_id=?', (job_id,workspace_id))

    def previous(self, target, exclude, workspace_id='default'):
        with self.connect() as db:
            return self.decode(db.execute("SELECT * FROM jobs WHERE target=? AND id!=? AND workspace_id=? AND state='completed' ORDER BY created_at DESC LIMIT 1", (target, exclude, workspace_id)).fetchone())
