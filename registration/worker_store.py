"""Persistent task state and task-scoped logs for the registration worker."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any


_SECRET_PATTERNS = (
    re.compile(r"(?i)(sso(?:-rw)?\s*[=:]\s*)[^\s;,]+"),
    re.compile(r"(?i)((?:password|passwd|access_token|refresh_token|id_token|authorization)\s*[=:]\s*)[^\s;,]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)


def redact_log_message(value: Any) -> str:
    message = str(value or "").replace("\x00", "").strip()
    for pattern in _SECRET_PATTERNS:
        message = pattern.sub(lambda match: match.group(1) + "[REDACTED]", message)
    return message[:8000]


class WorkerStore:
    """SQLite-backed task metadata with monotonically increasing log cursors."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
        self._db = sqlite3.connect(
            str(self.data_dir / "registration-worker.db"),
            check_same_thread=False,
            timeout=30,
        )
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                requested INTEGER NOT NULL DEFAULT 0,
                processed INTEGER NOT NULL DEFAULT 0,
                succeeded INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                skipped INTEGER NOT NULL DEFAULT 0,
                current_email TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL,
                started_at REAL,
                finished_at REAL,
                cancel_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS task_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS task_logs_task_id_id ON task_logs(task_id, id)"
        )
        self._db.commit()
        self._secure_files()

    def _secure_files(self) -> None:
        for path in self.data_dir.glob("registration-worker.db*"):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def _task_from_row(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        try:
            value["payload"] = json.loads(value.get("payload") or "{}")
        except Exception:
            value["payload"] = {}
        value["cancelRequested"] = bool(value.pop("cancel_requested", 0))
        value["requested"] = int(value.get("requested") or 0)
        value["processed"] = int(value.get("processed") or 0)
        value["succeeded"] = int(value.get("succeeded") or 0)
        value["failed"] = int(value.get("failed") or 0)
        value["skipped"] = int(value.get("skipped") or 0)
        value["progress"] = (
            min(100.0, round(value["processed"] * 100.0 / value["requested"], 1))
            if value["requested"] > 0
            else 0.0
        )
        for key in ("created_at", "started_at", "finished_at"):
            raw = value.get(key)
            output_key = {
                "created_at": "createdAt",
                "started_at": "startedAt",
                "finished_at": "finishedAt",
            }[key]
            value.pop(key, None)
            value[output_key] = raw
        return value

    def create_task(
        self,
        kind: str,
        requested: int,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        task_id = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self._db.execute(
                """
                INSERT INTO tasks(id, kind, status, requested, payload, created_at)
                VALUES(?, ?, 'queued', ?, ?, ?)
                """,
                (
                    task_id,
                    str(kind),
                    max(0, int(requested)),
                    json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":")),
                    now,
                ),
            )
            self._db.commit()
        return self.get_task(task_id) or {}

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM tasks WHERE id = ?",
                (str(task_id),),
            ).fetchone()
        return self._task_from_row(row)

    def latest_task(self, kind: str = "") -> dict[str, Any] | None:
        query = "SELECT * FROM tasks"
        params: tuple[Any, ...] = ()
        if kind:
            query += " WHERE kind = ?"
            params = (str(kind),)
        query += " ORDER BY created_at DESC LIMIT 1"
        with self._lock:
            row = self._db.execute(query, params).fetchone()
        return self._task_from_row(row)

    def list_tasks(self, limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 100))
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._task_from_row(row) for row in rows if row is not None]

    def update_task(self, task_id: str, **changes: Any) -> dict[str, Any] | None:
        allowed = {
            "status",
            "processed",
            "succeeded",
            "failed",
            "skipped",
            "current_email",
            "error",
            "started_at",
            "finished_at",
            "cancel_requested",
            "requested",
        }
        values = {key: value for key, value in changes.items() if key in allowed}
        if values:
            assignments = ", ".join("%s = ?" % key for key in values)
            params = list(values.values()) + [str(task_id)]
            with self._lock:
                self._db.execute(
                    "UPDATE tasks SET %s WHERE id = ?" % assignments,
                    params,
                )
                self._db.commit()
        return self.get_task(task_id)

    def increment_task(
        self,
        task_id: str,
        *,
        processed: int = 0,
        succeeded: int = 0,
        failed: int = 0,
        skipped: int = 0,
        current_email: str | None = None,
    ) -> dict[str, Any] | None:
        sets = []
        params: list[Any] = []
        for column, amount in (
            ("processed", processed),
            ("succeeded", succeeded),
            ("failed", failed),
            ("skipped", skipped),
        ):
            if amount:
                sets.append("%s = %s + ?" % (column, column))
                params.append(int(amount))
        if current_email is not None:
            sets.append("current_email = ?")
            params.append(str(current_email))
        if sets:
            params.append(str(task_id))
            with self._lock:
                self._db.execute(
                    "UPDATE tasks SET %s WHERE id = ?" % ", ".join(sets),
                    params,
                )
                self._db.commit()
        return self.get_task(task_id)

    def append_log(self, task_id: str, message: Any) -> int:
        text = redact_log_message(message)
        now = time.time()
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO task_logs(task_id, created_at, message) VALUES(?, ?, ?)",
                (str(task_id), now, text),
            )
            self._db.commit()
            return int(cursor.lastrowid or 0)

    def list_logs(
        self,
        task_id: str,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 5000))
        with self._lock:
            rows = self._db.execute(
                """
                SELECT id, created_at, message
                FROM task_logs
                WHERE task_id = ? AND id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (str(task_id), max(0, int(after_id)), limit),
            ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "createdAt": row["created_at"],
                "message": row["message"],
            }
            for row in rows
        ]

    def mark_interrupted(self) -> int:
        now = time.time()
        with self._lock:
            cursor = self._db.execute(
                """
                UPDATE tasks
                SET status = 'interrupted',
                    error = CASE
                        WHEN error = '' THEN 'worker 重启，原任务已中断'
                        ELSE error
                    END,
                    finished_at = COALESCE(finished_at, ?)
                WHERE status IN ('running', 'cancelling')
                """,
                (now,),
            )
            self._db.commit()
            return int(cursor.rowcount or 0)

    def has_active_task(self) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM tasks WHERE status IN ('queued', 'running', 'cancelling') LIMIT 1"
            ).fetchone()
        return row is not None

    def close(self) -> None:
        with self._lock:
            self._db.close()
