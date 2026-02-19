import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone


_LOCK = threading.Lock()


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _default_db_path() -> str:
    return os.path.join(_project_root(), "frontend", "instance", "app.db")


DB_PATH = os.getenv("APP_DB_PATH", _default_db_path())


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _now_iso() -> str:
    # Use system local time with offset for UI/log readability.
    return datetime.now().astimezone().isoformat()


def _record_id(task_id: str, agent_ip: str, file_hash: str, path: str) -> str:
    if not file_hash:
        file_hash = hashlib.sha256(f"{task_id}|{agent_ip}|{path}".encode("utf-8")).hexdigest()
    return f"{task_id}|{agent_ip}|{file_hash}"


def init_db():
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS persisted_agents (
                agent_ip TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                last_seen REAL NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_files (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                agent_ip TEXT NOT NULL,
                file_hash TEXT,
                filename TEXT NOT NULL,
                path TEXT NOT NULL,
                language TEXT,
                confidence REAL,
                reason TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pending_agent ON pending_files(agent_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_pending_task ON pending_files(task_id)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS deletion_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_ip TEXT NOT NULL,
                task_id TEXT,
                file_hash TEXT,
                path TEXT,
                status TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_delrep_agent ON deletion_reports(agent_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_delrep_task ON deletion_reports(task_id)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS delete_command_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_ip TEXT NOT NULL,
                task_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                error TEXT,
                created_at TEXT NOT NULL,
                sent_at TEXT
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_delcmd_agent ON delete_command_queue(agent_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_delcmd_status ON delete_command_queue(status)")
        conn.commit()
        conn.close()


def upsert_agent(agent_ip: str, status: str):
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO persisted_agents(agent_ip, status, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(agent_ip) DO UPDATE SET
                status=excluded.status,
                last_seen=excluded.last_seen
            """,
            (agent_ip, status, time.time()),
        )
        conn.commit()
        conn.close()


def touch_agent(agent_ip: str):
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE persisted_agents
            SET last_seen=?
            WHERE agent_ip=?
            """,
            (time.time(), agent_ip),
        )
        conn.commit()
        conn.close()


def list_agents():
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        rows = cur.execute(
            "SELECT agent_ip, status, last_seen FROM persisted_agents ORDER BY agent_ip"
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]


def replace_pending_files(task_id: str, agent_ip: str, files):
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM pending_files WHERE task_id=? AND agent_ip=?",
            (task_id, agent_ip),
        )
        for item in files:
            path = item.get("filepath") or item.get("path") or ""
            filename = item.get("filename") or os.path.basename(path) or "unknown"
            file_hash = item.get("file_hash", "")
            rid = _record_id(task_id, agent_ip, file_hash, path)
            cur.execute(
                """
                INSERT OR REPLACE INTO pending_files(
                    id, task_id, agent_ip, file_hash, filename, path, language,
                    confidence, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rid,
                    task_id,
                    agent_ip,
                    file_hash,
                    filename,
                    path,
                    item.get("language") or item.get("type"),
                    float(item.get("confidence", 0.0)),
                    item.get("reason", ""),
                    item.get("modified_time") or _now_iso(),
                ),
            )
        conn.commit()
        conn.close()


def list_pending_files(search: str = ""):
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        if search.strip():
            token = f"%{search.strip().lower()}%"
            rows = cur.execute(
                """
                SELECT * FROM pending_files
                WHERE LOWER(filename) LIKE ?
                   OR LOWER(path) LIKE ?
                   OR LOWER(agent_ip) LIKE ?
                   OR LOWER(task_id) LIKE ?
                   OR LOWER(COALESCE(language, '')) LIKE ?
                ORDER BY created_at DESC
                """,
                (token, token, token, token, token),
            ).fetchall()
        else:
            rows = cur.execute("SELECT * FROM pending_files ORDER BY created_at DESC").fetchall()
        conn.close()
        records = []
        for row in rows:
            d = dict(row)
            d["status"] = "pending"
            records.append(d)
        return records


def get_pending_by_ids(record_ids):
    if not record_ids:
        return []
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        placeholders = ",".join(["?"] * len(record_ids))
        rows = cur.execute(
            f"SELECT * FROM pending_files WHERE id IN ({placeholders})",
            tuple(record_ids),
        ).fetchall()
        conn.close()
        records = []
        for row in rows:
            d = dict(row)
            d["status"] = "pending"
            records.append(d)
        return records


def delete_pending_by_ids(record_ids):
    if not record_ids:
        return
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        placeholders = ",".join(["?"] * len(record_ids))
        cur.execute(f"DELETE FROM pending_files WHERE id IN ({placeholders})", tuple(record_ids))
        conn.commit()
        conn.close()


def add_deletion_reports(agent_ip: str, task_id: str, reports):
    if not reports:
        return
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        for item in reports:
            cur.execute(
                """
                INSERT INTO deletion_reports(
                    agent_ip, task_id, file_hash, path, status, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    agent_ip,
                    task_id,
                    item.get("file_hash"),
                    item.get("path"),
                    item.get("status", "unknown"),
                    item.get("details", ""),
                    _now_iso(),
                ),
            )
        conn.commit()
        conn.close()


def list_deletion_reports(limit: int = 200):
    limit = max(1, min(int(limit), 2000))
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        rows = cur.execute(
            "SELECT * FROM deletion_reports ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]


def enqueue_delete_command(agent_ip: str, task_id: str, payload: dict):
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        payload_json = json.dumps(payload, sort_keys=True)

        # Prevent duplicate pending commands for the same agent/task/payload.
        existing = cur.execute(
            """
            SELECT id FROM delete_command_queue
            WHERE agent_ip=? AND task_id=? AND payload_json=? AND status='pending'
            LIMIT 1
            """,
            (agent_ip, task_id, payload_json),
        ).fetchone()
        if existing:
            conn.close()
            return int(existing["id"])

        cur.execute(
            """
            INSERT INTO delete_command_queue(
                agent_ip, task_id, payload_json, status, created_at
            ) VALUES (?, ?, ?, 'pending', ?)
            """,
            (agent_ip, task_id, payload_json, _now_iso()),
        )
        conn.commit()
        cmd_id = cur.lastrowid
        conn.close()
        return cmd_id


def fetch_pending_delete_commands(agent_ip: str, limit: int = 20):
    limit = max(1, min(int(limit), 100))
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        rows = cur.execute(
            """
            SELECT id, payload_json
            FROM delete_command_queue
            WHERE agent_ip=? AND status='pending'
            ORDER BY id ASC
            LIMIT ?
            """,
            (agent_ip, limit),
        ).fetchall()
        conn.close()
        result = []
        for row in rows:
            result.append({
                "id": row["id"],
                "payload": json.loads(row["payload_json"]),
            })
        return result


def mark_delete_command_sent(cmd_id: int):
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE delete_command_queue
            SET status='sent', sent_at=?, error=NULL
            WHERE id=?
            """,
            (_now_iso(), cmd_id),
        )
        conn.commit()
        conn.close()


def mark_delete_command_failed(cmd_id: int, error: str):
    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE delete_command_queue
            SET status='pending', error=?
            WHERE id=?
            """,
            ((error or "")[:500], cmd_id),
        )
        conn.commit()
        conn.close()


def remove_pending_after_deletion_report(agent_ip: str, task_id: str, reports):
    """
    Remove pending files once agent confirms deletion.
    Match by task/agent and then by hash or path.
    """
    if not reports:
        return

    with _LOCK:
        conn = _connect()
        cur = conn.cursor()
        for rep in reports:
            status = rep.get("status")
            details = (rep.get("details") or "").lower()

            # Treat "failed + not found in quarantine" as terminal too:
            # file is effectively absent on agent.
            terminal = (
                status == "deleted" or
                (status == "failed" and "not found in quarantine" in details)
            )

            if not terminal:
                continue

            file_hash = rep.get("file_hash") or ""
            path = rep.get("path") or ""

            if file_hash:
                cur.execute(
                    """
                    DELETE FROM pending_files
                    WHERE task_id=? AND agent_ip=? AND file_hash=?
                    """,
                    (task_id, agent_ip, file_hash),
                )
            elif path:
                cur.execute(
                    """
                    DELETE FROM pending_files
                    WHERE task_id=? AND agent_ip=? AND path=?
                    """,
                    (task_id, agent_ip, path),
                )
        conn.commit()
        conn.close()
