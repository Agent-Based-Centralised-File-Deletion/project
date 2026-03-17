import hashlib
import json
import os
import threading
import time
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import bindparam, create_engine, text


_LOCK = threading.Lock()


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _default_db_path() -> str:
    return os.path.join(_project_root(), "frontend", "instance", "app.db")


def _normalize_database_url(raw_value: str) -> str:
    value = (raw_value or "").strip()
    if not value:
        value = _default_db_path()

    # Heroku-style URL.
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value[len("postgres://"):]

    # Add modern driver if user passed plain postgresql URL.
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value[len("postgresql://"):]

    # Already explicit with driver.
    if value.startswith("postgresql+"):
        return value

    # Explicit SQLite URL.
    if value.startswith("sqlite:///"):
        return value

    # Treat as filesystem path.
    abs_path = os.path.abspath(value)
    return f"sqlite:///{abs_path}"


def resolve_database_url() -> str:
    raw = (
        os.getenv("APP_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("SQLALCHEMY_DATABASE_URI")
        or os.getenv("APP_DB_PATH")
        or _default_db_path()
    )
    return _normalize_database_url(raw)


def flask_database_uri() -> str:
    return resolve_database_url()


_DATABASE_URL = resolve_database_url()
_IS_SQLITE = _DATABASE_URL.startswith("sqlite:///")

if _IS_SQLITE:
    sqlite_file = _DATABASE_URL.replace("sqlite:///", "", 1)
    sqlite_dir = os.path.dirname(sqlite_file)
    if sqlite_dir:
        os.makedirs(sqlite_dir, exist_ok=True)
    _ENGINE = create_engine(
        _DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 10},
        pool_pre_ping=True,
        future=True,
    )
else:
    _ENGINE = create_engine(_DATABASE_URL, pool_pre_ping=True, future=True)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _record_id(task_id: str, agent_ip: str, file_hash: str, path: str) -> str:
    if not file_hash:
        file_hash = hashlib.sha256(f"{task_id}|{agent_ip}|{path}".encode("utf-8")).hexdigest()
    return f"{task_id}|{agent_ip}|{file_hash}"


def _rows(result) -> List[Dict[str, Any]]:
    return [dict(row) for row in result.mappings().all()]


def init_db():
    with _LOCK:
        with _ENGINE.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS persisted_agents (
                        agent_ip TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        last_seen DOUBLE PRECISION NOT NULL
                    )
                    """
                )
            )

            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS pending_files (
                        id TEXT PRIMARY KEY,
                        task_id TEXT NOT NULL,
                        agent_ip TEXT NOT NULL,
                        file_hash TEXT,
                        filename TEXT NOT NULL,
                        path TEXT NOT NULL,
                        language TEXT,
                        confidence DOUBLE PRECISION,
                        reason TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pending_agent ON pending_files(agent_ip)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pending_task ON pending_files(task_id)"))

            if _IS_SQLITE:
                conn.execute(
                    text(
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
                )
                conn.execute(
                    text(
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
                )
            else:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS deletion_reports (
                            id BIGSERIAL PRIMARY KEY,
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
                )
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS delete_command_queue (
                            id BIGSERIAL PRIMARY KEY,
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
                )

            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_delrep_agent ON deletion_reports(agent_ip)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_delrep_task ON deletion_reports(task_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_delcmd_agent ON delete_command_queue(agent_ip)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_delcmd_status ON delete_command_queue(status)"))

            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS daily_task_counter (
                        date_key TEXT PRIMARY KEY,
                        last_value INTEGER NOT NULL
                    )
                    """
                )
            )


def upsert_agent(agent_ip: str, status: str):
    with _LOCK:
        with _ENGINE.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO persisted_agents(agent_ip, status, last_seen)
                    VALUES (:agent_ip, :status, :last_seen)
                    ON CONFLICT(agent_ip) DO UPDATE SET
                        status=excluded.status,
                        last_seen=excluded.last_seen
                    """
                ),
                {"agent_ip": agent_ip, "status": status, "last_seen": time.time()},
            )


def update_agent_status(agent_ip: str, status: str):
    """
    Update status only while preserving last_seen.
    If the row does not exist, create it with current timestamp.
    """
    with _LOCK:
        with _ENGINE.begin() as conn:
            result = conn.execute(
                text(
                    """
                    UPDATE persisted_agents
                    SET status=:status
                    WHERE agent_ip=:agent_ip
                    """
                ),
                {"status": status, "agent_ip": agent_ip},
            )
            if result.rowcount == 0:
                conn.execute(
                    text(
                        """
                        INSERT INTO persisted_agents(agent_ip, status, last_seen)
                        VALUES (:agent_ip, :status, :last_seen)
                        """
                    ),
                    {"agent_ip": agent_ip, "status": status, "last_seen": time.time()},
                )


def touch_agent(agent_ip: str):
    with _LOCK:
        with _ENGINE.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE persisted_agents
                    SET last_seen=:last_seen
                    WHERE agent_ip=:agent_ip
                    """
                ),
                {"last_seen": time.time(), "agent_ip": agent_ip},
            )


def list_agents():
    with _LOCK:
        with _ENGINE.connect() as conn:
            rows = _rows(
                conn.execute(
                    text("SELECT agent_ip, status, last_seen FROM persisted_agents ORDER BY agent_ip")
                )
            )
        return rows


def replace_pending_files(task_id: str, agent_ip: str, files):
    with _LOCK:
        with _ENGINE.begin() as conn:
            conn.execute(
                text("DELETE FROM pending_files WHERE task_id=:task_id AND agent_ip=:agent_ip"),
                {"task_id": task_id, "agent_ip": agent_ip},
            )

            for item in files:
                path = item.get("filepath") or item.get("path") or ""
                filename = item.get("filename") or os.path.basename(path) or "unknown"
                file_hash = item.get("file_hash", "")
                rid = _record_id(task_id, agent_ip, file_hash, path)
                conn.execute(
                    text(
                        """
                        INSERT INTO pending_files(
                            id, task_id, agent_ip, file_hash, filename, path, language,
                            confidence, reason, created_at
                        ) VALUES (
                            :id, :task_id, :agent_ip, :file_hash, :filename, :path, :language,
                            :confidence, :reason, :created_at
                        )
                        ON CONFLICT(id) DO UPDATE SET
                            task_id=excluded.task_id,
                            agent_ip=excluded.agent_ip,
                            file_hash=excluded.file_hash,
                            filename=excluded.filename,
                            path=excluded.path,
                            language=excluded.language,
                            confidence=excluded.confidence,
                            reason=excluded.reason,
                            created_at=excluded.created_at
                        """
                    ),
                    {
                        "id": rid,
                        "task_id": task_id,
                        "agent_ip": agent_ip,
                        "file_hash": file_hash,
                        "filename": filename,
                        "path": path,
                        "language": item.get("language") or item.get("type"),
                        "confidence": float(item.get("confidence", 0.0)),
                        "reason": item.get("reason", ""),
                        "created_at": item.get("modified_time") or _now_iso(),
                    },
                )


def list_pending_files(search: str = ""):
    with _LOCK:
        with _ENGINE.connect() as conn:
            if search.strip():
                token = f"%{search.strip().lower()}%"
                rows = _rows(
                    conn.execute(
                        text(
                            """
                            SELECT * FROM pending_files
                            WHERE LOWER(filename) LIKE :token
                               OR LOWER(path) LIKE :token
                               OR LOWER(agent_ip) LIKE :token
                               OR LOWER(task_id) LIKE :token
                               OR LOWER(COALESCE(language, '')) LIKE :token
                            ORDER BY created_at DESC
                            """
                        ),
                        {"token": token},
                    )
                )
            else:
                rows = _rows(conn.execute(text("SELECT * FROM pending_files ORDER BY created_at DESC")))

        records = []
        for row in rows:
            row["status"] = "pending"
            records.append(row)
        return records


def get_pending_by_ids(record_ids):
    if not record_ids:
        return []
    with _LOCK:
        with _ENGINE.connect() as conn:
            stmt = text("SELECT * FROM pending_files WHERE id IN :record_ids").bindparams(
                bindparam("record_ids", expanding=True)
            )
            rows = _rows(
                conn.execute(
                    stmt,
                    {"record_ids": list(record_ids)},
                )
            )

        records = []
        for row in rows:
            row["status"] = "pending"
            records.append(row)
        return records


def delete_pending_by_ids(record_ids):
    if not record_ids:
        return
    with _LOCK:
        with _ENGINE.begin() as conn:
            stmt = text("DELETE FROM pending_files WHERE id IN :record_ids").bindparams(
                bindparam("record_ids", expanding=True)
            )
            conn.execute(stmt, {"record_ids": list(record_ids)})


def add_deletion_reports(agent_ip: str, task_id: str, reports):
    if not reports:
        return
    with _LOCK:
        with _ENGINE.begin() as conn:
            for item in reports:
                conn.execute(
                    text(
                        """
                        INSERT INTO deletion_reports(
                            agent_ip, task_id, file_hash, path, status, details, created_at
                        ) VALUES (
                            :agent_ip, :task_id, :file_hash, :path, :status, :details, :created_at
                        )
                        """
                    ),
                    {
                        "agent_ip": agent_ip,
                        "task_id": task_id,
                        "file_hash": item.get("file_hash"),
                        "path": item.get("path"),
                        "status": item.get("status", "unknown"),
                        "details": item.get("details", ""),
                        "created_at": _now_iso(),
                    },
                )


def list_deletion_reports(limit: int = 200):
    limit = max(1, min(int(limit), 2000))
    with _LOCK:
        with _ENGINE.connect() as conn:
            rows = _rows(
                conn.execute(
                    text("SELECT * FROM deletion_reports ORDER BY id DESC LIMIT :limit"),
                    {"limit": limit},
                )
            )
        return rows


def enqueue_delete_command(agent_ip: str, task_id: str, payload: dict):
    with _LOCK:
        with _ENGINE.begin() as conn:
            payload_json = json.dumps(payload, sort_keys=True)
            existing = conn.execute(
                text(
                    """
                    SELECT id FROM delete_command_queue
                    WHERE agent_ip=:agent_ip AND task_id=:task_id AND payload_json=:payload_json AND status='pending'
                    ORDER BY id ASC
                    LIMIT 1
                    """
                ),
                {"agent_ip": agent_ip, "task_id": task_id, "payload_json": payload_json},
            ).mappings().first()

            if existing:
                return int(existing["id"])

            if _IS_SQLITE:
                result = conn.execute(
                    text(
                        """
                        INSERT INTO delete_command_queue(
                            agent_ip, task_id, payload_json, status, created_at
                        ) VALUES (:agent_ip, :task_id, :payload_json, 'pending', :created_at)
                        """
                    ),
                    {
                        "agent_ip": agent_ip,
                        "task_id": task_id,
                        "payload_json": payload_json,
                        "created_at": _now_iso(),
                    },
                )
                return int(result.lastrowid)

            created = conn.execute(
                text(
                    """
                    INSERT INTO delete_command_queue(
                        agent_ip, task_id, payload_json, status, created_at
                    ) VALUES (:agent_ip, :task_id, :payload_json, 'pending', :created_at)
                    RETURNING id
                    """
                ),
                {
                    "agent_ip": agent_ip,
                    "task_id": task_id,
                    "payload_json": payload_json,
                    "created_at": _now_iso(),
                },
            ).mappings().first()
            return int(created["id"])


def fetch_pending_delete_commands(agent_ip: str, limit: int = 20):
    limit = max(1, min(int(limit), 100))
    with _LOCK:
        with _ENGINE.connect() as conn:
            rows = _rows(
                conn.execute(
                    text(
                        """
                        SELECT id, payload_json
                        FROM delete_command_queue
                        WHERE agent_ip=:agent_ip AND status='pending'
                        ORDER BY id ASC
                        LIMIT :limit
                        """
                    ),
                    {"agent_ip": agent_ip, "limit": limit},
                )
            )

    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "payload": json.loads(row["payload_json"]),
        })
    return result


def mark_delete_command_sent(cmd_id: int):
    with _LOCK:
        with _ENGINE.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE delete_command_queue
                    SET status='sent', sent_at=:sent_at, error=NULL
                    WHERE id=:cmd_id
                    """
                ),
                {"sent_at": _now_iso(), "cmd_id": cmd_id},
            )


def mark_delete_command_failed(cmd_id: int, error: str):
    with _LOCK:
        with _ENGINE.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE delete_command_queue
                    SET status='pending', error=:error
                    WHERE id=:cmd_id
                    """
                ),
                {"error": (error or "")[:500], "cmd_id": cmd_id},
            )


def remove_pending_after_deletion_report(agent_ip: str, task_id: str, reports):
    """
    Remove pending files once agent confirms deletion.
    Match by task/agent and then by hash or path.
    """
    if not reports:
        return

    with _LOCK:
        with _ENGINE.begin() as conn:
            for rep in reports:
                status = rep.get("status")
                details = (rep.get("details") or "").lower()

                terminal = (
                    status == "deleted" or
                    (status == "failed" and "not found in quarantine" in details)
                )
                if not terminal:
                    continue

                file_hash = rep.get("file_hash") or ""
                path = rep.get("path") or ""

                if file_hash:
                    conn.execute(
                        text(
                            """
                            DELETE FROM pending_files
                            WHERE task_id=:task_id AND agent_ip=:agent_ip AND file_hash=:file_hash
                            """
                        ),
                        {"task_id": task_id, "agent_ip": agent_ip, "file_hash": file_hash},
                    )
                elif path:
                    conn.execute(
                        text(
                            """
                            DELETE FROM pending_files
                            WHERE task_id=:task_id AND agent_ip=:agent_ip AND path=:path
                            """
                        ),
                        {"task_id": task_id, "agent_ip": agent_ip, "path": path},
                    )


def next_daily_task_id() -> str:
    """
    Generate task IDs in DDMMYYYY-N format with a daily counter starting from 1.
    """
    date_key = datetime.now().strftime("%d%m%Y")
    with _LOCK:
        with _ENGINE.begin() as conn:
            row = conn.execute(
                text("SELECT last_value FROM daily_task_counter WHERE date_key=:date_key"),
                {"date_key": date_key},
            ).mappings().first()
            next_value = 1
            if row:
                next_value = int(row["last_value"]) + 1
                conn.execute(
                    text("UPDATE daily_task_counter SET last_value=:next_value WHERE date_key=:date_key"),
                    {"next_value": next_value, "date_key": date_key},
                )
            else:
                conn.execute(
                    text("INSERT INTO daily_task_counter(date_key, last_value) VALUES (:date_key, :last_value)"),
                    {"date_key": date_key, "last_value": next_value},
                )
    return f"{date_key}-{next_value}"


def peek_next_daily_task_id() -> str:
    """
    Return the next task ID in DDMMYYYY-N format without incrementing the counter.
    """
    date_key = datetime.now().strftime("%d%m%Y")
    with _LOCK:
        with _ENGINE.connect() as conn:
            row = conn.execute(
                text("SELECT last_value FROM daily_task_counter WHERE date_key=:date_key"),
                {"date_key": date_key},
            ).mappings().first()
    next_value = (int(row["last_value"]) + 1) if row else 1
    return f"{date_key}-{next_value}"
