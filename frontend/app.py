from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
from collections import defaultdict
import ipaddress
import logging
import os
import re
import sys
import threading


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.api.instructions import create_scan_instruction, SUPPORTED_LANGUAGES
from backend.orchestrator.agent_registry import get_active_agents, update_status
from backend.network.protocol import send_message
from backend.network.tcp_server import start_master
from models import db, DeletionAuditLog
from shared import persistence
from shared.constants import HEARTBEAT_TIMEOUT


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "SQLALCHEMY_DATABASE_URI",
    persistence.flask_database_uri(),
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
with app.app_context():
    db.create_all()
persistence.init_db()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
_MASTER_THREAD_STARTED = False
AGENT_STALE_SECONDS = int(os.getenv("AGENT_STALE_SECONDS", max(HEARTBEAT_TIMEOUT * 2, 1)))
LANGUAGE_LABELS = {
    "java": "Java",
    "c": "C",
    "cpp": "C++",
    "python": "Python",
    "php": "PHP",
    "javascript": "JavaScript",
    "html": "HTML",
    "css": "CSS",
    "mysql": "MySQL",
    "nosql": "NoSQL",
    "perl": "Perl",
    "prolog": "Prolog",
    "matlab": "MATLAB",
    "assembly": "Assembly",
}
LAB_LAYOUTS = [
    {
        "key": "lab1",
        "title": "CSL 1 & 2",
        "subtitle": "Lab 1 layout with 100 PCs",
        "rows": [
            ["10.20.9.101", "10.20.9.102", "10.20.9.103", "10.20.9.104", "10.20.9.105", None, "10.20.9.106", "10.20.9.107", "10.20.9.108", "10.20.9.109", "10.20.9.110", None, "10.20.9.151", "10.20.9.152", "10.20.9.153", "10.20.9.154", "10.20.9.155", None, "10.20.9.156", "10.20.9.157", "10.20.9.158", "10.20.9.159", "10.20.9.160"],
            ["10.20.9.111", "10.20.9.112", "10.20.9.113", "10.20.9.114", "10.20.9.115", None, "10.20.9.116", "10.20.9.117", "10.20.9.118", "10.20.9.119", "10.20.9.120", None, "10.20.9.161", "10.20.9.162", "10.20.9.163", "10.20.9.164", "10.20.9.165", None, "10.20.9.166", "10.20.9.167", "10.20.9.168", "10.20.9.169", "10.20.9.170"],
            ["10.20.9.121", "10.20.9.122", "10.20.9.123", "10.20.9.124", "10.20.9.125", None, "10.20.9.126", "10.20.9.127", "10.20.9.128", "10.20.9.129", "10.20.9.130", None, "10.20.9.171", "10.20.9.172", "10.20.9.173", "10.20.9.174", "10.20.9.175", None, "10.20.9.176", "10.20.9.177", "10.20.9.178", "10.20.9.179", "10.20.9.180"],
            ["10.20.9.131", "10.20.9.132", "10.20.9.133", "10.20.9.134", "10.20.9.135", None, "10.20.9.136", "10.20.9.137", "10.20.9.138", "10.20.9.139", "10.20.9.140", None, "10.20.9.181", "10.20.9.182", "10.20.9.183", "10.20.9.184", "10.20.9.185", None, "10.20.9.186", "10.20.9.187", "10.20.9.188", "10.20.9.189", "10.20.9.190"],
            ["10.20.9.141", "10.20.9.142", "10.20.9.143", "10.20.9.144", "10.20.9.145", None, "10.20.9.146", "10.20.9.147", "10.20.9.148", "10.20.9.149", "10.20.9.150", None, "10.20.9.191", "10.20.9.192", "10.20.9.193", "10.20.9.194", "10.20.9.195", None, "10.20.9.196", "10.20.9.197", "10.20.9.198", "10.20.9.199", "10.20.9.200"],
        ],
    },
    {
        "key": "lab2",
        "title": "CSL 3 & 4",
        "subtitle": "Lab 2 layout with 100 PCs",
        "rows": [
            ["10.20.9.1", "10.20.9.2", "10.20.9.3", "10.20.9.4", "10.20.9.5", None, "10.20.9.6", "10.20.9.7", "10.20.9.8", "10.20.9.9", "10.20.9.10", None, "10.20.9.51", "10.20.9.52", "10.20.9.53", "10.20.9.54", "10.20.9.55", None, "10.20.9.56", "10.20.9.57", "10.20.9.58", "10.20.9.59", "10.20.9.60"],
            ["10.20.9.11", "10.20.9.12", "10.20.9.13", "10.20.9.14", "10.20.9.15", None, "10.20.9.16", "10.20.9.17", "10.20.9.18", "10.20.9.19", "10.20.9.20", None, "10.20.9.61", "10.20.9.62", "10.20.9.63", "10.20.9.64", "10.20.9.65", None, "10.20.9.66", "10.20.9.67", "10.20.9.68", "10.20.9.69", "10.20.9.70"],
            ["10.20.9.21", "10.20.9.22", "10.20.9.23", "10.20.9.24", "10.20.9.25", None, "10.20.9.26", "10.20.9.27", "10.20.9.28", "10.20.9.29", "10.20.9.30", None, "10.20.9.71", "10.20.9.72", "10.20.9.73", "10.20.9.74", "10.20.9.75", None, "10.20.9.76", "10.20.9.77", "10.20.9.78", "10.20.9.79", "10.20.9.80"],
            ["10.20.9.31", "10.20.9.32", "10.20.9.33", "10.20.9.34", "10.20.9.35", None, "10.20.9.36", "10.20.9.37", "10.20.9.38", "10.20.9.39", "10.20.9.40", None, "10.20.9.81", "10.20.9.82", "10.20.9.83", "10.20.9.84", "10.20.9.85", None, "10.20.9.86", "10.20.9.87", "10.20.9.88", "10.20.9.89", "10.20.9.90"],
            ["10.20.9.41", "10.20.9.42", "10.20.9.43", "10.20.9.44", "10.20.9.45", None, "10.20.9.46", "10.20.9.47", "10.20.9.48", "10.20.9.49", "10.20.9.50", None, "10.20.9.91", "10.20.9.92", "10.20.9.93", "10.20.9.94", "10.20.9.95", None, "10.20.9.96", "10.20.9.97", "10.20.9.98", "10.20.9.99", "10.20.9.100"],
        ],
    },
]


def _start_master_thread_if_enabled():
    global _MASTER_THREAD_STARTED
    if _MASTER_THREAD_STARTED:
        return

    if os.getenv("START_MASTER_WITH_UI", "0") != "1":
        logger.info("START_MASTER_WITH_UI disabled; expecting external backend master.")
        _MASTER_THREAD_STARTED = True
        return

    threading.Thread(target=start_master, daemon=True).start()
    _MASTER_THREAD_STARTED = True
    logger.info("Embedded master TCP server started on 0.0.0.0:5000")


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _is_absolute_path_any_os(path: str) -> bool:
    if not path:
        return False
    return bool(re.match(r"^[A-Za-z]:[\\/]", path) or path.startswith("/"))


def _is_online(raw_status: str, last_seen_ts, now_ts: float) -> bool:
    if str(raw_status).upper() == "OFFLINE":
        return False
    if not last_seen_ts:
        return False
    try:
        return (now_ts - float(last_seen_ts)) <= AGENT_STALE_SECONDS
    except (TypeError, ValueError):
        return False


def _canonical_agent_ip(raw_ip) -> str:
    value = str(raw_ip or "").strip()
    if not value:
        return ""

    # Handle common IPv4-mapped IPv6 representation.
    if value.lower().startswith("::ffff:"):
        value = value.split(":", 3)[-1].strip()

    # Handle IPv4 with accidental port suffix.
    if value.count(":") == 1 and "." in value:
        host, _, port = value.rpartition(":")
        if host and port.isdigit():
            value = host.strip()

    try:
        parsed = ipaddress.ip_address(value)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except ValueError:
        return value


def _infer_languages_from_instruction(instruction: str):
    text = instruction.lower()
    inferred = set()

    # Keep this conservative; default remains python if no clear hit.
    mapping = {
        "java": ["java", ".java"],
        "c": [" c ", " c-language ", ".c "],
        "cpp": ["c++", "cpp", ".cpp", ".cc", ".cxx", ".hpp"],
        "python": ["python", ".py"],
        "php": ["php", ".php", ".phtml"],
        "javascript": ["javascript", "js", ".js", ".jsx", ".mjs", ".cjs"],
        "html": ["html", ".html", ".htm"],
        "css": ["css", ".css", ".scss", ".sass", ".less"],
        "mysql": ["mysql", "sql", ".sql", "select ", "create table"],
        "nosql": ["nosql", "mongodb", "cassandra", "db.", "$set", "keyspace"],
        "matlab": ["matlab", ".m"],
        "perl": ["perl", ".pl", ".pm"],
        "prolog": ["prolog", ":-", "?-"],
        "assembly": ["assembly", ".asm", "mov ", "jmp ", "section ."],
    }

    padded = f" {text} "
    for lang, hints in mapping.items():
        for hint in hints:
            if hint in padded or hint in text:
                inferred.add(lang)
                break

    if not inferred:
        inferred = {"python"}
    return list(inferred)


def _normalize_custom_languages(raw_custom_languages):
    if not isinstance(raw_custom_languages, dict):
        return {}

    normalized = {}
    for raw_name, raw_spec in raw_custom_languages.items():
        name = str(raw_name).strip().lower()
        if not name:
            continue
        if name in SUPPORTED_LANGUAGES:
            raise ValueError(f"Custom language '{name}' already exists as a built-in language")
        if not isinstance(raw_spec, dict):
            raise ValueError(f"Custom language spec for '{name}' must be an object")

        raw_patterns = raw_spec.get("patterns", [])
        patterns = []
        if not isinstance(raw_patterns, list):
            raise ValueError(f"patterns for '{name}' must be a list")
        for idx, item in enumerate(raw_patterns, start=1):
            if isinstance(item, dict):
                regex = str(item.get("regex", "")).strip()
                description = str(item.get("description", "")).strip() or f"custom pattern {idx}"
            else:
                regex = str(item).strip()
                description = f"custom pattern {idx}"
            if not regex:
                continue
            try:
                re.compile(regex)
            except re.error as exc:
                raise ValueError(f"Invalid regex in patterns for '{name}': {regex} ({exc})")
            patterns.append({"regex": regex, "description": description})
        if not patterns:
            raise ValueError(f"Custom language '{name}' requires at least one valid regex pattern")

        raw_signatures = raw_spec.get("signature_patterns", [])
        if raw_signatures is None:
            raw_signatures = []
        if not isinstance(raw_signatures, list):
            raise ValueError(f"signature_patterns for '{name}' must be a list")
        signature_patterns = []
        for item in raw_signatures:
            regex = str(item).strip()
            if not regex:
                continue
            try:
                re.compile(regex)
            except re.error as exc:
                raise ValueError(f"Invalid regex in signature_patterns for '{name}': {regex} ({exc})")
            signature_patterns.append(regex)

        raw_keywords = raw_spec.get("keywords", [])
        if raw_keywords is None:
            raw_keywords = []
        if not isinstance(raw_keywords, list):
            raise ValueError(f"keywords for '{name}' must be a list")
        keywords = [str(k).strip() for k in raw_keywords if str(k).strip()]

        raw_extensions = raw_spec.get("extensions", [])
        if raw_extensions is None:
            raw_extensions = []
        if not isinstance(raw_extensions, list):
            raise ValueError(f"extensions for '{name}' must be a list")
        extensions = []
        for ext in raw_extensions:
            value = str(ext).strip().lower()
            if not value:
                continue
            if not value.startswith("."):
                value = f".{value}"
            extensions.append(value)

        normalized[name] = {
            "patterns": patterns,
            "signature_patterns": signature_patterns,
            "keywords": keywords,
            "extensions": sorted(set(extensions)),
        }

    return normalized


def _flatten_pending_files(search: str = ""):
    return persistence.list_pending_files(search=search)


def _group_records_by_agent(records):
    grouped = defaultdict(list)
    for r in records:
        key = (r["agent_ip"], r.get("task_id") or "unknown-task")
        grouped[key].append({
            "file_hash": r.get("file_hash", ""),
            "path": r.get("path", ""),
            "record_id": r.get("id", "")
        })
    return grouped


def _remove_records_from_queue(records):
    persistence.delete_pending_by_ids([r["id"] for r in records])


def _persist_audit_logs(records, action: str, notes: str = ""):
    for rec in records:
        db.session.add(DeletionAuditLog(
            record_id=rec.get("id", ""),
            task_id=rec.get("task_id"),
            agent_ip=rec.get("agent_ip"),
            file_hash=rec.get("file_hash"),
            filename=rec.get("filename", "unknown"),
            path=rec.get("path", ""),
            language=rec.get("language"),
            confidence=rec.get("confidence"),
            action=action,
            notes=notes,
            created_at=datetime.now()
        ))
    db.session.commit()


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/verification")
def verification():
    return render_template("verification.html")


@app.route("/ui-config", methods=["GET"])
def ui_config():
    try:
        total_expected_agents = 0
        for section in LAB_LAYOUTS:
            total_expected_agents += sum(1 for row in section["rows"] for cell in row if cell)

        supported = sorted(SUPPORTED_LANGUAGES)
        language_options = [{"value": lang, "label": LANGUAGE_LABELS.get(lang, lang.upper())} for lang in supported]

        sections = []
        for section in LAB_LAYOUTS:
            sections.append({
                "key": section["key"],
                "title": section["title"],
                "subtitle": section["subtitle"],
                "rows": section["rows"],
            })
        sections.append({
            "key": "other",
            "title": "Other",
            "subtitle": "Agents not mapped to configured lab layouts",
            "rows": [],
        })

        return jsonify({
            "supported_languages": language_options,
            "lab_sections": sections,
            "total_expected_agents": total_expected_agents,
        })
    except Exception as e:
        logger.error("Error getting UI config: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/next-task-id", methods=["GET"])
def next_task_id():
    try:
        return jsonify({"task_id": persistence.peek_next_daily_task_id()})
    except Exception as e:
        logger.error("Error getting next task id: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/submit-instruction", methods=["POST"])
def submit_instruction():
    try:
        data = request.get_json(silent=True) or {}
        instruction = str(data.get("instruction", "")).strip()
        target_languages = data.get("target_languages")
        custom_languages = data.get("custom_languages")
        clear_all = bool(data.get("clear_all"))
        scan_path = str(data.get("scan_path", "")).strip()
        raw_date_filter = data.get("date_filter")

        if not target_languages and not clear_all:
            if not instruction:
                return jsonify({"error": "Instruction cannot be empty"}), 400
            target_languages = _infer_languages_from_instruction(instruction)

        target_languages = [str(x).lower().strip() for x in target_languages if str(x).strip()]
        custom_languages = _normalize_custom_languages(custom_languages)
        invalid = [x for x in target_languages if x not in SUPPORTED_LANGUAGES and x not in custom_languages]
        if invalid:
            return jsonify({"error": f"Unsupported languages: {invalid}"}), 400
        if not clear_all and not target_languages:
            return jsonify({"error": "At least one target language must be specified"}), 400
        if not scan_path:
            return jsonify({"error": "scan_path is required"}), 400
        if not _is_absolute_path_any_os(scan_path):
            return jsonify({"error": "scan_path must be an absolute path"}), 400

        date_filter = None
        if isinstance(raw_date_filter, dict):
            start_raw = raw_date_filter.get("start")
            end_raw = raw_date_filter.get("end")
            start = str(start_raw).strip() if start_raw is not None else ""
            end = str(end_raw).strip() if end_raw is not None else ""
            if start or end:
                try:
                    date_filter = {}
                    if start:
                        datetime.fromisoformat(start)
                        date_filter["start"] = start
                    if end:
                        datetime.fromisoformat(end)
                        date_filter["end"] = end
                    if start and end and datetime.fromisoformat(start) > datetime.fromisoformat(end):
                        return jsonify({"error": "date_filter.start must be before date_filter.end"}), 400
                except ValueError:
                    return jsonify({"error": "date_filter values must be ISO datetime strings"}), 400

        task = create_scan_instruction(
            target_languages=target_languages,
            date_filter=date_filter,
            scan_paths=[scan_path],
            custom_languages=custom_languages,
            clear_all=clear_all,
        )
        active_agents = get_active_agents()
        active_agents_by_canonical = {}
        for raw_ip, info in active_agents.items():
            canonical_ip = _canonical_agent_ip(raw_ip)
            if not canonical_ip:
                continue
            current = active_agents_by_canonical.get(canonical_ip)
            if not current or float(info.get("last_seen", 0.0) or 0.0) >= float(current.get("last_seen", 0.0) or 0.0):
                merged = info.copy()
                merged["_raw_ip"] = raw_ip
                active_agents_by_canonical[canonical_ip] = merged

        now_ts = datetime.now(tz=timezone.utc).timestamp()
        persisted_agents = persistence.list_agents()
        online_persisted_ips = {
            _canonical_agent_ip(item.get("agent_ip"))
            for item in persisted_agents
            if item.get("agent_ip") and _is_online(item.get("status", ""), item.get("last_seen"), now_ts)
        }
        candidate_ips = sorted({ip for ip in (set(active_agents_by_canonical.keys()) | online_persisted_ips) if ip})
        if not candidate_ips:
            return jsonify({"error": "No active agents available"}), 400

        dispatched = 0
        queued = 0
        failed = []
        for agent_ip in candidate_ips:
            info = active_agents_by_canonical.get(agent_ip) or {}
            conn = info.get("conn")
            if conn is not None:
                try:
                    send_message(conn, task)
                    update_status(info.get("_raw_ip", agent_ip), "SCANNING")
                    dispatched += 1
                    continue
                except Exception as e:
                    logger.error("Failed live dispatch to %s: %s", agent_ip, e)

            # Fallback: queue for backend to send on next heartbeat.
            try:
                persistence.enqueue_delete_command(agent_ip, task["task_id"], task)
                queued += 1
            except Exception as e:
                failed.append(agent_ip)
                logger.error("Failed queueing scan task for %s: %s", agent_ip, e)

        logger.info("Task %s dispatched=%d queued=%d", task["task_id"], dispatched, queued)
        return jsonify({
            "message": f"Instruction dispatched to {dispatched} agent(s), queued for {queued} agent(s)",
            "task_id": task["task_id"],
            "target_languages": target_languages,
            "custom_languages": custom_languages,
            "scan_path": scan_path,
            "date_filter": date_filter,
            "queued_agents": queued,
            "failed_agents": failed
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Error submitting instruction: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/clients-status", methods=["GET"])
def clients_status():
    try:
        status_list = []
        now_ts = datetime.now(tz=timezone.utc).timestamp()
        merged = {}

        for item in persistence.list_agents():
            raw_ip = item.get("agent_ip")
            agent_ip = _canonical_agent_ip(raw_ip)
            if not agent_ip:
                continue
            raw_status = item.get("status", "OFFLINE")
            last_seen_ts = item.get("last_seen")
            online = _is_online(raw_status, last_seen_ts, now_ts)
            normalized_raw_status = raw_status if online else "OFFLINE"

            # Keep persisted status aligned for stale agents without rewriting last_seen.
            if raw_ip and not online and str(raw_status).upper() != "OFFLINE":
                persistence.update_agent_status(raw_ip, "OFFLINE")

            current = merged.get(agent_ip)
            item_last_seen = float(last_seen_ts or 0.0)
            if not current:
                merged[agent_ip] = {
                    "ip": agent_ip,
                    "online": online,
                    "raw_status": normalized_raw_status,
                    "last_seen_ts": item_last_seen,
                }
            else:
                current["online"] = current["online"] or online
                if item_last_seen >= current["last_seen_ts"]:
                    current["last_seen_ts"] = item_last_seen
                    current["raw_status"] = normalized_raw_status

        for idx, agent_ip in enumerate(sorted(merged.keys()), start=1):
            rec = merged[agent_ip]
            last_seen = (
                datetime.fromtimestamp(rec["last_seen_ts"], tz=timezone.utc).isoformat()
                if rec["last_seen_ts"]
                else None
            )

            status_list.append({
                "id": idx,
                "name": f"Agent {idx}",
                "ip": agent_ip,
                "ip_address": agent_ip,
                "status": "online" if rec["online"] else "offline",
                "raw_status": rec["raw_status"] if rec["online"] else "OFFLINE",
                "last_seen": last_seen
            })

        return jsonify(status_list)
    except Exception as e:
        logger.error("Error getting client status: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/files-preview", methods=["GET"])
def files_preview():
    try:
        search = request.args.get("search", "").strip()
        return jsonify(_flatten_pending_files(search=search))
    except Exception as e:
        logger.error("Error getting files preview: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/audit-logs", methods=["GET"])
def audit_logs():
    try:
        limit = int(request.args.get("limit", 200))
        limit = max(1, min(limit, 1000))
        rows = (
            DeletionAuditLog.query
            .order_by(DeletionAuditLog.created_at.desc())
            .limit(limit)
            .all()
        )
        audit_rows = [{
            "id": row.id,
            "record_id": row.record_id,
            "task_id": row.task_id,
            "agent_ip": row.agent_ip,
            "file_hash": row.file_hash,
            "filename": row.filename,
            "path": row.path,
            "language": row.language,
            "confidence": row.confidence,
            "action": row.action,
            "action_by": row.action_by,
            "notes": row.notes,
            "created_at": row.created_at.isoformat() if row.created_at else None
        } for row in rows]

        report_rows = []
        for rep in persistence.list_deletion_reports(limit=limit):
            report_rows.append({
                "id": f"rep-{rep.get('id')}",
                "record_id": "",
                "task_id": rep.get("task_id"),
                "agent_ip": rep.get("agent_ip"),
                "file_hash": rep.get("file_hash"),
                "filename": rep.get("path", "").split("\\")[-1].split("/")[-1] if rep.get("path") else "unknown",
                "path": rep.get("path", ""),
                "language": None,
                "confidence": None,
                "action": "delete_confirmed" if rep.get("status") == "deleted" else "delete_failed",
                "action_by": "agent",
                "notes": rep.get("details", ""),
                "created_at": rep.get("created_at"),
            })

        combined = audit_rows + report_rows
        combined.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        # Hide dispatch-failed noise rows from UI; keep them in DB for troubleshooting.
        combined = [row for row in combined if row.get("action") != "delete_dispatch_failed"]

        # If same file has confirmed deletion, hide older failed-not-found noise rows.
        confirmed_keys = set()
        for row in combined:
            if row.get("action") == "delete_confirmed":
                confirmed_keys.add((row.get("task_id"), row.get("agent_ip"), row.get("file_hash"), row.get("path")))

        filtered = []
        for row in combined:
            if row.get("action") == "delete_failed":
                key = (row.get("task_id"), row.get("agent_ip"), row.get("file_hash"), row.get("path"))
                if key in confirmed_keys:
                    continue
            filtered.append(row)

        return jsonify(filtered[:limit])
    except Exception as e:
        logger.error("Error getting audit logs: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/approve-deletion", methods=["POST"])
def approve_deletion():
    try:
        data = request.get_json(silent=True) or {}
        file_ids = data.get("file_ids", [])
        if not isinstance(file_ids, list) or not file_ids:
            return jsonify({"error": "file_ids must be a non-empty list"}), 400

        selected = persistence.get_pending_by_ids(file_ids)
        if not selected:
            return jsonify({"error": "No matching pending files found"}), 404

        entries_by_agent = _group_records_by_agent(selected)
        active_agents = get_active_agents()

        sent_to = 0
        queued = 0
        delivered_record_ids = set()
        queued_record_ids = set()
        undelivered_agents = []

        for (agent_ip, task_id), approved_entries in entries_by_agent.items():
            payload = {
                "type": "delete_approved",
                "task_id": task_id,
                "approved_entries": approved_entries,
                "approved_hashes": [x.get("file_hash", "") for x in approved_entries if x.get("file_hash")],
                "timestamp": _now_iso(),
            }
            agent_info = active_agents.get(agent_ip)

            # If socket is available in this process, dispatch immediately.
            try:
                if agent_info and agent_info.get("conn"):
                    send_message(agent_info["conn"], payload)
                    update_status(agent_ip, "DELETION_DISPATCHED")
                    sent_to += 1
                    for item in approved_entries:
                        rid = item.get("record_id")
                        if rid:
                            delivered_record_ids.add(rid)
                else:
                    # Cross-process fallback: queue command for backend to send on next heartbeat.
                    persistence.enqueue_delete_command(agent_ip, task_id, payload)
                    queued += 1
                    for item in approved_entries:
                        rid = item.get("record_id")
                        if rid:
                            queued_record_ids.add(rid)
                    logger.info("Queued delete command for %s task=%s", agent_ip, task_id)
            except Exception as e:
                logger.error("Failed delete dispatch to %s: %s", agent_ip, e)
                try:
                    persistence.enqueue_delete_command(agent_ip, task_id, payload)
                    queued += 1
                    for item in approved_entries:
                        rid = item.get("record_id")
                        if rid:
                            queued_record_ids.add(rid)
                    logger.info("Queued delete command after dispatch failure for %s task=%s", agent_ip, task_id)
                except Exception:
                    undelivered_agents.append(agent_ip)

        delivered = [r for r in selected if r.get("id") in delivered_record_ids]

        if delivered:
            _persist_audit_logs(
                delivered,
                action="delete_dispatched",
                notes=f"Approved in UI and dispatched to {sent_to} agent(s)"
            )
            _remove_records_from_queue(delivered)

        queued_records = [r for r in selected if r.get("id") in queued_record_ids]
        if queued_records and queued > 0:
            _persist_audit_logs(
                queued_records,
                action="delete_queued",
                notes="Delete command queued; will dispatch on next agent heartbeat"
            )
            _remove_records_from_queue(queued_records)

        handled_record_ids = delivered_record_ids | queued_record_ids
        undelivered = [r for r in selected if r.get("id") not in handled_record_ids]
        if undelivered:
            _persist_audit_logs(
                undelivered,
                action="delete_dispatch_failed",
                notes="Agent not connected or dispatch failed; kept pending"
            )

        return jsonify({
            "message": f"Dispatch success: {len(delivered)} file(s), queued: {len(queued_records)} file(s), failed: {len(undelivered)} file(s).",
            "sent_to_agents": sent_to,
            "queued_agents": queued,
            "undelivered_agents": sorted(set(undelivered_agents)),
        })
    except Exception as e:
        logger.error("Error approving deletion: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/reject-deletion", methods=["POST"])
def reject_deletion():
    try:
        data = request.get_json(silent=True) or {}
        file_ids = data.get("file_ids", [])
        if not isinstance(file_ids, list) or not file_ids:
            return jsonify({"error": "file_ids must be a non-empty list"}), 400

        selected = persistence.get_pending_by_ids(file_ids)
        if not selected:
            return jsonify({"error": "No matching pending files found"}), 404

        _persist_audit_logs(selected, action="rejected", notes="Rejected in UI")
        _remove_records_from_queue(selected)
        return jsonify({"message": f"Rejected {len(selected)} file(s)"})
    except Exception as e:
        logger.error("Error rejecting deletion: %s", e)
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Avoid duplicate server thread under Flask debug reloader.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or os.getenv("FLASK_DEBUG", "0") != "1":
        _start_master_thread_if_enabled()
    app.run(host="0.0.0.0", port=int(os.getenv("FLASK_RUN_PORT", 5001)), debug=True)
