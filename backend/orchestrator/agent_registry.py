import time
from threading import Lock

try:
    from shared import persistence
except ModuleNotFoundError:
    persistence = None

_agents = {}
_lock = Lock()


def register_agent(agent_ip, conn, addr):
    with _lock:
        _agents[agent_ip] = {
            "conn": conn,
            "addr": addr,
            "status": "IDLE",
            "last_seen": time.time()
        }
    if persistence:
        persistence.init_db()
        persistence.upsert_agent(agent_ip, "IDLE")


def update_status(agent_ip, status):
    with _lock:
        if agent_ip in _agents:
            _agents[agent_ip]["status"] = status
            _agents[agent_ip]["last_seen"] = time.time()
    if persistence:
        persistence.upsert_agent(agent_ip, status)


def touch(agent_ip):
    with _lock:
        if agent_ip in _agents:
            _agents[agent_ip]["last_seen"] = time.time()
    if persistence:
        persistence.touch_agent(agent_ip)


def remove_agent(agent_ip):
    with _lock:
        _agents.pop(agent_ip, None)
    if persistence:
        persistence.upsert_agent(agent_ip, "OFFLINE")


def get_active_agents():
    with _lock:
        return {
            ip: info.copy()
            for ip, info in _agents.items()
            if info["status"] != "OFFLINE"
        }


def mark_offline_inactive(timeout=30):
    now = time.time()
    with _lock:
        for ip, info in _agents.items():
            if now - info["last_seen"] > timeout:
                info["status"] = "OFFLINE"
                if persistence:
                    persistence.upsert_agent(ip, "OFFLINE")
