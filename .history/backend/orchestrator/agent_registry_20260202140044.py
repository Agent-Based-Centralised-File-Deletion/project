import time
from threading import Lock

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


def update_status(agent_ip, status):
    with _lock:
        if agent_ip in _agents:
            _agents[agent_ip]["status"] = status
            _agents[agent_ip]["last_seen"] = time.time()


def touch(agent_ip):
    with _lock:
        if agent_ip in _agents:
            _agents[agent_ip]["last_seen"] = time.time()


def remove_agent(agent_ip):
    with _lock:
        _agents.pop(agent_ip, None)


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
