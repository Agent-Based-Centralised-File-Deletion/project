# backend/orchestrator/agent_registry.py

import time

_agents = {}


def register_agent(agent_id, conn, addr):
    _agents[agent_id] = {
        "conn": conn,
        "addr": addr,
        "status": "IDLE",
        "last_seen": time.time()
    }


def update_status(agent_id, status):
    if agent_id in _agents:
        _agents[agent_id]["status"] = status
        _agents[agent_id]["last_seen"] = time.time()


def remove_agent(agent_id):
    _agents.pop(agent_id, None)


def get_active_agents():
    return {
        aid: info
        for aid, info in _agents.items()
        if info["status"] != "OFFLINE"
    }


def mark_offline_inactive(timeout=30):
    now = time.time()
    for aid, info in _agents.items():
        if now - info["last_seen"] > timeout:
            info["status"] = "OFFLINE"
