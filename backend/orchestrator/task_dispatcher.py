try:
    from backend.network.protocol import send_message
    from backend.orchestrator.agent_registry import update_status
    from backend.api.instructions import SUPPORTED_LANGUAGES
except ModuleNotFoundError:
    from network.protocol import send_message
    from orchestrator.agent_registry import update_status
    from api.instructions import SUPPORTED_LANGUAGES


def dispatch_scan_task(conn, agent_ip):
    task = {
        "type": "scan_task",
        "task_id": "test_scan_001",
        "target_languages": sorted(SUPPORTED_LANGUAGES),
        "date_filter": None,
        "scan_paths": []
    }

    send_message(conn, task)
    update_status(agent_ip, "SCANNING")

    print(f"[MASTER] Scan task dispatched → {agent_ip}")
