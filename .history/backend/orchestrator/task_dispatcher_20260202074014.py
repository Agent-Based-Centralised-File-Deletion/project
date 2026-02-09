from network.protocol import send_message
from orchestrator.agent_registry import update_status


def dispatch_initial_task(conn, agent_id):
    task = {
        "type": "scan_task",
        "task_id": "test_scan_001",
        "target_languages": ["python"],
        "date_filter": None
    }

    send_message(conn, task)
    update_status(agent_id, "SCANNING")
    print(f"[MASTER] Scan task sent to {agent_id}")
