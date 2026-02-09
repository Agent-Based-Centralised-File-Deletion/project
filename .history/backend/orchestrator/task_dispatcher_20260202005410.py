from network.protocol import send_message


def dispatch_initial_task(conn):
    scan_task = {
        "type": "scan_task",
        "task_id": "test_scan_001",
        "target_languages": ["python"],
        "date_filter": None
    }

    send_message(conn, scan_task)
    print("[MASTER] Scan task dispatched")
