import json
import time

def handle_agent(conn, addr):
    agent_ip, agent_port = addr
    print(f"[MASTER] Agent connected from {agent_ip}:{agent_port}")

    try:
        # ---- Receive registration ----
        data = conn.recv(1024).decode()
        print(f"[MASTER] Registration from {agent_ip}: {data}")

        # ---- WAIT a bit (important) ----
        time.sleep(3)

        # ---- SEND A TEST SCAN TASK ----
        scan_task = {
            "type": "scan_task",
            "task_id": "test_scan_001",
            "target_languages": ["python"],
            "date_filter": None
        }

        msg = json.dumps(scan_task).encode("utf-8")
        conn.sendall(len(msg).to_bytes(4, "big"))
        conn.sendall(msg)

        print(f"[MASTER] Sent scan_task to {agent_ip}")

        # ---- RECEIVE SCAN RESULTS ----
        length_data = conn.recv(4)
        if length_data:
            length = int.from_bytes(length_data, "big")
            result_data = conn.recv(length)
            results = json.loads(result_data.decode())
            print(f"[MASTER] Scan results from {agent_ip}:")
            print(json.dumps(results, indent=2))

    except Exception as e:
        print(f"[MASTER] Error with agent {agent_ip}: {e}")

    finally:
        conn.close()
        print(f"[MASTER] Connection closed for {agent_ip}\n")
