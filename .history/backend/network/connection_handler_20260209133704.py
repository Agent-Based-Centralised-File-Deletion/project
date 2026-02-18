from network.protocol import receive_message
from orchestrator.agent_registry import (
    register_agent,
    remove_agent,
    update_status,
    touch
)
from orchestrator.task_dispatcher import dispatch_scan_task
from orchestrator.result_collector import result_collector

def handle_agent(conn, addr):
    agent_ip, _ = addr

    try:
        # Receive and validate registration
        registration = receive_message(conn)
        if not registration or registration.get("type") != "register":
            raise Exception("Invalid registration message")

        register_agent(agent_ip, conn, addr)
        print(f"[MASTER] Agent registered: {agent_ip}")

        # Dispatch initial task after registration
        dispatch_scan_task(conn, agent_ip)

        # Listen for incoming messages
        while True:
            message = receive_message(conn)
            if message is None:
                print(f"[MASTER] No message received, closing connection for {agent_ip}")
                break

            touch(agent_ip)
            msg_type = message.get("type")

            if msg_type in ("scan_result", "scan_results"):
                task_id = message.get("task_id")
                files = message.get("files", [])

                result_collector.add_scan_result(
                    agent_ip=agent_ip,
                    task_id=task_id,
                    files=files
                )

                update_status(agent_ip, "AWAITING_APPROVAL")

                print(f"[MASTER] Scan result received from {agent_ip}")
                print(f"[MASTER] Task: {task_id}, Files: {len(files)}")

            elif msg_type == "heartbeat":
                # Keep-alive; no action required
                pass

            else:
                print(f"[MASTER] Unknown message type from {agent_ip}: {msg_type}")

    except Exception as e:
        print(f"[MASTER] Error [{agent_ip}]: {e}")

    finally:
        remove_agent(agent_ip)
        try:
            conn.close()
        except Exception:
            pass
        print(f"[MASTER] Agent disconnected: {agent_ip}")
