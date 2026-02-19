try:
    from backend.network.protocol import receive_message, send_message
    from backend.orchestrator.agent_registry import (
        register_agent,
        remove_agent,
        update_status,
        touch
    )
    from backend.orchestrator.task_dispatcher import dispatch_scan_task
    from backend.orchestrator.result_collector import result_collector
    from shared import persistence
except ModuleNotFoundError:
    from network.protocol import receive_message, send_message
    from orchestrator.agent_registry import (
        register_agent,
        remove_agent,
        update_status,
        touch
    )
    from orchestrator.task_dispatcher import dispatch_scan_task
    from orchestrator.result_collector import result_collector
    persistence = None


def _dispatch_queued_delete_commands(agent_ip, conn):
    if not persistence:
        return

    persistence.init_db()
    commands = persistence.fetch_pending_delete_commands(agent_ip)
    for cmd in commands:
        cmd_id = cmd.get("id")
        payload = cmd.get("payload", {})
        if payload.get("type") != "delete_approved":
            payload["type"] = "delete_approved"
        try:
            send_message(conn, payload)
            persistence.mark_delete_command_sent(cmd_id)
            print(f"[MASTER] Sent queued delete command {cmd_id} -> {agent_ip}")
        except Exception as e:
            persistence.mark_delete_command_failed(cmd_id, str(e))
            print(f"[MASTER] Failed queued delete command {cmd_id} -> {agent_ip}: {e}")
            break

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
                task_id = message.get("task_id") or "unknown-task"
                files = message.get("files")
                if files is None:
                    files = message.get("results", [])

                result_collector.add_scan_result(
                    agent_ip=agent_ip,
                    task_id=task_id,
                    files=files
                )
                if persistence:
                    persistence.init_db()
                    persistence.replace_pending_files(task_id, agent_ip, files)

                update_status(agent_ip, "AWAITING_APPROVAL")

                print(f"[MASTER] Scan result received from {agent_ip}")
                print(f"[MASTER] Task: {task_id}, Files: {len(files)}")

            elif msg_type == "heartbeat":
                # Keep-alive; no action required
                _dispatch_queued_delete_commands(agent_ip, conn)

            elif msg_type == "deletion_report":
                task_id = message.get("task_id") or "unknown-task"
                reports = message.get("reports", [])
                if persistence:
                    persistence.init_db()
                    persistence.add_deletion_reports(agent_ip, task_id, reports)
                    persistence.remove_pending_after_deletion_report(agent_ip, task_id, reports)
                update_status(agent_ip, "IDLE")
                ok = sum(1 for r in reports if r.get("status") == "deleted")
                print(f"[MASTER] Deletion report from {agent_ip} - task {task_id}: {ok}/{len(reports)} deleted")
                _dispatch_queued_delete_commands(agent_ip, conn)

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
