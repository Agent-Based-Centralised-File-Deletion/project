import os
import sys
import ipaddress

try:
    from backend.network.protocol import receive_message, send_message
    from backend.orchestrator.agent_registry import (
        register_agent,
        remove_agent,
        update_status,
        touch
    )
    from backend.orchestrator.result_collector import result_collector
    from shared import persistence
except ModuleNotFoundError:
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    from network.protocol import receive_message, send_message
    from orchestrator.agent_registry import (
        register_agent,
        remove_agent,
        update_status,
        touch
    )
    from orchestrator.result_collector import result_collector
    try:
        from shared import persistence
    except ModuleNotFoundError:
        persistence = None


def _dispatch_queued_commands(agent_ip, conn):
    if not persistence:
        return

    persistence.init_db()
    commands = persistence.fetch_pending_delete_commands(agent_ip)
    for cmd in commands:
        cmd_id = cmd.get("id")
        payload = cmd.get("payload", {})
        try:
            send_message(conn, payload)
            persistence.mark_delete_command_sent(cmd_id)
            print(f"[MASTER] Sent queued command {cmd_id} ({payload.get('type')}) -> {agent_ip}")
        except Exception as e:
            persistence.mark_delete_command_failed(cmd_id, str(e))
            print(f"[MASTER] Failed queued command {cmd_id} -> {agent_ip}: {e}")
            break


def _resolve_agent_identity(registration: dict, peer_ip: str) -> str:
    """
    Prefer client-provided identity when it is a valid IPv4 address.
    This allows lab layouts to map correctly even when peer_ip is NAT'd.
    """
    reg = registration or {}
    for key in ("local_ip", "client_id"):
        candidate = str(reg.get(key, "")).strip()
        if not candidate:
            continue
        try:
            ip = ipaddress.ip_address(candidate)
            if ip.version == 4:
                return candidate
        except ValueError:
            pass
    return peer_ip


def handle_agent(conn, addr):
    peer_ip, _ = addr
    agent_ip = peer_ip

    try:
        # Receive and validate registration
        registration = receive_message(conn)
        if not registration or registration.get("type") != "register":
            raise Exception("Invalid registration message")

        agent_ip = _resolve_agent_identity(registration, peer_ip)
        register_agent(agent_ip, conn, addr)
        print(f"[MASTER] Agent registered: {agent_ip} (peer: {peer_ip})")

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
                _dispatch_queued_commands(agent_ip, conn)

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
                _dispatch_queued_commands(agent_ip, conn)

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
