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
        
        registration = receive_message(conn)
        if not registration or registration.get("type") != "register":
            raise Exception("Invalid registration message")

        register_agent(agent_ip, conn, addr)
        print(f"[MASTER] Agent registered: {agent_ip}")

        
        dispatch_scan_task(conn, agent_ip)

        
        while True:
            message = receive_message(conn)
            if not message:
                break

            touch(agent_ip)

            msg_type = message.get("type")

            if msg_type == "scan_result":
                update_status(agent_ip, "AWAITING_APPROVAL")
                print(f"[MASTER] Scan result from {agent_ip}")
                print(message)

            elif msg_type == "heartbeat":
                pass  

    except Exception as e:
        print(f"[MASTER] Error [{agent_ip}]: {e}")

    finally:
        remove_agent(agent_ip)
        conn.close()
        print(f"[MASTER] Agent disconnected: {agent_ip}")
