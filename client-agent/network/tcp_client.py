import socket
import json
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional,List
from dataclasses import asdict

from config import logger
from detector import FileAnalysisResult


class MasterCommunicator:
    """Handles communication with master node"""
    
    def __init__(self, master_ip: str, master_port: int, client_id: str, config_url: str = ""):
        self.master_ip = master_ip
        self.master_port = master_port
        self.client_id = client_id
        self.config_url = config_url
        self._bootstrap_master_ip = master_ip
        self.socket = None
        self.connected = False

    def _candidate_config_urls(self):
        urls = []
        if self.config_url:
            urls.append(self.config_url.rstrip("/"))

        # Fallback: infer frontend URL from bootstrap master host.
        if self._bootstrap_master_ip:
            inferred = f"http://{self._bootstrap_master_ip}:5001"
            if inferred not in urls:
                urls.append(inferred)
        return urls

    def _refresh_endpoint_from_frontend(self):
        """Fetch the latest master endpoint from frontend settings API."""
        urls = self._candidate_config_urls()
        if not urls:
            return

        for base_url in urls:
            url = f"{base_url}/master-endpoint"
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    if resp.status != 200:
                        continue
                    payload = json.loads(resp.read().decode("utf-8"))
                    master_ip = str(payload.get("master_ip", "")).strip()
                    master_port = int(payload.get("master_port", self.master_port))
                    if master_ip and 1 <= master_port <= 65535:
                        self.master_ip = master_ip
                        self.master_port = master_port
                        logger.info(f"Loaded master endpoint from frontend: {self.master_ip}:{self.master_port}")
                        return
            except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as e:
                logger.warning(f"Could not fetch master endpoint from frontend ({url}): {e}")
    
    def connect(self) -> bool:
        """Connect to master node"""
        try:
            self._refresh_endpoint_from_frontend()
            if not str(self.master_ip).strip():
                raise ValueError("MASTER_IP is empty and no frontend endpoint resolved")

            logger.info(f"Connecting to master endpoint {self.master_ip}:{self.master_port}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.master_ip, self.master_port))
            self.connected = True
            
            # Send registration message
            self._send_message({
                'type': 'register',
                'client_id': self.client_id,
                'timestamp': datetime.now().isoformat()
            })
            
            logger.info(f"Connected to master at {self.master_ip}:{self.master_port}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to connect to master: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Disconnect from master"""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
            self.connected = False
    
    def _send_message(self, message: dict):
        """Send JSON message to master"""
        try:
            data = json.dumps(message).encode('utf-8')
            # Send length prefix
            self.socket.sendall(len(data).to_bytes(4, 'big'))
            # Send data
            self.socket.sendall(data)
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.connected = False
            raise
    
    def receive_message(self, timeout: float = 5.0) -> Optional[dict]:
        """Receive JSON message from master"""
        try:
            self.socket.settimeout(timeout)
            # Receive length prefix
            length_data = self.socket.recv(4)
            if not length_data:
                return None
            
            length = int.from_bytes(length_data, 'big')
            
            # Receive data
            data = b''
            while len(data) < length:
                chunk = self.socket.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk
            
            return json.loads(data.decode('utf-8'))
        
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Failed to receive message: {e}")
            self.connected = False
            return None
    
    def send_scan_results(self, task_id: str, results: List[FileAnalysisResult]):
        """Send scan results to master"""
        serialized = [asdict(r) for r in results]
        message = {
            'type': 'scan_results',
            'task_id': task_id,
            'client_id': self.client_id,
            'timestamp': datetime.now().isoformat(),
            'files': serialized,
            # Backward-compatibility for older consumers
            'results': serialized
        }
        self._send_message(message)
        logger.info(f"Sent {len(results)} scan results to master for task {task_id}")
    
    def send_heartbeat(self):
        """Send heartbeat to master"""
        message = {
            'type': 'heartbeat',
            'client_id': self.client_id,
            'timestamp': datetime.now().isoformat()
        }
        self._send_message(message)

    def send_deletion_report(self, task_id: str, reports: list):
        """Send deletion outcome report to master."""
        message = {
            'type': 'deletion_report',
            'task_id': task_id,
            'client_id': self.client_id,
            'timestamp': datetime.now().isoformat(),
            'reports': reports,
        }
        self._send_message(message)
        logger.info(f"Sent deletion report with {len(reports)} entries for task {task_id}")
