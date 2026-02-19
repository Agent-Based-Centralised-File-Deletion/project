import socket
import json
from datetime import datetime
from typing import Optional,List
from dataclasses import asdict

from config import logger
from detector import FileAnalysisResult


class MasterCommunicator:
    """Handles communication with master node"""
    
    def __init__(self, master_ip: str, master_port: int, client_id: str):
        self.master_ip = master_ip
        self.master_port = master_port
        self.client_id = client_id
        self.socket = None
        self.connected = False
    
    def connect(self) -> bool:
        """Connect to master node"""
        try:
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
