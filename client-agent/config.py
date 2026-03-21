import os
import socket
import logging


def _int_env(*keys, default):
    for key in keys:
        value = os.getenv(key)
        if value is not None and str(value).strip():
            return int(value)
    return int(default)


def _str_env(*keys, default):
    for key in keys:
        value = os.getenv(key)
        if value is not None and str(value).strip():
            cleaned = str(value).strip()
            # Handle values copied with wrapping quotes, e.g. "C:\CodeSweep\logs"
            if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
                cleaned = cleaned[1:-1].strip()
            return cleaned
    return str(default)


def _scan_dirs():
    raw = _str_env("SCAN_DIRS", default="")
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts


def _detect_local_ip_for_master(master_ip: str, master_port: int) -> str:
    """
    Detect the outbound local IPv4 used to reach the master.
    This avoids manual CLIENT_ID setup on every lab PC.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((master_ip, int(master_port)))
            ip = sock.getsockname()[0]
            if ip and ip != "127.0.0.1":
                return ip
    except Exception:
        pass
    return ""


# Configuration
_DEFAULT_QUARANTINE_DIR = r"C:\CodeSweep\quarantine" if os.name == "nt" else "/quarantine"
_DEFAULT_LOG_DIR = r"C:\CodeSweep\logs" if os.name == "nt" else "/logs"
_MASTER_IP = _str_env('MASTER_IP', 'BACKEND_HOST', default='127.0.0.1')
_MASTER_PORT = _int_env('MASTER_PORT', 'BACKEND_PORT', default=5000)
_AUTO_CLIENT_ID = _detect_local_ip_for_master(_MASTER_IP, _MASTER_PORT) or socket.gethostname()

CONFIG = {
    # Support both legacy and docker-compose variable names.
    'MASTER_IP': _MASTER_IP,
    'MASTER_PORT': _MASTER_PORT,
    'CLIENT_ID': _str_env('CLIENT_ID', default=_AUTO_CLIENT_ID),
    # No implicit default scan path; only explicit SCAN_DIRS values are used.
    'SCAN_DIRECTORIES': _scan_dirs(),
    'QUARANTINE_DIR': _str_env('QUARANTINE_DIR', default=_DEFAULT_QUARANTINE_DIR),
    'LOG_DIR': _str_env('LOG_DIR', default=_DEFAULT_LOG_DIR),
    # Keep heartbeat short so queued commands are picked up quickly in split
    # frontend/backend deployments.
    'HEARTBEAT_INTERVAL': _int_env('HEARTBEAT_INTERVAL', default=5),
    'RECONNECT_DELAY': _int_env('RECONNECT_DELAY', default=10),
}

# Setup logging
os.makedirs(CONFIG['LOG_DIR'], exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{CONFIG['LOG_DIR']}/agent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ClientAgent')
