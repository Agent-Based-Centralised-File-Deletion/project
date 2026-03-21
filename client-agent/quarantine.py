import os
import os
import shutil
from typing import Tuple
from config import logger


class QuarantineManager:
    """Manages file quarantine"""
    
    def __init__(self, quarantine_dir: str):
        self.quarantine_dir = quarantine_dir
        os.makedirs(quarantine_dir, exist_ok=True)
    
    def quarantine_file(self, filepath: str) -> Tuple[bool, str]:
        """
        Move file to quarantine
        
        Returns:
            (success: bool, quarantine_path: str)
        """
        try:
            quarantine_path = self._quarantine_path(filepath)
            
           
            os.makedirs(os.path.dirname(quarantine_path), exist_ok=True)
            
           
            shutil.move(filepath, quarantine_path)
            logger.info(f"Quarantined: {filepath} -> {quarantine_path}")
            
            return True, quarantine_path
        
        except Exception as e:
            logger.error(f"Failed to quarantine {filepath}: {e}")
            return False, ''

    def quarantine_directory(self, dirpath: str) -> Tuple[bool, str]:
        """Move a directory to quarantine."""
        try:
            quarantine_path = self._quarantine_path(dirpath)
            os.makedirs(os.path.dirname(quarantine_path), exist_ok=True)
            shutil.move(dirpath, quarantine_path)
            logger.info(f"Quarantined directory: {dirpath} -> {quarantine_path}")
            return True, quarantine_path
        except Exception as e:
            logger.error(f"Failed to quarantine directory {dirpath}: {e}")
            return False, ''
    
    def restore_file(self, quarantine_path: str, original_path: str) -> bool:
        """Restore file from quarantine"""
        try:
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(quarantine_path, original_path)
            logger.info(f"Restored: {quarantine_path} -> {original_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore {quarantine_path}: {e}")
            return False
    
    def delete_quarantined(self, quarantine_path: str) -> bool:
        """Permanently delete quarantined file"""
        try:
            if os.path.isdir(quarantine_path):
                shutil.rmtree(quarantine_path)
            else:
                os.remove(quarantine_path)
            logger.info(f"Deleted: {quarantine_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {quarantine_path}: {e}")
            return False

    def _quarantine_path(self, path: str) -> str:
        # Build a relative path that works on both Linux and Windows.
        # Windows drive letters are preserved as a top-level directory.
        abs_path = os.path.abspath(path)
        drive, tail = os.path.splitdrive(abs_path)
        tail = tail.lstrip("/\\")
        if drive:
            drive_prefix = drive.replace(":", "")
            rel_path = os.path.join(drive_prefix, tail) if tail else drive_prefix
        else:
            rel_path = tail
        return os.path.join(self.quarantine_dir, rel_path)
