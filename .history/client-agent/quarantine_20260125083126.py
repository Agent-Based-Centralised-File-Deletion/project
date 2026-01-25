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
            # Create quarantine subdirectory structure matching original
            rel_path = os.path.relpath(filepath, '/')
            quarantine_path = os.path.join(self.quarantine_dir, rel_path)
            
            # Create parent directories
            os.makedirs(os.path.dirname(quarantine_path), exist_ok=True)
            
            # Move file
            shutil.move(filepath, quarantine_path)
            logger.info(f"Quarantined: {filepath} -> {quarantine_path}")
            
            return True, quarantine_path
        
        except Exception as e:
            logger.error(f"Failed to quarantine {filepath}: {e}")
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
            os.remove(quarantine_path)
            logger.info(f"Deleted: {quarantine_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {quarantine_path}: {e}")
            return False