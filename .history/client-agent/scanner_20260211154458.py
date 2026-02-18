import os
from datetime import datetime
from typing import List, Dict, Optional
from config import logger


class FileScanner:
    """Scans directories for files"""
    
    def __init__(self, directories: List[str]):
        self.directories = directories
    
    def scan(self, file_extensions: Optional[List[str]] = None,
             date_filter: Optional[Dict] = None) -> List[str]:
        """
        Scan directories for files
        
        Args:
            file_extensions: List of extensions to filter (None = all files)
            date_filter: Dict with 'start' and 'end' datetime objects
        
        Returns:
            List of file paths
        """
        files = []
        
        for directory in self.directories:
            if not os.path.exists(directory):
                logger.warning(f"Directory does not exist: {directory}")
                continue
            
            logger.info(f"Scanning directory: {directory}")
            
            try:
                for root, _, filenames in os.walk(directory):
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        
                        
                        if not os.access(filepath, os.R_OK):
                            continue
                        
                        
                        if file_extensions:
                            if not any(filename.endswith(ext) for ext in file_extensions):
                                continue
                        
                        # Filter by date if specified
                        if date_filter:
                            try:
                                mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                                if 'start' in date_filter and mtime < date_filter['start']:
                                    continue
                                if 'end' in date_filter and mtime > date_filter['end']:
                                    continue
                            except Exception:
                                continue
                        
                        files.append(filepath)
            
            except Exception as e:
                logger.error(f"Error scanning {directory}: {e}")
        
        logger.info(f"Found {len(files)} files to analyze")
        return files