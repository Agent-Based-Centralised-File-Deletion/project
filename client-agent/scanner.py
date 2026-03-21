import os
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

    def scan_clear_all_entries(self,
                               date_filter: Optional[Dict] = None,
                               exclude_paths: Optional[List[str]] = None):
        """Collect top-level files and directories for clear-all mode."""
        files = []
        directories = []
        exclude_paths = [os.path.abspath(path) for path in (exclude_paths or []) if path]

        for directory in self.directories:
            if not os.path.exists(directory):
                logger.warning(f"Directory does not exist: {directory}")
                continue

            logger.info(f"Scanning clear-all directory: {directory}")

            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        path = entry.path
                        if self._is_under_excluded_path(path, exclude_paths):
                            continue

                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if self._should_skip_directory(entry.name):
                                    continue
                                if not self._matches_date_filter(path, date_filter):
                                    continue
                                directories.append(path)
                            elif entry.is_file(follow_symlinks=False):
                                if self._should_skip_file(entry.name):
                                    continue
                                if not os.access(path, os.R_OK):
                                    continue
                                if not self._matches_date_filter(path, date_filter):
                                    continue
                                files.append(path)
                        except OSError:
                            continue
            except Exception as e:
                logger.error(f"Error scanning {directory}: {e}")

        logger.info(f"Found {len(files)} files and {len(directories)} directories for clear-all mode")
        return {
            "files": files,
            "directories": directories,
        }

    def _matches_date_filter(self, path: str, date_filter: Optional[Dict]) -> bool:
        if not date_filter:
            return True
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(path))
            if 'start' in date_filter and mtime < date_filter['start']:
                return False
            if 'end' in date_filter and mtime > date_filter['end']:
                return False
            return True
        except Exception:
            return False

    def _is_under_excluded_path(self, path: str, exclude_paths: List[str]) -> bool:
        candidate = os.path.abspath(path)
        for excluded in exclude_paths:
            try:
                if os.path.commonpath([candidate, excluded]) == excluded:
                    return True
            except ValueError:
                continue
        return False

    def _should_skip_directory(self, dirname: str) -> bool:
        return dirname.strip().lower() in {
            "$recycle.bin",
            "system volume information",
            "recovery",
            "__macosx",
        }

    def _should_skip_file(self, filename: str) -> bool:
        name = filename.strip().lower()
        _, ext = os.path.splitext(name)
        if ext in {".lnk", ".url", ".pif"}:
            return True
        return name in {
            "desktop.ini",
            "thumbs.db",
            "ehthumbs.db",
        }
