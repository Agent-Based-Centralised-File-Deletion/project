import threading
import time
import os
import hashlib
import threading
from datetime import datetime
from pathlib import Path

from config import CONFIG, logger
from detector import PatternBasedDetector, FileAnalysisResult
from scanner import FileScanner
from quarantine import QuarantineManager
from network.tcp_client import MasterCommunicator


class ClientAgent:
    """Main client agent orchestrator"""
    
    def __init__(self):
        self.config = CONFIG
        self.detector = PatternBasedDetector()
        self.quarantine = QuarantineManager(self.config['QUARANTINE_DIR'])
        self.communicator = MasterCommunicator(
            self.config['MASTER_IP'],
            self.config['MASTER_PORT'],
            self.config['CLIENT_ID']
        )
        self.running = False
        self.current_task = None
    
    def start(self):
        """Start the agent"""
        self.running = True
        
        # Connect to master
        while self.running and not self.communicator.connect():
            time.sleep(self.config['RECONNECT_DELAY'])
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        
        # Main loop - listen for tasks
        self._main_loop()
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self.running and self.communicator.connected:
            try:
                self.communicator.send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
            time.sleep(self.config['HEARTBEAT_INTERVAL'])
    
    def _main_loop(self):
        """Main event loop"""
        while self.running:
            try:
                # Receive task from master
                message = self.communicator.receive_message(timeout=5.0)
                
                if message:
                    self._handle_message(message)
                
                # Reconnect if disconnected
                if not self.communicator.connected:
                    logger.warning("Disconnected from master, reconnecting...")
                    time.sleep(self.config['RECONNECT_DELAY'])
                    self.communicator.connect()
            
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                self.running = False
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                time.sleep(1)
    
    def _handle_message(self, message: dict):
        """Handle message from master"""
        msg_type = message.get('type')
        
        if msg_type == 'scan_task':
            self._execute_scan_task(message)
        elif msg_type == 'delete_approved':
            self._execute_deletion(message)
        elif msg_type == 'restore_file':
            self._restore_file(message)
        else:
            logger.warning(f"Unknown message type: {msg_type}")
    
    def _execute_scan_task(self, task: dict):
        """Execute file scanning task"""
        logger.info(f"Received scan task: {task.get('task_id')}")
        self.current_task = task
        
        # Extract task parameters
        target_languages = task.get('target_languages', ['python', 'matlab', 'perl'])
        target_language_set = {str(lang).strip().lower() for lang in target_languages if str(lang).strip()}
        clear_all = bool(task.get('clear_all'))
        custom_languages = task.get('custom_languages', {})
        date_filter = self._parse_date_filter(task.get('date_filter'))
        scan_paths = [str(p).strip() for p in task.get('scan_paths', []) if str(p).strip()]
        if not scan_paths:
            legacy_scan_path = str(task.get('scan_path', '')).strip()
            if legacy_scan_path:
                scan_paths = [legacy_scan_path]

        if not scan_paths:
            scan_paths = list(self.config.get('SCAN_DIRECTORIES', []))

        if not scan_paths:
            return

        scanner = FileScanner(scan_paths)
        excluded_paths = [
            self.config.get('QUARANTINE_DIR', ''),
            self.config.get('LOG_DIR', ''),
        ]

        if clear_all:
            self._execute_clear_all_task(task, scanner, date_filter, excluded_paths)
            return

        # Apply custom language definitions for this task.
        self.detector.configure_custom_languages(custom_languages)
        
        # Scan files
        files = scanner.scan(date_filter=date_filter)
        
        # Analyze files
        results = []
        for filepath in files:
            result = self.detector.analyze_file(filepath)

            # Quarantine only files that match requested targets. Keep a small
            # compatibility bridge for C/C++ overlap and extension-led ambiguity.
            extension_lang = self._extension_language(filepath)
            is_target_language = self._matches_target_language(
                detected_language=result.language,
                extension_language=extension_lang,
                target_languages=target_language_set,
            )
            ambiguous_threshold = 0.70
            if extension_lang in target_language_set:
                ambiguous_threshold = 0.45
            should_quarantine = (
                (result.decision == 'delete' and is_target_language) or
                (result.decision == 'ambiguous' and is_target_language and result.confidence >= ambiguous_threshold)
            )

            if should_quarantine:
                success, quarantine_path = self.quarantine.quarantine_file(filepath)
                if success:
                    result.filepath = quarantine_path  # Update to quarantine path
                    results.append(result)
                else:
                    logger.error(f"Failed to quarantine: {filepath}")
        
        # Send results to master
        if results:
            task_id = str(task.get('task_id') or 'unknown-task')
            self.communicator.send_scan_results(task_id, results)
        else:
            logger.info("No files found matching criteria")

    def _execute_clear_all_task(self, task: dict, scanner: FileScanner, date_filter, excluded_paths):
        """Quarantine non-system top-level files and directories for a clear-all task."""
        candidates = scanner.scan_clear_all_entries(
            date_filter=date_filter,
            exclude_paths=excluded_paths,
        )
        results = []

        for dirpath in candidates.get('directories', []):
            success, quarantine_path = self.quarantine.quarantine_directory(dirpath)
            if success:
                results.append(self._build_clear_all_result(
                    original_path=dirpath,
                    quarantine_path=quarantine_path,
                    item_type='directory',
                ))
            else:
                logger.error(f"Failed to quarantine directory: {dirpath}")

        for filepath in candidates.get('files', []):
            success, quarantine_path = self.quarantine.quarantine_file(filepath)
            if success:
                results.append(self._build_clear_all_result(
                    original_path=filepath,
                    quarantine_path=quarantine_path,
                    item_type='file',
                ))
            else:
                logger.error(f"Failed to quarantine file: {filepath}")

        if results:
            task_id = str(task.get('task_id') or 'unknown-task')
            self.communicator.send_scan_results(task_id, results)
        else:
            logger.info("No clear-all candidates found")

    def _extension_language(self, filepath: str):
        ext = Path(filepath).suffix.lower()
        if not ext:
            return None
        for lang, exts in self.detector.EXTENSIONS.items():
            if ext in exts:
                return lang
        return None

    def _matches_target_language(self, detected_language: str, extension_language: str, target_languages: set):
        detected = str(detected_language or '').lower()
        ext_lang = str(extension_language or '').lower()

        if detected in target_languages:
            return True
        if ext_lang in target_languages:
            return True

        # C and C++ syntax often overlaps heavily in pattern scoring.
        if detected == 'c' and 'cpp' in target_languages and ext_lang == 'cpp':
            return True
        if detected == 'cpp' and 'c' in target_languages and ext_lang == 'c':
            return True

        return False

    def _parse_date_filter(self, raw_date_filter):
        """Convert incoming date filter payload to datetime objects for scanner."""
        if not isinstance(raw_date_filter, dict):
            return None

        parsed = {}
        for key in ("start", "end"):
            value = raw_date_filter.get(key)
            if not value:
                continue
            if isinstance(value, datetime):
                parsed[key] = value
                continue
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    continue
                try:
                    parsed[key] = datetime.fromisoformat(text.replace("Z", "+00:00"))
                except ValueError:
                    logger.warning("Invalid %s in date_filter: %s", key, value)
        return parsed or None

    def _build_clear_all_result(self, original_path: str, quarantine_path: str, item_type: str):
        original = Path(original_path)
        try:
            stat_result = os.stat(quarantine_path)
            size = int(stat_result.st_size)
            modified_time = datetime.fromtimestamp(stat_result.st_mtime).isoformat()
        except OSError:
            size = 0
            modified_time = datetime.now().isoformat()

        return FileAnalysisResult(
            filepath=quarantine_path,
            filename=original.name,
            size=size,
            modified_time=modified_time,
            decision='delete',
            confidence=1.0,
            language=f'clear-all-{item_type}',
            method='clear-all',
            reason='Quarantined by clear-all folders/files task',
            file_hash=self._clear_all_hash(original_path, item_type),
        )

    def _clear_all_hash(self, path: str, item_type: str) -> str:
        return hashlib.sha256(f"{item_type}:{os.path.abspath(path)}".encode('utf-8')).hexdigest()
    
    def _execute_deletion(self, message: dict):
        """Execute approved file deletions"""
        task_id = str(message.get('task_id') or 'unknown-task')
        approved_entries = message.get('approved_entries')
        approved_hashes = message.get('approved_hashes', [])

        if not approved_entries:
            approved_entries = [{'file_hash': h} for h in approved_hashes]

        logger.info(f"Deleting {len(approved_entries)} approved files for task {task_id}")

        reports = []

        for entry in approved_entries:
            file_hash = (entry or {}).get('file_hash', '')
            hint_path = (entry or {}).get('path', '')
            deleted = False
            deleted_path = ''
            details = ''

            # Prefer the explicit quarantine path from the approval payload.
            # Clear-all tasks rely on this for both files and directories.
            if hint_path and os.path.exists(hint_path):
                deleted = self.quarantine.delete_quarantined(hint_path)
                deleted_path = hint_path
                details = 'deleted by path' if deleted else 'path found but delete failed'

            # Fallback: try hash-based lookup for legacy file-only entries.
            if not deleted and file_hash:
                for root, _, files in os.walk(self.config['QUARANTINE_DIR']):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        if self.detector._calculate_hash(filepath) == file_hash:
                            deleted = self.quarantine.delete_quarantined(filepath)
                            deleted_path = filepath
                            details = 'deleted by hash' if deleted else 'hash found but delete failed'
                            break
                    if deleted or details:
                        break

            if not deleted and not details:
                details = 'file not found in quarantine'

            reports.append({
                'file_hash': file_hash,
                'path': deleted_path or hint_path,
                'status': 'deleted' if deleted else 'failed',
                'details': details,
            })

        deleted_count = sum(1 for r in reports if r['status'] == 'deleted')
        logger.info(f"Deleted {deleted_count}/{len(reports)} files for task {task_id}")

        try:
            self.communicator.send_deletion_report(task_id, reports)
        except Exception as e:
            logger.error(f"Failed to send deletion report: {e}")
    
    def _restore_file(self, message: dict):
        """Restore file from quarantine"""
        file_hash = message.get('file_hash')
        original_path = message.get('original_path')
        
        # Find and restore file
        # Implementation similar to deletion
        logger.info(f"Restoring file: {original_path}")
    
    def stop(self):
        """Stop the agent"""
        self.running = False
        self.communicator.disconnect()


if __name__ == '__main__':
    agent = ClientAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
        logger.info("Agent stopped")
