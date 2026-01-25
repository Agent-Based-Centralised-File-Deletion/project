

class ClientAgent:
    """Main client agent orchestrator"""
    
    def __init__(self):
        self.config = CONFIG
        self.detector = PatternBasedDetector()
        self.scanner = FileScanner(self.config['SCAN_DIRECTORIES'])
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
        logger.info(f"Client Agent {self.config['CLIENT_ID']} starting...")
        
        # Connect to master
        while self.running and not self.communicator.connect():
            logger.info(f"Retrying connection in {self.config['RECONNECT_DELAY']}s...")
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
        date_filter = task.get('date_filter')
        
        # Scan files
        files = self.scanner.scan(date_filter=date_filter)
        
        # Analyze files
        results = []
        for filepath in files:
            result = self.detector.analyze_file(filepath)
            
            # Filter by target language
            if result.language in target_languages or result.decision == 'ambiguous':
                # Quarantine files marked for deletion or ambiguous
                if result.decision in ['delete', 'ambiguous']:
                    success, quarantine_path = self.quarantine.quarantine_file(filepath)
                    if success:
                        result.filepath = quarantine_path  # Update to quarantine path
                        results.append(result)
                    else:
                        logger.error(f"Failed to quarantine: {filepath}")
        
        # Send results to master
        if results:
            self.communicator.send_scan_results(results)
        else:
            logger.info("No files found matching criteria")
    
    def _execute_deletion(self, message: dict):
        """Execute approved file deletions"""
        approved_hashes = message.get('approved_hashes', [])
        logger.info(f"Deleting {len(approved_hashes)} approved files")
        
        deleted_count = 0
        for file_hash in approved_hashes:
            # Find file in quarantine by hash
            # (In production, maintain a hash->path mapping)
            # For now, we'll search quarantine directory
            for root, _, files in os.walk(self.config['QUARANTINE_DIR']):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if self.detector._calculate_hash(filepath) == file_hash:
                        if self.quarantine.delete_quarantined(filepath):
                            deleted_count += 1
                        break
        
        logger.info(f"Deleted {deleted_count} files")
    
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