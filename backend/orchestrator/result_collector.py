from collections import defaultdict

try:
    # Works when imported as part of the backend package (e.g., from frontend/app.py).
    from backend.api.verification import VerificationQueue
except ModuleNotFoundError:
    # Fallback for legacy execution contexts inside backend/ package root.
    from api.verification import VerificationQueue


class ResultCollector:
    """
    Collects scan results from agents and prepares them
    for human verification.
    """

    def __init__(self):
        self._results = defaultdict(dict)
        self._verification_queue = VerificationQueue()

    def add_scan_result(self, agent_ip, task_id, files):
        """
        Store scan results from an agent.

        files = [
            {
                "path": "...",
                "type": "python",
                "size": 1234,
                "modified": "2026-02-01T10:20:00"
            }
        ]
        """

        self._results[task_id][agent_ip] = files

        # Forward to verification layer
        self._verification_queue.add_result(
            agent_ip=agent_ip,
            task_id=task_id,
            files=files
        )

    def get_task_results(self, task_id):
        """
        Return all agent results for a task.
        """
        return self._results.get(task_id, {})

    def get_pending_verification(self):
        """
        Return tasks waiting for admin approval.
        """
        return self._verification_queue.list_pending()

    def get_approved_results(self, task_id):
        """
        Return approved file lists for deletion.
        """
        return self._verification_queue.get_approved(task_id)

    def clear_task(self, task_id):
        """
        Remove task after deletion is completed.
        """
        self._results.pop(task_id, None)
        self._verification_queue.clear_task(task_id)


result_collector = ResultCollector()
