class VerificationQueue:
    """
    Holds scan results until admin approval.
    """

    def __init__(self):
        self._pending = {}

    def add_result(self, agent_ip, task_id, files):
        """
        Store scan results for verification.
        """
        if task_id not in self._pending:
            self._pending[task_id] = {}

        self._pending[task_id][agent_ip] = {
            "files": files,
            "approved": False
        }

    def list_pending(self):
        """
        Return all pending tasks for UI display.
        """
        return self._pending

    def approve_agent(self, task_id, agent_ip):
        """
        Approve deletion for one agent.
        """
        if task_id in self._pending and agent_ip in self._pending[task_id]:
            self._pending[task_id][agent_ip]["approved"] = True

    def approve_task(self, task_id):
        """
        Approve deletion for all agents in a task.
        """
        if task_id in self._pending:
            for agent in self._pending[task_id]:
                self._pending[task_id][agent]["approved"] = True

    def get_approved(self, task_id):
        """
        Get approved file lists for final deletion.
        """
        approved = {}

        if task_id in self._pending:
            for agent_ip, info in self._pending[task_id].items():
                if info["approved"]:
                    approved[agent_ip] = info["files"]

        return approved

    def clear_task(self, task_id):
        """
        Remove task after deletion.
        """
        self._pending.pop(task_id, None)
