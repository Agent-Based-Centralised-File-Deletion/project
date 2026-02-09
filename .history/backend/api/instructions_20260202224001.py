import uuid
from datetime import datetime


SUPPORTED_LANGUAGES = {"python", "matlab", "c", "cpp", "java"}


def create_scan_instruction(
    target_languages,
    date_filter=None
):
    """
    Converts admin intent into a structured scan task.
    """

    if not target_languages:
        raise ValueError("At least one target language must be specified")

    invalid = set(target_languages) - SUPPORTED_LANGUAGES
    if invalid:
        raise ValueError(f"Unsupported languages: {invalid}")

    task = {
        "type": "scan_task",
        "task_id": f"scan-{uuid.uuid4().hex[:8]}",
        "target_languages": list(target_languages),
        "date_filter": date_filter,
        "created_at": datetime.utcnow().isoformat()
    }

    return task
