import uuid
from datetime import datetime

from shared.languages import get_supported_languages


def create_scan_instruction(
    target_languages,
    date_filter=None
):
    """
    Converts admin intent into a structured scan task.
    """

    if not target_languages:
        raise ValueError("At least one target language must be specified")

    supported_languages = get_supported_languages()
    invalid = set(target_languages) - supported_languages
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
