from datetime import datetime

from shared import persistence


SUPPORTED_LANGUAGES = {
    "java",
    "c",
    "cpp",
    "python",
    "php",
    "javascript",
    "html",
    "css",
    "mysql",
    "nosql",
    "perl",
    "prolog",
    "matlab",
    "assembly",
}


def create_scan_instruction(
    target_languages,
    date_filter=None,
    scan_paths=None
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
        "task_id": persistence.next_daily_task_id(),
        "target_languages": list(target_languages),
        "date_filter": date_filter,
        "scan_paths": list(scan_paths or []),
        "created_at": datetime.utcnow().isoformat()
    }

    return task
