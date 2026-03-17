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
    scan_paths=None,
    custom_languages=None
):
    """
    Converts admin intent into a structured scan task.
    """

    if not target_languages:
        raise ValueError("At least one target language must be specified")

    custom_languages = custom_languages or {}
    custom_language_keys = {str(k).lower().strip() for k in custom_languages.keys() if str(k).strip()}
    invalid = set(target_languages) - (SUPPORTED_LANGUAGES | custom_language_keys)
    if invalid:
        raise ValueError(f"Unsupported languages: {invalid}")

    task = {
        "type": "scan_task",
        "task_id": persistence.next_daily_task_id(),
        "target_languages": list(target_languages),
        "date_filter": date_filter,
        "scan_paths": list(scan_paths or []),
        "custom_languages": custom_languages,
        "created_at": datetime.utcnow().isoformat()
    }

    return task
