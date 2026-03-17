from __future__ import annotations

import ast
import pprint
import textwrap
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DETECTOR_PATH = PROJECT_ROOT / "client-agent" / "detector.py"
DETECTOR_CLASS = "PatternBasedDetector"
LANGUAGE_MAP_NAMES = ("PATTERNS", "KEYWORDS", "EXTENSIONS", "SIGNATURE_PATTERNS")

SPECIAL_LABELS = {
    "css": "CSS",
    "html": "HTML",
    "javascript": "JavaScript",
    "matlab": "MATLAB",
}


def _read_detector_source() -> str:
    return DETECTOR_PATH.read_text(encoding="utf-8")


def _load_detector_maps():
    source = _read_detector_source()
    module = ast.parse(source)
    class_node = next(
        (node for node in module.body if isinstance(node, ast.ClassDef) and node.name == DETECTOR_CLASS),
        None,
    )
    if class_node is None:
        raise RuntimeError(f"Could not find {DETECTOR_CLASS} in {DETECTOR_PATH}")

    maps = {}
    spans = {}
    for node in class_node.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in LANGUAGE_MAP_NAMES:
            continue

        maps[target.id] = ast.literal_eval(node.value)
        spans[target.id] = (node.lineno, node.end_lineno)

    missing = [name for name in LANGUAGE_MAP_NAMES if name not in maps]
    if missing:
        raise RuntimeError(f"Missing detector maps: {', '.join(missing)}")

    return source, maps, spans


def _language_label(language: str) -> str:
    return SPECIAL_LABELS.get(language, language.replace("_", " ").title())


def _normalize_language_key(language: str) -> str:
    key = str(language or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not key:
        raise ValueError("Language name is required")
    if not all(ch.isalnum() or ch == "_" for ch in key):
        raise ValueError("Language name may only contain letters, numbers, spaces, hyphens, or underscores")
    return key


def _normalize_string_list(values) -> list[str]:
    cleaned = []
    for value in values or []:
        item = str(value or "").strip()
        if item:
            cleaned.append(item)
    return cleaned


def _normalize_extensions(values) -> list[str]:
    normalized = []
    for ext in _normalize_string_list(values):
        if not ext.startswith("."):
            ext = f".{ext}"
        normalized.append(ext.lower())
    return list(dict.fromkeys(normalized))


def _normalize_patterns(values) -> list[tuple[str, str]]:
    normalized = []
    for value in values or []:
        pattern = str((value or {}).get("pattern", "")).strip()
        description = str((value or {}).get("description", "")).strip() or "custom pattern"
        if pattern:
            normalized.append((pattern, description))
    return normalized


def get_detector_language_order() -> list[str]:
    _, maps, _ = _load_detector_maps()
    return list(maps["PATTERNS"].keys())


def get_supported_languages() -> set[str]:
    return set(get_detector_language_order())


def get_language_options() -> list[dict[str, str]]:
    return [
        {"value": language, "label": _language_label(language)}
        for language in get_detector_language_order()
    ]


def build_instruction_hint_mapping() -> dict[str, list[str]]:
    _, maps, _ = _load_detector_maps()
    mapping = {}

    for language in maps["PATTERNS"].keys():
        hints = [language]
        spaced = language.replace("_", " ")
        if spaced != language:
            hints.append(spaced)
        hints.extend(ext.lower() for ext in maps["EXTENSIONS"].get(language, []))
        mapping[language] = list(dict.fromkeys(hints))

    return mapping


def _format_assignment(name: str, value) -> str:
    assignment = f"{name} = {pprint.pformat(value, sort_dicts=False, width=100)}"
    return textwrap.indent(assignment, " " * 4) + "\n"


def add_detector_language(
    language: str,
    *,
    keywords=None,
    extensions=None,
    patterns=None,
    signature_patterns=None,
) -> dict[str, str]:
    key = _normalize_language_key(language)
    normalized_keywords = list(dict.fromkeys(_normalize_string_list(keywords)))
    normalized_extensions = _normalize_extensions(extensions)
    normalized_patterns = _normalize_patterns(patterns)
    normalized_signatures = list(dict.fromkeys(_normalize_string_list(signature_patterns)))

    if not (normalized_patterns or normalized_keywords or normalized_signatures):
        raise ValueError("Add at least one keyword, regex pattern, or signature pattern")

    source, maps, spans = _load_detector_maps()
    if key in maps["PATTERNS"]:
        raise ValueError(f"Language '{key}' already exists")

    maps["PATTERNS"][key] = normalized_patterns
    maps["KEYWORDS"][key] = normalized_keywords
    maps["EXTENSIONS"][key] = normalized_extensions
    maps["SIGNATURE_PATTERNS"][key] = normalized_signatures

    lines = source.splitlines(keepends=True)
    for name, (start, end) in sorted(spans.items(), key=lambda item: item[1][0], reverse=True):
        lines[start - 1:end] = [_format_assignment(name, maps[name])]

    DETECTOR_PATH.write_text("".join(lines), encoding="utf-8")
    return {"value": key, "label": _language_label(key)}
