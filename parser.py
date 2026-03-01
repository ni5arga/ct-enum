from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _split_names(value: str) -> list[str]:
    return [v.strip() for v in value.replace("\n", " ").split() if v.strip()]


def _normalize(name: str) -> str:
    name = name.lower().strip()
    while name.startswith("*."):
        name = name[2:]
    return name


def extract_names_crtsh(entries: list[dict]) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        for field in ("name_value", "common_name"):
            raw = entry.get(field)
            if isinstance(raw, str):
                for part in _split_names(raw):
                    normalized = _normalize(part)
                    if normalized:
                        names.add(normalized)
    logger.debug("parser: extracted %d unique names from crt.sh entries", len(names))
    return names


def extract_names_censys(entries: list[dict]) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        for name in entry.get("parsed.names", []):
            if isinstance(name, str):
                names.add(_normalize(name))
    logger.debug("parser: extracted %d unique names from Censys entries", len(names))
    return names


def filter_subdomains(names: set[str], domain: str) -> list[str]:
    suffix = f".{domain}"
    valid: list[str] = []
    for name in names:
        if name == domain:
            continue
        if name.endswith(suffix) and _is_valid_hostname(name):
            valid.append(name)
    logger.debug("parser: %d valid subdomains after filtering", len(valid))
    return sorted(valid)


def _is_valid_hostname(hostname: str) -> bool:
    if len(hostname) > 253:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    return all(c in allowed for c in hostname) and not hostname.startswith("-")