from __future__ import annotations
import re

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain: {domain!r}")
    return domain


def exponential_backoff(attempt: int, base: float = 2.0, cap: float = 60.0) -> float:
    return min(cap, base ** attempt)


def aligned_table(subdomains: list[str]) -> str:
    if not subdomains:
        return "  (none found)"
    lines = [f"  {s}" for s in subdomains]
    return "\n".join(lines)
