"""Shared scan settings and stable report definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3}
SITE_DIR_NAMES = frozenset(("site-packages", "dist-packages"))
CUSTOMIZE_NAMES = frozenset(("sitecustomize.py", "usercustomize.py"))


@dataclass(frozen=True)
class ScanOptions:
    max_file_bytes: int = 1_048_576
    max_visited_files: int = 500_000
    max_wheel_members: int = 100_000
    max_wheel_total_bytes: int = 256 * 1024 * 1024
    max_import_targets: int = 64
    include_source_lines: bool = False
    python_version: tuple[int, int] | None = None


def severity_for(indicators: list[dict[str, Any]]) -> str:
    return max((i["severity"] for i in indicators), key=lambda v: SEVERITY[v], default="info")


def new_artifact(path: str, kind: str, *, location: str, environment: str | None,
                 version: str | None) -> dict[str, Any]:
    return {
        "path": path,
        "kind": kind,
        "location": location,
        "environment": environment,
        "python_version": version,
        "startup_status": "unknown",
        "sha256": None,
        "size_bytes": None,
        "filesystem": None,
        "severity": "info",
        "indicators": [],
        "imports": [],
        "entry_points": [],
        "path_extensions": [],
        "record_integrity": None,
        "errors": [],
    }


def indicator(code: str, severity: str, detail: str, *, line: int | None = None,
              source: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"code": code, "severity": severity, "detail": detail}
    if line is not None:
        item["line"] = line
    if source is not None:
        item["source"] = source
    return item


def parse_version(value: str) -> tuple[int, int]:
    try:
        parts = value.split(".")
        if len(parts) != 2 or not all(p.isascii() and p.isdigit() for p in parts):
            raise ValueError
        major, minor = map(int, parts)
        if major != 3 or minor > 99:
            raise ValueError
        return major, minor
    except ValueError as exc:
        raise ValueError("Python version must be 3.MINOR, such as 3.13 or 3.15") from exc
