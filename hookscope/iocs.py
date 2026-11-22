"""Source-attributed SHA-256 intelligence loading."""

from __future__ import annotations

import csv
from pathlib import Path
import re
from typing import Any

SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


def load_hashes(paths: list[Path]) -> dict[str, list[dict[str, str]]]:
    known: dict[str, list[dict[str, str]]] = {}
    for path in paths:
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError(f"IOC CSV exceeds 8 MiB: {path}")
        with path.open("r", newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or not {"Type", "Value"}.issubset(reader.fieldnames):
                raise ValueError(f"invalid IOC CSV columns: {path}")
            for number, row in enumerate(reader, start=2):
                if number > 50_001:
                    raise ValueError(f"IOC CSV exceeds 50,000 rows: {path}")
                if (row.get("Type") or "").strip().casefold() != "sha256":
                    continue
                digest = (row.get("Value") or "").strip().lower()
                if not SHA256_RE.fullmatch(digest):
                    raise ValueError(f"invalid SHA-256 at {path}:{number}")
                match = {
                    "campaign": (row.get("Campaign") or "").strip(),
                    "role": (row.get("Role") or "").strip(),
                    "source_url": (row.get("SourceURL") or "").strip(),
                }
                if match not in known.setdefault(digest, []):
                    known[digest].append(match)
    return known


def match_iocs(digest: str, known: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    return list(known.get(digest, []))
