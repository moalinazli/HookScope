"""Compare two offline HookScope JSON inventories without executing target code."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any

MAX_REPORT_SIZE = 32 * 1024 * 1024
MAX_ARTIFACTS = 100_000


def load_report(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_REPORT_SIZE:
        raise ValueError("report exceeds 32 MiB size limit")
    with path.open("rb") as handle:
        contents = handle.read(MAX_REPORT_SIZE + 1)
    if len(contents) > MAX_REPORT_SIZE:
        raise ValueError("report grew beyond 32 MiB limit")
    try:
        result = json.loads(contents)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid HookScope JSON report") from error
    if not isinstance(result, dict) or result.get("scan_type") not in ("snapshot", "wheel"):
        raise ValueError("expected a HookScope snapshot or wheel report")
    if not isinstance(result.get("artifacts"), list) or not isinstance(result.get("target"), str):
        raise ValueError("missing report target/artifacts")
    if len(result["artifacts"]) > MAX_ARTIFACTS:
        raise ValueError("too many artifacts in report")
    for artifact in result["artifacts"]:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            raise ValueError("invalid artifact in report")
        if not isinstance(artifact.get("severity"), str):
            raise ValueError("missing artifact severity")
    return result


def _indexed(artifacts: list[dict]) -> dict[str, dict]:
    indexed = {}
    for item in artifacts:
        path = item["path"]
        if not path or path in indexed:
            raise ValueError("duplicate or empty artifact path in report")
        indexed[path] = item
    return indexed


def compare(old: dict, new: dict, *, allow_different_root: bool = False) -> dict:
    if old["scan_type"] != new["scan_type"]:
        raise ValueError("cannot compare different scan types")
    if old["target"] != new["target"] and not allow_different_root:
        raise ValueError("scan roots differ; use --allow-different-root if intentional")
    before, after = _indexed(old["artifacts"]), _indexed(new["artifacts"])
    added, removed, modified, unchanged = [], [], [], 0
    for name in sorted(before.keys() | after.keys()):
        left, right = before.get(name), after.get(name)
        if left is None:
            added.append({"path": name, "sha256": right.get("sha256"), "severity": right["severity"]})
        elif right is None:
            removed.append({"path": name, "sha256": left.get("sha256"), "severity": left["severity"]})
        else:
            keys = ("sha256", "kind", "startup_status", "severity")
            changes = {key: {"old": left.get(key), "new": right.get(key)}
                       for key in keys if left.get(key) != right.get(key)}
            # An unchanged .pth can import a modified module. Detect changes in the
            # resolved module graph and indicators without dumping sensitive code.
            for key in ("resolved_imports", "ioc_matches", "record_integrity", "errors", "entry_points"):
                prev, curr = left.get(key), right.get(key)
                if prev != curr:
                    def fingerprint(value: object) -> str:
                        raw = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")
                        return hashlib.sha256(raw).hexdigest()[:16]
                    changes[key + "_digest"] = {"old": fingerprint(prev), "new": fingerprint(curr)}
            if changes:
                modified.append({"path": name, "changes": changes})
            else:
                unchanged += 1
    return {
        "format": "hookscope-diff-1",
        "old_target": old["target"], "new_target": new["target"],
        "old_complete": old.get("complete"), "new_complete": new.get("complete"),
        "added": added, "removed": removed, "modified": modified, "unchanged": unchanged,
        "changed": bool(added or removed or modified),
    }


def format_text(result: dict) -> str:
    lines = ["HookScope inventory comparison", "=" * 29,
             f"Old: {result['old_target']}", f"New: {result['new_target']}",
             f"Added: {len(result['added'])} | Removed: {len(result['removed'])} | "
             f"Modified: {len(result['modified'])} | Unchanged: {result['unchanged']}"]
    if not result["old_complete"] or not result["new_complete"]:
        lines.append("WARNING: one inventory has incomplete coverage; differences may be misleading")
    for category, symbol in (("added", "+"), ("removed", "-"), ("modified", "~")):
        for item in result[category]:
            # JSON-quoted path avoids terminal control injection from attacker-chosen filenames.
            lines.append(f" {symbol} {json.dumps(item['path'], ensure_ascii=True)}")
            if category == "modified":
                for key, change in sorted(item["changes"].items()):
                    lines.append(f"    {key}: {change['old']!r} -> {change['new']!r}")
    return "\n".join(lines) + "\n"
