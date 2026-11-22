"""Read-only wheel analysis, with RECORD verification and bounded ZIP processing."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile
from typing import Any

from .analyze import inspect_content, kind_for
from .models import ScanOptions, new_artifact

DATA_SEGMENT = re.compile(r"^[^/]+\.data/(purelib|platlib)/(.+)$")


def _valid_member(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name or ":" in name.split("/", 1)[0]:
        return False
    parts = name.split("/")
    return not any(part in {"", ".", ".."} for part in parts) or name.endswith("/") and all(
        part not in {"", ".", ".."} for part in parts[:-1])


def _classify_member(name: str) -> tuple[str | None, str | None]:
    """Return target installation library and relative installed path."""
    matched = DATA_SEGMENT.fullmatch(name)
    if matched:
        return matched.group(1), matched.group(2)
    # Root-of-wheel files are installed into Root-Is-Purelib's library.
    if "/" not in name or not name.split("/", 1)[0].endswith((".dist-info", ".data")):
        return "wheel_root", name
    return None, None


def _record_lines(wheel: zipfile.ZipFile, names: set[str], issues: list[dict]) -> dict[str, tuple[str, str]]:
    record_paths = [n for n in names if n.endswith(".dist-info/RECORD")]
    if len(record_paths) != 1:
        issues.append({"code": "record_missing_or_ambiguous", "path": "RECORD",
                       "detail": f"expected one RECORD file, found {len(record_paths)}"})
        return {}
    try:
        if wheel.getinfo(record_paths[0]).file_size > 10 * 1024 * 1024:
            raise ValueError("RECORD too large")
        content = wheel.read(record_paths[0])
        parsed: dict[str, tuple[str, str]] = {}
        for line in csv.reader(io.StringIO(content.decode("utf-8-sig"))):
            if len(line) != 3 or not line[0]:
                issues.append({"code": "record_malformed_row", "path": record_paths[0],
                               "detail": "RECORD row must have path, hash, and size"})
                continue
            if line[0] in parsed:
                issues.append({"code": "record_duplicate_row", "path": line[0],
                               "detail": "Duplicate RECORD entry is ambiguous"})
                continue
            parsed[line[0]] = (line[1], line[2])
        return parsed
    except (UnicodeError, ValueError, RuntimeError, OSError, zipfile.BadZipFile) as exc:
        issues.append({"code": "record_invalid", "path": record_paths[0], "detail": str(exc)})
        return {}


def _record_status(path: str, content: bytes, record: dict[str, tuple[str, str]]) -> str:
    if path not in record:
        return "not_listed"
    declared, length = record[path]
    if length:
        try:
            if int(length) != len(content):
                return "record_size_mismatch"
        except ValueError:
            return "record_invalid_size"
    if not declared:
        return "unhashed"
    try:
        algorithm, payload = declared.split("=", 1)
        if algorithm not in {"sha256", "sha384", "sha512"}:
            return "unsupported_algorithm"
        expected = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        actual = hashlib.new(algorithm, content).digest()
        return "matches_record" if actual == expected else "record_mismatch"
    except (ValueError, TypeError, base64.binascii.Error):
        return "record_invalid_hash"


def scan_wheel(path: Path, options: ScanOptions, known: dict) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".whl":
        raise ValueError("wheel input must be an existing non-symlink .whl file")
    path = path.absolute()
    issues: list[dict[str, str]] = []
    artifacts: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    wheel_hash = digest.hexdigest()
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > options.max_wheel_members:
                raise ValueError("wheel exceeds member count limit")
            total_bytes = sum(info.file_size for info in infos)
            if total_bytes > options.max_wheel_total_bytes:
                raise ValueError("wheel exceeds expanded size limit")
            valid: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                name = info.filename
                if not _valid_member(name):
                    issues.append({"code": "unsafe_wheel_member", "path": name,
                                   "detail": "absolute, traversal or invalid archive path"})
                    continue
                if name in valid:
                    issues.append({"code": "duplicate_wheel_member", "path": name,
                                   "detail": "duplicate archive member"})
                    continue
                # Some wheel formats can contain symlink entries: never follow or treat them as regular data.
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    issues.append({"code": "wheel_symlink", "path": name,
                                   "detail": "symlink member omitted"})
                    continue
                valid[name] = info
            names = set(valid)
            record = _record_lines(archive, names, issues)
            targets: list[tuple[str, str, str]] = []
            mapped: dict[str, list[str]] = {"purelib": [], "platlib": [], "wheel_root": []}
            wheel_metadata = [n for n in names if n.endswith(".dist-info/WHEEL")]
            root_library = "purelib"
            if len(wheel_metadata) != 1:
                issues.append({"code": "wheel_metadata_missing_or_ambiguous", "path": "WHEEL",
                               "detail": f"expected one WHEEL metadata file, found {len(wheel_metadata)}"})
            if len(wheel_metadata) == 1:
                try:
                    if valid[wheel_metadata[0]].file_size > 65_536:
                        raise ValueError("WHEEL metadata exceeds size limit")
                    metadata = archive.read(wheel_metadata[0]).decode("utf-8")
                    for entry in metadata.splitlines():
                        key, _, val = entry.partition(":")
                        if key.strip().casefold() == "root-is-purelib":
                            root_library = "purelib" if val.strip().casefold() == "true" else "platlib"
                except (UnicodeError, ValueError, RuntimeError, OSError, zipfile.BadZipFile):
                    issues.append({"code": "wheel_metadata_unreadable", "path": wheel_metadata[0],
                                   "detail": "Could not determine Root-Is-Purelib"})
            for name in sorted(names):
                library, installed_path = _classify_member(name)
                if library and installed_path:
                    mapped[library].append(name)
                    if "/" not in installed_path and kind_for(installed_path):
                        targets.append((name, library, installed_path))
            # Per-site set of a same-stem .start is needed to model the 3.15 transition.
            companion = {(root_library if lib == "wheel_root" else lib, installed)
                         for _, lib, installed in targets if installed.endswith(".start")}
            for name, library, installed in targets:
                kind = kind_for(installed)
                if not kind:
                    continue
                artifact = new_artifact(name, kind, location="wheel_library_candidate",
                                        environment=None, version=None)
                artifact["installed_path"] = installed
                artifact["wheel_location"] = library
                artifact["installed_library"] = root_library if library == "wheel_root" else library
                artifact["deployment_state"] = "not_installed"
                info = valid[name]
                if info.file_size > options.max_file_bytes:
                    artifact["errors"].append("file exceeds configured byte limit")
                    artifacts.append(artifact)
                    continue
                if info.compress_size and info.file_size > info.compress_size * 200:
                    artifact["errors"].append("suspicious compression ratio; entry omitted")
                    artifacts.append(artifact)
                    continue
                try:
                    content = archive.read(info)
                except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                    artifact["errors"].append(f"cannot read zip entry: {exc}")
                    artifacts.append(artifact)
                    continue
                artifact["record_integrity"] = _record_status(name, content, record)
                if artifact["record_integrity"] != "matches_record":
                    issues.append({"code": "wheel_record_issue", "path": name,
                                   "detail": artifact["record_integrity"]})
                def resolve_module(module: str) -> dict:
                    module_rel = module.replace(".", "/")
                    possibilities = (module_rel + ".py", module_rel + "/__init__.py")
                    candidate_paths = []
                    active_library = root_library if library == "wheel_root" else library
                    for mapped_library, all_paths in mapped.items():
                        current_library = root_library if mapped_library == "wheel_root" else mapped_library
                        if current_library != active_library:
                            continue
                        for candidate in all_paths:
                            _, check = _classify_member(candidate)
                            if check in possibilities:
                                candidate_paths.append(candidate)
                    candidate_paths = sorted(set(candidate_paths))
                    ancestors = []
                    parts = module.split(".")
                    if 1 < len(parts) <= 32:
                        expected = {"/".join(parts[:n]) + "/__init__.py" for n in range(1, len(parts))}
                        for mapped_library, all_paths in mapped.items():
                            current_library = root_library if mapped_library == "wheel_root" else mapped_library
                            if current_library != active_library:
                                continue
                            for member in all_paths:
                                _, relative_member = _classify_member(member)
                                if relative_member in expected:
                                    ancestors.append(member)
                    return {"status": "not_found_in_wheel" if not candidate_paths else
                            "resolved_in_snapshot" if len(candidate_paths) == 1 else
                            "multiple_candidates_order_unknown", "candidates": candidate_paths,
                            "initializer_candidates": sorted(set(ancestors))}

                def read_module(member: str) -> bytes | None:
                    entry = valid.get(member)
                    if entry is None or entry.file_size > options.max_file_bytes:
                        return None
                    try:
                        return archive.read(entry)
                    except (RuntimeError, OSError, zipfile.BadZipFile):
                        return None

                artifact = inspect_content(artifact, content, options, known,
                                           companion_start=(kind == "pth" and
                                                            (root_library if library == "wheel_root" else library,
                                                             installed[:-4] + ".start") in companion),
                                           module_resolver=resolve_module, module_reader=read_module)
                artifacts.append(artifact)
    except zipfile.BadZipFile as exc:
        raise ValueError("invalid wheel ZIP archive") from exc
    return {
        "scan_type": "wheel",
        "target": path.as_posix(),
        "sha256": wheel_hash,
        "complete": not issues and all(not a["errors"] for a in artifacts),
        "stats": {"artifacts": len(artifacts), "members": len(infos), "expanded_size_bytes": total_bytes},
        "issues": issues,
        "environments": [{"wheel_root_library": root_library, "installed": False}],
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
    }
