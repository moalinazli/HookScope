"""Snapshot traversal and bounded, symlink-resistant artifact inspection."""

from __future__ import annotations

from collections import defaultdict
import os
from pathlib import Path
import stat
from typing import Any

from .analyze import inspect_content, kind_for
from .models import CUSTOMIZE_NAMES, SITE_DIR_NAMES, ScanOptions, new_artifact

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "__pycache__"})


def _safe_read(root: Path, relative: str, max_bytes: int) -> bytes:
    """On POSIX, use directory-relative O_NOFOLLOW at every path component."""
    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts) or Path(relative).is_absolute():
        raise OSError("invalid relative path")
    if os.name == "posix" and hasattr(os, "O_NOFOLLOW"):
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=directory)
                os.close(directory)
                directory = next_fd
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise OSError("not a regular file")
                if info.st_size > max_bytes:
                    raise OSError("file exceeds byte limit")
                chunks = []
                remaining = max_bytes + 1
                while remaining:
                    chunk = os.read(fd, min(65_536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
                if len(content) > max_bytes:
                    raise OSError("file exceeds byte limit while reading")
                return content
            finally:
                os.close(fd)
        finally:
            os.close(directory)
    # Portable fallback: reject existing symlinks, including ancestors.
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise OSError("symlink component denied")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise OSError("not a regular file")
    if current.stat().st_size > max_bytes:
        raise OSError("file exceeds byte limit")
    with current.open("rb") as stream:
        result = stream.read(max_bytes + 1)
        if len(result) > max_bytes:
            raise OSError("file exceeds byte limit")
        return result


def _is_regular_no_symlink(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _environment(root: Path, site_relative: str) -> tuple[str | None, bool | None]:
    parts = Path(site_relative).parts
    if len(parts) >= 3 and parts[-2].startswith("python") and parts[-3] in {"lib", "lib64"}:
        prefix = Path(*parts[:-3]) if len(parts) > 3 else Path(".")
    elif len(parts) >= 2 and parts[-2].casefold() == "lib":
        prefix = Path(*parts[:-2]) if len(parts) > 2 else Path(".")
    else:
        return None, None
    cfg_rel = (prefix / "pyvenv.cfg").as_posix()
    try:
        data = _safe_read(root, cfg_rel, 65_536).decode("utf-8-sig")
    except (OSError, UnicodeError):
        return None, None
    system_sites = None
    for line in data.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().casefold() == "include-system-site-packages":
            system_sites = value.strip().casefold() == "true"
    return prefix.as_posix(), system_sites


def _local_module_candidates(root: Path, site_dir: str, module: str,
                             extra_dirs: list[str]) -> list[str]:
    parts = module.split(".")
    if not parts or len(parts) > 32 or any(not p.isidentifier() for p in parts):
        return []
    relative_module = "/".join(parts)
    candidates = []
    for base in [site_dir, *extra_dirs]:
        for suffix in (".py", "/__init__.py"):
            path = os.path.normpath(os.path.join(base, relative_module + suffix))
            if os.path.commonpath([root.as_posix(), os.path.join(root, path)]) != root.as_posix():
                continue
            if _is_regular_no_symlink(root / path):
                candidates.append(path.replace(os.sep, "/"))
    return sorted(set(candidates))


def _path_extensions(root: Path, site_dir: str, data: bytes) -> list[str]:
    """Collect existing directory entries from .pth, without resolving symlinks."""
    try:
        lines = data.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        return []
    result = []
    for line in lines:
        if not line.strip() or line.startswith("#") or line.startswith(("import ", "import\t")):
            continue
        item = line.strip()
        if "\x00" in item:
            continue
        if item.startswith("/"):
            candidate = os.path.normpath(os.path.join(root.as_posix(), item.lstrip("/")))
        else:
            candidate = os.path.normpath(os.path.join(root.as_posix(), site_dir, item))
        try:
            relative = os.path.relpath(candidate, root.as_posix())
            if relative == ".." or relative.startswith(".." + os.sep):
                continue
            target = root / relative
            if target.is_dir() and not target.is_symlink():
                result.append(relative.replace(os.sep, "/"))
        except (OSError, ValueError):
            continue
    return sorted(set(result))


def scan_snapshot(root: Path, options: ScanOptions, known: dict) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("snapshot root must be an existing, non-symlink directory")
    root = Path(os.path.abspath(root))
    discovered: list[tuple[str, str | None, str]] = []
    sites: set[str] = set()
    issues: list[dict[str, str]] = []
    files_seen = 0
    complete = True

    def onwalk_error(error: OSError) -> None:
        nonlocal complete
        complete = False
        issues.append({"code": "walk_error", "path": str(error.filename or ""),
                       "detail": error.strerror or "unreadable directory"})

    for base, dirs, files in os.walk(root, followlinks=False, onerror=onwalk_error):
        safe_dirs = []
        for directory in sorted(dirs):
            if directory in SKIP_DIRS:
                continue
            candidate = Path(base) / directory
            if candidate.is_symlink():
                try:
                    resolved = candidate.resolve(strict=True)
                    internal_alias = (resolved == root or root in resolved.parents) and resolved.is_dir()
                except (OSError, RuntimeError):
                    internal_alias = False
                # An internal alias to an ordinary directory is covered when its
                # physical target is traversed. An alias itself named site-packages
                # can change startup semantics and must not be silently ignored.
                missing_coverage = not internal_alias or directory in SITE_DIR_NAMES
                if missing_coverage:
                    complete = False
                if len(issues) < 128:
                    issues.append({"code": "symlink_directory_skipped" if missing_coverage else "internal_symlink_alias",
                                   "path": candidate.relative_to(root).as_posix(),
                                   "detail": "Startup directory may be hidden behind this alias" if missing_coverage
                                             else "Internal directory alias skipped; physical target is scanned"})
                continue
            safe_dirs.append(directory)
        dirs[:] = safe_dirs
        files_seen += len(files)
        if files_seen > options.max_visited_files:
            complete = False
            issues.append({"code": "file_count_limit", "path": ".",
                           "detail": f"limit of {options.max_visited_files} visited files exceeded"})
            break
        rel_base = Path(base).relative_to(root).as_posix()
        is_site = Path(base).name in SITE_DIR_NAMES
        if is_site:
            sites.add(rel_base)
        for name in sorted(files):
            kind = kind_for(name)
            if not kind:
                continue
            if kind != "customize" and not is_site:
                continue
            relative = (Path(rel_base) / name).as_posix()
            discovered.append((relative, rel_base if is_site else None, kind))

    # Whole-directory knowledge is required for matching .start to a .pth.
    companion = {path for path, _, kind in discovered if kind == "start"}
    site_extensions: dict[str, list[str]] = defaultdict(list)
    for path, site, kind in discovered:
        if kind != "pth" or not site:
            continue
        try:
            data = _safe_read(root, path, options.max_file_bytes)
            site_extensions[site].extend(_path_extensions(root, site, data))
        except OSError:
            continue
    output = []
    environments = []
    for site in sorted(sites):
        prefix, include_system = _environment(root, site)
        environments.append({"site_directory": site, "venv_prefix": prefix,
                             "include_system_site_packages": include_system,
                             "startup_artifact_count": sum(1 for _, s, _ in discovered if s == site)})
    for relative, site, kind in discovered:
        environment, include_system = _environment(root, site) if site else (None, None)
        record = new_artifact(relative, kind, location="site_directory" if site else "outside_site_directory",
                              environment=environment, version=None)
        record["include_system_site_packages"] = include_system
        try:
            metadata = (root / relative).lstat()
            record["filesystem"] = {
                "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                "uid": getattr(metadata, "st_uid", None),
                "gid": getattr(metadata, "st_gid", None),
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
        except OSError:
            pass
        if kind == "customize" and not site:
            record["resolution_note"] = "Module outside recognized site directory; relevant sys.path unknown"
        try:
            data = _safe_read(root, relative, options.max_file_bytes)
            extra = sorted(set(site_extensions.get(site, []))) if site else []

            def resolve_module(name: str) -> dict:
                if not site:
                    return {"status": "import_path_unknown", "candidates": []}
                candidates = _local_module_candidates(root, site, name, extra)
                status = ("not_found_in_snapshot" if not candidates else
                          "resolved_in_snapshot" if len(candidates) == 1 else "multiple_candidates_order_unknown")
                ancestors = []
                parts = name.split(".")
                if 1 < len(parts) <= 32:
                    for i in range(1, len(parts)):
                        prefix = ".".join(parts[:i])
                        ancestors.extend(_local_module_candidates(root, site, prefix, extra))
                ancestors = [path for path in sorted(set(ancestors)) if path.endswith("/__init__.py")]
                return {"status": status, "candidates": candidates,
                        "initializer_candidates": ancestors}

            def read_module(path: str) -> bytes | None:
                try:
                    return _safe_read(root, path, options.max_file_bytes)
                except OSError:
                    return None

            record = inspect_content(
                record, data, options, known,
                companion_start=(kind == "pth" and relative[:-4] + ".start" in companion),
                module_resolver=resolve_module, module_reader=read_module)
            if record["errors"]:
                complete = False
        except OSError as error:
            complete = False
            record["errors"].append(f"artifact_not_read: {str(error)}")
        output.append(record)

    return {
        "scan_type": "snapshot",
        "target": root.as_posix(),
        "complete": complete,
        "stats": {"visited_files": files_seen, "site_directories": len(sites),
                  "artifacts": len(output)},
        "issues": issues,
        "environments": environments,
        "artifacts": sorted(output, key=lambda item: item["path"]),
    }
