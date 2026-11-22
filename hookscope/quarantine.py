"""Explicit, reversible remediation for inspected startup artifacts.

Operations use directory-relative file descriptors and reject symlink components on
POSIX. Moves are atomic on one filesystem. There is deliberately no auto-cleanup.
"""
from __future__ import annotations

from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import Any

from .models import SEVERITY
from .snapshot import scan_snapshot
from .models import ScanOptions

ID_RE = re.compile(r"^[0-9a-f]{24}$")
ALLOWED_NAMES = frozenset({"sitecustomize.py", "usercustomize.py"})


def default_vault() -> Path:
    return Path.home() / ".local" / "share" / "hookscope" / "quarantine"


def _validate_relative(value: str) -> tuple[str, ...]:
    if not value or os.path.isabs(value) or "\\" in value or "\x00" in value:
        raise ValueError("expected a relative artifact path inside the scan root")
    parts = value.split("/")
    if any(not part or part in (".", "..") for part in parts):
        raise ValueError("unsafe relative artifact path")
    name = parts[-1]
    if name not in ALLOWED_NAMES and not name.endswith((".pth", ".start")):
        raise ValueError("path is not a Python startup artifact")
    return tuple(parts)


def _validate_dir(path: Path, *, create: bool = False) -> Path:
    """Disallow symlink ancestry even when the final directory is not a link."""
    absolute = Path(os.path.abspath(path))
    if absolute == Path("/"):
        raise ValueError("refusing an unbounded filesystem root")
    current = Path(absolute.anchor)
    for item in absolute.parts[1:]:
        current = current / item
        if current.is_symlink():
            raise ValueError("symlink in directory path is not permitted")
        if not current.exists():
            if not create:
                raise ValueError(f"directory does not exist: {current}")
            current.mkdir(mode=0o700)
        if not current.is_dir():
            raise ValueError(f"not a directory: {current}")
    return absolute


def _secure_vault(root: Path, vault: Path, *, create: bool) -> Path:
    location = _validate_dir(vault, create=create)
    if location == root or root in location.parents or location in root.parents:
        raise ValueError("quarantine vault must be separate from the scanned tree")
    if os.name == "posix":
        mode = location.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            # A previously existing vault with broader permissions is unsafe.
            # An explicit, newly created private directory is always 0700.
            raise ValueError("quarantine vault permissions must be 0700")
    return location


def _open_directory_chain(root: Path, parts: tuple[str, ...]) -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("quarantine requires POSIX O_NOFOLLOW support")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for item in parts:
            next_fd = os.open(item, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_fd(fd: int, *, limit: int = 32 * 1024 * 1024) -> tuple[str, os.stat_result]:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("artifact is not a regular file")
    if info.st_size > limit:
        raise ValueError("artifact exceeds the quarantine file-size limit")
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    seen = 0
    while True:
        data = os.read(fd, 65_536)
        if not data:
            break
        seen += len(data)
        if seen > limit:
            raise ValueError("artifact exceeded the quarantine byte limit during read")
        digest.update(data)
    return digest.hexdigest(), info


def _write_manifest(directory: Path, data: dict[str, Any]) -> None:
    # A quarantine receipt never embeds executable content.
    raw = (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    fd = os.open(directory / "receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def _load_receipt(vault: Path, entry_id: str) -> tuple[Path, dict]:
    if not ID_RE.fullmatch(entry_id):
        raise ValueError("invalid quarantine ID")
    location = vault / entry_id
    _validate_dir(location)
    path = location / "receipt.json"
    if path.is_symlink():
        raise ValueError("quarantine receipt must not be a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 64 * 1024 + 1)
    finally:
        os.close(fd)
    if len(raw) > 64 * 1024:
        raise ValueError("receipt exceeds size limit")
    info = json.loads(raw)
    if info.get("id") != entry_id or info.get("schema") != 1:
        raise ValueError("receipt mismatch")
    _validate_relative(info.get("relative_path", ""))
    return location, info


def find_candidate(root: Path, relative_path: str, *, min_severity: str = "low") -> dict:
    _validate_relative(relative_path)
    if min_severity not in SEVERITY:
        raise ValueError("invalid minimum severity")
    result = scan_snapshot(root, ScanOptions(), {})
    record = next((a for a in result["artifacts"] if a["path"] == relative_path), None)
    if record is None or not record.get("sha256"):
        raise ValueError("file was not recognized and read by the startup-artifact scanner")
    if SEVERITY[record["severity"]] < SEVERITY[min_severity]:
        raise ValueError("artifact is below requested review threshold")
    if record.get("errors"):
        raise ValueError("artifact analysis is incomplete; review before remediation")
    return record


def quarantine_artifact(root: Path, relative_path: str, expected_hash: str, vault: Path,
                        *, reason: str = "analyst_confirmed") -> dict:
    """Move an explicitly selected artifact after re-verifying its SHA-256."""
    parts = _validate_relative(relative_path)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("a verified SHA-256 is required")
    root = _validate_dir(root)
    vault = _secure_vault(root, vault, create=True)
    parent_fd = _open_directory_chain(root, parts[:-1])
    entry_id = secrets.token_hex(12)
    item_dir = vault / entry_id
    try:
        item_dir.mkdir(mode=0o700)
        dst_fd = _open_directory_chain(item_dir, ())
        try:
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=parent_fd)
            try:
                digest, original = _read_fd(file_fd)
                if digest != expected_hash:
                    raise ValueError("file changed since scan; refusing quarantine")
                current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
                    original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns
                ):
                    raise ValueError("file identity changed during verification")
                if original.st_nlink != 1:
                    raise ValueError("file has multiple hard links; cannot safely isolate by rename")
                original_mode = stat.S_IMODE(original.st_mode)
                # Rename is atomic and fails safely for different devices (EXDEV).
                os.rename(parts[-1], "artifact.data", src_dir_fd=parent_fd, dst_dir_fd=dst_fd)
                try:
                    moved_fd = os.open("artifact.data", os.O_RDONLY | os.O_NOFOLLOW,
                                       dir_fd=dst_fd)
                    try:
                        moved_digest, moved = _read_fd(moved_fd)
                    finally:
                        os.close(moved_fd)
                    if (moved_digest != digest or moved.st_ino != original.st_ino
                            or moved.st_dev != original.st_dev):
                        raise ValueError("moved artifact verification failed")
                    receipt = {
                        "schema": 1, "id": entry_id,
                        "created_utc": datetime.now(timezone.utc).isoformat(),
                        "root": str(root), "relative_path": relative_path,
                        "sha256": digest, "original_mode": original_mode,
                        "reason": reason, "status": "quarantined",
                    }
                    _write_manifest(item_dir, receipt)
                except BaseException:
                    if not os.path.exists(root / relative_path):
                        os.rename("artifact.data", parts[-1], src_dir_fd=dst_fd, dst_dir_fd=parent_fd)
                    raise
            finally:
                os.close(file_fd)
        finally:
            os.close(dst_fd)
    except BaseException:
        try:
            if item_dir.exists() and not any(item_dir.iterdir()):
                item_dir.rmdir()
        except OSError:
            pass
        raise
    finally:
        os.close(parent_fd)
    return receipt


def restore_artifact(vault: Path, entry_id: str) -> dict:
    vault = _validate_dir(vault)
    item_dir, receipt = _load_receipt(vault, entry_id)
    if receipt["status"] != "quarantined":
        raise ValueError("entry is not in quarantine")
    root = _validate_dir(Path(receipt["root"]))
    if root == vault or root in vault.parents or vault in root.parents:
        raise ValueError("unsafe restored target/vault overlap")
    parts = _validate_relative(receipt["relative_path"])
    parent_fd = _open_directory_chain(root, parts[:-1])
    try:
        if os.path.lexists(root / receipt["relative_path"]):
            raise ValueError("original target is occupied; refusing overwrite")
        src_fd = _open_directory_chain(item_dir, ())
        try:
            fd = os.open("artifact.data", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=src_fd)
            try:
                digest, original = _read_fd(fd)
            finally:
                os.close(fd)
            if digest != receipt["sha256"]:
                raise ValueError("quarantined data hash mismatch")
            # File at destination is never overwritten: hard-link then unlink on same filesystem.
            os.link("artifact.data", parts[-1], src_dir_fd=src_fd, dst_dir_fd=parent_fd,
                    follow_symlinks=False)
            os.unlink("artifact.data", dir_fd=src_fd)
        finally:
            os.close(src_fd)
    finally:
        os.close(parent_fd)
    receipt["status"] = "restored"
    receipt["restored_utc"] = datetime.now(timezone.utc).isoformat()
    # Receipt remains as a historical record. Write an updated copy atomically.
    fd, tmp = tempfile.mkstemp(prefix=".receipt-", dir=item_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(receipt, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, item_dir / "receipt.json")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return receipt


def list_quarantine(vault: Path) -> list[dict]:
    if not vault.exists():
        return []
    vault = _validate_dir(vault)
    output = []
    for path in sorted(vault.iterdir()):
        if not ID_RE.fullmatch(path.name) or path.is_symlink():
            continue
        try:
            _, receipt = _load_receipt(vault, path.name)
            output.append(receipt)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
    return output


def purge_artifact(vault: Path, entry_id: str) -> dict:
    vault = _validate_dir(vault)
    item_dir, receipt = _load_receipt(vault, entry_id)
    if receipt["status"] != "quarantined":
        raise ValueError("cannot purge an entry already restored")
    src_fd = _open_directory_chain(item_dir, ())
    try:
        fd = os.open("artifact.data", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=src_fd)
        try:
            digest, _ = _read_fd(fd)
        finally:
            os.close(fd)
        if digest != receipt["sha256"]:
            raise ValueError("quarantined data hash mismatch; refusing purge")
        os.unlink("artifact.data", dir_fd=src_fd)
    finally:
        os.close(src_fd)
    receipt["status"] = "purged"
    receipt["purged_utc"] = datetime.now(timezone.utc).isoformat()
    fd, tmp = tempfile.mkstemp(prefix=".receipt-", dir=item_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(receipt, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, item_dir / "receipt.json")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return receipt


def verify_quarantine(vault: Path) -> dict:
    """Read-only check of receipt/file integrity, with explicit failure records."""
    if not vault.exists():
        return {"vault": str(vault), "entries": [], "checked": 0, "problems": 0, "ok": True}
    vault = _validate_dir(vault)
    entries = []
    for item_dir in sorted(vault.iterdir()):
        if not ID_RE.fullmatch(item_dir.name):
            continue
        result: dict[str, Any] = {"id": item_dir.name, "status": "invalid", "ok": False}
        try:
            location, receipt = _load_receipt(vault, item_dir.name)
            result["status"] = receipt["status"]
            result["path"] = receipt["relative_path"]
            expected = receipt.get("sha256")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("invalid SHA-256 in receipt")
            if receipt["status"] == "quarantined":
                directory_fd = _open_directory_chain(location, ())
                try:
                    fd = os.open("artifact.data", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory_fd)
                    try:
                        digest, info = _read_fd(fd)
                    finally:
                        os.close(fd)
                finally:
                    os.close(directory_fd)
                if info.st_nlink != 1:
                    raise ValueError("quarantined file has unexpected hard links")
                if digest != expected:
                    raise ValueError("quarantined file SHA-256 differs from receipt")
            elif receipt["status"] in ("restored", "purged"):
                if os.path.lexists(location / "artifact.data"):
                    raise ValueError("closed entry unexpectedly retains artifact.data")
            else:
                raise ValueError("unrecognized receipt status")
            result["ok"] = True
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            result["error"] = str(error)
        entries.append(result)
    problems = sum(not item["ok"] for item in entries)
    return {"vault": str(vault), "entries": entries, "checked": len(entries),
            "problems": problems, "ok": problems == 0}
