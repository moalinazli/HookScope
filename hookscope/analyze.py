"""Static interpretation of Python startup configuration; never imports target code."""

from __future__ import annotations

import ast
import hashlib
import re
from typing import Any, Callable

from .iocs import match_iocs
from .models import CUSTOMIZE_NAMES, ScanOptions, indicator, severity_for

ENTRY_POINT_RE = re.compile(r"^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*):([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$")
VERSION_RE = re.compile(r"(?:^|/)python3\.(\d{1,2})t?(?:/|$)")
MAX_STARTUP_LINES = 8192


def version_from_path(path: str) -> tuple[int, int] | None:
    found = VERSION_RE.search(path.replace("\\", "/"))
    return (3, int(found.group(1))) if found else None


def kind_for(name: str) -> str | None:
    if name.endswith(".pth"):
        return "pth"
    if name.endswith(".start"):
        return "start"
    if name in CUSTOMIZE_NAMES:
        return "customize"
    return None


def parse_imports(statement: str) -> list[str]:
    """Get directly named import modules; dynamic import arguments are opaque."""
    try:
        tree = ast.parse(statement)
    except (SyntaxError, UnicodeError, ValueError, RecursionError):
        return []
    result: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            result.append(node.module)
    return sorted(set(result))


def _preview(line: str, options: ScanOptions) -> dict[str, str]:
    if not options.include_source_lines:
        return {}
    # An explicit option: the source line may contain credentials or payload text.
    return {"source": line[:240]}


def _ast_signals(data: bytes) -> list[str]:
    try:
        tree = ast.parse(data.decode("utf-8-sig"))
    except (UnicodeError, SyntaxError, ValueError, RecursionError):
        return ["unparseable_python"]
    signals: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name) and target.id in {"eval", "exec", "compile", "__import__"}:
                signals.add("dynamic_code_execution_candidate")
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                parent = target.value.id
                if parent in {"subprocess", "os"} and target.attr in {"run", "Popen", "call", "system", "popen"}:
                    signals.add("process_execution_candidate")
                if parent in {"socket", "requests", "urllib"}:
                    signals.add("network_api_candidate")
    return sorted(signals)


def inspect_content(record: dict[str, Any], data: bytes, options: ScanOptions,
                    known: dict[str, list[dict[str, str]]], *,
                    companion_start: bool = False,
                    module_resolver: Callable[[str], dict[str, Any]] | None = None,
                    module_reader: Callable[[str], bytes | None] | None = None) -> dict[str, Any]:
    """Interpret a candidate artifact without evaluating its Python content."""
    record["size_bytes"] = len(data)
    record["sha256"] = hashlib.sha256(data).hexdigest()
    record["ioc_matches"] = match_iocs(record["sha256"], known)
    if record["ioc_matches"]:
        record["indicators"].append(indicator(
            "known_sha256", "high", "SHA-256 matched a source-attributed IOC"))
    kind = record["kind"]
    try:
        # CPython 3.13+ tries UTF-8 then a locale fallback for .pth.
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        record["indicators"].append(indicator(
            "decoding_loss", "low", "Non-UTF-8 bytes; content interpretation may differ by Python version/locale"))
    version = options.python_version or version_from_path(record["path"])
    if version:
        record["python_version"] = ".".join(map(str, version))
    if kind == "pth":
        _parse_pth(record, text, options, version, companion_start)
    elif kind == "start":
        _parse_start(record, text, options, version)
    else:
        record["startup_status"] = "candidate_import_path_unverified"
        record["indicators"].append(indicator(
            "customize_module", "low", "Customize module found; import path precedence is not established"))
        for signal in _ast_signals(data):
            record["indicators"].append(indicator(signal, "medium" if signal != "unparseable_python" else "low",
                                                  "Static AST pattern found; execution is not established"))
    # Analyze the direct module associated with executable import/entry point.
    if module_resolver:
        targets = sorted(set(entry["module"] for entry in record["imports"] + record["entry_points"]))
        if len(targets) > options.max_import_targets:
            record["errors"].append("too many import targets; resolution truncated")
        for name in targets[:options.max_import_targets]:
            resolution = module_resolver(name)
            item: dict[str, Any] = {"module": name, **resolution}
            if module_reader and resolution.get("status") == "resolved_in_snapshot" and len(resolution.get("candidates", [])) == 1:
                candidate = resolution["candidates"][0]
                module_bytes = module_reader(candidate)
                if module_bytes is not None:
                    item["module_sha256"] = hashlib.sha256(module_bytes).hexdigest()
                    item["ioc_matches"] = match_iocs(item["module_sha256"], known)
                    if item["ioc_matches"]:
                        record["indicators"].append(indicator(
                            "known_imported_module_sha256", "high",
                            f"Imported module SHA-256 matched a source-attributed IOC: {name}"))
                    item["static_signals"] = _ast_signals(module_bytes)
                    for signal in item["static_signals"]:
                        if signal != "unparseable_python":
                            record["indicators"].append(indicator(
                                "imported_module_" + signal, "medium",
                                f"Static signal in directly imported module: {name}"))
                else:
                    item["module_inspection"] = "not_readable_or_size_limited"
            if module_reader:
                parents = []
                for parent in resolution.get("initializer_candidates", [])[:32]:
                    parent_data = module_reader(parent)
                    parent_record: dict[str, Any] = {"path": parent}
                    if parent_data is None:
                        parent_record["inspection"] = "not_readable_or_size_limited"
                    else:
                        parent_record["sha256"] = hashlib.sha256(parent_data).hexdigest()
                        parent_record["static_signals"] = _ast_signals(parent_data)
                        parent_record["ioc_matches"] = match_iocs(parent_record["sha256"], known)
                        if parent_record["ioc_matches"]:
                            record["indicators"].append(indicator(
                                "known_imported_initializer_sha256", "high",
                                f"Ancestor package initializer SHA-256 matched a source-attributed IOC: {parent}"))
                        for signal in parent_record["static_signals"]:
                            if signal != "unparseable_python":
                                record["indicators"].append(indicator(
                                    "imported_initializer_" + signal, "medium",
                                    f"Static signal in ancestor package initializer: {parent}"))
                    parents.append(parent_record)
                if parents:
                    item["parent_initializers"] = parents
            record.setdefault("resolved_imports", []).append(item)
    record["severity"] = severity_for(record["indicators"])
    return record


def _parse_pth(record: dict[str, Any], text: str, options: ScanOptions,
               version: tuple[int, int] | None, companion_start: bool) -> None:
    executable = []
    lines = text.splitlines()
    if len(lines) > MAX_STARTUP_LINES:
        record["errors"].append("startup line count limit exceeded; content truncated")
    for line_no, line in enumerate(lines[:MAX_STARTUP_LINES], 1):
        if line.startswith(("import ", "import\t")):
            names = parse_imports(line)
            item: dict[str, Any] = {"line": line_no, "modules": names,
                                     "line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest()}
            item.update(_preview(line, options))
            executable.append(item)
            for module in names:
                record["imports"].append({"module": module, "line": line_no})
            for signal in _ast_signals(line.encode("utf-8")):
                if signal != "unparseable_python":
                    record["indicators"].append(indicator("pth_line_" + signal, "medium",
                                                          "Executable line contains a static execution/network API pattern", line=line_no))
            record["indicators"].append(indicator(
                "pth_executable_line", "medium", "Executable import line in a processed .pth file", line=line_no))
        elif line.strip() and not line.startswith("#"):
            record["path_extensions"].append({"line": line_no, "path": line.strip()})
    record["executable_lines"] = executable
    if companion_start and version and version >= (3, 15):
        record["startup_status"] = "suppressed_by_matching_start"
        record["indicators"].append(indicator(
            "matching_start", "info", "A same-stem .start file suppresses .pth executable lines in Python 3.15+"))
    elif version and (3, 18) <= version <= (3, 19):
        record["startup_status"] = "executable_lines_deprecated_ignored"
    elif version and version >= (3, 20):
        record["startup_status"] = "executable_lines_warn_planned"
    elif executable:
        record["startup_status"] = "candidate_executable"
    else:
        record["startup_status"] = "path_configuration_only"
    if record["startup_status"] in {"suppressed_by_matching_start", "executable_lines_deprecated_ignored",
                                     "executable_lines_warn_planned"}:
        for item in record["indicators"]:
            if item["code"].startswith("pth_executable_line") or item["code"].startswith("pth_line_"):
                item["severity"] = "info"


def _parse_start(record: dict[str, Any], text: str, options: ScanOptions,
                 version: tuple[int, int] | None) -> None:
    entries = []
    lines = text.splitlines()
    if len(lines) > MAX_STARTUP_LINES:
        record["errors"].append("startup line count limit exceeded; content truncated")
    for line_no, line in enumerate(lines[:MAX_STARTUP_LINES], 1):
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        # PEP 829 requires a complete entry-point reference; inline comments are not valid.
        matched = ENTRY_POINT_RE.fullmatch(clean)
        item: dict[str, Any] = {"line": line_no, "entry": clean, "valid": bool(matched)}
        item.update(_preview(line, options))
        entries.append(item)
        if matched:
            record["entry_points"].append({"module": matched.group(1),
                                            "callable": matched.group(2), "line": line_no})
        else:
            record["indicators"].append(indicator(
                "invalid_start_entry", "low", "Malformed .start entry-point syntax", line=line_no))
    record["declared_entries"] = entries
    valid_entries = bool(record["entry_points"])
    if valid_entries:
        record["indicators"].append(indicator(
            "startup_entry_point", "info" if version and version < (3, 15) else "medium",
            "Syntactically valid package startup callable declared in .start file"))
    if version and version < (3, 15):
        record["startup_status"] = "not_supported_before_3_15"
    elif entries and not valid_entries:
        record["startup_status"] = "invalid_entries_only"
    elif version is None:
        record["startup_status"] = "possible_on_python_315_plus" if valid_entries else "empty_configuration"
    else:
        record["startup_status"] = "candidate_executable" if valid_entries else "empty_configuration"
