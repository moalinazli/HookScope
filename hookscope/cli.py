"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import shlex
from pathlib import Path
import sys
import tempfile
import datetime
import shutil
import subprocess

from . import __version__
from .iocs import load_hashes
from .models import SEVERITY, ScanOptions, parse_version
from .report import finalize, to_html, to_json, to_sarif, to_text, _safe_terminal
from .snapshot import scan_snapshot
from .wheels import scan_wheel
from .quarantine import (default_vault, find_candidate, quarantine_artifact,
                         list_quarantine, restore_artifact, purge_artifact, verify_quarantine)
from .lab import create_lab
from .banner import render as render_banner
from .diff import load_report, compare, format_text

FORMATS = {"json": to_json, "text": to_text, "sarif": to_sarif, "html": to_html}


def _version_arg(value: str) -> tuple[int, int]:
    try:
        return parse_version(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hookscope", description="Offline Python startup artifact auditor (T1546.018)")
    parser.add_argument("--version", action="version", version=f"HookScope {__version__}")
    parser.epilog = ("First time? Run 'hookscope' for the menu, 'hookscope start' to scan, "
                     "or 'hookscope help' for plain-language instructions.")
    sub = parser.add_subparsers(dest="command", required=False)
    helper = sub.add_parser("help", help="Quick-start guide; optionally explain a command")
    helper.add_argument("topic", nargs="?", help="Command name, e.g. scan or quarantine")
    start = sub.add_parser("start", help="Easy read-only scan and save both HTML and JSON reports")
    start.add_argument("--root", type=Path, help="Directory to inspect; Termux defaults to $PREFIX/lib")
    start.add_argument("--report-dir", type=Path, help="Where to save reports (default ~/hookscope-reports)")
    start.add_argument("--no-open", action="store_true", help="Do not open the HTML report in Termux")
    report = sub.add_parser("report", help="Open the latest saved HTML report in Termux")
    report.add_argument("--report-dir", type=Path, help="Where reports are stored")
    report.add_argument("--path-only", action="store_true", help="Only print the latest file path")
    export = sub.add_parser("export", help="Copy latest HTML + JSON to phone Downloads for sharing")
    export.add_argument("--report-dir", type=Path, help="Location of previously saved reports")
    export.add_argument("--output-dir", type=Path, help="Destination (Termux default /sdcard/Download)")
    export.add_argument("--yes", action="store_true", help="Explicitly confirm copying sensitive reports")
    sub.add_parser("doctor", help="Check Python, scan location and report setup without scanning")

    banner = sub.add_parser("banner", help="Preview the terminal identity without scanning")
    banner.add_argument("--no-color", action="store_true")
    banner.add_argument("--ascii", action="store_true")
    delta = sub.add_parser("diff", help="Compare two JSON scan inventories offline")
    delta.add_argument("--old", required=True, type=Path)
    delta.add_argument("--new", required=True, type=Path)
    delta.add_argument("--allow-different-root", action="store_true")
    delta.add_argument("--format", choices=("json", "text"), default="text")
    delta.add_argument("--output", type=Path)
    delta.add_argument("--fail-on-change", action="store_true")
    verify = sub.add_parser("quarantine-verify", help="Verify vault receipts and SHA-256 without modifications")
    verify.add_argument("--vault", type=Path, default=default_vault())
    verify.add_argument("--format", choices=("json", "text"), default="text")
    for name in ("scan", "wheel"):
        cmd = sub.add_parser(name, help="Scan a filesystem snapshot" if name == "scan" else "Inspect a Python wheel offline")
        if name == "scan":
            cmd.add_argument("--root", type=Path, required=True)
        else:
            cmd.add_argument("path", type=Path)
        cmd.add_argument("--format", choices=sorted(FORMATS), default="text")
        cmd.add_argument("--no-banner", action="store_true", help="Suppress terminal branding")
        cmd.add_argument("--output", type=Path, help="Report file; defaults to standard output")
        cmd.add_argument("--ioc-csv", action="append", default=[], type=Path,
                         help="CSV with Type,Value,Campaign,Role,SourceURL (repeatable)")
        cmd.add_argument("--python-version", metavar="3.15", type=_version_arg,
                         help="Interpreter version for static startup semantics")
        cmd.add_argument("--max-file-bytes", type=int, default=1_048_576)
        cmd.add_argument("--max-visited-files", type=int, default=500_000)
        cmd.add_argument("--include-source-lines", action="store_true",
                         help="Include .pth/.start lines in output (may disclose secrets)")
        cmd.add_argument("--strict", action="store_true", help="Exit 2 when a scan is incomplete")
        cmd.add_argument("--fail-on", choices=("never", "low", "medium", "high"), default="never",
                         help="Exit 3 for findings at or above the requested severity")
        if name == "scan":
            cmd.add_argument("--review", action="store_true",
                             help="Prompt to quarantine reviewed artifacts after a scan (interactive TTY only)")
            cmd.add_argument("--review-min-severity", choices=("low", "medium", "high"), default="medium")
            cmd.add_argument("--vault", type=Path, default=default_vault())

    quarantine = sub.add_parser("quarantine", help="Quarantine one analyst-selected startup artifact")
    quarantine.add_argument("--root", type=Path, required=True)
    quarantine.add_argument("--path", required=True, help="Exact relative path displayed in the scan")
    quarantine.add_argument("--vault", type=Path, default=default_vault())
    quarantine.add_argument("--yes", action="store_true", help="Explicitly confirm without interactive input")
    quarantine.add_argument("--min-severity", choices=("info", "low", "medium", "high"), default="low")

    for name in ("restore", "purge"):
        cmd = sub.add_parser(name, help=f"{name.capitalize()} an identified quarantine entry")
        cmd.add_argument("--id", required=True, help="24-hex quarantine ID")
        cmd.add_argument("--vault", type=Path, default=default_vault())
        cmd.add_argument("--yes", action="store_true", help="Explicitly confirm without interactive input")
    vault_ls = sub.add_parser("quarantine-list", help="Show tracked quarantine entries")
    vault_ls.add_argument("--vault", type=Path, default=default_vault())
    demo = sub.add_parser("lab-create", help="Create an isolated random-named benign startup-hook test")
    demo.add_argument("--root", type=Path, default=Path.home() / "hookscope-lab")
    demo.add_argument("--no-verify", action="store_true")
    return parser


def _write_atomic(path: Path, text: str) -> None:
    # Report files may contain sensitive source paths and optional source lines.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".hookscope-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _ask_confirm(prompt: str, *, yes: bool = False) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing non-interactive changes; run from a terminal or provide --yes.", file=sys.stderr)
        return False
    try:
        return input(prompt + " [y/N]: ").strip().casefold() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return False


def _print_candidate(root: Path, artifact: dict, vault: Path) -> None:
    # repr avoids terminal-control injection in filenames and raw paths.
    print("\nCandidate:", repr(artifact["path"]), file=sys.stderr)
    print("  Priority:", artifact["severity"], "  Startup:", artifact["startup_status"], file=sys.stderr)
    print("  SHA-256:", artifact["sha256"], file=sys.stderr)
    print("  Reasons:", file=sys.stderr)
    for item in artifact.get("indicators", [])[:6]:
        print("   -", item["code"], file=sys.stderr)
    command = "hookscope quarantine --root " + shlex.quote(str(root)) + " --path " + shlex.quote(artifact["path"])
    if vault != default_vault():
        command += " --vault " + shlex.quote(str(vault))
    print("  Manual command:", _safe_terminal(command), file=sys.stderr)


def _do_quarantine(root: Path, artifact: dict, vault: Path, *, yes: bool = False) -> bool:
    _print_candidate(root, artifact, vault)
    print("  Action: move startup file into private quarantine; imported modules stay untouched.", file=sys.stderr)
    if not _ask_confirm("Quarantine this exact file?", yes=yes):
        print("  Skipped; nothing changed.", file=sys.stderr)
        return False
    receipt = quarantine_artifact(root, artifact["path"], artifact["sha256"], vault)
    print("  REMOVED FROM STARTUP PATH; quarantined ID:", receipt["id"], file=sys.stderr)
    print("  Restore: hookscope restore --id " + receipt["id"], file=sys.stderr)
    print("  Permanently delete: hookscope purge --id " + receipt["id"], file=sys.stderr)
    return True


def _review_scan(root: Path, result: dict, threshold: str, vault: Path) -> None:
    from .models import SEVERITY
    if not sys.stdin.isatty():
        print("Interactive review requires a terminal; no files changed.", file=sys.stderr)
        return
    candidates = [a for a in result["artifacts"]
                  if a.get("sha256") and not a.get("errors")
                  and SEVERITY[a["severity"]] >= SEVERITY[threshold]]
    print(f"\nInteractive review: {len(candidates)} candidate(s). Presence is not a malware verdict.", file=sys.stderr)
    if not result["complete"]:
        print("Warning: scan coverage was incomplete; review results accordingly.", file=sys.stderr)
    for artifact in candidates:
        try:
            _do_quarantine(root, artifact, vault)
        except (OSError, ValueError) as exc:
            print("  Could not quarantine:", str(exc), file=sys.stderr)
    print("Review ended. The saved scan report, if any, reflects PRE-quarantine state.", file=sys.stderr)


def _report_dir(value: Path | None = None) -> Path:
    return value if value is not None else Path.home() / "hookscope-reports"


def _default_scan_root() -> Path | None:
    # Only advertise an automatic target inside a recognizable Termux install.
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" not in prefix:
        return None
    candidate = Path(prefix) / "lib"
    return candidate if candidate.is_dir() else None


def _quick_guide() -> None:
    print("\nHookScope — Python startup security checker")
    print("It looks for Python startup configuration files that deserve review.")
    print("Finding a startup file does NOT automatically mean malware.\n")
    print("START HERE")
    print("  hookscope            Interactive menu (in a terminal)")
    print("  hookscope start      Scan your Termux Python folder; read-only")
    print("  hookscope report     Open your most recent report")
    print("  hookscope export     Copy both reports to phone Downloads (asks first)")
    print("  hookscope doctor     Check where the tool can scan")
    print("  hookscope help scan  Full options for the scanner")
    print("\nAdvanced commands: scan, wheel, diff, quarantine-list, restore, purge")
    print("No files are removed by a scan. Quarantine requires separate approval.\n")


def _doctor() -> int:
    root = _default_scan_root()
    print("HookScope environment check")
    print("  Python: " + sys.version.split()[0])
    print("  Platform: " + os.name)
    print("  Termux detected: " + ("yes" if root is not None else "no"))
    print("  Default scan folder: " + (_safe_terminal(str(root)) if root else "not detected"))
    print("  Reports folder: " + _safe_terminal(str(_report_dir())))
    print("  Scan mode: read-only unless separately confirmed for quarantine")
    if root is None:
        print("  Next: hookscope start --root /path/to/python/snapshot")
    else:
        print("  Next: hookscope start")
    return 0


def _latest_report(directory: Path) -> Path | None:
    if not directory.is_dir():
        return None
    # Reports created by `start` use a strict basename; ignore arbitrary files.
    options = [p for p in directory.glob("scan-*.html")
               if p.is_file() and not p.is_symlink()]
    return max(options, key=lambda p: p.name) if options else None


def _open_report(path: Path) -> bool:
    executable = shutil.which("termux-open") if "com.termux" in os.environ.get("PREFIX", "") else None
    if executable:
        # A local HTML file with no JavaScript/external assets is handed to the viewer.
        result = subprocess.run([executable, str(path)], check=False, capture_output=True, text=True)
        if result.returncode == 0:
            print("Opened report in your browser.")
            return True
        print("Browser open failed: " + _safe_terminal(result.stderr.strip()))
    else:
        print("Open this HTML file in a browser: " + _safe_terminal(str(path)))
        print("On Termux: termux-open " + _safe_terminal(shlex.quote(str(path))))
    return False


def _export_reports(report_dir: Path | None, output_dir: Path | None, *, yes: bool = False) -> int:
    latest = _latest_report(_report_dir(report_dir))
    if latest is None:
        print("No saved report yet. Run 'hookscope start' first.")
        return 2
    matching_json = latest.with_suffix(".json")
    if not matching_json.is_file() or matching_json.is_symlink():
        print("Matching JSON report was not found; nothing copied.", file=sys.stderr)
        return 2
    destination = output_dir or Path("/sdcard/Download")
    if not destination.is_dir():
        print("Downloads folder not found: " + _safe_terminal(str(destination)), file=sys.stderr)
        print("On Termux, check storage access or run: termux-setup-storage", file=sys.stderr)
        return 2
    targets = [(latest, destination / ("hookscope-" + latest.name)),
               (matching_json, destination / ("hookscope-" + matching_json.name))]
    if any(target.exists() or target.is_symlink() for _, target in targets):
        print("These reports are already in Downloads; no file overwritten.", file=sys.stderr)
        for _, target in targets:
            print("  " + _safe_terminal(str(target)), file=sys.stderr)
        return 2
    print("Reports may contain private paths and forensic details.")
    if not _ask_confirm("Copy latest HTML and JSON to a shared folder?", yes=yes):
        print("Cancelled; no files copied.")
        return 2
    created = []
    try:
        for source, target in targets:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            created.append(target)
            with os.fdopen(fd, "wb") as sink, source.open("rb") as inp:
                shutil.copyfileobj(inp, sink, length=128 * 1024)
        for _, target in targets:
            print("Exported: " + _safe_terminal(str(target)))
        print("In your phone's Downloads, attach these two files to the chat.")
        return 0
    except OSError:
        # Avoid misleading partial paired exports; never overwrite an existing file.
        for target in created:
            try:
                target.unlink()
            except OSError:
                pass
        raise


def _run_start(root: Path | None, report_dir: Path | None, *, open_browser: bool = True) -> int:
    chosen = root if root is not None else _default_scan_root()
    if chosen is None:
        print("No default Python folder found. Nothing was scanned.")
        print("Try: hookscope start --root /path/to/python/snapshot")
        print("Or run: hookscope doctor")
        return 2
    chosen = chosen.resolve(strict=False)
    if not chosen.is_dir():
        print("Scan folder does not exist: " + _safe_terminal(str(chosen)), file=sys.stderr)
        return 2
    reports = _report_dir(report_dir).resolve(strict=False)
    if reports == chosen or chosen in reports.parents:
        print("Reports cannot be written inside the scanned folder.", file=sys.stderr)
        return 2
    print("Scanning Python startup files (no changes to your files)...", flush=True)
    print("Folder: " + _safe_terminal(str(chosen)), flush=True)
    result = scan_snapshot(chosen, ScanOptions(), {})
    finalize(result)
    # Microseconds avoid overwrites even if a second scan happens instantly.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    html_path = reports / f"scan-{stamp}.html"
    json_path = reports / f"scan-{stamp}.json"
    _write_atomic(html_path, to_html(result))
    _write_atomic(json_path, to_json(result))
    artifacts = result.get("artifacts", [])
    print("\nSCAN COMPLETE" if result.get("complete") else "\nSCAN FINISHED — COVERAGE INCOMPLETE")
    print("  Startup files found: " + str(len(artifacts)))
    print("  Known IOC hash matches: " + str(result.get("summary", {}).get("known_ioc_matches", 0)))
    print("  Coverage: " + ("complete within selected folder" if result.get("complete") else "some locations could not be checked"))
    print("  HTML: " + _safe_terminal(str(html_path)))
    print("  JSON: " + _safe_terminal(str(json_path)))
    if not artifacts:
        print("  Meaning: no matching startup files in this folder; NOT proof the device is clean.")
        print("  If you quarantined a file earlier, zero findings afterwards may be expected.")
    else:
        print("  Meaning: review the files; their presence alone is NOT proof of malware.")
        print("  To review before quarantine: hookscope scan --root " + _safe_terminal(shlex.quote(str(chosen))) + " --review")
    print("  Later: hookscope report  |  Help: hookscope help")
    if open_browser and sys.stdout.isatty() and "com.termux" in os.environ.get("PREFIX", ""):
        _open_report(html_path)
    return 0 if result.get("complete") else 2


def _menu() -> int:
    render_banner(version="v" + __version__)
    while True:
        print("\n  1  Scan Python startup files (read-only)")
        print("  2  View latest report")
        print("  3  Export reports to Downloads (share)")
        print("  4  Create a safe test lab")
        print("  5  List quarantined files")
        print("  6  Help / what does HookScope do?")
        print("  7  Check setup")
        print("  0  Exit")
        try:
            choice = input("Choose [0-7]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExit. No changes made.")
            return 0
        if choice == "0":
            print("Goodbye.")
            return 0
        if choice == "1":
            _run_start(None, None)
        elif choice == "2":
            recent = _latest_report(_report_dir())
            if recent is None:
                print("No saved report yet. Choose 1 to scan first.")
            else:
                print("Latest report: " + _safe_terminal(str(recent)))
                _open_report(recent)
        elif choice == "3":
            _export_reports(None, None)
        elif choice == "4":
            print("Creates only a harmless hook in a separate virtual environment.")
            if _ask_confirm("Create safe test lab?"):
                data = create_lab(Path.home() / "hookscope-lab")
                print("Lab: " + _safe_terminal(data["scope"]))
                print("Scan it with: hookscope start --root " + shlex.quote(str(Path.home() / "hookscope-lab")))
        elif choice == "5":
            rows = list_quarantine(default_vault())
            print(json.dumps(rows, indent=2))
            print("Restore requires confirmation: hookscope restore --id ID")
        elif choice == "6":
            _quick_guide()
        elif choice == "7":
            _doctor()
        else:
            print("Enter a number from 0 to 7.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            if sys.stdin.isatty() and sys.stdout.isatty():
                return _menu()
            _quick_guide()
            return 0
        if args.command == "help":
            if not args.topic:
                _quick_guide()
                return 0
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    if args.topic in action.choices:
                        action.choices[args.topic].print_help()
                        return 0
            print("Unknown command. Run 'hookscope --help' to list commands.", file=sys.stderr)
            return 2
        if args.command == "doctor":
            return _doctor()
        if args.command == "export":
            return _export_reports(args.report_dir, args.output_dir, yes=args.yes)
        if args.command == "start":
            return _run_start(args.root, args.report_dir, open_browser=not args.no_open)
        if args.command == "report":
            latest = _latest_report(_report_dir(args.report_dir))
            if latest is None:
                print("No saved report yet. Run 'hookscope start' first.")
                return 2
            print("Latest HTML report: " + _safe_terminal(str(latest)))
            if not args.path_only and sys.stdout.isatty():
                _open_report(latest)
            return 0
        if args.command == "banner":
            render_banner(force=True, no_color=args.no_color, ascii_only=args.ascii,
                          version="v" + __version__)
            return 0
        if args.command == "diff":
            comparison = compare(load_report(args.old), load_report(args.new),
                                 allow_different_root=args.allow_different_root)
            content = (json.dumps(comparison, indent=2, ensure_ascii=True) + "\n"
                       if args.format == "json" else format_text(comparison))
            if args.output:
                _write_atomic(args.output, content)
            else:
                sys.stdout.write(content)
            return 3 if comparison["changed"] and args.fail_on_change else 0
        if args.command == "quarantine-verify":
            state = verify_quarantine(args.vault)
            if args.format == "json":
                print(json.dumps(state, indent=2, ensure_ascii=True))
            else:
                print(f"Vault: {state['vault']} | Entries: {state['checked']} | Problems: {state['problems']}")
                for item in state['entries']:
                    print(("OK " if item['ok'] else "FAIL ") + item['id'] + " " + item['status']
                          + ((" " + item.get('error', '')) if not item['ok'] else ""))
            return 0 if state["ok"] else 2
        if args.command == "lab-create":
            result = create_lab(args.root, verify=not args.no_verify)
            print(json.dumps(result, indent=2))
            print("\nScan it with: hookscope scan --root " + shlex.quote(str(args.root)) + " --review")
            print("This canary executes only inside the new test venv; it is not malware.")
            return 0 if result.get("verified", True) else 2
        if args.command == "quarantine-list":
            print(json.dumps(list_quarantine(args.vault), indent=2))
            return 0
        if args.command == "quarantine":
            root = Path(os.path.abspath(args.root))
            artifact = find_candidate(root, args.path, min_severity=args.min_severity)
            return 0 if _do_quarantine(root, artifact, args.vault, yes=args.yes) else 2
        if args.command in ("restore", "purge"):
            text = "Restore this startup file to its original active path?" if args.command == "restore" else "Permanently delete this quarantined file?"
            if not _ask_confirm(text + " ID=" + args.id, yes=args.yes):
                print("No changes made.")
                return 2
            receipt = (restore_artifact(args.vault, args.id) if args.command == "restore"
                       else purge_artifact(args.vault, args.id))
            print(json.dumps(receipt, indent=2))
            return 0
        if not (1 <= args.max_file_bytes <= 32 * 1024 * 1024) or args.max_visited_files < 1:
            parser.error("invalid scanning limits")
        if args.command == "scan" and args.review and args.format != "text" and not args.output:
            parser.error("--review with JSON/HTML/SARIF requires --output to keep stdout machine-readable")
        options = ScanOptions(max_file_bytes=args.max_file_bytes,
                              max_visited_files=args.max_visited_files,
                              include_source_lines=args.include_source_lines,
                              python_version=args.python_version)
        known = load_hashes(args.ioc_csv)
        if args.command == "scan":
            if args.output:
                root = args.root.resolve(strict=False)
                output = args.output.resolve(strict=False)
                if output == root or root in output.parents:
                    raise ValueError("refusing to write a report inside the scanned snapshot")
            result = scan_snapshot(args.root, options, known)
        else:
            result = scan_wheel(args.path, options, known)
        finalize(result)
        if args.format == "text" and not args.output and not args.no_banner:
            render_banner(stream=sys.stdout, version="v" + __version__)
        content = FORMATS[args.format](result)
        if args.output:
            _write_atomic(args.output, content)
        else:
            try:
                sys.stdout.write(content)
                sys.stdout.flush()
            except BrokenPipeError:
                return 0
        if args.command == "scan" and args.review:
            _review_scan(Path(os.path.abspath(args.root)), result, args.review_min_severity, args.vault)
        if args.strict and not result["complete"]:
            return 2
        if args.fail_on != "never" and any(
            SEVERITY[a["severity"]] >= SEVERITY[args.fail_on] for a in result["artifacts"]):
            return 3
        return 0
    except (OSError, ValueError, PermissionError, KeyError) as exc:
        print(f"hookscope: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
