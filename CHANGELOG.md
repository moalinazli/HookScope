# Changelog

## 1.5.0 — 2026-11-22

- Added no-argument, numbered interactive menu and safe non-TTY quick-start fallback.
- Added beginner commands `start`, `report`, `export`, `help` and `doctor`, keeping the advanced CLI intact.
- Easy scan auto-selects a recognized Termux `$PREFIX/lib` or takes an explicit `--root`, saves two timestamped reports, and opens HTML via `termux-open` when available.
- Added novice-oriented "How to use this report" HTML section and collapsed advanced diagnostic commands.
- Added first-run, default-root, report-save/open, no-root and PTY regression tests; preserves read-only defaults.

## 1.4.0 — 2026-11-22

- Integrated responsive Nazlabadi terminal identity, with no banner in machine-readable or redirected output and an explicit `--no-banner` option.
- Added `hookscope banner` for a standalone terminal preview.
- Added `hookscope diff` for bounded, offline before/after comparison of JSON inventories, including resolved-module fingerprints.
- Added `hookscope quarantine-verify` to detect altered, missing, or unexpectedly linked vault artifacts.
- Refuse quarantining a startup file with more than one hard link.
- A refused or non-interactive destructive command now exits 2, rather than falsely reporting success.
- Added interactive TTY regression testing and negative-input tests for new commands.
- No network activity, auto-remediation, external runtime dependencies, or dynamic importing of scanned code added.

# Changelog

## 1.3.0 — Explicit, reversible quarantine and live Termux canary lab

- Added `scan --review`, presenting exact candidate path, SHA-256, reasoning, and confirmation in an interactive terminal.
- Added `quarantine`, `quarantine-list`, `restore` and `purge` with receipts, identity/hash checks, explicit prompts and safe POSIX file handling.
- Added manually copyable quarantine commands in terminal and static HTML reports.
- Added `lab-create`: a scoped randomly named virtual environment containing a harmless but genuinely executable `.pth` canary.
- Added live tests proving quarantine stops startup execution and restore re-enables it, plus interactive PTY, hash-change, symlink, path-traversal and overwrite safety tests.
- Kept ordinary scanning and wheel inspection strictly read-only, no target-code execution.

# Changelog

## 1.2.0 — Evidence-first reporting

- Rebuilt the standalone HTML report for phone and desktop layouts, with a readable forensic-summary hierarchy, artifact detail panels and code-level evidence.
- Explicitly distinguish **coverage gaps** from **informational internal symlink aliases** rather than presenting all traversal events as equivalent security issues.
- Added an actionable zero-finding state: no discovered artifact is **not** a clean-endpoint verdict.
- Expose the existing traversal counters and recognized Python site directories in HTML instead of hiding that data in JSON.
- Group individual indicator detail, SHA-256, Python version, file mode and statically resolved module targets in expandable findings.
- Bound HTML detail rendering for large result sets; JSON remains the complete machine-readable export.
- Preserve offline output: no JavaScript, remote assets, external fonts or network requests.
- Added regression tests for report semantics, injected HTML, empty scans, legacy metadata and rich artifact results.

## 1.1.0 — Scanner hardening

See [AUDIT.md](AUDIT.md) for the previous scanner correctness work, including symlink traversal, IOC imported-module matching, Python free-threaded directory names, Wheel RECORD validation and real interpreter checks.
