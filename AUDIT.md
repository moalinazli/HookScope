## v1.5 first-run UX audit (2026-11-22)

- `hookscope` without arguments now has a safe terminal menu; piped executions print quick-start help and exit, without scanning or prompting.
- Termux `$PREFIX/lib` is used only when explicitly running `start` or selecting scan from the menu, not at import or help time.
- `start` only writes reports outside the scanned root; no quarantine occurs implicitly. Reports use atomic saves and retain separate timestamps.
- Report HTML is static with CSP restrictions; beginner guidance is plain-text instructions, not a privileged browser control.
- CLI `scan`, `wheel`, `diff`, quarantine and JSON/SARIF flags are unchanged. No runtime third-party packages required.
- Residual risk: direct Android 1.5 verification and Windows/macOS CI are pending. There is no guarantee of complete malware detection.

# HookScope 1.4.0 — Security and release audit

HookScope is an offline, static Python startup-exposure auditor. It is not a running EDR agent, behavioral antivirus, or verified host-cleanliness certification.

## Changes reviewed

- Terminal branding runs only on an interactive text output and respects `--no-banner`, `NO_COLOR`, and terminal width; redirected JSON/SARIF are unchanged.
- Differential inventory review uses the saved JSON report, verifies its format and size, detects added/removed artifacts and changes in startup file hash, classification, resolved-module graph, IOC matches and integrity metadata.
- Quarantine validation checks read-only SHA-256 receipts; corruption causes a nonzero exit. Quarantine now refuses hardlinked files rather than misrepresenting a rename as complete isolation.
- Real test hooks remain restricted to a named laboratory root. Regular scanning never imports inspected target modules.

## Strengths and boundaries

- Snapshots and Wheels are scanned without executing their contents.
- Input limits defend against many malformed or oversized inputs; they are not a formal sandbox for hostile filesystems.
- Static module-resolution results are hypotheses; the real interpreter's import order, flags, Python version, active site paths and environment can differ.
- Imported module fingerprints in comparisons improve change detection but cannot capture every runtime code path or all external dependencies.
- Restoring a quarantined file can re-enable startup behavior; the user must explicitly authorize it.
- A quarantine is a single-file move, not malware eradication. Previously executed code, imported modules and related files require separate response.
- The tool has not been validated on the target user's Termux installation or all OS/Python combinations.

## Evidence

`tests/test_release_14.py` covers the new interfaces. `tests/test_real_venv.py` and `tests/test_quarantine.py` retain live interpreter and interactive/remediation checks. The release artifact contains generated local test output and a SHA-256 manifest; GitHub Actions has not run yet.
