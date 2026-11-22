# HookScope v1.5.0 — Beginner-friendly release

HookScope is an offline Python startup exposure auditor (MITRE ATT&CK T1546.018). It inspects startup artifacts in snapshots and wheels without importing inspected Python code. A finding is an investigative lead, not a conclusive malware verdict.

## User-facing improvements

- **`hookscope`** with no arguments opens a numbered terminal menu. In pipes/non-TTY sessions it prints a brief nonblocking guide.
- **`hookscope start`** performs a read-only guided scan of the Termux-owned Python libraries when `$PREFIX/lib` is available, or accepts an explicit `--root` elsewhere. It saves matching timestamped HTML and JSON files and can open the report via `termux-open`.
- **`hookscope export`** copies the latest matched HTML/JSON pair into Downloads, after explicit confirmation and without overwriting existing files.
- **`hookscope report`** opens the latest saved HTML report, `hookscope help` offers an approachable guide, `hookscope help scan` shows command-specific options and `hookscope doctor` identifies an appropriate scan folder without executing a scan.
- HTML reports now put **How to use this report** before advanced terminal troubleshooting; dense scan commands are collapsed by default.
- Scanner, offline wheel inspection, comparison, approved quarantine, restore, purge, receipt verification, CLI machine-readable formats and Nazlabadi terminal branding are preserved from v1.4.

## Safety and scope

- Automatic startup scan is only selected in a recognized Termux prefix. On other platforms `start` requires `--root`.
- Scans are read-only. Quarantine/restore/purge still require explicit human confirmation.
- User-chosen scanned content is not executed. The optional safe-lab creator is a separately approved operation that executes only its **own** synthetic hook.
- Does not claim to detect every malware family or verify the whole Android device.

See `VALIDATION.md` for executed test evidence and unverified platforms.
