# Release validation — HookScope v1.5.0

**Verification date:** 2026-11-22. **Local environment:** Linux / Python 3.13.5.

## Tested locally

- **119 Python unit and integration tests passed** via `python -m unittest discover -s tests -q`.
- All 107 inherited v1.4 tests remain passing, plus 12 first-run, Termux-style path, export privacy, interactive PTY, report and beginner HTML tests.
- Executed the no-argument CLI in a pseudo-terminal, selecting `0`, proving the menu opens and exits. In non-TTY subprocesses the no-argument CLI prints a quick guide instead of blocking.
- Exercised `hookscope help`, `hookscope help scan`, `hookscope doctor`, and saved-report discovery.
- Exercised `hookscope start` against a synthetic `.pth` fixture, confirmed the finding and both HTML/JSON outputs. Default Termux prefix detection was simulated using a controlled test folder; this is **not** a live Android runtime test.
- Verified `hookscope export` refuses copying without consent and copies both reports with `--yes` into a temporary Downloads-like directory without overwriting existing files.
- Previous v1.4 tests cover static analysis, wheel scanning, IOC matching, hardlink/symlink protections, quarantine/restore/purge safety, `diff`, and terminal banner output.

## Installed-Wheel validation

The distributable Wheel was built locally with no runtime requirements, installed in a new isolated Python environment, and run outside the source checkout. A filesystem fixture containing one harmless `.pth` file produced one finding and a standalone HTML/JSON report.

## Not verified here

- Running **v1.5.0** directly on the user's Android/Termux phone or opening `termux-open` there. v1.4 installation and banner were confirmed from the user's earlier terminal output.
- Remote CI outcomes on Windows/macOS or all listed Python versions. A GitHub workflow is supplied, not a claim that it ran.
- Detection of every malicious startup hook, dynamic runtime effects or malware in unrelated device areas.
- Third-party security assessment and live EDR/SIEM integrations.

Successful local tests do not establish 100% detection or platform compatibility.
