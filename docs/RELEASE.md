# Release checklist — HookScope 1.4.0

## Completed in the local Linux builder

- [x] Unit and integration test suite (including real Python virtual-environment execution)
- [x] Installed the freshly built Wheel into a separate virtual environment
- [x] Compared baseline and modified JSON inventories through the installed CLI
- [x] Exercised quarantine, restore and SHA-256 verification
- [x] Verified the ASCII/Unicode terminal banner on a real pseudo-terminal
- [x] Checked that JSON output contains no terminal branding
- [x] SHA-256 checksums generated for shipped files

## Required before claiming cross-platform verification

- [ ] Run actual GitHub Actions matrix on Linux, macOS and Windows
- [ ] Run direct Termux smoke test of the v1.4.0 Wheel on Android
- [ ] Confirm the report is complete or document skipped filesystem paths
- [ ] Independently validate detection coverage against auditd/Falco/Splunk telemetry

## Publication steps

1. Create a new GitHub repository using the source tree, excluding `dist/`, `*.egg-info`, `__pycache__/`, and local test logs.
2. Push a tagged release `v1.4.0` after the GitHub Actions matrix passes.
3. Attach the built Wheel and SHA-256 checksums to the release, with a note identifying the validated platform.
4. Include a short demonstration of a harmless lab hook, scan, interactive approval, quarantine and restore.
5. Avoid unqualified "malware detector", "100% accurate", "enterprise certified", or "bypasses Falco" claims.

See [AUDIT.md](../AUDIT.md) for scope and evidence limitations.
