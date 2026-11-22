# Confirmed remediation and safe test lab

HookScope v1.3 introduces **explicit, reversible quarantine**. Scanner findings are not malware verdicts. Remediation is a distinct, interactive action; ordinary `scan` and `wheel` inspection remain read-only.

## Safe test on Linux / Termux

Install a locally built HookScope wheel using a trusted Python interpreter, then:

```bash
hookscope lab-create --root "$HOME/hookscope-lab"
hookscope scan --root "$HOME/hookscope-lab" --review
```

`lab-create` creates a randomly named **virtual environment inside that visible, dedicated lab directory** and installs a harmless but genuinely executable `.pth` startup hook. The hook only writes `HOOK_STARTED` to a local marker and prints `HOOKSCOPE_LAB_CANARY_EXECUTED`. The lab command explicitly executes its generated Python once for verification, reporting the observed output.

The subsequent **scanner does not execute the hook**. Use the `--review` interactive option for terminal prompts; answer `y` only if the file matches the exact entry you want to quarantine. The prompt prints the relative path, severity, SHA-256, reasons, and equivalent CLI command.

After quarantine, execute the Python binary shown in the lab-create output to verify it now prints only `APP_MAIN`. The importable `hookscope_canary.py` file intentionally remains in the test venv; only the triggering `.pth` is moved. Restore the hook by its quarantine ID if you wish to repeat the demo.

The lab directory is **not placed in ordinary Termux site-packages**. It is deliberately separate from your active Python installation. The random component avoids predictable test paths; the tool always discloses the generated location and never hides it from the owner.

## Interactive remediation

```bash
hookscope scan --root "$PREFIX/lib" --review
```

Only candidates at `medium` or above are prompted by default. To inspect lower-priority candidates, use `--review-min-severity low`. To keep a separate pre-remediation report:

```bash
hookscope scan --root "$PREFIX/lib" --format html --output "$HOME/report.html" --review
```

The static HTML contains a **copyable manual quarantine command** for each eligible snapshot artifact. It cannot invoke system commands or change files from the browser, by design.

## Exact-path commands

```bash
hookscope quarantine --root "$PREFIX/lib" \
  --path 'python3.13/site-packages/suspect.pth'

hookscope quarantine-list
hookscope restore --id QUARANTINE_ID
hookscope purge --id QUARANTINE_ID
```

Quarantine prompts for consent and moves the exact named file to a private vault, defaulting to `$HOME/.local/share/hookscope/quarantine`, which must have mode `0700`. It re-verifies SHA-256 and file identity immediately before moving the file. It refuses symlink components, unrecognized files, changed hashes, cross-filesystem renames, occupied restore targets, and unprivileged access failures. Each quarantine entry has a unique ID and a mode-0600 JSON receipt with source path and SHA-256.

**Permanent deletion (`purge`)** removes only the selected file already in quarantine and requires separate confirmation. Restoration recreates the original path if vacant, without overwriting newer data. This is intentionally not a recursive malware remover: only the single analyst-approved startup artifact is moved. Imported modules are retained because they may be shared with legitimate applications.

Automation scripts must pass `--yes` to remediation commands; there is no implicit noninteractive approval. The `scan --review` mode requires an interactive TTY and does not modify files when input is redirected.

## Security boundaries and failure cases

- POSIX-specific file-descriptor handling is used for mutation. Windows mutation is not supported.
- Quarantine and target must be on the same filesystem. On `EXDEV`, no fallback copying is attempted.
- Quarantine is not an antimalware verdict. Verify a finding before removing it; legitimate `.pth` packages exist.
- Quarantining the entrypoint prevents this particular trigger from firing, but other triggers, running processes, and imported modules may remain.
- A running process that already imported the hook is not stopped.
- Source directories may be modified concurrently by other processes. Hash and inode verification narrow races but cannot provide full isolation against a privileged concurrent adversary. For active incidents prefer a read-only snapshot or offline examination.
- If a crash happens between an atomic move and receipt creation, the vault could contain an unreceipted file; retain the vault for recovery rather than deleting it blindly.
- Restoring and purging keep historical receipts. Filesystem or disk failures can interrupt receipt updates; check the file and receipt manually on failure.
- Do not run the test lab inside a production interpreter or under an unknown Python environment.
- Termux compatibility is a supported target but has not been measured on the user's actual Android phone; tests in this release were executed on Linux.
