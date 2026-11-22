# HookScope on Termux

Termux is a supported *best-effort* environment, not a substitute for testing every Android release and filesystem. The CLI uses Python 3.10+ and no external runtime libraries. In this release, Linux/POSIX behavior was tested; direct execution on the user's phone must be verified after installation.

## Install a downloaded Wheel

Save `hookscope-1.5.0-py3-none-any.whl` to the phone's Downloads directory. The filename matters.

```sh
pkg install python
termux-setup-storage
ls -l /sdcard/Download/hookscope-1.5.0-py3-none-any.whl
python -m pip install --upgrade /sdcard/Download/hookscope-1.5.0-py3-none-any.whl
hookscope --version
hookscope banner
```

Do not run the pip command until `ls` confirms the file exists. Depending on the download method, the file may have a slightly different name; inspect it with `ls` rather than using a hard-coded missing path.

## First run — easiest way

```sh
hookscope                 # open numbered menu
# Choose 1 to inspect the current Termux Python library; no files are changed.
hookscope start           # or skip the menu, scan directly, and open HTML report
hookscope report          # reopen the newest HTML report
hookscope export          # copy both reports into Downloads for sharing
hookscope help            # learn commands and meanings
hookscope doctor          # check auto-detected Termux path
```

`start` saves matching HTML/JSON reports under `~/hookscope-reports/` and opens HTML via `termux-open` when available in an interactive terminal. You do **not** need to type complex `find`, `--strict`, or `--format` options for normal use. If `termux-open` is not available, use the printed file path manually. Reports contain paths and may contain sensitive details; review them before sending them to others.

**What does zero mean?** It means no matching startup files inside the scanned directory. It is not a clean-phone verdict. If you already quarantined the lab hook, it is normal for the next scan to find zero hooks.

## Inspect without modifying anything

```sh
hookscope scan --root "$PREFIX/lib" --format html --output "$HOME/hookscope.html"
termux-open "$HOME/hookscope.html"
hookscope scan --root "$PREFIX/lib" --format json --output "$HOME/hookscope.json"
```

No findings means no matching artifacts were reported **within the inspected directory**. It is not proof that Android or even all Python installations are clean. Check `complete`, `issues`, and `environments` in JSON before interpreting results.

## Safe validation and reviewed remediation

```sh
hookscope lab-create --root "$HOME/hookscope-lab"
hookscope scan --root "$HOME/hookscope-lab" --review
hookscope quarantine-list
hookscope quarantine-verify
```

The lab creates a harmless `.pth` hook only inside a randomly named virtual environment within the specified directory; it logs a local marker. Do not quarantine startup files inside `$PREFIX/lib` unless you understand the effects on legitimate installed packages. Prefer read-only scanning first.

## Track changes

```sh
hookscope scan --root "$PREFIX/lib" --format json --output "$HOME/baseline.json"
# Repeat at a later time:
hookscope scan --root "$PREFIX/lib" --format json --output "$HOME/current.json"
hookscope diff --old "$HOME/baseline.json" --new "$HOME/current.json"
```

Reports contain local paths and may reveal installed packages. Review before sharing publicly. No privileged Android app directories are inspected without OS-granted permissions.
