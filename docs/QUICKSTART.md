# First 60 seconds with HookScope

HookScope checks Python startup configuration files in directories you choose. It does **not** scan the entire Android phone for every kind of malware. Seeing a `.pth` startup file is not proof of malicious activity.

## On Termux

After installing the supplied Wheel, enter **only**:

```sh
hookscope
```

Choose `1` to scan (read-only). The program saves an HTML report and a JSON report and tries to open the HTML report in the phone browser.

To skip the menu:

```sh
hookscope start
```

To revisit the report:

```sh
hookscope report
```

To send both reports to an analyst, enter:

```sh
hookscope export
```

Reply `y` to the sharing prompt, then attach the two `hookscope-scan-...` files from your phone's **Downloads** folder. Reports can reveal file paths or other sensitive details, so read them before sharing.

For all available commands:

```sh
hookscope help
hookscope --help
hookscope help scan
```

## If the result says zero files

Zero simply means the selected directory had no matching startup artifacts at the moment of the scan. A `.pth` file that was quarantined earlier will no longer be in the startup path, so a later scan can correctly report zero. The HTML report explains this. To view quarantined entries, run `hookscope quarantine-list`.

## Need a safe test?

Menu option `4` creates a harmless, real `.pth` hook in a **separate lab virtual environment** only with confirmation. This action is distinct from normal read-only scanning.

## Other platforms

If the program cannot recognize a Termux Python prefix, it will not guess a system-wide folder. Specify the scan folder:

```sh
hookscope start --root /path/to/python/filesystem
```

## About quarantine

Normal scans and `start` are read-only. To request a separate, interactive quarantine review, use the advanced `hookscope scan --root /path/to/scope --review` command. Read the reasoning first; automatically deleting every `.pth` file can break healthy Python installations. Restore and purge remain explicit operations.
