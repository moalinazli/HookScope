"""Isolated, real CPython startup integration test (Linux/macOS only)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
import venv


@unittest.skipUnless(os.name == "posix", "real startup venv test requires POSIX")
class RealInterpreterTests(unittest.TestCase):
    def test_executable_hook_actually_runs_and_scanner_remains_static(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = root / "sandbox-env"
            venv.EnvBuilder(with_pip=False, symlinks=False).create(env)
            python = env / "bin" / "python"
            site = env / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
            self.assertTrue(site.is_dir())
            (site / "trigger.pth").write_text("import harmless_trigger\n")
            marker = root / "marker.txt"
            (site / "harmless_trigger.py").write_text(
                "from pathlib import Path\n"
                + "Path(" + repr(str(marker)) + ").open('a').write('hook\\n')\n"
                + "print('HOOK_EXECUTED')\n")

            def run_py(*args):
                return subprocess.run([str(python), *args], check=True, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip().splitlines()

            self.assertEqual(run_py("-c", "print('APP_EXECUTED')"),
                             ["HOOK_EXECUTED", "APP_EXECUTED"])
            self.assertEqual(marker.read_text(), "hook\n")
            self.assertEqual(run_py("-S", "-c", "print('APP_EXECUTED')"), ["APP_EXECUTED"])
            self.assertEqual(marker.read_text(), "hook\n")
            self.assertEqual(run_py("-I", "-c", "print('APP_EXECUTED')"),
                             ["HOOK_EXECUTED", "APP_EXECUTED"])
            self.assertEqual(marker.read_text(), "hook\nhook\n")

            output = root / "scan.json"
            # The trusted host Python runs HookScope, NOT the instrumented venv.
            run = subprocess.run([sys.executable, "-m", "hookscope", "scan", "--root", str(env),
                                  "--python-version", f"{sys.version_info.major}.{sys.version_info.minor}",
                                  "--format", "json", "--output", str(output), "--strict"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(marker.read_text(), "hook\nhook\n", "scanner must not execute target")
            report = json.loads(output.read_text())
            self.assertTrue(report["complete"])
            found = next(a for a in report["artifacts"] if a["path"].endswith("trigger.pth"))
            self.assertEqual(found["startup_status"], "candidate_executable")
            self.assertEqual(found["severity"], "medium")
            self.assertEqual(found["resolved_imports"][0]["status"], "resolved_in_snapshot")

if __name__ == "__main__":
    unittest.main()
