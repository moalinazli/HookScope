from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "snapshot"
        self.site = self.root / "usr/lib/python3.13/site-packages"
        self.site.mkdir(parents=True)
        (self.site / "hook.pth").write_text("import test\n")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "hookscope", *map(str, args)],
                              capture_output=True, text=True, check=False)

    def test_scan_json(self):
        result = self.run_cli("scan", "--root", self.root, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["stats"]["artifacts"], 1)

    def test_fail_on_medium(self):
        result = self.run_cli("scan", "--root", self.root, "--fail-on", "medium")
        self.assertEqual(result.returncode, 3)

    def test_fail_on_high_does_not_fail_on_medium(self):
        result = self.run_cli("scan", "--root", self.root, "--fail-on", "high")
        self.assertEqual(result.returncode, 0)

    def test_missing_snapshot_fails(self):
        result = self.run_cli("scan", "--root", self.root / "missing")
        self.assertEqual(result.returncode, 2)

    def test_invalid_version_handled(self):
        result = self.run_cli("scan", "--root", self.root, "--python-version", "foo")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_refuse_report_inside_snapshot(self):
        result = self.run_cli("scan", "--root", self.root, "--output", self.root / "x.json")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "x.json").exists())

    def test_html_report_output(self):
        report = Path(self.tmp.name) / "report.html"
        result = self.run_cli("scan", "--root", self.root, "--format", "html", "--output", report)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Content-Security-Policy", report.read_text())

    def test_sarif_output(self):
        result = self.run_cli("scan", "--root", self.root, "--format", "sarif")
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["version"], "2.1.0")
        self.assertTrue(report["runs"][0]["results"])


if __name__ == "__main__":
    unittest.main()
