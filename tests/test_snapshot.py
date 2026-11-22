from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hookscope.iocs import load_hashes
from hookscope.models import ScanOptions
from hookscope.report import finalize, to_html, to_json, to_sarif
from hookscope.snapshot import _safe_read, scan_snapshot


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "root"
        self.site = self.root / "srv/app/.venv/lib/python3.13/site-packages"
        self.site.mkdir(parents=True)
        (self.root / "srv/app/.venv/pyvenv.cfg").write_text(
            "home = /usr/bin\ninclude-system-site-packages = false\n")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, version=None, cap=1024 * 1024):
        return scan_snapshot(self.root, ScanOptions(python_version=version, max_file_bytes=cap), {})

    def artifact(self, name):
        return next(x for x in self.scan()["artifacts"] if x["path"].endswith("/" + name))

    def test_empty_root(self):
        result = self.scan()
        self.assertTrue(result["complete"])
        self.assertEqual(result["stats"]["artifacts"], 0)
        self.assertEqual(result["stats"]["site_directories"], 1)

    def test_executable_pth_recognizes_real_prefix(self):
        (self.site / "a.pth").write_text("# import fake\n import not_executable\nimport real_hook\n")
        result = self.artifact("a.pth")
        self.assertEqual(result["startup_status"], "candidate_executable")
        self.assertEqual(result["imports"][0]["module"], "real_hook")
        self.assertEqual(result["executable_lines"][0]["line"], 3)
        self.assertEqual(len(result["executable_lines"]), 1)

    def test_path_only_pth_not_an_alarm(self):
        (self.site / "paths.pth").write_text("# note\n./src\n")
        result = self.artifact("paths.pth")
        self.assertEqual(result["startup_status"], "path_configuration_only")
        self.assertEqual(result["severity"], "info")

    def test_pth_semicolon_dangerous_call_evidence(self):
        (self.site / "a.pth").write_text("import os; os.system('echo test')\n")
        codes = [i["code"] for i in self.artifact("a.pth")["indicators"]]
        self.assertIn("pth_line_process_execution_candidate", codes)

    def test_import_module_resolved_without_executing(self):
        (self.site / "trigger.pth").write_text("import hook_module\n")
        (self.site / "hook_module.py").write_text("raise AssertionError('should never execute')\n")
        found = self.artifact("trigger.pth")["resolved_imports"][0]
        self.assertEqual(found["status"], "resolved_in_snapshot")
        self.assertIn("module_sha256", found)

    def test_imported_module_ast_indicators(self):
        (self.site / "trigger.pth").write_text("import hook_module\n")
        (self.site / "hook_module.py").write_text("import subprocess\nsubprocess.run(['true'])\n")
        found = self.artifact("trigger.pth")
        self.assertIn("process_execution_candidate", found["resolved_imports"][0]["static_signals"])

    def test_relative_module_resolution_from_pth_added_directory(self):
        other = self.site / "external"
        other.mkdir()
        (other / "bootstrap.py").write_text("pass\n")
        (self.site / "a.pth").write_text("./external\nimport bootstrap\n")
        found = self.artifact("a.pth")
        self.assertEqual(found["resolved_imports"][0]["status"], "resolved_in_snapshot")

    def test_missing_import_does_not_claim_proof_of_nonexecution(self):
        (self.site / "a.pth").write_text("import os\n")
        found = self.artifact("a.pth")["resolved_imports"][0]
        self.assertEqual(found["status"], "not_found_in_snapshot")

    def test_customize_outside_site_is_found_but_unverified(self):
        app = self.root / "project"
        app.mkdir()
        (app / "sitecustomize.py").write_text("print('test')\n")
        found = self.artifact("sitecustomize.py")
        self.assertEqual(found["location"], "outside_site_directory")
        self.assertEqual(found["startup_status"], "candidate_import_path_unverified")

    def test_customize_inside_site_detected(self):
        (self.site / "usercustomize.py").write_text("# normal user site\n")
        self.assertEqual(self.artifact("usercustomize.py")["severity"], "low")

    def test_environment_detected_without_running_interpreter(self):
        (self.site / "a.pth").write_text("import test\n")
        a = self.artifact("a.pth")
        self.assertEqual(a["environment"], "srv/app/.venv")
        self.assertFalse(a["include_system_site_packages"])
        self.assertEqual(a["python_version"], "3.13")
        self.assertIn("mtime_ns", a["filesystem"])

    def test_start_entries_not_executable_before_315(self):
        (self.site / "a.start").write_text("pkg.module:func\n")
        self.assertEqual(self.artifact("a.start")["startup_status"], "not_supported_before_3_15")

    def test_start_entries_315(self):
        (self.site / "a.start").write_text("pkg.module:func\n")
        found = self.scan((3, 15))["artifacts"][0]
        self.assertEqual(found["entry_points"][0]["module"], "pkg.module")
        self.assertEqual(found["entry_points"][0]["callable"], "func")

    def test_start_inline_comment_is_invalid(self):
        (self.site / "a.start").write_text("pkg.mod:run # not valid\n")
        self.assertIn("invalid_start_entry", [i["code"] for i in self.artifact("a.start")["indicators"]])

    def test_315_companion_overrides_executable_pth(self):
        (self.site / "a.pth").write_text("import old\n")
        (self.site / "a.start").write_text("new.module:func\n")
        found = next(a for a in self.scan((3, 15))["artifacts"] if a["kind"] == "pth")
        self.assertEqual(found["startup_status"], "suppressed_by_matching_start")
        self.assertEqual(len(found["imports"]), 1)

    def test_318_legacy_pth_ignored(self):
        (self.site / "a.pth").write_text("import legacy\n")
        found = self.scan((3, 18))["artifacts"][0]
        self.assertEqual(found["startup_status"], "executable_lines_deprecated_ignored")

    def test_320_warning_status(self):
        (self.site / "a.pth").write_text("import legacy\n")
        self.assertEqual(self.scan((3, 20))["artifacts"][0]["startup_status"], "executable_lines_warn_planned")

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires special privileges")
    def test_pth_symlink_cannot_be_read(self):
        external = self.root / "outside.pth"
        external.write_text("import suspicious\n")
        (self.site / "link.pth").symlink_to(external)
        found = self.artifact("link.pth")
        self.assertTrue(found["errors"])
        self.assertFalse(self.scan()["complete"])

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires special privileges")
    def test_symlink_directory_is_not_traversed(self):
        linked = self.root / "outside/site-packages"
        linked.mkdir(parents=True)
        (linked / "x.pth").write_text("import danger\n")
        (self.root / "linked").symlink_to(linked.parent, target_is_directory=True)
        self.assertEqual(len(self.scan()["artifacts"]), 1)

    def test_large_artifact_rejected_incomplete(self):
        (self.site / "big.pth").write_bytes(b"X" * 150)
        found = self.scan(cap=64)
        self.assertFalse(found["complete"])
        self.assertIsNone(found["artifacts"][0]["sha256"])

    def test_ioc_exact_match(self):
        data = b"import known\n"
        (self.site / "a.pth").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        ioc = self.root.parent / "ioc.csv"
        ioc.write_text("Type,Value,Campaign,Role,SourceURL\nsha256," + digest + ",fixture,pth,https://example.org\n")
        try:
            result = scan_snapshot(self.root, ScanOptions(), load_hashes([ioc]))["artifacts"][0]
            self.assertEqual(result["severity"], "high")
            self.assertEqual(result["ioc_matches"][0]["campaign"], "fixture")
        finally:
            ioc.unlink()

    def test_source_lines_default_hidden(self):
        (self.site / "a.pth").write_text("import super_secret\n")
        report = self.artifact("a.pth")
        self.assertNotIn("source", report["executable_lines"][0])
        report = scan_snapshot(self.root, ScanOptions(include_source_lines=True), {})["artifacts"][0]
        self.assertEqual(report["executable_lines"][0]["source"], "import super_secret")

    def test_report_formats_escaped(self):
        (self.site / "a.pth").write_text("import test\n")
        result = finalize(self.scan())
        self.assertEqual(json.loads(to_json(result))["schema_version"], "1.0")
        self.assertEqual(json.loads(to_sarif(result))["version"], "2.1.0")
        self.assertIn("Content-Security-Policy", to_html(result))
        self.assertNotIn("<script>", to_html(result))

    def test_file_limit(self):
        for n in range(3):
            (self.site / f"a{n}.pth").write_text("import test\n")
        report = scan_snapshot(self.root, ScanOptions(max_visited_files=2), {})
        self.assertFalse(report["complete"])
        self.assertTrue(report["issues"])

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires special privileges")
    def test_root_symlink_refused(self):
        link = self.root.parent / "link_to_root"
        link.symlink_to(self.root, target_is_directory=True)
        try:
            with self.assertRaises(ValueError):
                scan_snapshot(link, ScanOptions(), {})
        finally:
            link.unlink()

    def test_pth_header_bom(self):
        (self.site / "a.pth").write_bytes(b"\xef\xbb\xbfimport boot\n")
        self.assertEqual(self.artifact("a.pth")["imports"][0]["module"], "boot")


if __name__ == "__main__":
    unittest.main()

class AdditionalHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.site = self.root / "opt/app/lib/python3.13/site-packages"
        self.site.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_line_count_limit_reports_incomplete(self):
        (self.site / "many.pth").write_text("# comment\n" * 8300 + "import late\n")
        report = scan_snapshot(self.root, ScanOptions(), {})
        self.assertFalse(report["complete"])
        self.assertTrue(report["artifacts"][0]["errors"])

    def test_unmodified_snapshot_scanning(self):
        target = self.site / "startup.pth"
        target.write_text("import demo\n")
        before = target.read_bytes(), target.stat().st_mtime_ns
        scan_snapshot(self.root, ScanOptions(), {})
        after = target.read_bytes(), target.stat().st_mtime_ns
        self.assertEqual(before, after)

    def test_file_with_control_char_is_safe_in_text_report(self):
        from hookscope.report import to_text
        target = self.site / "escape\x1b[31m.pth"
        target.write_text("import demo\n")
        output = to_text(finalize(scan_snapshot(self.root, ScanOptions(), {})))
        self.assertNotIn("\x1b", output)
        self.assertIn("\\x1b", output)

    def test_empty_customize_module_is_inventory(self):
        (self.site / "sitecustomize.py").write_text("\n")
        report = scan_snapshot(self.root, ScanOptions(), {})
        self.assertEqual(report["artifacts"][0]["severity"], "low")
        self.assertFalse(report["artifacts"][0]["resolved_imports"] if "resolved_imports" in report["artifacts"][0] else [])
