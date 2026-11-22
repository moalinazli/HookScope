from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from hookscope.models import ScanOptions
from hookscope.wheels import scan_wheel


def make_wheel(path: Path, artifacts: dict[str, bytes], *, changed_record=False):
    """Create a synthetic wheel with installer-style RECORD metadata."""
    items = dict(artifacts)
    metadata = b"Wheel-Version: 1.0\nGenerator: unittest\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    items["demo-1.0.dist-info/WHEEL"] = metadata
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    for name, data in sorted(items.items()):
        digest = hashlib.sha256(data).digest()
        value = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if changed_record and name.endswith(".pth"):
            value = "X" * len(value)
        writer.writerow([name, "sha256=" + value, len(data)])
    writer.writerow(["demo-1.0.dist-info/RECORD", "", ""])
    items["demo-1.0.dist-info/RECORD"] = buf.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for name, data in items.items():
            wheel.writestr(name, data)


class WheelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "demo-1.0-py3-none-any.whl"

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, version=None):
        return scan_wheel(self.path, ScanOptions(python_version=version), {})

    def test_purelib_pth_and_module_resolution(self):
        make_wheel(self.path, {
            "demo-1.0.data/purelib/startup.pth": b"import helper\n",
            "demo-1.0.data/purelib/helper.py": b"import subprocess\nsubprocess.run(['true'])\n",
        })
        report = self.scan()
        self.assertTrue(report["complete"])
        self.assertEqual(report["stats"]["artifacts"], 1)
        artifact = report["artifacts"][0]
        self.assertEqual(artifact["record_integrity"], "matches_record")
        self.assertEqual(artifact["resolved_imports"][0]["status"], "resolved_in_snapshot")
        self.assertEqual(artifact["severity"], "medium")

    def test_wheel_root_pth(self):
        make_wheel(self.path, {"top.pth": b"import helper\n", "helper.py": b"pass\n"})
        found = self.scan()["artifacts"][0]
        self.assertEqual(found["wheel_location"], "wheel_root")
        self.assertEqual(found["deployment_state"], "not_installed")
        self.assertEqual(found["record_integrity"], "matches_record")

    def test_platlib_pth(self):
        make_wheel(self.path, {"demo-1.0.data/platlib/test.pth": b"import helper\n"})
        self.assertEqual(self.scan()["artifacts"][0]["wheel_location"], "platlib")

    def test_wheel_start_only_on_315(self):
        make_wheel(self.path, {"a.start": b"pkg.module:initialize\n"})
        self.assertEqual(self.scan((3, 14))["artifacts"][0]["startup_status"], "not_supported_before_3_15")
        self.assertEqual(self.scan((3, 15))["artifacts"][0]["startup_status"], "candidate_executable")

    def test_companion_pth_suppressed(self):
        make_wheel(self.path, {"a.start": b"new.module:initialize\n", "a.pth": b"import old\n"})
        pth = next(x for x in self.scan((3, 15))["artifacts"] if x["kind"] == "pth")
        self.assertEqual(pth["startup_status"], "suppressed_by_matching_start")

    def test_record_modified(self):
        make_wheel(self.path, {"trigger.pth": b"import demo\n"}, changed_record=True)
        result = self.scan()
        self.assertFalse(result["complete"])
        self.assertEqual(result["artifacts"][0]["record_integrity"], "record_mismatch")

    def test_data_scripts_are_not_startup_file(self):
        make_wheel(self.path, {"demo-1.0.data/scripts/a.pth": b"import demo\n"})
        self.assertEqual(self.scan()["artifacts"], [])

    def test_zip_traversal_rejected_without_extraction(self):
        make_wheel(self.path, {"../outside.pth": b"import demo\n", "good.pth": b"import safe\n"})
        report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["artifacts"]), 1)
        self.assertTrue(any(i["code"] == "unsafe_wheel_member" for i in report["issues"]))
        self.assertFalse((Path(self.tmp.name).parent / "outside.pth").exists())

    def test_invalid_zip_rejected(self):
        self.path.write_bytes(b"not zip")
        with self.assertRaises(ValueError):
            self.scan()

    def test_zip_total_limit(self):
        make_wheel(self.path, {"big.py": b"X" * 10000})
        with self.assertRaises(ValueError):
            scan_wheel(self.path, ScanOptions(max_wheel_total_bytes=100), {})

    def test_member_size_limit(self):
        make_wheel(self.path, {"big.pth": b"X" * 128})
        report = scan_wheel(self.path, ScanOptions(max_file_bytes=40), {})
        self.assertFalse(report["complete"])
        self.assertTrue(report["artifacts"][0]["errors"])

    def test_valid_wheel_has_its_sha256(self):
        make_wheel(self.path, {"a.pth": b"import test\n"})
        report = self.scan()
        self.assertEqual(report["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()

class WheelCrossLocationTests(unittest.TestCase):
    def test_root_pth_and_purelib_start_are_companions(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "demo-1.0-py3-none-any.whl"
            make_wheel(target, {
                "a.pth": b"import old\n",
                "demo-1.0.data/purelib/a.start": b"new.mod:run\n",
                "demo-1.0.data/purelib/new/mod.py": b"def run(): pass\n",
            })
            report = scan_wheel(target, ScanOptions(python_version=(3, 15)), {})
            pth = next(r for r in report["artifacts"] if r["kind"] == "pth")
            entry = next(r for r in report["artifacts"] if r["kind"] == "start")
            self.assertEqual(pth["startup_status"], "suppressed_by_matching_start")
            self.assertEqual(entry["resolved_imports"][0]["status"], "resolved_in_snapshot")
