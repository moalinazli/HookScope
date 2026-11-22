"""V1.4 regression coverage: public CLI, diff integrity, safe vault audit, and TTY branding."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hookscope.banner import render
from hookscope.diff import compare, load_report, format_text
from hookscope.quarantine import find_candidate, quarantine_artifact, verify_quarantine, restore_artifact, purge_artifact


def document(root="/mnt/evidence", artifacts=None, complete=True):
    return {"scan_type": "snapshot", "target": root, "complete": complete,
            "artifacts": artifacts if artifacts is not None else []}


def artifact(path="lib/python3.13/site-packages/sample.pth", sha=None, sev="medium"):
    return {"path": path, "sha256": sha or "1" * 64, "kind": "pth",
            "startup_status": "candidate_executable", "severity": sev}


class BannerTests(unittest.TestCase):
    def test_banner_silent_on_noninteractive_stream(self):
        destination = io.StringIO()
        self.assertFalse(render(stream=destination))
        self.assertEqual(destination.getvalue(), "")

    def test_banner_forced_has_author_not_fake_detection(self):
        destination = io.StringIO()
        render(stream=destination, force=True, version="v1.4.0", width=80)
        self.assertIn("NAZLABADI", destination.getvalue())
        self.assertIn("HOOKSCOPE", destination.getvalue())
        self.assertNotIn("MALWARE FOUND", destination.getvalue())

    def test_banner_very_narrow_terminal(self):
        destination = io.StringIO()
        render(stream=destination, force=True, version="v1.4.0", width=18)
        self.assertIn("HookScope v1.4.0", destination.getvalue())

    def test_banner_compact(self):
        destination = io.StringIO()
        render(stream=destination, force=True, version="v1.4.0", width=40)
        self.assertIn("PYTHON STARTUP AUDITOR", destination.getvalue())

    def test_banner_explicit_cli(self):
        result = subprocess.run([sys.executable, "-m", "hookscope", "banner", "--no-color"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NAZLABADI", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_json_cli_has_no_banner_even_when_asked_for_regular_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, "-m", "hookscope", "scan", "--root", tmp,
                                     "--format", "json"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["scan_type"], "snapshot")
            self.assertNotIn("NAZLABADI", result.stdout)

    @unittest.skipUnless(os.name == "posix", "pseudo-terminal required")
    def test_real_tty_scan_banner_and_no_banner(self):
        import pty
        import select
        with tempfile.TemporaryDirectory() as directory:
            for suppress in (False, True):
                master, slave = pty.openpty()
                try:
                    cmd = [sys.executable, "-m", "hookscope", "scan", "--root", directory]
                    if suppress:
                        cmd.append("--no-banner")
                    proc = subprocess.Popen(cmd, stdout=slave, stderr=slave, stdin=slave, close_fds=True,
                                            env={**os.environ, "TERM": "xterm-256color"})
                    os.close(slave)
                    slave = -1
                    output = b""
                    while proc.poll() is None:
                        readable, _, _ = select.select([master], [], [], 0.2)
                        if readable:
                            try:
                                output += os.read(master, 65536)
                            except OSError:
                                break
                    while True:
                        try:
                            data = os.read(master, 65536)
                            if not data:
                                break
                            output += data
                        except OSError:
                            break
                    self.assertEqual(proc.wait(timeout=3), 0, output[-2000:])
                    self.assertEqual(b"NAZLABADI" in output, not suppress)
                finally:
                    if slave >= 0:
                        os.close(slave)
                    os.close(master)


class DiffTests(unittest.TestCase):
    def test_unmodified(self):
        x = document(artifacts=[artifact()])
        result = compare(x, x)
        self.assertEqual(result["unchanged"], 1)
        self.assertFalse(result["changed"])

    def test_added_removed_modified(self):
        a = artifact(sha="0" * 64)
        b = artifact(sha="2" * 64)
        old = document(artifacts=[a, artifact("a.pth")])
        new = document(artifacts=[b, artifact("b.pth")])
        result = compare(old, new)
        self.assertEqual([len(result[key]) for key in ("added", "removed", "modified")], [1, 1, 1])
        self.assertTrue(result["changed"])
        self.assertIn("sha256", result["modified"][0]["changes"])

    def test_imported_module_change_detected_without_pth_change(self):
        before = artifact()
        after = artifact()
        before["resolved_imports"] = [{"module": "helper", "module_sha256": "a" * 64}]
        after["resolved_imports"] = [{"module": "helper", "module_sha256": "b" * 64}]
        comparison = compare(document(artifacts=[before]), document(artifacts=[after]))
        self.assertTrue(comparison["changed"])
        self.assertIn("resolved_imports_digest", comparison["modified"][0]["changes"])

    def test_mismatched_root_fails_closed(self):
        with self.assertRaises(ValueError):
            compare(document("/tmp/a"), document("/tmp/b"))
        self.assertFalse(compare(document("/tmp/a"), document("/tmp/b"), allow_different_root=True)["changed"])

    def test_duplicate_artifact_path_rejected(self):
        with self.assertRaises(ValueError):
            compare(document(artifacts=[artifact(), artifact()]), document())

    def test_untrusted_filename_is_escaped_in_terminal(self):
        report = compare(document(), document(artifacts=[artifact("\x1b[31m.pth")]))
        text = format_text(report)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\u001b", text)

    def test_incomplete_report_warning(self):
        result = compare(document(complete=False), document())
        self.assertIn("WARNING", format_text(result))

    def test_reject_large_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "big.json"
            with p.open("wb") as handle:
                handle.truncate(32 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                load_report(p)

    def test_invalid_json_and_missing_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "r.json"
            for raw in ('{ not json }', '{"scan_type":"snapshot"}', '[]'):
                p.write_text(raw)
                with self.assertRaises(ValueError):
                    load_report(p)

    def test_diff_cli_exit_status_and_machine_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            before, after = Path(tmp) / "before.json", Path(tmp) / "after.json"
            before.write_text(json.dumps(document()))
            after.write_text(json.dumps(document(artifacts=[artifact()])))
            result = subprocess.run([sys.executable, "-m", "hookscope", "diff", "--old", str(before),
                                     "--new", str(after), "--format", "json", "--fail-on-change"],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertTrue(json.loads(result.stdout)["changed"])
            self.assertNotIn("NAZLABADI", result.stdout)


@unittest.skipUnless(os.name == "posix", "quarantine supports POSIX")
class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "root"
        self.site = self.root / "lib/python3.13/site-packages"
        self.site.mkdir(parents=True)
        self.file = self.site / "test.pth"
        self.file.write_text("import test_module\n")
        self.vault = Path(self.tmp.name) / "vault"
        self.relative = "lib/python3.13/site-packages/test.pth"

    def quarantine(self):
        item = find_candidate(self.root, self.relative)
        return quarantine_artifact(self.root, self.relative, item["sha256"], self.vault)

    def test_quarantined_artifact_verifies(self):
        self.quarantine()
        result = verify_quarantine(self.vault)
        self.assertTrue(result["ok"])
        self.assertEqual(result["checked"], 1)

    def test_vault_tampering_detected(self):
        receipt = self.quarantine()
        (self.vault / receipt["id"] / "artifact.data").write_text("changed")
        result = verify_quarantine(self.vault)
        self.assertFalse(result["ok"])
        self.assertEqual(result["problems"], 1)

    def test_missing_data_detected(self):
        receipt = self.quarantine()
        (self.vault / receipt["id"] / "artifact.data").unlink()
        self.assertFalse(verify_quarantine(self.vault)["ok"])

    def test_valid_restored_receipt(self):
        receipt = self.quarantine()
        restore_artifact(self.vault, receipt["id"])
        self.assertTrue(verify_quarantine(self.vault)["ok"])

    def test_valid_purged_receipt(self):
        receipt = self.quarantine()
        purge_artifact(self.vault, receipt["id"])
        self.assertTrue(verify_quarantine(self.vault)["ok"])

    def test_hardlinked_source_refused(self):
        link = Path(self.tmp.name) / "other-link.pth"
        os.link(self.file, link)
        candidate = find_candidate(self.root, self.relative)
        with self.assertRaisesRegex(ValueError, "multiple hard links"):
            quarantine_artifact(self.root, self.relative, candidate["sha256"], self.vault)
        self.assertTrue(self.file.exists())
        self.assertTrue(link.exists())

    def test_verify_cli_returns_nonzero_on_corruption(self):
        receipt = self.quarantine()
        (self.vault / receipt["id"] / "artifact.data").write_text("different")
        proc = subprocess.run([sys.executable, "-m", "hookscope", "quarantine-verify", "--vault", str(self.vault),
                               "--format", "json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["problems"], 1)

    def test_verify_cli_success(self):
        self.quarantine()
        proc = subprocess.run([sys.executable, "-m", "hookscope", "quarantine-verify", "--vault", str(self.vault)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Problems: 0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
