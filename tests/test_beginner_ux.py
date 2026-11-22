"""First-run and Termux UX regression tests for v1.5."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def run_cli(*args, env=None):
    return subprocess.run([sys.executable, '-m', 'hookscope', *map(str, args)],
                          capture_output=True, text=True, env=env)


class BeginnerUXTests(unittest.TestCase):
    def test_no_args_in_pipe_is_quick_guide_not_blocking(self):
        r = run_cli()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('hookscope start', r.stdout)
        self.assertIn('hookscope report', r.stdout)
        self.assertIn('No files are removed', r.stdout)

    def test_help_alias_and_command_topic(self):
        self.assertIn('START HERE', run_cli('help').stdout)
        s = run_cli('help', 'scan')
        self.assertEqual(s.returncode, 0, s.stderr)
        self.assertIn('--root', s.stdout)
        self.assertIn('--review', s.stdout)
        self.assertEqual(run_cli('help', 'nonexistent').returncode, 2)

    def test_doctor_does_not_auto_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            env = {**os.environ, 'HOME': temp, 'PREFIX': '/nonexistent/not-termux'}
            r = run_cli('doctor', env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('not detected', r.stdout)
            self.assertFalse((Path(temp) / 'hookscope-reports').exists())

    def test_beginner_start_saves_two_valid_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / 'snapshot'
            site = root / 'lib/python3.13/site-packages'
            site.mkdir(parents=True)
            (site / 'canary.pth').write_text('import harmless_module\n')
            reports = base / 'reports'
            r = run_cli('start', '--root', root, '--report-dir', reports, '--no-open')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('Startup files found: 1', r.stdout)
            self.assertIn('NOT proof of malware', r.stdout)
            json_paths = list(reports.glob('scan-*.json'))
            html_paths = list(reports.glob('scan-*.html'))
            self.assertEqual(len(json_paths), 1)
            self.assertEqual(len(html_paths), 1)
            self.assertEqual(json.loads(json_paths[0].read_text())['stats']['artifacts'], 1)
            html = html_paths[0].read_text()
            self.assertIn('How to use this report', html)
            self.assertIn('hookscope start', html)
            self.assertIn('Advanced: verify folders', html)
            self.assertIn('details class="panel advanced-help"', html)
            self.assertNotIn('How to verify the scope</h2>', html)
            q = run_cli('report', '--report-dir', reports, '--path-only')
            self.assertEqual(q.returncode, 0, q.stderr)
            self.assertIn(str(html_paths[0]), q.stdout)

    def test_start_with_zero_finding_explains_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'scope'
            (root / 'lib/python3.13/site-packages').mkdir(parents=True)
            reports = Path(temp) / 'reports'
            r = run_cli('start', '--root', root, '--report-dir', reports, '--no-open')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('NOT proof the device is clean', r.stdout)
            self.assertIn('quarantined a file earlier', r.stdout)

    def test_termux_start_default_folder(self):
        with tempfile.TemporaryDirectory(prefix='com.termux-tests-') as temp:
            prefix = Path(temp) / 'usr'
            (prefix / 'lib/python3.13/site-packages').mkdir(parents=True)
            reports = Path(temp) / 'out'
            env = {**os.environ, 'PREFIX': str(prefix)}
            r = run_cli('start', '--report-dir', reports, '--no-open', env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(str(prefix / 'lib'), r.stdout)
            self.assertTrue(any(reports.glob('scan-*.html')))

    def test_default_without_termux_requires_root(self):
        r = run_cli('start', '--no-open', env={**os.environ, 'PREFIX': '/usr'})
        self.assertEqual(r.returncode, 2)
        self.assertIn('--root', r.stdout)

    def test_report_missing_and_missing_root_are_friendly(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(run_cli('report', '--report-dir', temp).returncode, 2)
            r = run_cli('start', '--root', Path(temp) / 'not_here')
            self.assertEqual(r.returncode, 2)
            self.assertIn('does not exist', r.stderr)
            self.assertNotIn('Traceback', r.stderr)

    def test_do_not_write_reports_inside_scan_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'scope'
            root.mkdir()
            r = run_cli('start', '--root', root, '--report-dir', root / 'reports')
            self.assertEqual(r.returncode, 2)
            self.assertFalse((root / 'reports').exists())

    def test_export_requires_explicit_approval_and_copies_both_files(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            scan = base / 'scan'; (scan / 'lib/python3.13/site-packages').mkdir(parents=True)
            reports = base / 'reports'; downloads = base / 'Download'; downloads.mkdir()
            self.assertEqual(run_cli('start', '--root', scan, '--report-dir', reports, '--no-open').returncode, 0)
            refused = run_cli('export', '--report-dir', reports, '--output-dir', downloads)
            self.assertEqual(refused.returncode, 2)
            self.assertEqual(list(downloads.iterdir()), [])
            exported = run_cli('export', '--report-dir', reports, '--output-dir', downloads, '--yes')
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertEqual(len(list(downloads.iterdir())), 2)
            exported_json = next(downloads.glob('*.json'))
            self.assertEqual(json.loads(exported_json.read_text())['scan_type'], 'snapshot')
            again = run_cli('export', '--report-dir', reports, '--output-dir', downloads, '--yes')
            self.assertEqual(again.returncode, 2)
            self.assertIn('no file overwritten', again.stderr)

    def test_export_refuses_without_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            reports = Path(temp) / 'reports'; reports.mkdir()
            (reports / 'scan-20261122.html').write_text('<html></html>')
            exports = Path(temp) / 'downloads'; exports.mkdir()
            r = run_cli('export', '--report-dir', reports, '--output-dir', exports, '--yes')
            self.assertEqual(r.returncode, 2)
            self.assertIn('Matching JSON', r.stderr)
            self.assertEqual(list(exports.iterdir()), [])

    @unittest.skipUnless(os.name == 'posix', 'PTY requires POSIX')
    def test_interactive_menu_exits_with_zero(self):
        import pty
        import select
        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen([sys.executable, '-m', 'hookscope'],
                                    stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                                    env={**os.environ, 'TERM': 'dumb'})
            os.close(slave)
            slave = -1
            os.write(master, b'0\n')
            buf = b''
            for _ in range(50):
                readable, _, _ = select.select([master], [], [], 0.1)
                if readable:
                    try:
                        buf += os.read(master, 4096)
                    except OSError:
                        break
                if proc.poll() is not None:
                    break
            self.assertEqual(proc.wait(timeout=3), 0, buf[-500:])
            self.assertIn(b'Choose [0-7]:', buf)
            self.assertIn(b'Goodbye', buf)
        finally:
            if slave >= 0:
                os.close(slave)
            os.close(master)


if __name__ == '__main__':
    unittest.main()
