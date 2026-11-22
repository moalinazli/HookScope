"""Regression tests from the release audit: previously missed coverage and integrity cases."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from hookscope.analyze import version_from_path
from hookscope.models import ScanOptions
from hookscope.report import finalize
from hookscope.snapshot import scan_snapshot
from hookscope.wheels import scan_wheel


class ReleaseAuditTests(unittest.TestCase):
    def test_free_threaded_python_version(self):
        self.assertEqual(version_from_path('env/lib/python3.13t/site-packages/a.pth'), (3, 13))
        self.assertEqual(version_from_path('env/lib/python3.15/site-packages/a.start'), (3, 15))

    def test_invalid_start_does_not_claim_execution(self):
        with tempfile.TemporaryDirectory() as d:
            site = Path(d) / 'env/lib/python3.15/site-packages'
            site.mkdir(parents=True)
            (site/'a.start').write_text('WRONG ENTRY\n')
            report = scan_snapshot(Path(d), ScanOptions(), {})
            a = report['artifacts'][0]
            self.assertEqual(a['startup_status'], 'invalid_entries_only')
            self.assertFalse(any(x['code'] == 'startup_entry_point' for x in a['indicators']))

    @unittest.skipUnless(sys.platform.startswith('linux') or sys.platform == 'darwin', 'requires symlink support')
    def test_symlink_site_directory_is_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'real').mkdir()
            (root/'real'/'active.pth').write_text('import demo\n')
            (root/'site-packages').symlink_to('real', target_is_directory=True)
            report = scan_snapshot(root, ScanOptions(), {})
            self.assertFalse(report['complete'])
            self.assertTrue(any(x['code'] == 'symlink_directory_skipped' for x in report['issues']))

    def test_malformed_version_is_cli_error_not_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            run = subprocess.run([sys.executable, '-m', 'hookscope', 'scan', '--root', d,
                                  '--python-version', 'invalid'], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(run.returncode, 2)
            self.assertNotIn('Traceback', run.stderr)

    def test_imported_module_known_hash_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            site = Path(d) / 'env/lib/python3.13/site-packages'
            site.mkdir(parents=True)
            module = b'import os\n'
            (site/'x.pth').write_text('import suspect\n')
            (site/'suspect.py').write_bytes(module)
            known = {hashlib.sha256(module).hexdigest(): [
                {'campaign': 'Test', 'role': 'Imported module', 'source_url': 'https://example.org'}]}
            report = scan_snapshot(Path(d), ScanOptions(), known)
            finalize(report)
            self.assertEqual(report['summary']['known_ioc_matches'], 1)
            self.assertEqual(report['artifacts'][0]['severity'], 'high')
            self.assertEqual(report['artifacts'][0]['resolved_imports'][0]['ioc_matches'][0]['campaign'], 'Test')

    @staticmethod
    def wheel(path, files, record_rows=None):
        items = dict(files)
        items['audit-1.0.dist-info/WHEEL'] = b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
        if record_rows is None:
            rows = [[name, 'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode(), str(len(data))]
                    for name, data in items.items()]
        else:
            rows = record_rows
        rows.append(['audit-1.0.dist-info/RECORD','',''])
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerows(rows)
        items['audit-1.0.dist-info/RECORD'] = buf.getvalue().encode()
        with zipfile.ZipFile(path, 'w') as z:
            for name,data in items.items():
                z.writestr(name, data)

    def test_duplicate_record_rows_are_not_trusted(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'audit-1.0-py3-none-any.whl'
            data=b'import hi\n'
            digest=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
            self.wheel(path, {'a.pth': data}, [['a.pth','sha256='+digest,str(len(data))],
                                               ['a.pth','sha256='+digest,str(len(data))]])
            result=scan_wheel(path,ScanOptions(),{})
            self.assertFalse(result['complete'])
            self.assertTrue(any(i['code']=='record_duplicate_row' for i in result['issues']))

    def test_record_size_mismatch_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'audit-1.0-py3-none-any.whl'
            data=b'import hi\n'
            digest=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
            self.wheel(path, {'a.pth':data}, [['a.pth','sha256='+digest,'1']])
            result=scan_wheel(path,ScanOptions(),{})
            self.assertFalse(result['complete'])
            self.assertEqual(result['artifacts'][0]['record_integrity'],'record_size_mismatch')

    def test_known_module_ioc_in_wheel(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'audit-1.0-py3-none-any.whl'
            content=b'import subprocess\n'
            self.wheel(path, {'a.pth': b'import x\n','x.py': content})
            digest=hashlib.sha256(content).hexdigest()
            report=scan_wheel(path, ScanOptions(), {digest:[{'campaign':'Test','role':'module','source_url':'https://example.org'}]})
            finalize(report)
            self.assertEqual(report['summary']['known_ioc_matches'],1)
            self.assertEqual(report['artifacts'][0]['severity'],'high')


if __name__ == '__main__':
    unittest.main()

class DeepInspectionTests(unittest.TestCase):
    def test_parent_initializer_ioc_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            site=Path(d)/'env/lib/python3.13/site-packages'
            package=site/'pkg'
            package.mkdir(parents=True)
            init=b'import os\nos.system("echo demo")\n'
            (package/'__init__.py').write_bytes(init)
            (package/'child.py').write_text('pass\n')
            (site/'a.pth').write_text('import pkg.child\n')
            sha=hashlib.sha256(init).hexdigest()
            known={sha:[{'campaign':'fixture','role':'parent init','source_url':'https://example.org'}]}
            report=scan_snapshot(Path(d),ScanOptions(),known)
            finalize(report)
            self.assertTrue(report['complete'])
            self.assertEqual(report['artifacts'][0]['severity'],'high')
            self.assertEqual(report['summary']['known_ioc_matches'],1)
            parent=report['artifacts'][0]['resolved_imports'][0]['parent_initializers'][0]
            self.assertEqual(parent['sha256'],sha)
            self.assertIn('process_execution_candidate',parent['static_signals'])

    @unittest.skipUnless(os.name == 'posix', 'non-UTF8 filesystem tests require POSIX')
    def test_all_report_formats_handle_non_utf8_filenames(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d,'site-packages'))
            filename=os.fsencode(os.path.join(d,'site-packages'))+b'/odd-\xff.pth'
            with open(filename,'wb') as stream:
                stream.write(b'import os\n')
            for fmt in ('text','json','sarif','html'):
                run=subprocess.run([sys.executable,'-m','hookscope','scan','--root',d,
                                    '--format',fmt],capture_output=True)
                self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace'))
                run.stdout.decode('utf-8')
                if fmt in ('json','sarif'):
                    json.loads(run.stdout)

    def test_interior_symlink_alias_has_full_scan_when_target_is_visited(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            site=root/'lib'/'python3.13'/'site-packages'
            site.mkdir(parents=True)
            (site/'a.pth').write_text('import demo\n')
            if os.name != 'posix':
                self.skipTest('symlink privileges vary across Windows CI')
            (root/'lib64').symlink_to('lib',target_is_directory=True)
            report=scan_snapshot(root,ScanOptions(),{})
            self.assertTrue(report['complete'])
            self.assertEqual(len(report['artifacts']),1)
            self.assertTrue(any(i['code']=='internal_symlink_alias' for i in report['issues']))

class IoCBoundaryTests(unittest.TestCase):
    def test_oversized_ioc_csv_refused(self):
        from hookscope.iocs import load_hashes
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'huge.csv'
            with path.open('wb') as f:
                f.seek(8 * 1024 * 1024)
                f.write(b'!')
            with self.assertRaisesRegex(ValueError,'exceeds 8 MiB'):
                load_hashes([path])
