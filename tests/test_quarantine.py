"""V1.3: deletion safety, receipt integrity and actual interpreter behavior."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hookscope.lab import create_lab
from hookscope.quarantine import (find_candidate, quarantine_artifact, restore_artifact,
                                  purge_artifact, list_quarantine)

@unittest.skipUnless(os.name == 'posix', 'quarantine requires safe POSIX file-descriptor operations')
class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name)
        self.root = self.parent / 'scan'
        self.site = self.root / 'lib/python3.13/site-packages'
        self.site.mkdir(parents=True)
        self.pth = self.site / 'hook.pth'
        self.pth.write_text('import hook_mod\n')
        self.vault = self.parent / 'vault'
        self.relative = 'lib/python3.13/site-packages/hook.pth'

    def tearDown(self):
        self.temporary.cleanup()

    def artifact(self):
        return find_candidate(self.root, self.relative)

    def quarantine(self):
        item = self.artifact()
        return quarantine_artifact(self.root, item['path'], item['sha256'], self.vault)

    def test_move_then_restore_same_content(self):
        original = self.pth.read_bytes()
        receipt = self.quarantine()
        self.assertFalse(self.pth.exists())
        self.assertEqual(len(list_quarantine(self.vault)), 1)
        self.assertEqual((self.vault/receipt['id']/'artifact.data').read_bytes(), original)
        back = restore_artifact(self.vault, receipt['id'])
        self.assertEqual(back['status'], 'restored')
        self.assertEqual(self.pth.read_bytes(), original)
        with self.assertRaises(ValueError):
            restore_artifact(self.vault, receipt['id'])

    def test_restore_refuses_overwrite(self):
        receipt = self.quarantine()
        self.pth.write_text('legitimate newer version\n')
        with self.assertRaises(ValueError):
            restore_artifact(self.vault, receipt['id'])
        self.assertEqual(self.pth.read_text(), 'legitimate newer version\n')

    def test_purge_permanently_deletes_quarantined_data(self):
        receipt = self.quarantine()
        final = purge_artifact(self.vault, receipt['id'])
        self.assertEqual(final['status'], 'purged')
        self.assertFalse((self.vault / receipt['id'] / 'artifact.data').exists())
        with self.assertRaises((ValueError, OSError)):
            restore_artifact(self.vault, receipt['id'])

    def test_changed_hash_refused(self):
        item = self.artifact()
        self.pth.write_text('import changed\n')
        with self.assertRaises(ValueError):
            quarantine_artifact(self.root, self.relative, item['sha256'], self.vault)
        self.assertTrue(self.pth.exists())

    def test_symlink_target_refused(self):
        self.pth.unlink()
        outside = self.parent / 'outside.txt'
        outside.write_text('keep me\n')
        self.pth.symlink_to(outside)
        with self.assertRaises((ValueError, OSError)):
            quarantine_artifact(self.root, self.relative, hashlib.sha256(outside.read_bytes()).hexdigest(), self.vault)
        self.assertEqual(outside.read_text(), 'keep me\n')

    def test_symlink_ancestor_refused(self):
        item = self.artifact()
        self.root.rename(self.parent/'original')
        self.root.symlink_to(self.parent/'original')
        with self.assertRaises((ValueError, OSError)):
            quarantine_artifact(self.root, self.relative, item['sha256'], self.vault)
        self.assertTrue((self.parent/'original'/self.relative).exists())

    def test_traversal_refused(self):
        for entry in ('../x.pth', 'a/../x.pth', '/etc/passwd', 'a//b.pth', 'a/./b.pth', 'bad.py'):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                quarantine_artifact(self.root, entry, '0'*64, self.vault)

    def test_private_permissions(self):
        receipt = self.quarantine()
        self.assertEqual(self.vault.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.vault/receipt['id']/'receipt.json').stat().st_mode & 0o777, 0o600)

    def test_no_implicit_noninteractive_changes(self):
        proc = subprocess.run([sys.executable, '-m', 'hookscope', 'quarantine',
                               '--root', str(self.root), '--path', self.relative,
                               '--vault', str(self.vault)],
                              input='', text=True, capture_output=True)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertTrue(self.pth.exists())

    def test_cli_quarantine_and_restore(self):
        proc = subprocess.run([sys.executable, '-m', 'hookscope', 'quarantine',
                               '--root', str(self.root), '--path', self.relative,
                               '--vault', str(self.vault), '--yes'], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.pth.exists())
        entry_id = list_quarantine(self.vault)[0]['id']
        proc = subprocess.run([sys.executable, '-m', 'hookscope', 'restore', '--id', entry_id,
                               '--vault', str(self.vault), '--yes'], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.pth.exists())

    def test_does_not_quarantine_arbitrary_files(self):
        with self.assertRaises(ValueError):
            find_candidate(self.root, 'lib/python3.13/site-packages/unknown.py')

@unittest.skipUnless(os.name == 'posix', 'live venv lab requires POSIX')
class SafeLabTests(unittest.TestCase):
    def test_random_named_scannable_and_quarantine_disables_real_hook(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'safe-lab'
            result = create_lab(root)
            self.assertTrue(result['verified'], result)
            self.assertIn('HOOKSCOPE_LAB_CANARY_EXECUTED', result['verification_output'])
            env = Path(result['venv'])
            relative = Path(result['hook']).relative_to(root).as_posix()
            candidate = find_candidate(root, relative)
            self.assertEqual(candidate['severity'], 'medium')
            self.assertTrue(Path(result['marker']).exists())
            before = Path(result['marker']).read_text()
            # Passive scan MUST NOT execute the hook.
            proc = subprocess.run([sys.executable, '-m', 'hookscope', 'scan', '--root', str(root),
                                   '--format', 'json'], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(before, Path(result['marker']).read_text())
            quarantined = quarantine_artifact(root, relative, candidate['sha256'], Path(temporary)/'vault')
            run = subprocess.run([result['python'], '-c', "print('APP_MAIN')"],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.strip(), 'APP_MAIN')
            self.assertEqual(Path(result['marker']).read_text(), before)
            restored = restore_artifact(Path(temporary)/'vault', quarantined['id'])
            run = subprocess.run([result['python'], '-c', "print('APP_MAIN')"],
                                 capture_output=True, text=True)
            self.assertIn('HOOKSCOPE_LAB_CANARY_EXECUTED', run.stdout)

if __name__ == '__main__':
    unittest.main()

@unittest.skipUnless(os.name == 'posix', 'PTY test requires POSIX')
class InteractiveReviewTests(unittest.TestCase):
    def test_actual_terminal_prompt_quarantines_after_yes(self):
        import pty
        import select
        import time
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'scan'
            site = root / 'lib/python3.13/site-packages'
            site.mkdir(parents=True)
            hook = site / 'real-test.pth'
            hook.write_text('import lab_demo\n')
            vault = Path(temporary) / 'vault'
            master, slave = pty.openpty()
            try:
                process = subprocess.Popen([sys.executable, '-m', 'hookscope', 'scan',
                                            '--root', str(root), '--review', '--vault', str(vault)],
                                           stdin=slave, stdout=slave, stderr=slave, close_fds=True)
                os.close(slave)
                slave = -1
                content = b''
                deadline = time.monotonic() + 12
                sent = False
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], .25)
                    if ready:
                        try:
                            content += os.read(master, 65536)
                        except OSError:
                            break
                        if b'Quarantine this exact file?' in content and not sent:
                            os.write(master, b'y\n')
                            sent = True
                    if process.poll() is not None:
                        break
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                self.assertTrue(sent, content[-2000:])
                self.assertEqual(process.returncode, 0, content[-2000:])
                self.assertFalse(hook.exists())
                self.assertIn('REMOVED FROM STARTUP PATH', content.decode('utf-8', 'replace'))
                self.assertEqual(len(list_quarantine(vault)), 1)
            finally:
                if slave >= 0:
                    os.close(slave)
                os.close(master)
