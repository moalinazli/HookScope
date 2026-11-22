"""Visible, scoped canary startup hook for validation; never a malware sample."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import venv


def create_lab(root: Path, *, verify: bool = True) -> dict:
    root = Path(os.path.abspath(root))
    if root in (Path('/'), Path.home(), Path('/tmp')):
        raise ValueError('choose a dedicated lab root, e.g. ~/hookscope-lab')
    # Never trust a symlink in the lab root or any existing parent.
    walk = Path(root.anchor)
    for part in root.parts[1:]:
        walk = walk / part
        if walk.is_symlink():
            raise ValueError('lab directory ancestry contains a symlink')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    leaf = root / ('lab-' + secrets.token_hex(4))
    leaf.mkdir(mode=0o700)
    env = leaf / 'env'
    try:
        venv.EnvBuilder(with_pip=False, symlinks=False).create(env)
        site = env / 'lib' / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'site-packages'
        if not site.is_dir():
            raise RuntimeError('this interpreter did not create a standard POSIX venv site-packages directory')
        marker = leaf / 'hook-executed.log'
        source = ("# HookScope test canary: no secrets, no internet, no system modification\n"
                  "from pathlib import Path\n"
                  f"Path({str(marker)!r}).open('a', encoding='utf-8').write('HOOK_STARTED\\n')\n"
                  "print('HOOKSCOPE_LAB_CANARY_EXECUTED')\n")
        (site / 'hookscope_canary.py').write_text(source, encoding='utf-8')
        (site / 'hookscope_lab.pth').write_text('import hookscope_canary\n', encoding='utf-8')
        interpreter = env / 'bin' / 'python'
        manifest = {
            'kind': 'hookscope_safe_test_lab', 'scope': str(leaf),
            'venv': str(env), 'python': str(interpreter),
            'hook': str(site / 'hookscope_lab.pth'),
            'marker': str(marker), 'behavior': 'local marker + terminal canary only',
        }
        (leaf / 'lab.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        if verify:
            # This explicitly executes ONLY the newly generated benign lab hook.
            run = subprocess.run([str(interpreter), '-c', "print('APP_MAIN')"],
                                 capture_output=True, text=True, timeout=20, check=False)
            manifest['verification_exit_code'] = run.returncode
            manifest['verification_output'] = run.stdout.strip()
            manifest['verified'] = (run.returncode == 0 and marker.exists()
                                    and 'HOOKSCOPE_LAB_CANARY_EXECUTED' in run.stdout)
            if not manifest['verified']:
                manifest['verification_stderr'] = run.stderr.strip()[-1000:]
        return manifest
    except Exception:
        # Keep the failed scoped environment for examination; no blind rm -rf.
        raise
