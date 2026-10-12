#!/usr/bin/env python3
"""Host smoke test for the first-party Android PIE source, not an Android test."""
import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
cc = shutil.which('cc')
assert cc, 'Host C compiler needed for V1.1 smoke test'
with tempfile.TemporaryDirectory(prefix='rm11-host-exec-') as directory:
    program = Path(directory) / 'rm11-test'
    subprocess.run([cc, '-Wall', '-Wextra', '-Werror', '-fPIE', '-pie',
                    str(root/'app/src/main/cpp/PackagedExecProbe.c'),
                    '-o', str(program)], check=True)
    good = subprocess.run([str(program), '--self-test'], capture_output=True, text=True, check=True)
    assert 'RM11_ANDROID_ELF_EXEC_OK' in good.stdout
    assert 'PAGE_SIZE=' in good.stdout
    bad = subprocess.run([str(program), '--unexpected'], capture_output=True, text=True)
    assert bad.returncode == 2
    print('PASS: V1.1 standalone ELF host smoke test and argument restriction')
