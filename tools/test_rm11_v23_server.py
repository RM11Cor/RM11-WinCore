#!/usr/bin/env python3
"""Host smoke-check for the *real* V2.3 Android ARM64 server bridge source.
This is NOT an ARM64/Android execution test; CI builds actual target binary.
"""
from pathlib import Path
import os, shutil, subprocess, tempfile
ROOT=Path(__file__).resolve().parent.parent
SRC=ROOT/'app/src/main/cpp/WineServerBridge.c'
compiler=shutil.which('cc')
if not compiler:
    raise SystemExit('SKIP: host C compiler unavailable')
with tempfile.TemporaryDirectory(prefix='rm11-v23-server-') as td:
    base=Path(td); ndir=base/'native'; ndir.mkdir()
    app=ndir/'librm11wineserverbridge.so'
    subprocess.run([compiler,'-D_GNU_SOURCE','-std=c11','-Wall','-Wextra','-Werror',
                    '-fPIE','-pie',str(SRC),'-o',str(app)],check=True)
    box=ndir/'librm11box64.so'
    box.write_text('#!/bin/sh\nprintf "RM11_TEST_BOX64_ARG=%s\\n" "$1"\n')
    box.chmod(0o755)
    wine=base/'user/usr/lib/wine'
    wine.mkdir(parents=True)
    server64=wine/'wineserver64'
    server64.write_text('synthetic wineserver64 path; never executed in preflight')
    env=os.environ.copy()
    env['RM11_WINESERVER64_PATH']=str(server64)
    success=subprocess.run([str(app),'--rm11-self-test'],capture_output=True,text=True,env=env)
    assert success.returncode==0 and 'RM11_WINESERVER_BRIDGE_PREFLIGHT_OK' in success.stdout,(success.stderr,success.stdout)
    link=wine/'wineserver'
    link.symlink_to(app)
    child=subprocess.run([str(link),'--diagnose-only'],capture_output=True,text=True,env=env)
    assert child.returncode==0,(child.stderr,child.stdout)
    assert 'RM11_WINESERVER_BRIDGE_ENTERED' in child.stderr
    assert 'RM11_TEST_BOX64_ARG=' + str(server64) in child.stdout
    env['RM11_WINESERVER64_PATH']='/tmp/untrusted/server64'
    bad=subprocess.run([str(app),'--rm11-self-test'],capture_output=True,text=True,env=env)
    assert bad.returncode==91 and 'RM11_WINESERVER_BRIDGE_BAD_SERVER_PATH' in bad.stderr
print('PASS RM11 V2.3 real ARM64 bridge C source host preflight, symlink spawn, invalid path fail-closed')
