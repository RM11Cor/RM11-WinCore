#!/usr/bin/env python3
"""Strict negative tests for licensing metadata + exact original guest ELF bytes.

The positive local test intentionally uses a FAKE copyright and the copied
known fixture bytes: it is a unit test, NOT a legal/package-source attestation.
Only the separate dpkg-owned CI gate establishes actual distro package origin.
"""
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'tools'))
from kernix_g2c_exact_libc_package_license_audit import audit_exact_guest_package

def rejected(action, label):
    try:
        action()
    except (ValueError,OSError):
        return
    raise AssertionError('Invalid license/ELF input accepted: '+label)

def test(fixture):
    with tempfile.TemporaryDirectory(prefix='kernix-g2c-license-audit-') as tmp:
        tmp=Path(tmp)
        src=tmp/'fixture'
        shutil.copytree(fixture,src)
        cross=tmp/'cross'
        cross.mkdir()
        shutil.copy2(src/'lib/x86_64-linux-gnu/libc.so.6',cross/'libc.so.6')
        shutil.copy2(src/'lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',cross/'ld-linux-x86-64.so.2')
        copyright=tmp/'copyright'
        copyright.write_text('Synthetic testing fixture, NOT a real copyright notice.\n' +
                             'Example test tag: LGPL-2.1.\n'+'*'*120)
        good=lambda: audit_exact_guest_package(src,cross,copyright,
                    'libc6-amd64-cross','2.39-0ubuntu8cross1',
                    'cross-toolchain-base')
        output=good()
        assert output['installed_cross_libc_exact_hash_match']
        assert output['installed_cross_dynamic_loader_exact_hash_match']
        assert output['distribution_approved'] is False
        assert output['license_reviewed_for_distribution'] is False
        assert output['fex_guest_executed_on_android'] is False

        def unsupported_package():
            return audit_exact_guest_package(src,cross,copyright,
                   'libc6-host-amd64','2.39-0ubuntu8cross1','cross-toolchain-base')
        rejected(unsupported_package,'wrong package')
        rejected(lambda:audit_exact_guest_package(src,cross,copyright,
                 'libc6-amd64-cross','x','cross-toolchain-base'),'wrong version')
        rejected(lambda:audit_exact_guest_package(src,cross,copyright,
                 'libc6-amd64-cross','2.39-0ubuntu8cross1','unknown-source'),
                 'unknown source')

        f=cross/'libc.so.6'
        before=f.read_bytes()
        f.write_bytes(before[:100]+bytes([before[100]^0x80])+before[101:])
        rejected(good,'cross package libc digest')
        f.write_bytes(before)

        f=cross/'ld-linux-x86-64.so.2'
        before=f.read_bytes()
        f.write_bytes(before[:-1]+bytes([before[-1]^1]))
        rejected(good,'cross package interpreter digest')
        f.write_bytes(before)

        f=src/'lib64/ld-linux-x86-64.so.2'
        before=f.read_bytes()
        f.write_bytes(before[:-1]+bytes([before[-1]^1]))
        rejected(good,'guest loader duplicate mismatch')
        f.write_bytes(before)

        original=copyright.read_text()
        copyright.write_text('Unknown proprietary license\n'+'X'*130)
        rejected(good,'missing LGPL notice')
        copyright.write_text(original)

        f=src/'PROVENANCE.json'
        original=f.read_text()
        data=json.loads(original)
        data['licenses_reviewed_for_distribution']=True
        f.write_text(json.dumps(data))
        rejected(good,'silent licensing status upgrade')
        f.write_text(original)
        assert good()['distribution_approved'] is False
        print('KERNIX_G2C_LIBC_LICENSING_SOURCE_AND_TAMPER_NEGATIVE_TESTS_PASS_NO_DISTRIBUTION')

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: test_g2c_libc_licensing_audit.py FIXTURE')
    test(Path(sys.argv[1]))
