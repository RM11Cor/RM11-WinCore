#!/usr/bin/env python3
"""KERNIX G2-C: link exact pinned glibc/loader ELF to a distro package notice.

AUDIT ONLY: does not ship guest binaries, grant distribution approval or
execute original FEX, guest ld-linux/glibc, Wine or Windows code.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

from kernix_g2c_fixture_gate import FILES

LIBC = 'lib/x86_64-linux-gnu/libc.so.6'
LOADER = 'lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
ALIAS = 'lib64/ld-linux-x86-64.so.2'
EXPECTED_PACKAGE = 'libc6-amd64-cross'
SOURCE_PACKAGE_NAMES = {'cross-toolchain-base', 'cross-toolchain-base-ports'}
PACKAGE_PATHS = {'libc.so.6': LIBC, 'ld-linux-x86-64.so.2': LOADER}


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def audit_exact_guest_package(fixture: Path, cross_lib: Path,
                              copyright_path: Path, package: str,
                              version: str, source: str):
    """Return evidence only after exact package provenance + licensing checks."""
    if package != EXPECTED_PACKAGE or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', version):
        raise ValueError('Cross-libc package identity/version rejected')
    if source not in SOURCE_PACKAGE_NAMES:
        raise ValueError('Cross-libc source package identity rejected')
    fixture = Path(fixture)
    raw = json.loads((fixture/'PROVENANCE.json').read_text())
    if (raw.get('schema') != 'kernix.g2c.android-handoff-CI-only.v1'
            or raw.get('licenses_reviewed_for_distribution') is not False
            or raw.get('android_apk_packaged') is not False
            or raw.get('android_guest_execution_verified') is not False):
        raise ValueError('Existing CI-only provenance was silently upgraded')
    manifest = json.loads((fixture/'manifest.json').read_text())
    if set(manifest.get('files', {})) != set(FILES):
        raise ValueError('Guest fixture allowlist changed')
    for file_name, (expected_len, expected_sha) in FILES.items():
        item = fixture/file_name
        if item.is_symlink() or not item.is_file():
            raise ValueError('Unexpected guest fixture symlink or missing file: '+file_name)
        blob = item.read_bytes()
        if len(blob) != expected_len or sha(blob) != expected_sha:
            raise ValueError('Guest fixture changed: '+file_name)
    if (fixture/LOADER).read_bytes() != (fixture/ALIAS).read_bytes():
        raise ValueError('Identical ld-linux interpreter copies changed')
    for pkg_filename, guest_name in PACKAGE_PATHS.items():
        path = Path(cross_lib)/pkg_filename
        if not path.is_file() or path.is_symlink():
            raise ValueError('Cross package ELF file unavailable: '+pkg_filename)
        blob = path.read_bytes()
        if sha(blob) != FILES[guest_name][1] or len(blob) != FILES[guest_name][0]:
            raise ValueError('Installed distro cross package differs from pinned x86 guest: '+pkg_filename)
    if not copyright_path.is_file() or copyright_path.is_symlink():
        raise ValueError('Source package copyright notice missing')
    notice = copyright_path.read_bytes()
    if len(notice) < 100 or len(notice) > 1024 * 1024:
        raise ValueError('Copyright notice size invalid')
    decoded = notice.decode('utf-8')
    if 'LGPL' not in decoded or not re.search(r'(?:LGPL|Lesser General Public License).*2\.1', decoded, re.I | re.S):
        raise ValueError('Source copyright does not identify LGPL-2.1')
    return {
        'schema':'kernix.g2c.exact-libc-binary-license-review.v1',
        'package':package,
        'version':version,
        'source_package':source,
        'guest_file_sha256':{k:v[1] for k,v in FILES.items()},
        'installed_cross_libc_exact_hash_match':True,
        'installed_cross_dynamic_loader_exact_hash_match':True,
        'upstream_package_copyright_sha256':sha(notice),
        'upstream_package_copyright_bytes':len(notice),
        'license_notice_available':True,
        'license_reviewed_for_distribution':False,
        'distribution_approved':False,
        'guest_interpreter_or_glibc_executed':False,
        'fex_guest_executed_on_android':False,
        'wine_games_executed_on_android':False,
        'note':'Exact package/notice identification ONLY. Relink/source-availability and distribution obligations need separate human review.'
    }


def main(argv):
    if len(argv) != 8:
        raise ValueError(
            'Usage: script FIXTURE CROSS_LIB_DIR COPYRIGHT PACKAGE VERSION SOURCE OUT_JSON')
    _, fixture, cross_lib, copyright, package, version, source, output = argv
    evidence = audit_exact_guest_package(
        Path(fixture),Path(cross_lib),Path(copyright),package,version,source)
    result = Path(output)
    result.parent.mkdir(parents=True,exist_ok=True)
    result.write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n')
    print('KERNIX_G2C_EXACT_BINARY_CROSS_PACKAGE_LICENSING_IDENTITY_PASS_NO_REDISTRIBUTION')


if __name__=='__main__':
    try:
        main(sys.argv)
    except (OSError, ValueError, KeyError) as exc:
        print('KERNIX_G2C_GUEST_LICENSE_IDENTITY_REJECTED:',exc,file=sys.stderr)
        raise SystemExit(2) from exc
