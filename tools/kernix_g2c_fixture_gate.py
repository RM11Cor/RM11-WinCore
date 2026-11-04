#!/usr/bin/env python3
"""Fail-closed handoff of one FEX-proven x86 guest bundle to Android CI.

No guest execution, process spawn, Android APK build, or distribution.
glibc and ld-linux are CI-only inputs pending runtime and license gates.
"""
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tarfile

SOURCE_SHA = '76b553c283c2f487d0feec324ad9b8d86344f050'
ARCHIVE_SHA = 'a8b24ad9b7b397fe1f45095cc27844e975b6b4b6fb00c1d9fbe830aa7131d7e6'
PASS = 'KERNIX_G2C_REAL_X86_DYNAMIC_PIE_DIRECT_ENTRY_STACK_AUXV_FEX_ARM64_PASS_NOT_GLIBC\n'
FILES = {
    'bin/kernix-dynamic-app': (13344, 'e54a92cf77d1453c86b70accfd949b9e4521ddd5d629ba09c0dcac07a1397b4a'),
    'lib/x86_64-linux-gnu/libc.so.6': (2118168, '7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906'),
    'lib/x86_64-linux-gnu/ld-linux-x86-64.so.2': (235408, 'cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae'),
    'lib64/ld-linux-x86-64.so.2': (235408, 'cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae'),
}
DIRS = {'.', 'bin', 'lib', 'lib/x86_64-linux-gnu', 'lib64'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def reject_if(condition, reason):
    if condition:
        raise ValueError(reason)


def verify_tar(blob):
    reject_if(sha(blob) != ARCHIVE_SHA, 'Archive digest mismatch')
    seen = set()
    payload = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            reject_if(name in seen, 'Duplicate tar member')
            seen.add(name)
            reject_if(member.issym() or member.islnk() or member.isdev(),
                      'Links and devices forbidden')
            reject_if(member.uid != 0 or member.gid != 0, 'Unexpected ownership')
            reject_if(bool(member.mode & 0o6000), 'Setid bits forbidden')
            if member.isdir():
                reject_if(name not in DIRS, 'Unexpected directory')
                continue
            reject_if(not member.isfile(), 'Unexpected tar type')
            reject_if(name not in FILES and name != 'manifest.json', 'Unexpected file')
            reject_if(member.size < 1 or member.size > 4 * 1024 * 1024,
                      'Oversized file')
            stream = archive.extractfile(member)
            reject_if(stream is None, 'Cannot read file')
            data = stream.read(member.size + 1)
            reject_if(len(data) != member.size, 'Short or oversized member')
            payload[name] = data
    reject_if(seen != DIRS | set(FILES) | {'manifest.json'}, 'Missing archive member')
    manifest = json.loads(payload['manifest.json'])
    reject_if(manifest['schema'] != 'kernix.g2c.android-fixed-guest-inputs.v1',
              'Unexpected manifest schema')
    reject_if(manifest['source_git_sha'] != SOURCE_SHA, 'Source revision changed')
    reject_if(manifest['android_device_executed'] or manifest['guest_dynamic_loader_executed']
              or manifest['wine_or_games_tested'], 'Unsupported execution claim')
    reject_if(set(manifest['extraction_allowlist']) != set(FILES) or
              len(manifest['extraction_allowlist']) != len(FILES),
              'Manifest allowlist mismatch')
    reject_if(set(manifest['files']) != set(FILES), 'Manifest inventory mismatch')
    for name, (size, digest) in FILES.items():
        data = payload[name]
        reject_if(len(data) != size or sha(data) != digest, name + ': bytes mismatch')
        reject_if(manifest['files'][name] != {'size': size, 'sha256': digest},
                  name + ': manifest mismatch')
        reject_if(data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1 or
                  data[18:20] != b'\x3e\0', name + ': not x86_64 ELF64')
    reject_if(payload['lib64/ld-linux-x86-64.so.2'] !=
              payload['lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'],
              'Loader copies differ')
    return payload, manifest


def main(inputs, outputs):
    source = Path(inputs)
    result = json.loads((source / 'g2c-result.json').read_text())
    reject_if(result['source_git_sha'] != SOURCE_SHA or not result['pass']
              or result['exit_code'] != 0 or
              not result['guest_code_executed_under_fex'] or
              result['android_device_executed'] or result['glibc_loader_executed']
              or result['wine_pe_executed'] or result['stdout'] != PASS,
              'Linux ARM64 original FEX execution evidence changed')
    check = (source / 'g2c-android-fixed-fixture-v1.sha256').read_text().split()
    reject_if(len(check) != 2 or check[0] != ARCHIVE_SHA or
              check[1] != 'dist/g2c-android-fixed-fixture-v1.tar.gz',
              'Checksum record changed')
    payload, manifest = verify_tar(
        (source / 'g2c-android-fixed-fixture-v1.tar.gz').read_bytes())
    reject_if(payload['manifest.json'] !=
              (source / 'g2c-android-fixed-fixture-v1/manifest.json').read_bytes(),
              'Independent manifest mismatch')
    target = Path(outputs)
    reject_if(target.exists() and any(target.iterdir()), 'Output is not empty')
    target.mkdir(parents=True, exist_ok=True)
    # Only exact allowlisted regular files. No tar.extractall, exec or APK upload.
    for name in FILES:
        dst = target / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(payload[name])
        dst.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (target / 'PROVENANCE.json').write_text(json.dumps({
        'schema': 'kernix.g2c.android-handoff-CI-only.v1',
        'fex_linux_arm64_pass': True,
        'android_guest_execution_verified': False,
        'android_apk_packaged': False,
        'licenses_reviewed_for_distribution': False,
        'source_sha': SOURCE_SHA,
        'archive_sha256': ARCHIVE_SHA,
    }, indent=2) + '\n')
    print('KERNIX_G2C_ANDROID_GUEST_BUNDLE_IMMUTABLE_HANDOFF_PASS_NOT_APK_OR_DEVICE')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('Usage: kernix_g2c_fixture_gate.py INPUT_ARTIFACT_DIR OUTPUT_CI_DIR')
    main(sys.argv[1], sys.argv[2])
