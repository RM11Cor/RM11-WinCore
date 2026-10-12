#!/usr/bin/env python3
"""Pin the public DEBUG certificate fingerprint in a keystore or built APK.

This **does not** make the bundled development signing key secure.  Anyone
with access to this source archive has the private development key.  Release
builds require a separately protected key and a trusted distribution channel.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = (ROOT / 'signing/EXPECTED-DEBUG-CERT-SHA256.txt').read_text().strip().upper()
KEYSTORE = ROOT / 'signing/rm11-development.jks'


def norm_digest(s):
    return re.sub(r'[^0-9a-fA-F]', '', s).upper()


def check_keystore():
    if not KEYSTORE.is_file():
        raise SystemExit('FAIL: development keystore missing; build must not fall back to a random GitHub debug key')
    p = subprocess.run(['keytool', '-list', '-v', '-alias', 'rm11-dev',
                        '-keystore', str(KEYSTORE), '-storepass', 'android'],
                       check=True, capture_output=True, text=True)
    match = re.search(r'^\s*SHA256:\s*([0-9A-Fa-f:]+)\s*$', p.stdout, re.MULTILINE)
    if not match or norm_digest(match.group(1)) != EXPECTED:
        raise SystemExit('FAIL: signing keystore was changed; existing V1.2+ APK updates will be rejected')
    print('PASS: stable V1.2 development key certificate SHA256:', EXPECTED)


def check_apk(apk_path):
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if not sdk:
        raise SystemExit('FAIL: ANDROID_HOME not configured for APK verification')
    signer = Path(sdk) / 'build-tools/36.0.0/apksigner'
    if not signer.is_file():
        raise SystemExit('FAIL: apksigner 36.0.0 missing')
    p = subprocess.run([str(signer), 'verify', '--print-certs', str(apk_path)],
                       check=True, capture_output=True, text=True)
    match = re.search(r'Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]+)', p.stdout)
    if not match or norm_digest(match.group(1)) != EXPECTED:
        raise SystemExit('FAIL: built APK has a different signer; DO NOT distribute it as an update')
    print('PASS: signed debug APK certificate matches pinned stable V1.2 key')


if __name__ == '__main__':
    check_keystore()
    if len(sys.argv) > 1:
        check_apk(Path(sys.argv[1]))
