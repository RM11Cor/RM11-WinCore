#!/usr/bin/env python3
"""Optional Wine loader packaging from the Ubuntu-signed wine64 APT package.

This is an authentic Linux x86-64 Wine launcher, *not* Wine for Android.
No libwine libraries, wineserver or Linux rootfs are bundled here, so --version
may fail on Android. Never replace a Wine ELF with a substitute test program.
"""
from pathlib import Path
import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
ASSET_DIR = ROOT / 'app/src/main/assets/wine_loader'
TARGET = ASSET_DIR / 'wine64.elf'
COPYRIGHT = ASSET_DIR / 'UBUNTU-WINE64-COPYRIGHT.txt'
LGPL = ASSET_DIR / 'LGPL-2.1.txt'
RECEIPT = ASSET_DIR / 'WINE64-PACKAGE-RECEIPT.txt'
MAX_SIZE = 10 * 1024 * 1024


def check_elf(data):
    """Accept only an ELF64 little-endian x86-64 Linux executable, not PE/APK."""
    if not 64 <= len(data) <= MAX_SIZE or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected bounded ELF64 x86-64 Linux loader')
    kind, cpu = struct.unpack_from('<HH', data, 16)
    if cpu != 62 or kind not in (2, 3):
        raise ValueError('Wrong machine or ELF executable type')
    pos = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size < 56 or count < 1 or count > 128 or pos + size * count > len(data):
        raise ValueError('Invalid ELF program header table')
    interpreters = []
    for i in range(count):
        header = pos + i * size
        if struct.unpack_from('<I', data, header)[0] == 3:
            offset, length = struct.unpack_from('<QQ', data, header + 8)[0], struct.unpack_from('<Q', data, header + 32)[0]
            if length < 4 or length > 256 or offset + length > len(data):
                raise ValueError('Bad ELF interpreter')
            interpreters.append(data[offset:offset+length].rstrip(b'\0'))
    if len(interpreters) != 1 or b'ld-linux-x86-64.so.2' not in interpreters[0]:
        raise ValueError('Expected one Linux x86-64 glibc loader')
    return interpreters[0].decode('ascii', 'replace')


def package(deb):
    with tempfile.TemporaryDirectory(prefix='rm11-wine64-deb-') as tmp:
        tree = Path(tmp) / 'unpacked'
        pkg = subprocess.check_output(['dpkg-deb', '-f', str(deb), 'Package'], text=True).strip()
        arch = subprocess.check_output(['dpkg-deb', '-f', str(deb), 'Architecture'], text=True).strip()
        ver = subprocess.check_output(['dpkg-deb', '-f', str(deb), 'Version'], text=True).strip()
        if pkg != 'wine64' or arch != 'amd64':
            raise ValueError('Not an Ubuntu/Debian amd64 wine64 package')
        subprocess.run(['dpkg-deb', '-x', str(deb), str(tree)], check=True)
        elf_path = tree / 'usr/lib/wine/wine64'
        license_path = tree / 'usr/share/doc/wine64/copyright'
        if not elf_path.is_file() or not license_path.is_file():
            raise ValueError('Wine package missing loader or license information')
        data = elf_path.read_bytes()
        interp = check_elf(data)
        ASSET_DIR.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(data)
        COPYRIGHT.write_bytes(license_path.read_bytes())
        host_lgpl = Path('/usr/share/common-licenses/LGPL-2.1')
        if not host_lgpl.is_file():
            raise ValueError('No full LGPL 2.1 license text in trusted build environment')
        LGPL.write_bytes(host_lgpl.read_bytes())
        RECEIPT.write_text(
            'Experimental Linux x86-64 Wine launcher (not a complete Wine runtime).\n'
            'Package: wine64\nArchitecture: amd64\nVersion: '+ver+'\n'
            'Source: signed distribution APT wine64 package; original Wine source at https://www.winehq.org/\n'
            'ELF interpreter: '+interp+'\n'
            'SHA256: '+hashlib.sha256(data).hexdigest()+'\n'
            'This file is redistributed unchanged. See UBUNTU-WINE64-COPYRIGHT.txt and LGPL-2.1.txt.\n'
            'No wineserver, libwine, glibc userland, DXVK or Windows execution supplied.\n', encoding='utf-8')
        print('Wine loader packaged:', ver, 'size', len(data), 'bytes; interpreter', interp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--deb', type=Path, help='Use a local distro wine64 amd64 .deb (for testing)')
    ap.add_argument('--required', action='store_true', help='Fail instead of optional skip')
    args = ap.parse_args()
    for path in (TARGET, COPYRIGHT, LGPL, RECEIPT):
        path.unlink(missing_ok=True)
    try:
        if args.deb:
            package(args.deb)
        else:
            with tempfile.TemporaryDirectory(prefix='rm11-apt-wine-') as tmp:
                subprocess.run(['apt-get', 'download', 'wine64'], cwd=tmp, timeout=240, check=True)
                debs = list(Path(tmp).glob('wine64_*_amd64.deb'))
                if len(debs) != 1:
                    raise ValueError('Expected exactly one signed-APT wine64 amd64 .deb')
                package(debs[0])
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        for path in (TARGET, COPYRIGHT, LGPL, RECEIPT):
            path.unlink(missing_ok=True)
        print('NOT PACKAGED: Wine loader unavailable:', str(exc), file=sys.stderr)
        if args.required:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
