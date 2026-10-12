#!/usr/bin/env python3
"""Stage Wine and native x86-64 dependencies from Ubuntu APT with checksums.

This is NOT a complete Wine runtime, not an Android Wine build and does not
provide a working Windows launcher. The only permitted test remains --version.
Keep package copyright notices and an integrity manifest in the APK.
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
DEST = ROOT / 'app/src/main/assets/wine_runtime_v21'
V20 = ROOT / 'app/src/main/assets/wine_loader'
FILES = (
    'usr/lib/wine/wine64',
    'usr/lib/wine/wineserver64',
    'usr/lib/x86_64-linux-gnu/wine/x86_64-unix/ntdll.so',
    'usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll',
    'usr/lib/x86_64-linux-gnu/libunwind.so.8',
    'usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8',
    'usr/lib/x86_64-linux-gnu/liblzma.so.5',
)
MAX_FILE = 128 * 1024 * 1024  # Match V2.2 Wine module packaging limit


def validate_elf(raw, cpu=62):
    if not 64 <= len(raw) <= MAX_FILE or raw[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Invalid ELF64 header')
    if struct.unpack_from('<H', raw, 18)[0] != cpu or struct.unpack_from('<H', raw, 16)[0] not in (2, 3):
        raise ValueError('Wrong ELF architecture/type')
    return True


def validate_pe64(raw):
    if not 512 <= len(raw) <= MAX_FILE or raw[:2] != b'MZ':
        raise ValueError('Not a Wine PE DLL')
    off = struct.unpack_from('<I', raw, 0x3c)[0]
    if off > len(raw) - 26 or raw[off:off + 4] != b'PE\0\0':
        raise ValueError('PE signature missing')
    if struct.unpack_from('<H', raw, off + 4)[0] != 0x8664 or struct.unpack_from('<H', raw, off + 24)[0] != 0x20b:
        raise ValueError('Not x86-64 PE32+ DLL')
    return True


def build(wine_deb, libwine_deb, unwind_deb, lzma_deb):
    wine = Path(wine_deb)
    lib = Path(libwine_deb)
    unwind = Path(unwind_deb)
    lzma = Path(lzma_deb)
    def field(deb, name):
        return subprocess.check_output(['dpkg-deb', '-f', str(deb), name], text=True).strip()
    package_map = {'wine64': wine, 'libwine': lib, 'libunwind8': unwind, 'liblzma5': lzma}
    for label, deb in package_map.items():
        if field(deb, 'Package') != label or field(deb, 'Architecture') != 'amd64':
            raise ValueError('Expected Ubuntu amd64 package: ' + label)
    ver = field(wine, 'Version')
    if ver != field(lib, 'Version'):
        raise ValueError('Mismatched Wine versions (wine64 and libwine)')
    old_receipt = (V20 / 'WINE64-PACKAGE-RECEIPT.txt').read_text(encoding='utf-8')
    if 'Version: ' + ver + '\n' not in old_receipt:
        raise ValueError('Wine packages do not match the already-packaged V2.0 Wine loader')
    with tempfile.TemporaryDirectory(prefix='rm11-v21-dpkg-') as td:
        root = Path(td)
        wroot = root / 'wine'
        lroot = root / 'libwine'
        uroot = root / 'unwind'
        zroot = root / 'lzma'
        for deb, target in ((wine, wroot), (lib, lroot), (unwind, uroot), (lzma, zroot)):
            subprocess.run(['dpkg-deb', '-x', str(deb), str(target)], check=True)
        if not (lroot / 'usr/share/doc/libwine/copyright').is_file():
            raise ValueError('Libwine redistributable copyright documentation absent')
        if DEST.exists():
            shutil.rmtree(DEST)
        DEST.mkdir(parents=True)
        for path, label in ((uroot/'usr/share/doc/libunwind8/copyright', 'libunwind8'),
                            (zroot/'usr/share/doc/liblzma5/copyright', 'liblzma5')):
            if not path.is_file():
                raise ValueError('Missing redistributable copyright notice: ' + label)
        manifest = ['# RM11 V2.1.4 - Ubuntu Wine x86-64 runtime subset',
                    'Version: ' + ver,
                    'Libunwind-Version: ' + field(unwind, 'Version'),
                    'Liblzma-Version: ' + field(lzma, 'Version'),
                    'Source: distro APT wine64, libwine, libunwind8 and liblzma5 amd64 packages',
                    'Use: diagnostic wine64 --version only; NO EXE support proven',
                    '# path<TAB>sha256<TAB>size']
        # Ubuntu Noble libwine contains ntdll.so and ntdll.dll, but does NOT ship
        # a file named x86_64-unix/libwine.so.1. Do not invent required assets.
        for rel in FILES:
            src_root = (wroot if rel.startswith('usr/lib/wine/') else lroot
                        if '/wine/' in rel else uroot
                        if Path(rel).name.startswith('libunwind') else zroot)
            src = src_root / rel
            if not src.is_file():
                raise ValueError('Required Wine component absent: ' + rel)
            raw = src.read_bytes()  # dereference Debian packaging symlinks safely
            if rel.endswith('.dll'):
                validate_pe64(raw)
            else:
                validate_elf(raw)
            out = DEST / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(raw)
            manifest.append(rel + '\t' + hashlib.sha256(raw).hexdigest() + '\t' + str(len(raw)))
        (DEST / 'LIBWINE-COPYRIGHT.txt').write_bytes((lroot / 'usr/share/doc/libwine/copyright').read_bytes())
        (DEST / 'LIBUNWIND-COPYRIGHT.txt').write_bytes((uroot / 'usr/share/doc/libunwind8/copyright').read_bytes())
        (DEST / 'LIBLZMA-COPYRIGHT.txt').write_bytes((zroot / 'usr/share/doc/liblzma5/copyright').read_bytes())
        # V2.0 copied Wine LGPL 2.1 notice; keep a copy with bundled runtime subset.
        shutil.copyfile(V20 / 'LGPL-2.1.txt', DEST / 'LGPL-2.1.txt')
        (DEST / 'COMPONENTS.tsv').write_text('\n'.join(manifest) + '\n', encoding='utf-8')
    print('RM11 V2.1.4 staged', len(FILES), 'Wine/dependency binaries; Wine', ver)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wine-deb', type=Path)
    parser.add_argument('--libwine-deb', type=Path)
    parser.add_argument('--unwind-deb', type=Path)
    parser.add_argument('--lzma-deb', type=Path)
    parser.add_argument('--required', action='store_true')
    args = parser.parse_args()
    try:
        supplied = [args.wine_deb, args.libwine_deb, args.unwind_deb, args.lzma_deb]
        if any(supplied) and not all(supplied):
            raise ValueError('Provide all four .deb files together')
        if all(supplied):
            build(*supplied)
        else:
            with tempfile.TemporaryDirectory(prefix='rm11-v21-apt-') as td:
                for name in ('wine64', 'libwine', 'libunwind8', 'liblzma5'):
                    subprocess.run(['apt-get', 'download', name], cwd=td, timeout=400, check=True)
                files = []
                for name in ('wine64', 'libwine', 'libunwind8', 'liblzma5'):
                    matching = list(Path(td).glob(name+'_*_amd64.deb'))
                    if len(matching) != 1:
                        raise ValueError('Expected exactly one amd64 package: ' + name)
                    files.append(matching[0])
                build(*files)
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as exc:
        if DEST.exists():
            shutil.rmtree(DEST)
        print('WINE V2.1 RUNTIME NOT PACKAGED: ' + str(exc), file=sys.stderr)
        if args.required:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
