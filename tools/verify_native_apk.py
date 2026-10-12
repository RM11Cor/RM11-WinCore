"""Post-build APK audit for first-party ARM64 modules and standalone executable."""
import sys
from pathlib import Path
from zipfile import ZipFile

if len(sys.argv) != 2:
    raise SystemExit("Usage: python3 tools/verify_native_apk.py app-debug.apk")
apk = Path(sys.argv[1])
expected = {
    'lib/arm64-v8a/librm11probe.so',
    'lib/arm64-v8a/librm11runtime_adapter.so',
    'lib/arm64-v8a/librm11execprobe.so',
    'lib/arm64-v8a/librm11wineserverbridge.so',
}
with ZipFile(apk) as archive:
    entries = set(archive.namelist())
    absent = expected - entries
    if absent:
        raise SystemExit("FAIL missing packaged native libs: " + ', '.join(sorted(absent)))
    data = archive.read('lib/arm64-v8a/librm11execprobe.so')
    if not data.startswith(b'\x7fELF') or data[18:20] != b'\xb7\x00':
        raise SystemExit('FAIL: standalone ARM64 PIE missing or malformed')
    import struct
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize = struct.unpack_from('<H', data, 54)[0]
    phnum = struct.unpack_from('<H', data, 56)[0]
    if phsize < 56 or phnum > 128 or phoff + phsize*phnum > len(data):
        raise SystemExit('FAIL: executable program header out of bounds')
    if not any(struct.unpack_from('<I', data, phoff+i*phsize)[0] == 3 for i in range(phnum)):
        raise SystemExit('FAIL: Android PIE missing PT_INTERP')
    guest_path = 'assets/box64_test/hello_x86_64.elf'
    if guest_path not in entries:
        raise SystemExit('FAIL: x86-64 Linux guest ELF missing from APK assets')
    guest = archive.read(guest_path)
    if (len(guest) > 256*1024 or guest[:6] != b'\x7fELF\x02\x01' or
        guest[16:20] != b'\x02\x00\x3e\x00' or b'RM11_X86_64_GUEST_EXEC_OK' not in guest):
        raise SystemExit('FAIL: packaged x86-64 guest invalid or missing success marker')
    import struct
    phoff = struct.unpack_from('<Q', guest, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', guest, 54)
    if phsize < 56 or not 1 <= phnum <= 64 or phoff + phsize*phnum > len(guest):
        raise SystemExit('FAIL: guest ELF program headers malformed')
    if any(struct.unpack_from('<I', guest, phoff + phsize*i)[0] == 3 for i in range(phnum)):
        raise SystemExit('FAIL: guest ELF unexpectedly has dynamic linker')
    print('PASS: Linux x86-64 freestanding test guest packaged as APK ASSET (not executed by Android)')
    dynamic_path = 'assets/box64_test/hello_glibc_x86_64.elf'
    if dynamic_path not in entries:
        raise SystemExit('FAIL: V1.5 glibc-linked Linux guest is missing from APK assets')
    dynamic_guest = archive.read(dynamic_path)
    if (not 64 <= len(dynamic_guest) <= 256*1024 or dynamic_guest[:6] != b'\x7fELF\x02\x01'
        or dynamic_guest[18:20] != b'\x3e\x00'
        or b'RM11_X86_64_GLIBC_DYNAMIC_OK' not in dynamic_guest
        or b'/lib64/ld-linux-x86-64.so.2' not in dynamic_guest
        or b'libc.so.6' not in dynamic_guest):
        raise SystemExit('FAIL: V1.5 dynamic guest architecture/loader/libc metadata invalid')
    print('PASS: x86-64 dynamic glibc test guest packaged as inert APK asset; Linux rootfs not included')
    maybe_box64 = 'lib/arm64-v8a/librm11box64.so'
    if maybe_box64 in entries:
        box64_data = archive.read(maybe_box64)
        if not box64_data.startswith(b'\x7fELF') or box64_data[18:20] != b'\xb7\x00':
            raise SystemExit('FAIL: experimental Box64 ELF has invalid ARM64 header')
        print('EXPERIMENTAL: upstream ARM64 Box64 appears in APK; on-device --version still required')
    else:
        print('NOT BUILT: optional experimental Box64 not packaged; official ARM64 probe still available')
print('PASS: ARM64 JNI libraries plus runnable ELF PIE packaged in APK')

# V2.0 authentic Wine ELF may be packaged from the signed Ubuntu APT wine64 package.
with ZipFile(apk) as archive:
    entry = 'assets/wine_loader/wine64.elf'
    if entry in archive.namelist():
        from hashlib import sha256
        receipt = archive.read('assets/wine_loader/WINE64-PACKAGE-RECEIPT.txt').decode('utf-8')
        archive.read('assets/wine_loader/UBUNTU-WINE64-COPYRIGHT.txt')
        archive.read('assets/wine_loader/LGPL-2.1.txt')
        data = archive.read(entry)
        if not 64 <= len(data) <= 10 * 1024 * 1024 or data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\x3e\x00':
            raise SystemExit('FAIL: V2.0 Wine x86-64 ELF package corrupted')
        if ('SHA256: '+sha256(data).hexdigest()) not in receipt:
            raise SystemExit('FAIL: V2.0 Wine asset/receipt mismatch')
        print('PASS: genuine Wine Linux ELF asset packaged, Wine --version on Android NOT verified')
    else:
        print('NOT PACKAGED: no genuine distro Wine loader asset; Android UI must show truthful status')

# V2.1 matched Wine library asset bundle: fixed paths, SHA-256 and minimal object format.
with ZipFile(apk) as archive:
    from hashlib import sha256
    import struct
    base='assets/wine_runtime_v21/'
    listing=archive.read(base+'COMPONENTS.tsv').decode('utf-8')
    paths=[
        'usr/lib/wine/wine64',
        'usr/lib/wine/wineserver64',
        'usr/lib/x86_64-linux-gnu/wine/x86_64-unix/ntdll.so',
        'usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll',
        'usr/lib/x86_64-linux-gnu/libunwind.so.8',
        'usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8',
        'usr/lib/x86_64-linux-gnu/liblzma.so.5',
    ]
    archive.read(base+'LIBWINE-COPYRIGHT.txt')
    archive.read(base+'LGPL-2.1.txt')
    archive.read(base+'LIBUNWIND-COPYRIGHT.txt')
    archive.read(base+'LIBLZMA-COPYRIGHT.txt')
    records={}
    for line in listing.splitlines():
        if line.startswith('#') or not '\t' in line: continue
        path,digest,size=line.split('\t')
        if path in records: raise SystemExit('FAIL: duplicate runtime entry '+path)
        records[path]=(digest,int(size))
    if set(records)!=set(paths): raise SystemExit('FAIL: missing/extra V2.1 Wine assets')
    for path in paths:
        data=archive.read(base+path)
        digest,size=records[path]
        if len(data)!=size or sha256(data).hexdigest()!=digest:
            raise SystemExit('FAIL: V2.1 Wine component SHA/size mismatch: '+path)
        if path.endswith('.dll'):
            if data[:2]!=b'MZ' or len(data)<512:
                raise SystemExit('FAIL V2.1 expected real PE DLL: '+path)
        elif data[:6]!=b'\x7fELF\x02\x01' or data[18:20]!=b'\x3e\x00':
            raise SystemExit('FAIL V2.1 expected x86-64 Linux ELF: '+path)
    print('PASS: V2.1.2 Wine/ntdll/unwind/lzma startup libraries fingerprinted and packaged (device launch NOT verified)')

# V2.2 Windows x86-64 PE test and matched Wine PE library subset.
with ZipFile(apk) as archive:
    from hashlib import sha256
    import struct
    base='assets/wine_exe_v22/'
    data=archive.read(base+'rm11_probe.exe')
    exp=archive.read(base+'PE-SHA256.txt').decode('ascii').strip()
    from build_v22_pe_guest import audit
    if audit(data)!=exp:
        raise SystemExit('FAIL: V2.2 Windows PE exe digest/format mismatch')
    raw_manifest=archive.read(base+'WINDOWS-COMPONENTS.tsv')
    if len(raw_manifest) > 64*1024:
        raise SystemExit('FAIL: Wine PE manifest exceeds on-device bounded-reader limit')
    listing=raw_manifest.decode('utf-8')
    archive.read(base+'LIBWINE-COPYRIGHT.txt')
    required={'usr/lib/x86_64-linux-gnu/wine/x86_64-windows/'+x for x in ('kernel32.dll','kernelbase.dll','wineboot.exe')}
    required|={'usr/share/wine/nls/'+x for x in ('locale.nls','l_intl.nls','c_1252.nls','c_437.nls')}
    required.add('usr/share/wine/wine.inf')
    records={}
    for line in listing.splitlines():
        if '\t' not in line or line.startswith('#'):continue
        rel,digest,size=line.split('\t')
        if rel in records: raise SystemExit('FAIL: duplicated V2.2 wine PE '+rel)
        records[rel]=(digest,int(size))
    if not required.issubset(records): raise SystemExit('FAIL: missing V2.2.1 Wine PE DLLs / NLS data / wine.inf')
    for rel,(digest,size) in records.items():
        binary=archive.read(base+rel)
        if sha256(binary).hexdigest()!=digest or len(binary)!=size:
            raise SystemExit('FAIL V2.2 Wine PE module integrity: '+rel)
    bridge=archive.read('lib/arm64-v8a/librm11wineserverbridge.so')
    if bridge[:4]!=b'\x7fELF' or bridge[18:20]!=b'\xb7\x00':
        raise SystemExit('FAIL: V2.2 ARM64 wineserver bridge missing/malformed')
    phoff=struct.unpack_from('<Q',bridge,32)[0]
    entsize,count=struct.unpack_from('<HH',bridge,54)
    if not any(struct.unpack_from('<I',bridge,phoff+i*entsize)[0]==3 for i in range(count)):
        raise SystemExit('FAIL: V2.2 wineserver bridge is not runnable ARM64 PIE')
    app_manifest = archive.read('AndroidManifest.xml')
    # AAPT binary XML cannot be verified with a textual grep; source validation
    # checks removal of the prior insecure heap-tagging opt-out; APK merge remains build-specific.
    print('PASS: V2.2.3 Win64 PE and matched Wine DLL/NLS/INF startup files hashed in APK; on-device crash unverified')
