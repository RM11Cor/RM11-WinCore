#!/usr/bin/env python3
"""Stage matched Wine DLLs and NLS data for an offline Win64 probe.

This is NOT a complete Wine prefix/rootfs and is NOT a general game launcher.
The libwine package must match the exact version staged for V2.1.4.
"""
from pathlib import Path
import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from build_v22_pe_guest import audit
from package_wine_runtime_v21 import validate_elf, validate_pe64

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'app/src/main/assets/wine_exe_v22'
V21=ROOT/'app/src/main/assets/wine_runtime_v21'
WIN='usr/lib/x86_64-linux-gnu/wine/x86_64-windows/'
UNIX='usr/lib/x86_64-linux-gnu/wine/x86_64-unix/'
# Core modules are required; optional Wine components are included when present.
REQUIRED=('kernel32.dll','kernelbase.dll','wineboot.exe')
OPTIONAL=('advapi32.dll','sechost.dll','rpcrt4.dll','msvcrt.dll','ucrtbase.dll',
          'user32.dll','gdi32.dll','win32u.dll','ws2_32.dll','bcrypt.dll',
          'shell32.dll','ole32.dll','oleaut32.dll','imm32.dll','shlwapi.dll',
          'version.dll','setupapi.dll','winhttp.dll','wininet.dll',
          'services.exe','explorer.exe','winedevice.exe','plugplay.exe',
          'rpcss.exe','rundll32.exe','conhost.exe','reg.exe','regedit.exe','regsvr32.exe')
OPTIONAL_UNIX=('win32u.so',)
MAX_FILE=128*1024*1024
NLS_REQUIRED=('locale.nls','l_intl.nls','c_1252.nls','c_437.nls')
NLS_DIR='usr/share/wine/nls/'
WINE_INF='usr/share/wine/wine.inf'
# Older Ubuntu Wine packages may place data one directory deeper. Output uses a
# single normalized, loader-compatible path regardless of package layout.
SOURCE_DATA_ROOTS=('usr/share/wine/', 'usr/share/wine/wine/')
MAX_NLS_FILE=8*1024*1024
MAX_MANIFEST_BYTES=1024*1024

def package(libwine_deb):
    from subprocess import check_output
    deb=Path(libwine_deb)
    if check_output(['dpkg-deb','-f',str(deb),'Package'],text=True).strip()!='libwine' or check_output(['dpkg-deb','-f',str(deb),'Architecture'],text=True).strip()!='amd64':
        raise ValueError('Expected Ubuntu amd64 libwine .deb')
    version=check_output(['dpkg-deb','-f',str(deb),'Version'],text=True).strip()
    stage_manifest=(V21/'COMPONENTS.tsv')
    if not stage_manifest.is_file() or ('Version: '+version+'\n') not in stage_manifest.read_text():
        raise ValueError('V2.2 libwine version does not match V2.1.4 Wine runtime')
    with tempfile.TemporaryDirectory(prefix='rm11-v22-extract-') as td:
        root=Path(td)
        subprocess.run(['dpkg-deb','-x',str(deb),str(root)],check=True)
        if not (root/'usr/share/doc/libwine/copyright').is_file():
            raise ValueError('Missing libwine package copyright')
        records=['# RM11 V2.3.5 full Wine PE/Unix modules + NLS', 'Version: '+version,
                 'Use: only built-in RM11 Windows PE test; arbitrary EXE not supported',
                 '# path<TAB>sha256<TAB>size']
        # V2.3.5: DON'T choose a small hand-picked DLL list. A subset can
        # pass wine --version yet leave wineboot, service host and RPC startup
        # without other Wine PE modules. Take ALL real amd64 Wine objects from
        # the exact same libwine Debian package and verify each file.
        wine_roots=(root / WIN, root / UNIX)
        candidates=[]
        for base in wine_roots:
            if not base.is_dir(): raise ValueError('Wine module tree missing: '+str(base))
            for src in sorted(base.iterdir()):
                if not src.is_file() or src.is_symlink(): continue
                if base == root / WIN and src.suffix.lower() in ('.dll','.exe'):
                    candidates.append(src)
                elif base == root / UNIX and src.suffix.lower() == '.so':
                    candidates.append(src)
        seen={str(x.relative_to(root)) for x in candidates}
        for name in REQUIRED:
            if WIN+name not in seen:
                raise ValueError('Missing mandatory Wine PE: '+name)
        for name in ('services.exe','explorer.exe','winedevice.exe','plugplay.exe','rpcss.exe'):
            if WIN+name not in seen:
                raise ValueError('Missing Wine bootstrap service: '+name)
        if UNIX+'ntdll.so' not in seen:
            raise ValueError('Missing Wine Unix ntdll.so')
        if len(candidates) < 100:
            raise ValueError('Incomplete libwine package: only '+str(len(candidates))+' Wine modules')
        for src in candidates:
            rel=src.relative_to(root).as_posix()
            raw=src.read_bytes()
            if not 512 <= len(raw) <= MAX_FILE:
                raise ValueError('Excessive/malformed Wine component: '+rel)
            if rel.startswith(UNIX): validate_elf(raw)
            else: validate_pe64(raw)
            dest=OUT/rel
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(raw)
            records.append(rel+'\t'+hashlib.sha256(raw).hexdigest()+'\t'+str(len(raw)))
        # Wine initializes locale data before EXE execution. Keep the official
        # NLS directory from the matched libwine build, never synthesize tables.
        # Resolve a single real source tree from the matched distro package.
        # Never mix NLS tables and wine.inf from different distributions.
        source_data = next((root / prefix for prefix in SOURCE_DATA_ROOTS
                            if all((root / prefix / 'nls' / name).is_file()
                                   for name in NLS_REQUIRED)
                            and (root / prefix / 'wine.inf').is_file()), None)
        if source_data is None:
            raise ValueError('Matched libwine missing NLS tables or wine.inf in supported package layouts')
        nls_files=sorted((source_data/'nls').glob('*.nls'))
        if not nls_files: raise ValueError('Matched libwine missing NLS data')
        if len(nls_files)>128: raise ValueError('Unexpected Wine NLS file count')
        for src in nls_files:
            if not src.is_file() or src.is_symlink(): raise ValueError('Invalid NLS entry: '+str(src))
            raw=src.read_bytes()
            if not 32 <= len(raw) <= MAX_NLS_FILE: raise ValueError('Invalid Wine NLS file size: '+src.name)
            rel=NLS_DIR+src.name
            dest=OUT/rel
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(raw)
            records.append(rel+'\t'+hashlib.sha256(raw).hexdigest()+'\t'+str(len(raw)))
        inf=source_data/'wine.inf'
        if not inf.is_file() or inf.is_symlink():
            raise ValueError('Matched libwine missing required wine.inf')
        inf_raw=inf.read_bytes()
        if not 32<=len(inf_raw)<=2*1024*1024: raise ValueError('Wine INF file invalid')
        inf_dest=OUT/WINE_INF;inf_dest.parent.mkdir(parents=True,exist_ok=True);inf_dest.write_bytes(inf_raw)
        records.append(WINE_INF+'\t'+hashlib.sha256(inf_raw).hexdigest()+'\t'+str(len(inf_raw)))
        print('PASS V2.2 matched Wine locale data staged:',len(nls_files),'NLS files and wine.inf')
        manifest_bytes=('\n'.join(records)+'\n').encode('utf-8')
        if len(manifest_bytes)>MAX_MANIFEST_BYTES:
            raise ValueError('Wine component manifest exceeds Android bounded-reader limit')
        (OUT/'WINDOWS-COMPONENTS.tsv').write_bytes(manifest_bytes)
        (OUT/'LIBWINE-COPYRIGHT.txt').write_bytes((root/'usr/share/doc/libwine/copyright').read_bytes())
        print('PASS V2.3.5 complete Wine module tree included:',len(candidates),'modules +',len(nls_files),'NLS; matched libwine',version)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--libwine-deb',type=Path)
    p.add_argument('--required',action='store_true')
    a=p.parse_args()
    try:
        if a.libwine_deb: package(a.libwine_deb)
        else:
            with tempfile.TemporaryDirectory(prefix='rm11-v22-apt-') as td:
                subprocess.run(['apt-get','download','libwine'],cwd=td,timeout=400,check=True)
                pkg=list(Path(td).glob('libwine_*_amd64.deb'))
                if len(pkg)!=1: raise ValueError('Expected one matching Ubuntu libwine package')
                package(pkg[0])
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print('V2.2 WINE PE NOT PACKAGED: '+str(e),file=sys.stderr)
        if a.required: raise SystemExit(1)

if __name__=='__main__':main()
