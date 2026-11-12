#!/usr/bin/env python3
"""Forza Horizon 5 Runtime R2: prepare a minimal genuine EXE launch smoke test.

Uses real R1 evidence. Streams only the real EXE and at most two optional DLLs
from the local game ZIP to a small, explicitly labelled staging directory.
No code patches, DRM changes, bulk asset extraction, APK or game launch.
R2 --collect publishes only sanitized category counts from the local raw log.
"""
from __future__ import annotations
import argparse
import io
import json
import os
import re
import shutil
import tempfile
import unittest
import zipfile
import zlib
from collections import Counter
from pathlib import Path

STAGE='R2'
DOWNLOAD=Path('/sdcard/Download')
OUT=DOWNLOAD/'FH5_RUNTIME_SMOKE_R2'
R1_ZIP=DOWNLOAD/'FH5_BOOT_R1_REPORTS.zip'
R1_JSON=DOWNLOAD/'FH5_BOOT_R1'/'R1_PE_BOOT_REPORT.json'
M78=Path.home()/'.fh5_m78'/'PRIVATE_ARCHIVE_SELECTION.json'
M77=Path.home()/'.fh5_m77'/'PRIVATE_SOURCE_CANDIDATES.json'
EXE='ForzaHorizon5.exe'
OPTIONAL=('steam_api64.dll','steamclient64.dll')
MAX_EXE=512*1024**2
MAX_DLL=96*1024**2
MAX_TOTAL=640*1024**2
MIN_FREE=1024**3
CHUNK=2*1024**2
MAX_LOG_READ=8*1024**2
MAX_LOG_LINES=30000

def r1_valid(x):
    return (isinstance(x,dict) and x.get('stage')=='R1' and
        x.get('status')=='R1_PE_ANALYSIS_COMPLETE' and
        x.get('amd64') is True and x.get('pe32plus') is True and
        x.get('exe_payload_crc_checked') is True and
        isinstance(x.get('exe_size_bytes'),int) and
        1024<x['exe_size_bytes']<=MAX_EXE)

def load_r1():
    try:
        if R1_JSON.is_file() and R1_JSON.stat().st_size<100000:
            v=json.loads(R1_JSON.read_text(encoding='utf8'))
            if r1_valid(v):return v
    except (OSError,ValueError,UnicodeError):pass
    try:
        with zipfile.ZipFile(R1_ZIP) as z:
            info=z.getinfo('FH5_BOOT_R1/R1_PE_BOOT_REPORT.json')
            if info.file_size<100000:
                v=json.loads(z.read(info).decode('utf8'))
                if r1_valid(v):return v
    except (OSError,ValueError,UnicodeError,KeyError,RuntimeError,zipfile.BadZipFile):pass
    return None

def candidates(roots=None):
    result=[]
    for file in (M78,M77):
        try:
            if not file.is_file() or file.stat().st_size>350000:continue
            obj=json.loads(file.read_text(encoding='utf8'))
            if obj.get('private_only') is not True:continue
            items=(obj.get('archives',[]) if obj.get('stage')=='M78' else
                   obj.get('source_locations',[]) if obj.get('stage')=='M77' else [])
            for row in items[:150]:
                if isinstance(row,dict) and isinstance(row.get('path'),str):
                    p=Path(row['path'])
                    if p.is_absolute() and p.is_file() and not p.is_symlink():result.append(p)
        except (OSError,ValueError,UnicodeError,TypeError):pass
    for root in roots if roots is not None else (DOWNLOAD,DOWNLOAD/'Games'):
        try:
            if root.is_dir():result.extend(p for p in root.glob('*.zip') if p.is_file())
        except OSError:pass
    unique={}
    for p in result:
        try:unique.setdefault(str(p.resolve()),p)
        except OSError:pass
    return list(unique.values())

def entry_basename(info):
    return info.filename.replace('\\','/').rsplit('/',1)[-1].lower()

def safe(info,max_bytes):
    mode=(info.external_attr>>16)&0o170000
    return (not info.is_dir() and not bool(info.flag_bits&1) and
       mode!=0o120000 and 0<info.file_size<=max_bytes and
       info.compress_size>0 and info.file_size<=info.compress_size*1000 and
       info.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED,
                              zipfile.ZIP_BZIP2,zipfile.ZIP_LZMA))

def find_target(z,r1):
    items=z.infolist()
    if len(items)>65000:return None
    hits=[i for i in items if entry_basename(i)==EXE.lower() and
          safe(i,MAX_EXE) and i.file_size==r1['exe_size_bytes']]
    if not hits:return None
    info=hits[0]
    if len(hits)>1:return None
    folder=info.filename.replace('\\','/').rsplit('/',1)[0] if '/' in info.filename.replace('\\','/') else ''
    optionals=[]
    for name in OPTIONAL:
        matching=[i for i in items if entry_basename(i)==name and
            ((i.filename.replace('\\','/').rsplit('/',1)[0] if '/' in i.filename.replace('\\','/') else '')==folder)
            and safe(i,MAX_DLL)]
        if len(matching)==1:optionals.append(matching[0])
    if info.file_size+sum(x.file_size for x in optionals)>MAX_TOTAL:
        return None
    return [info]+optionals

def find_source(r1,paths=None):
    for p in paths if paths is not None else candidates():
        try:
            with zipfile.ZipFile(p) as z:
                target=find_target(z,r1)
                if target:return p,target
        except (OSError,PermissionError,RuntimeError,ValueError,MemoryError,zipfile.BadZipFile):
            continue
    return None,None

def local_crc_matches(path,info):
    if not path.is_file() or path.is_symlink() or path.stat().st_size!=info.file_size:
        return False
    crc=0
    with path.open('rb') as f:
        while True:
            b=f.read(CHUNK)
            if not b:break
            crc=zlib.crc32(b,crc)
    return crc==info.CRC

def stream_member(z,info,target):
    if target.exists() or target.is_symlink():
        if local_crc_matches(target,info):return 'reused_verified'
        raise RuntimeError('existing_stage_file_does_not_match_archive; nothing overwritten')
    fd,name=tempfile.mkstemp(prefix='.r2_partial_',dir=target.parent)
    temp=Path(name)
    count=0
    try:
        with os.fdopen(fd,'wb') as dst,z.open(info) as src:
            while True:
                part=src.read(CHUNK)
                if not part:break
                count+=len(part)
                if count>info.file_size:raise RuntimeError('size_limit')
                dst.write(part)
            dst.flush()
            os.fsync(dst.fileno())
        if count!=info.file_size or not local_crc_matches(temp,info):
            raise RuntimeError('crc_or_size_failure')
        if target.exists() or target.is_symlink():
            raise RuntimeError('stage_file_appeared_during_write')
        temp.rename(target)
        return 'written_crc_verified'
    finally:
        try:temp.unlink(missing_ok=True)
        except OSError:pass

def stage(source,selected,dest):
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        raise RuntimeError('unsafe_stage_directory')
    dest.mkdir(parents=True,exist_ok=True)
    available=shutil.disk_usage(dest).free
    need=sum(i.file_size for i in selected)
    if available<need+MIN_FREE:
        return {'stage':STAGE,'status':'R2_INSUFFICIENT_FREE_SPACE',
                'required_bytes_with_margin':need+MIN_FREE,'free_bytes':available}
    outputs=[]
    with zipfile.ZipFile(source) as z:
        for i in selected:
            # Caller chooses exact basenames only. Never trust member paths for output.
            name=entry_basename(i)
            if name not in {EXE.lower(),*OPTIONAL}:raise RuntimeError('unsafe_member')
            dest_path=dest/(EXE if name==EXE.lower() else name)
            operation=stream_member(z,i,dest_path)
            outputs.append({'kind':'exe' if name==EXE.lower() else 'optional_steam_dll',
                'bytes':i.file_size,'crc_verified':True,'operation':operation})
    return {'stage':STAGE,'status':'R2_MINIMAL_BOOT_STAGING_READY',
        'staged_files':outputs,'staged_file_count':len(outputs),
        'stage_total_bytes':sum(x['bytes'] for x in outputs),
        'staged_exe_size_bytes':next(x['bytes'] for x in outputs if x['kind']=='exe'),
        'free_bytes_after':shutil.disk_usage(dest).free,
        'legitimate_steam_login_required':True,
        'runtime_launched':False,'full_game_assets_present':False,
        'full_game_expected_to_boot':False,'game_assets_extracted':False,
        'source_modified':False,'no_game_bytes_uploaded':True,
        'next_action':'Open R2_BOOT_TEST.bat from this folder in the existing Wine/Bannerlator container. Observe any window, then run --collect in Termux.'}

def scan_log(path):
    if not path.is_file() or path.is_symlink():
        return {'status':'R2_NO_BOOT_LOG_YET','boot_attempt_observed':False}
    size=path.stat().st_size
    counts=Counter()
    total=0;read=0
    pattern={
        'steam_or_auth':re.compile(r'steam|license|login|account|authentication',re.I),
        'd3d12_dxgi_vkd3d':re.compile(r'd3d12|dxgi|vkd3d|device_removed|swapchain',re.I),
        'graphics_window':re.compile(r'winex11|x11|surface|vulkan|wsi|window',re.I),
        'dll_or_loader':re.compile(r'loaddll|import_dll|library.*not found|failed.*dll|ntdll',re.I),
        'process_exception':re.compile(r'exception|c0000005|c0000135|access.violation|unhandled',re.I),
        'missing_files_or_data':re.compile(r'file not found|no such file|path not found|missing asset',re.I),
        'media':re.compile(r'mfplat|mfreadwrite|media.foundation|wmv|video',re.I)
    }
    exit_code=None
    with path.open('rb') as f:
        while read<MAX_LOG_READ and total<MAX_LOG_LINES:
            line=f.readline(min(65536,MAX_LOG_READ-read))
            if not line:break
            read+=len(line);total+=1
            text=line.decode('utf8',errors='replace')
            m=re.search(r'R2_EXIT_CODE=(-?[0-9]{1,11})',text)
            if m:
                try:exit_code=int(m.group(1))
                except ValueError:pass
            for name,pattern_re in pattern.items():
                if pattern_re.search(text):counts[name]+=1
            if 'err:' in text:counts['wine_err_lines']+=1
    return {'status':'R2_BOOT_LOG_SUMMARIZED','boot_attempt_observed':True,
        'raw_log_size_bytes':size,'bytes_scanned':read,'lines_scanned':total,
        'log_truncated_for_privacy_and_resource_limit':size>read,
        'exit_code_from_bat':exit_code,'signal_counts':dict(counts),
        'boot_success_verified':False,'game_window_verified':False,
        'raw_log_uploaded':False,'private_paths_uploaded':False,
        'interpretation':'Counters are weak hints. Missing paths or Steam errors in this deliberately incomplete smoke folder are expected.'}

def public_report(data):
    if not isinstance(data,dict):data={'stage':STAGE,'status':'R2_BAD_REPORT'}
    clean=dict(data)
    clean['stage']=STAGE
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'R2_PUBLIC_STATUS.json').write_text(json.dumps(clean,indent=2)+'\n',encoding='utf8')
    outzip=DOWNLOAD/'FH5_BOOT_R2_REPORTS.zip'
    with zipfile.ZipFile(outzip,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(OUT/'R2_PUBLIC_STATUS.json','FH5_BOOT_R2/R2_PUBLIC_STATUS.json')
    print('[FH5 R2]',clean.get('status'))
    print('[FH5 R2] Public report:',outzip)
    return clean

class Tests(unittest.TestCase):
    def fixture(self):
        d=tempfile.TemporaryDirectory()
        p=Path(d.name)/'game.zip'
        with zipfile.ZipFile(p,'w') as z:
            z.writestr('Game/ForzaHorizon5.exe',b'MZ'+b'A'*3000)
            z.writestr('Game/steam_api64.dll',b'DLLDATA'*50)
            z.writestr('Game/media/large_asset.dat',b'X'*8192)
        r1={'stage':'R1','status':'R1_PE_ANALYSIS_COMPLETE',
            'amd64':True,'pe32plus':True,'exe_payload_crc_checked':True,
            'exe_size_bytes':3002}
        return d,p,r1
    def test_r1_gate(self):
        _,_,r=self.fixture()
        self.assertTrue(r1_valid(r))
    def test_r1_reject(self):self.assertFalse(r1_valid({'stage':'R1'}))
    def test_member_basename(self):
        i=zipfile.ZipInfo('Dir\\ForzaHorizon5.exe')
        self.assertEqual(entry_basename(i),'forzahorizon5.exe')
    def test_archive_select(self):
        d,p,r=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:items=find_target(z,r)
            self.assertEqual(len(items),2)
            self.assertEqual(entry_basename(items[0]),'forzahorizon5.exe')
        finally:d.cleanup()
    def test_real_stage(self):
        d,p,r=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:items=find_target(z,r)
            output=stage(p,items,Path(d.name)/'staged')
            self.assertEqual(output['status'],'R2_MINIMAL_BOOT_STAGING_READY')
            self.assertFalse(output['runtime_launched'])
            self.assertTrue((Path(d.name)/'staged'/EXE).is_file())
            self.assertFalse((Path(d.name)/'staged'/'large_asset.dat').exists())
            self.assertNotIn(str(p),json.dumps(output))
        finally:d.cleanup()
    def test_reuse_stage(self):
        d,p,r=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:items=find_target(z,r)
            dest=Path(d.name)/'staged'
            stage(p,items,dest)
            result=stage(p,items,dest)
            self.assertTrue(all(x['operation']=='reused_verified' for x in result['staged_files']))
        finally:d.cleanup()
    def test_detect_tamper(self):
        d,p,r=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:items=find_target(z,r)
            dest=Path(d.name)/'staged'
            stage(p,items,dest)
            (dest/EXE).write_bytes(b'TAMPER')
            with self.assertRaises(RuntimeError):stage(p,items,dest)
        finally:d.cleanup()
    def test_log_privacy(self):
        with tempfile.TemporaryDirectory() as root:
            f=Path(root)/'R2_BOOT_RAW.log'
            f.write_text('err:module:import_dll could not load /my/secret/user/download/path.dll\n'
                         'warn:vkd3d d3d12 device lost\nR2_EXIT_CODE=3\n',encoding='utf8')
            report=scan_log(f)
            self.assertEqual(report['exit_code_from_bat'],3)
            self.assertNotIn('/my/secret',json.dumps(report))
            self.assertIn('d3d12_dxgi_vkd3d',report['signal_counts'])
    def test_missing_log(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(scan_log(Path(root)/'missing.log')['status'],'R2_NO_BOOT_LOG_YET')
    def test_zip_crc(self):
        d,p,r=self.fixture()
        try:
            with zipfile.ZipFile(p) as z:items=find_target(z,r)
            dest=Path(d.name)/'staged'
            stage(p,items,dest)
            self.assertTrue(local_crc_matches(dest/EXE,items[0]))
        finally:d.cleanup()
    def test_no_unsafe_zip_entry(self):
        z=zipfile.ZipInfo('Game/evil.exe')
        z.file_size=1000;z.compress_size=100
        self.assertEqual(entry_basename(z),'evil.exe')
    def test_reject_large(self):
        z=zipfile.ZipInfo('ForzaHorizon5.exe')
        z.file_size=MAX_EXE+1;z.compress_size=MAX_EXE
        self.assertFalse(safe(z,MAX_EXE))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--collect',action='store_true')
    parser.add_argument('--selftest',action='store_true')
    opts=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    if opts.selftest:
        output=io.StringIO()
        r=unittest.TextTestRunner(stream=output,verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
        print(output.getvalue())
        return 0 if r.wasSuccessful() else 1
    if opts.collect:
        report=scan_log(OUT/'R2_BOOT_RAW.log')
        public_report(report)
        return 0 if report['status']=='R2_BOOT_LOG_SUMMARIZED' else 17
    r1=load_r1()
    if not r1:
        public_report({'status':'R2_REQUIRES_R1_REPORT',
              'next_action':'Keep FH5_BOOT_R1_REPORTS.zip in Download.'})
        return 17
    source,selection=find_source(r1)
    if source is None:
        public_report({'status':'R2_ORIGINAL_EXE_ARCHIVE_NOT_FOUND',
            'next_action':'Keep the original Forza ZIP accessible in Downloads; rerun R1 if its local location has changed.'})
        return 17
    try:
        report=stage(source,selection,OUT)
    except (OSError,RuntimeError,ValueError,EOFError,zipfile.BadZipFile,MemoryError) as err:
        report={'status':'R2_STAGE_FAILED','error_class':type(err).__name__,
            'next_action':'Do not delete or overwrite existing files; inspect the local Termux error and retry.'}
    public_report(report)
    return 0 if report.get('status')=='R2_MINIMAL_BOOT_STAGING_READY' else 17

if __name__=='__main__':
    raise SystemExit(main())
