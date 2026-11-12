#!/usr/bin/env python3
"""FH5 Runtime R1: inspect the REAL game's PE64 imports inside the local ZIP.

No game launch or DRM bypass is attempted. All game bytes stay on the phone.
A bounded temporary copy of ONLY ForzaHorizon5.exe is deleted on exit.
Reports exclude local paths, hashes, arbitrary imported names and game bytes.
"""
from __future__ import annotations
import argparse
import io
import json
import os
import re
import struct
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

OUT=Path('/sdcard/Download')
M78=Path.home()/'.fh5_m78'/'PRIVATE_ARCHIVE_SELECTION.json'
M77=Path.home()/'.fh5_m77'/'PRIVATE_SOURCE_CANDIDATES.json'
MAX_EXE=512*1024*1024
MAX_READ=4*1024*1024
MAX_SECTIONS=96
MAX_IMPORTS=2048
MAX_DIAGNOSTIC_SECONDS=240
SAFE_DLLS={
    'd3d12.dll':'d3d12','dxgi.dll':'dxgi','d3d11.dll':'d3d11',
    'd3dcompiler_47.dll':'d3dcompiler','vulkan-1.dll':'vulkan',
    'steam_api64.dll':'steam_api64','steamclient64.dll':'steamclient64',
    'xgameruntime.dll':'xgameruntime','xboxliveapi.dll':'xboxliveapi',
    'gameinput.dll':'gameinput','xinput1_4.dll':'xinput',
    'mfplat.dll':'media_foundation','mf.dll':'media_foundation',
    'vcruntime140.dll':'vc_runtime','msvcp140.dll':'vc_runtime',
    'ucrtbase.dll':'ucrt','kernel32.dll':'kernel32',
    'kernelbase.dll':'kernelbase','ntdll.dll':'ntdll',
    'bcrypt.dll':'bcrypt','winhttp.dll':'winhttp'
}

def readat(f,pos,n,limit):
    if not isinstance(pos,int) or pos<0 or n<0 or n>16384 or pos+n>limit:
        return None
    f.seek(pos)
    data=f.read(n)
    return data if len(data)==n else None

def number(buf,pos,width):
    if buf is None or pos<0 or pos+width>len(buf):return None
    return int.from_bytes(buf[pos:pos+width],'little')

def pe_inspect(f,limit):
    result={'pe32plus':False,'amd64':False,'import_table_present':False,
            'recognized_dependencies':[],'unknown_dll_count':0,
            'dll_count':0,'import_name_read_errors':0,
            'parse_state':'invalid_dos','no_game_bytes_in_report':True}
    hdr=readat(f,0,64,limit)
    if hdr is None or hdr[:2]!=b'MZ':return result
    peoff=number(hdr,0x3c,4)
    if peoff is None or peoff<64 or peoff>min(limit-24,16*1024*1024):
        result['parse_state']='invalid_pe_offset';return result
    sig=readat(f,peoff,24,limit)
    if sig is None or sig[:4]!=b'PE\x00\x00':
        result['parse_state']='invalid_nt_signature';return result
    machine=number(sig,4,2); sections=number(sig,6,2)
    osz=number(sig,20,2)
    result['amd64']=machine==0x8664
    result['section_count']=sections
    if sections<1 or sections>MAX_SECTIONS or osz<112 or osz>4096:
        result['parse_state']='invalid_section_layout';return result
    opt=readat(f,peoff+24,osz,limit)
    if opt is None:return {**result,'parse_state':'truncated_optional'}
    kind=number(opt,0,2)
    result['pe32plus']=kind==0x20b
    if not result['pe32plus'] or not result['amd64']:
        result['parse_state']='unsupported_architecture';return result
    directories=number(opt,108,4)
    if directories is None or directories<2 or osz<128:
        result['parse_state']='no_directory_table';return result
    import_rva=number(opt,120,4)
    result['import_table_present']=bool(import_rva)
    raw=readat(f,peoff+24+osz,sections*40,limit)
    if raw is None:
        result['parse_state']='truncated_section_table';return result
    sectors=[]
    for i in range(sections):
        p=i*40
        vsize=number(raw,p+8,4);vaddr=number(raw,p+12,4)
        rsize=number(raw,p+16,4);raddr=number(raw,p+20,4)
        if None in (vsize,vaddr,rsize,raddr):continue
        if raddr>limit or rsize>limit-raddr:continue
        sectors.append((vaddr,max(vsize,rsize),raddr,rsize))
    def addr(rva,n):
        if rva is None or not isinstance(rva,int) or rva<0 or n>1024:return None
        if rva<min(peoff+24+osz+sections*40,4096):
            return rva if rva+n<=limit else None
        for vaddr,vspan,raddr,rsize in sectors:
            if vaddr<=rva and rva-vaddr+n<=rsize and rva-vaddr+n<=vspan:
                return raddr+(rva-vaddr)
        return None
    if not import_rva:
        result['parse_state']='valid_pe_no_static_imports';return result
    table=addr(import_rva,20)
    if table is None:
        result['parse_state']='import_directory_unmapped';return result
    safe=set()
    unknown=0
    seen=set()
    terminated=False
    for i in range(MAX_IMPORTS):
        b=readat(f,table+i*20,20,limit)
        if b is None:
            result['parse_state']='import_descriptors_truncated';break
        if b==bytes(20):
            terminated=True;break
        nrva=number(b,12,4)
        pos=addr(nrva,1)
        if pos is None:
            result['import_name_read_errors']+=1;continue
        name=readat(f,pos,min(256,limit-pos),limit)
        if name is None:
            result['import_name_read_errors']+=1;continue
        end=name.find(b'\x00')
        if end<1:
            result['import_name_read_errors']+=1;continue
        try:
            dll=name[:end].decode('ascii').lower()
        except UnicodeDecodeError:
            result['import_name_read_errors']+=1;continue
        if dll in seen:continue
        seen.add(dll)
        if dll in SAFE_DLLS:
            safe.add(SAFE_DLLS[dll])
        else:
            unknown+=1
    result['recognized_dependencies']=sorted(safe)
    result['unknown_dll_count']=unknown
    result['dll_count']=len(seen)
    result['parse_state']='static_imports_parsed' if terminated else result.get('parse_state','import_table_scan_limit')
    if result['parse_state']=='invalid_dos':
        result['parse_state']='import_table_scan_limit'
    return result

def game_exe_name(name):
    return name.replace('\\','/').split('/')[-1].lower()=='forzahorizon5.exe'

def zip_candidates():
    found=[]
    for source in (M78,M77):
        try:
            if source.stat().st_size>350000:continue
            obj=json.loads(source.read_text(encoding='utf8'))
            if obj.get('private_only') is not True:continue
            items=obj.get('archives',[]) if obj.get('stage')=='M78' else obj.get('source_locations',[])
            for x in items[:120]:
                if not isinstance(x,dict) or not isinstance(x.get('path'),str):continue
                p=Path(x['path'])
                if p.is_absolute() and p.is_file() and not p.is_symlink():
                    found.append(p)
        except (OSError,TypeError,UnicodeError,ValueError):pass
    if not found:
        for root in (Path('/sdcard/Download'),Path('/sdcard/Games')):
            try:
                found.extend(p for p in root.glob('*.zip') if p.is_file())
            except OSError:pass
    unique={}
    for p in found:
        try:unique.setdefault(str(p.resolve()),p)
        except OSError:pass
    return list(unique.values())

def get_exe_member(path):
    try:
        with zipfile.ZipFile(path) as z:
            items=z.infolist()
            if len(items)>65000:return None
            cand=[i for i in items if game_exe_name(i.filename) and not i.is_dir()]
            cand=[i for i in cand if not i.flag_bits&1 and 1024<=i.file_size<=MAX_EXE]
            return cand[0].filename if cand else None
    except (OSError,RuntimeError,ValueError,zipfile.BadZipFile,MemoryError):return None

def inspect_archive(path,member):
    with zipfile.ZipFile(path) as z:
        info=z.getinfo(member)
        if info.file_size>MAX_EXE or info.flag_bits&1:
            return {'status':'R1_UNSAFE_OR_UNSUPPORTED_EXE'}
        if info.compress_size==0 or info.file_size>info.compress_size*1000:
            return {'status':'R1_ARCHIVE_EXPANSION_LIMIT'}
        start=time.monotonic()
        with tempfile.TemporaryFile(mode='w+b') as dst:
            read=0
            with z.open(info) as src:
                while True:
                    if time.monotonic()-start>MAX_DIAGNOSTIC_SECONDS:
                        return {'status':'R1_TIME_BUDGET_EXCEEDED'}
                    block=src.read(MAX_READ)
                    if not block:break
                    read+=len(block)
                    if read>MAX_EXE:return {'status':'R1_EXE_LIMIT_EXCEEDED'}
                    dst.write(block)
            if read!=info.file_size:return {'status':'R1_INCOMPLETE_READ'}
            dst.flush()
            pe=pe_inspect(dst,read)
        pe.update({'status':'R1_PE_ANALYSIS_COMPLETE','exe_size_bytes':read,
            'exe_payload_crc_checked':True,'exe_only_extracted_temporarily':True,
            'game_files_modified':False,'game_assets_extracted':False,
            'runtime_launched':False,'original_game_authenticity_verified':False,
            'owned_launcher_authentication_verified':False})
        known=pe.get('recognized_dependencies',[])
        if 'steam_api64' in known:
            pe['platform_hint']='STEAM_IMPORT_HINT'
        elif any(x in known for x in ('xgameruntime','xboxliveapi')):
            pe['platform_hint']='XBOX_RUNTIME_IMPORT_HINT'
        else:
            pe['platform_hint']='PLATFORM_UNCONFIRMED'
        pe['next_runtime_gate']='Use legitimate launcher/account in a Wine+FEX+VKD3D environment; capture loader, graphics and process exit diagnostics.'
        return pe

def safe_run():
    paths=zip_candidates()
    for p in paths:
        member=get_exe_member(p)
        if member:
            try:return inspect_archive(p,member)
            except (OSError,ValueError,RuntimeError,EOFError,zipfile.BadZipFile,MemoryError):
                return {'status':'R1_EXE_READ_ERROR','stage':'R1'}
    return {'status':'R1_NO_EXE_IN_ACCESSIBLE_ARCHIVES','archive_paths_checked':len(paths),
            'stage':'R1','next_action':'Keep ZIP in Download. Give Termux storage permission and rerun.'}

def synthetic_pe(dll='steam_api64.dll'):
    b=bytearray(4096)
    b[:2]=b'MZ'
    struct.pack_into('<I',b,60,128)
    b[128:132]=b'PE\x00\x00'
    struct.pack_into('<H',b,132,0x8664)
    struct.pack_into('<H',b,134,1)
    struct.pack_into('<H',b,148,0xf0)
    opt=152
    struct.pack_into('<H',b,opt,0x20b)
    struct.pack_into('<I',b,opt+108,16)
    struct.pack_into('<I',b,opt+120,0x1100)
    struct.pack_into('<I',b,opt+124,40)
    section=opt+0xf0
    b[section:section+8]=b'.rdata\x00\x00'
    struct.pack_into('<I',b,section+8,0x800)
    struct.pack_into('<I',b,section+12,0x1000)
    struct.pack_into('<I',b,section+16,0x800)
    struct.pack_into('<I',b,section+20,0x200)
    struct.pack_into('<I',b,0x300+12,0x1200)
    b[0x400:0x400+len(dll)]=dll.encode('ascii')
    return bytes(b)

class Checks(unittest.TestCase):
    def test_pe_import(self):
        b=synthetic_pe()
        r=pe_inspect(io.BytesIO(b),len(b))
        self.assertTrue(r['amd64']);self.assertTrue(r['pe32plus'])
        self.assertEqual(r['recognized_dependencies'],['steam_api64'])
    def test_no_mz(self):
        r=pe_inspect(io.BytesIO(bytes(4096)),4096)
        self.assertEqual(r['parse_state'],'invalid_dos')
    def test_broken_pe(self):
        b=bytearray(synthetic_pe());b[128:132]=b'FAIL'
        self.assertEqual(pe_inspect(io.BytesIO(b),len(b))['parse_state'],'invalid_nt_signature')
    def test_import_absent(self):
        b=bytearray(synthetic_pe());struct.pack_into('<I',b,152+120,0)
        self.assertEqual(pe_inspect(io.BytesIO(b),len(b))['parse_state'],'valid_pe_no_static_imports')
    def test_wrong_architecture(self):
        b=bytearray(synthetic_pe());struct.pack_into('<H',b,132,0x14c)
        self.assertEqual(pe_inspect(io.BytesIO(b),len(b))['parse_state'],'unsupported_architecture')
    def test_unknown_privacy(self):
        b=synthetic_pe('private_CUSTOM_name.dll')
        r=pe_inspect(io.BytesIO(b),len(b))
        self.assertEqual(r['unknown_dll_count'],1)
        self.assertNotIn('private_CUSTOM_name',json.dumps(r))
    def test_filename(self):
        self.assertTrue(game_exe_name('Games/ForzaHorizon5.exe'))
        self.assertFalse(game_exe_name('fakeForzaHorizon5.exe'))
    def test_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'file.zip'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('game/ForzaHorizon5.exe',synthetic_pe())
            self.assertEqual(get_exe_member(p),'game/ForzaHorizon5.exe')
            r=inspect_archive(p,'game/ForzaHorizon5.exe')
            self.assertEqual(r['platform_hint'],'STEAM_IMPORT_HINT')
            self.assertFalse(r['runtime_launched'])
            self.assertNotIn(str(p),json.dumps(r))
    def test_zip_no_exe(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'file.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('other.exe',b'MZ')
            self.assertIsNone(get_exe_member(p))
    def test_exe_too_short(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'file.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('ForzaHorizon5.exe',b'MZ')
            self.assertIsNone(get_exe_member(p))
    def test_limited_pe(self):
        r=pe_inspect(io.BytesIO(b'MZ'),2)
        self.assertEqual(r['parse_state'],'invalid_dos')

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    log=io.StringIO()
    tests=unittest.TextTestRunner(stream=log,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    tdir=OUT/'FH5_BOOT_R1'
    tdir.mkdir(exist_ok=True)
    (tdir/'R1_SELF_TESTS.txt').write_text(log.getvalue(),encoding='utf8')
    report={'stage':'R1','status':'R1_SELFTEST_FAILED'}
    if tests.wasSuccessful():
        report=safe_run()
        report['stage']='R1'
    (tdir/'R1_PE_BOOT_REPORT.json').write_text(
        json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    (tdir/'R1_STATUS.txt').write_text(report['status']+'\n',encoding='utf8')
    archive=OUT/'FH5_BOOT_R1_REPORTS.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for file in tdir.glob('R1_*'):
            if file.suffix in ('.txt','.json'):
                z.write(file,arcname='FH5_BOOT_R1/'+file.name)
    print('[FH5 R1]',report['status'])
    print('[FH5 R1] Upload only:',archive)
    return 0 if report['status']=='R1_PE_ANALYSIS_COMPLETE' else 17

if __name__=='__main__':raise SystemExit(main())
