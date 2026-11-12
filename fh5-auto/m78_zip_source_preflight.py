#!/usr/bin/env python3
"""FH5 M78: conservative ZIP game-source preflight, without extraction.
Public output is aggregate-only. Paths remain in Termux private storage.
File names and PE headers do not authenticate game provenance or completeness.
"""
from __future__ import annotations
import io, json, os, re, shutil, struct, sys, time, unittest, zipfile
from collections import Counter, deque
from pathlib import Path

STAGE = 'M78'
OUT = Path('/sdcard/Download/FH5_M78')
PRIV77 = Path.home()/'.fh5_m77'/'PRIVATE_SOURCE_CANDIDATES.json'
PRIV78 = Path.home()/'.fh5_m78'/'PRIVATE_ARCHIVE_SELECTION.json'
M77_PUBLIC = Path('/sdcard/Download/FH5_M77/M77_STORAGE_REPORT.json')
DATA_EXTS = ('.bin','.dat','.pak','.arc','.bundle','.zip','.modelbin',
             '.carbin','.shaderbin','.materialbin','.data','.big','.fsb')
MAX_MEMBERS = 50000
MAX_ARCHIVES = 30
SCAN_LIMIT = 12000
SCAN_DEPTH = 6
DEADLINE_SECONDS = 100
MAX_HEADER = 4096
MIN_FREE_MARGIN = 3 * 1024**3
ZIP_BOMB_RATIO = 1000

def is_exe(name):
    return name.replace('\\','/').split('/')[-1].lower() == 'forzahorizon5.exe'

def member_unsafe(name):
    normal = name.replace('\\','/')
    parts = normal.split('/')
    return (normal.startswith('/') or bool(re.match(r'^[A-Za-z]:',normal)) or
            any(part == '..' for part in parts) or '\x00' in name)

def valid_m77_doc(value):
    return (isinstance(value,dict) and value.get('stage')=='M77' and
            value.get('status')=='M77_STORAGE_DISCOVERY_COMPLETE' and
            value.get('zip_archives_with_forza_exe_member',0)>=1 and
            value.get('scan_read_only') is True)

def find_prior():
    try:
        if M77_PUBLIC.stat().st_size<50000 and valid_m77_doc(
            json.loads(M77_PUBLIC.read_text(encoding='utf8'))):
            return True
    except (OSError,ValueError,UnicodeError): pass
    for p in sorted(Path('/sdcard/Download').glob('FH5_M77_REPORTS*.zip')):
        try:
            with zipfile.ZipFile(p) as z:
                item=z.getinfo('FH5_M77/M77_STORAGE_REPORT.json')
                if item.file_size>50000:continue
                if valid_m77_doc(json.loads(z.read(item).decode('utf8'))):return True
        except (OSError,ValueError,UnicodeError,RuntimeError,zipfile.BadZipFile,KeyError):continue
    return False

def zip_like(path):
    try:
        with path.open('rb') as f:return f.read(4) in (b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08')
    except (OSError,PermissionError):return False

def private_candidates(path):
    try:
        if not path.is_file() or path.stat().st_size>100000:return []
        value=json.loads(path.read_text(encoding='utf8'))
        if value.get('stage')!='M77' or value.get('private_only') is not True:return []
        records=value.get('source_locations')
        if not isinstance(records,list):return []
        candidates=[]
        for rec in records[:100]:
            if not isinstance(rec,dict) or not isinstance(rec.get('path'),str):continue
            p=Path(rec['path'])
            if not p.is_absolute():continue
            try:
                if p.is_file() and not p.is_symlink() and zip_like(p):candidates.append(p)
            except OSError:pass
        return candidates
    except (OSError,ValueError,UnicodeError,TypeError):return []

def fallback_candidates():
    roots=[Path('/sdcard/Download'),Path('/sdcard/Games'),
           Path('/sdcard'),Path('/storage/emulated/0/Download')]
    queue=deque();seen=set();paths=[];budget=0;start=time.monotonic()
    for p in roots:
        try:
            real=str(p.resolve())
            if p.is_dir() and real not in seen:queue.append((p,0));seen.add(real)
        except OSError:pass
    while queue and budget<SCAN_LIMIT and time.monotonic()-start<DEADLINE_SECONDS:
        here,depth=queue.popleft()
        try:
            with os.scandir(here) as scan:items=list(scan)
        except (OSError,PermissionError):continue
        for item in items:
            if budget>=SCAN_LIMIT or time.monotonic()-start>=DEADLINE_SECONDS:break
            budget+=1
            name=item.name.lower()
            if name.startswith('.') or re.match(r'^fh5_m\d',name):continue
            try:
                if item.is_symlink():continue
                if item.is_dir(follow_symlinks=False):
                    if (depth<SCAN_DEPTH and name not in
                        ('android','dcim','pictures','movies','music','cache','obb')):
                        p=Path(item.path);real=str(p.resolve())
                        if real not in seen:seen.add(real);queue.append((p,depth+1))
                elif item.is_file(follow_symlinks=False):
                    if name.endswith('.zip') and zip_like(Path(item.path)):
                        paths.append(Path(item.path))
            except (OSError,PermissionError):continue
    return paths, bool(queue and (budget>=SCAN_LIMIT or time.monotonic()-start>=DEADLINE_SECONDS))

def pe_header(z,member):
    if member.flag_bits & 1:return 'encrypted'
    if member.file_size<512 or member.file_size>2*1024**3:return 'unverified'
    if member.compress_size==0 or member.file_size>member.compress_size*ZIP_BOMB_RATIO:
        return 'unsafe_ratio'
    try:
        with z.open(member,'r') as f:data=f.read(MAX_HEADER)
        if len(data)<64 or data[:2]!=b'MZ':return 'not_mz'
        offset=struct.unpack_from('<I',data,60)[0]
        if not 64<=offset<=MAX_HEADER-26 or offset+26>len(data):return 'bad_pe_offset'
        if data[offset:offset+4]!=b'PE\x00\x00':return 'not_pe'
        machine=struct.unpack_from('<H',data,offset+4)[0]
        opt=struct.unpack_from('<H',data,offset+24)[0]
        return 'pe64_amd64' if machine==0x8664 and opt==0x20b else 'pe_other'
    except (OSError,RuntimeError,EOFError,ValueError,struct.error,
            zipfile.BadZipFile):return 'unreadable'

def evaluate(path):
    try:
        if not path.is_file() or path.is_symlink() or not zip_like(path):
            return {'state':'not_zip'}
        with zipfile.ZipFile(path) as z:
            members=z.infolist()
            if len(members)>MAX_MEMBERS:
                return {'state':'metadata_limit','entries':len(members)}
            files=[i for i in members if not i.is_dir()]
            bad=sum(member_unsafe(i.filename) for i in files)
            enc=sum(bool(i.flag_bits&1) for i in files)
            ratio=sum(bool(i.compress_size==0 and i.file_size>0 or
                  i.compress_size>0 and i.file_size>i.compress_size*ZIP_BOMB_RATIO)
                  for i in files)
            total=sum(i.file_size for i in files)
            compressed=sum(i.compress_size for i in files)
            large_data=sum(i.file_size>=10*1024**2 and
                    i.filename.lower().endswith(DATA_EXTS) for i in files)
            named_data=sum(i.filename.lower().endswith(DATA_EXTS) for i in files)
            exe=[i for i in files if is_exe(i.filename)]
            pe=[pe_header(z,i) for i in exe[:3]]
            return dict(state='candidate' if exe else 'not_game_named',
                entries=len(files),exe_count=len(exe),pe64_count=pe.count('pe64_amd64'),
                exe_header_outcomes=dict(Counter(pe)),
                suspicious_members=bad,encrypted_members=enc,
                extreme_ratio_members=ratio,uncompressed_bytes=total,
                compressed_member_bytes=compressed,large_data_entries=large_data,
                named_data_entries=named_data,central_directory_read=True,
                crc_data_verified=False,multipart_complete_verified=False,
                archive_bytes=path.stat().st_size)
    except (OSError,PermissionError,ValueError,RuntimeError,zipfile.BadZipFile,
            MemoryError,OverflowError):return {'state':'zip_unreadable'}

def free_bytes():
    try:return shutil.disk_usage('/sdcard/Download').free
    except OSError:return None

def summarize(rows,prior_verified,scan_truncated,free):
    games=[r for p,r in rows if r.get('state')=='candidate']
    selected=sorted(games,key=lambda r:(
        r.get('pe64_count',0)>0,
        r.get('named_data_entries',0)>0,
        r.get('large_data_entries',0),
        r.get('uncompressed_bytes',0)),reverse=True)
    best=selected[0] if selected else None
    public=dict(stage=STAGE,read_only=True,status='M78_ZIP_METADATA_PREFLIGHT_COMPLETE',
        m77_public_report_verified=prior_verified,private_m77_candidates_reused=True,
        fallback_scan_budget_exhausted=scan_truncated,archives_inspected=len(rows),
        zip_archives_listing_forza_exe=len(games),pe64_amd64_archive_candidates=sum(
            r.get('pe64_count',0)>0 for r in games),
        central_directory_errors=sum(r.get('state')=='zip_unreadable' for p,r in rows),
        source_authenticated=False,game_complete_verified=False,game_port_complete=False,
        no_game_file_bytes_uploaded=True,game_files_extracted=False,
        zip_payload_crc_verified=False,encrypted_members_checked_via_metadata=True,
        disk_free_bytes=free)
    if best:
        needed=best['uncompressed_bytes']+MIN_FREE_MARGIN
        public.update(source_state=(
            'PE64_GAME_NAMED_ZIP_WITH_DATA' if best['pe64_count'] and best['large_data_entries']
            else 'EXE_NAME_ONLY_NEEDS_MORE_PROVENANCE'),
            selected_archive_summary=best,
            free_space_sufficient_for_full_extraction=None if free is None else free>=needed,
            estimated_extraction_with_margin_bytes=needed,
            next_gate=('Keep archive intact. First confirm install-media completeness and verify ZIP payload integrity using a separate bounded verification stage; do not extract until free space is sufficient.'))
    else:
        public.update(source_state='NO_REUSABLE_FORZA_ZIP_CANDIDATE',
            selected_archive_summary=None,free_space_sufficient_for_full_extraction=None,
            estimated_extraction_with_margin_bytes=None,
            next_gate='Rerun M77 or inspect the private local candidate list; no public paths are required.')
    return public

class Checks(unittest.TestCase):
    def test_isexe(self):self.assertTrue(is_exe('Game/ForzaHorizon5.exe'))
    def test_case(self):self.assertTrue(is_exe('FORZAHORIZON5.EXE'))
    def test_notexe(self):self.assertFalse(is_exe('FakeForzaHorizon5.exe'))
    def test_traversal(self):self.assertTrue(member_unsafe('a/../b'))
    def test_drive(self):self.assertTrue(member_unsafe('C:\\x.exe'))
    def test_absolute(self):self.assertTrue(member_unsafe('/abs/test'))
    def test_safe_member(self):self.assertFalse(member_unsafe('Game/Media/x.bin'))
    def test_m77(self):self.assertTrue(valid_m77_doc({
        'stage':'M77','status':'M77_STORAGE_DISCOVERY_COMPLETE',
        'zip_archives_with_forza_exe_member':1,'scan_read_only':True}))
    def test_m77_reject(self):self.assertFalse(valid_m77_doc({'stage':'M77'}))
    def test_archive_and_pe(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.zip';exe=bytearray(512);exe[:2]=b'MZ'
            struct.pack_into('<I',exe,60,128);exe[128:132]=b'PE\x00\x00'
            struct.pack_into('<H',exe,132,0x8664)
            struct.pack_into('<H',exe,152,0x20b)
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('ForzaHorizon5.exe',exe,compress_type=zipfile.ZIP_STORED)
                z.writestr('media/test.bin',b'0'*1024,compress_type=zipfile.ZIP_STORED)
            r=evaluate(p)
            self.assertEqual(r['pe64_count'],1)
            self.assertEqual(r['named_data_entries'],1)
            self.assertEqual(r['state'],'candidate')
    def test_zip_noexe(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'empty.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('hello.txt','hi')
            self.assertEqual(evaluate(p)['state'],'not_game_named')
    def test_bad_zip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.zip';p.write_bytes(b'PK\x03\x04')
            self.assertEqual(evaluate(p)['state'],'zip_unreadable')
    def test_not_zip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.zip';p.write_bytes(b'foo')
            self.assertEqual(evaluate(p)['state'],'not_zip')
    def test_summarize_empty(self):
        self.assertEqual(summarize([],False,False,None)['source_state'],
                         'NO_REUSABLE_FORZA_ZIP_CANDIDATE')
    def test_privacy(self):
        r={'state':'candidate','exe_count':1,'pe64_count':0,
            'large_data_entries':0,'named_data_entries':0,'uncompressed_bytes':42}
        s=json.dumps(summarize([(Path('/secret/game/foo.zip'),r)],False,False,None))
        self.assertNotIn('/secret',s)
    def test_no_false_auth(self):
        r={'state':'candidate','exe_count':1,'pe64_count':1,
            'large_data_entries':1,'named_data_entries':1,'uncompressed_bytes':42}
        self.assertFalse(summarize([(Path('/secret.zip'),r)],True,False,1)['source_authenticated'])
    def test_private_bad(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'m77.json';p.write_text('{}')
            self.assertEqual(private_candidates(p),[])

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    output=io.StringIO()
    tests=unittest.TextTestRunner(stream=output,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    (OUT/'M78_LOCAL_TESTS.txt').write_text(output.getvalue(),encoding='utf8')
    if not tests.wasSuccessful():
        report={'stage':STAGE,'status':'M78_SELFTEST_FAILED'}
    else:
        prior=find_prior()
        candidates=private_candidates(PRIV77)
        fallback=False
        if not candidates:
            candidates,fallback=fallback_candidates()
        unique={};rows=[]
        for p in candidates:
            try:key=str(p.resolve())
            except OSError:continue
            if key in unique:continue
            unique[key]=True
            if len(rows)>=MAX_ARCHIVES:break
            rows.append((p,evaluate(p)))
        report=summarize(rows,prior,fallback,free_bytes())
        report['private_m77_candidates_reused']=bool(private_candidates(PRIV77))
        try:
            PRIV78.parent.mkdir(parents=True,exist_ok=True)
            PRIV78.write_text(json.dumps({
                'stage':STAGE,'private_only':True,
                'archives':[{'path':str(p),'state':r.get('state')} for p,r in rows]},indent=2)+'\n',encoding='utf8')
            PRIV78.chmod(0o600)
        except OSError:pass
    (OUT/'M78_ARCHIVE_REPORT.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    (OUT/'M78_STATUS.txt').write_text(report['status']+'\n'+report.get('source_state','')+'\n',encoding='utf8')
    dest=OUT.parent/'FH5_M78_REPORTS.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED) as z:
        for f in sorted(OUT.glob('M78_*')):
            if f.is_file() and f.suffix in ('.txt','.json'):z.write(f,'FH5_M78/'+f.name)
    print('[M78]',report['status'],report.get('source_state',''))
    print('[M78] Public evidence:',dest)
    print('[M78] Local private archive paths are NOT included.')
    return 0 if report['status']=='M78_ZIP_METADATA_PREFLIGHT_COMPLETE' else 17

if __name__=='__main__':raise SystemExit(main())
