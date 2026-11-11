#!/usr/bin/env python3
"""M76 bounded read-only Forza Horizon 5 source preflight.
Game ownership, authenticity, mesh formats and playability are NOT verified.
Only aggregate metadata and test results go into public reports.
"""
import argparse, io, json, os, re, struct, time, unittest, zipfile
from pathlib import Path
from collections import Counter, deque

OUT=Path('/sdcard/Download/FH5_M76')
PRIOR=Path('/sdcard/Download/FH5_M75/M75_WINDOW_REPORT.json')
ROOTS=('/sdcard/Download','/sdcard/Games','/sdcard/Documents','/sdcard/Forza Horizon 5','/sdcard/ForzaHorizon5')
ASSETS=('.modelbin','.carbin','.shaderbin','.materialbin')
MAX_ITEMS=9000
MAX_DEPTH=5
MAX_ARCHIVES=12
MAX_SECONDS=75

def norm(s):return re.sub('[^a-z0-9]','',s.lower())
def is_probe(name):
    s=norm(name)
    return bool(re.match(r'^fh5m\d',s) or s.startswith(('fh5auto','fh5nextstage','fh5sourcegate')))
def hint(name):
    s=norm(name)
    return 'forzahorizon5' in s or ('fh5' in s and not re.match(r'^fh5m\d',s))
def pe64(path):
    try:
        if path.stat().st_size<512:return False
        with path.open('rb') as f:
            lead=f.read(64)
            if lead[:2]!=b'MZ':return False
            pos=struct.unpack_from('<I',lead,60)[0]
            if pos<64 or pos>4096 or pos+26>path.stat().st_size:return False
            f.seek(pos);header=f.read(26)
        return (len(header)==26 and header[:4]==b'PE\x00\x00' and
                struct.unpack_from('<H',header,4)[0]==0x8664 and
                struct.unpack_from('<H',header,24)[0]==0x20b)
    except (OSError,ValueError,struct.error):return False
def archive_magic(p):
    try:
        with p.open('rb') as f:head=f.read(8)
    except (OSError,ValueError):return 'unreadable'
    if head.startswith((b'PK\x03\x04',b'PK\x05\x06')):return 'zip'
    if head.startswith(b'7z\xbc\xaf\x27\x1c'):return '7z'
    if head.startswith((b'Rar!\x1a\x07\x00',b'Rar!\x1a\x07\x01\x00')):return 'rar'
    return 'unknown'
def zip_names_only(p):
    try:
        with zipfile.ZipFile(p) as z:
            if len(z.filelist)>120000:return {'limit':True}
            exe=False;assets=0
            for m in z.filelist:
                if m.is_dir() or is_probe(m.filename):continue
                basename=Path(m.filename).name.lower()
                exe|=basename=='forzahorizon5.exe'
                assets+=Path(basename).suffix in ASSETS
            return {'exe':exe,'assets':assets}
    except (OSError,zipfile.BadZipFile,RuntimeError,ValueError,MemoryError):
        return {'unreadable':True}
def m75_gate(p):
    try:
        if p.stat().st_size>65536:return False
        d=json.loads(p.read_text(encoding='utf8'))
        return (d.get('stage')=='M75' and
          d.get('status')=='M75_WINDOW_DISTRIBUTION_COMPLETE_NO_FORMAT_CLAIM' and
          d.get('m74_full_revalidation_passed') is True and
          d.get('same_m72_m73_members_reverified')==8 and
          d.get('original_forza_asset_authenticated') is False and
          not d.get('error_counts'))
    except (OSError,TypeError,ValueError):return False

def inspect(roots, max_items=MAX_ITEMS, max_depth=MAX_DEPTH, seconds=MAX_SECONDS):
    start=time.monotonic()
    queue=deque();seen=set();counts=Counter();archives=[]
    for root in roots:
        p=Path(root)
        try:
            if p.is_symlink():continue
            if p.is_dir():
                real=str(p.resolve())
                if real not in seen:seen.add(real);queue.append((p,0,hint(p.name)))
            elif p.is_file():queue.append((p,0,hint(p.name)))
        except OSError:continue
    while queue and counts['visited']<max_items and time.monotonic()-start<seconds:
        here,level,marked=queue.popleft()
        try:
            if here.is_file():entries=[here]
            else:
                with os.scandir(here) as it:entries=[Path(x.path) for x in it]
        except OSError:
            counts['unreadable_dirs']+=1;continue
        for p in entries:
            if counts['visited']>=max_items or time.monotonic()-start>=seconds:break
            counts['visited']+=1
            name=p.name
            if is_probe(name):continue
            try:
                if p.is_symlink():continue
                directory=p.is_dir(); regular=p.is_file()
            except OSError:continue
            relevant=marked or hint(name)
            if directory:
                if level>=max_depth or name.startswith('.') or name.lower() in ('android','dcim','pictures','movies','music','thumbnails','obb'):continue
                if relevant or level<=1 or norm(name) in ('games','pcgames','windows','steam','common','downloads'):
                    try:
                        real=str(p.resolve())
                        if real not in seen:seen.add(real);queue.append((p,level+1,relevant))
                    except OSError:pass
                continue
            if not regular:continue
            low=name.lower();ext=p.suffix.lower()
            if low=='forzahorizon5.exe':
                counts['named_exes']+=1
                if pe64(p):counts['pe64_exes']+=1
            if relevant and ext in ASSETS:counts['loose_assets']+=1
            if relevant and (ext in ('.zip','.7z','.rar','.001') or re.search(r'\.part\d+\.rar$',low)):
                counts['archive_names']+=1
                if len(archives)<MAX_ARCHIVES:archives.append(p)
    for a in archives:
        k=archive_magic(a);counts['magic_'+k]+=1
        if k=='zip':
            v=zip_names_only(a)
            counts['zip_exe_members']+=bool(v.get('exe'))
            counts['zip_asset_members']+=v.get('assets',0)
            counts['zip_listing_limit']+=bool(v.get('limit'))
            counts['zip_listing_error']+=bool(v.get('unreadable'))
    if counts['pe64_exes']:
        state='EXTRACTED_EXE_CANDIDATE_WITH_ASSETS' if counts['loose_assets'] else 'EXTRACTED_EXE_CANDIDATE_ASSETS_NOT_FOUND'
    elif sum(counts['magic_'+x] for x in ('zip','7z','rar')):
        state='ARCHIVE_ONLY_EXTRACT_BEFORE_PARSER'
    elif counts['named_exes']:state='EXECUTABLE_NAME_ONLY_INVALID_OR_INCOMPLETE'
    else:state='NO_GAME_COPY_FOUND_IN_SCANNED_ROOTS'
    truncated=bool(queue and (counts['visited']>=max_items or time.monotonic()-start>=seconds))
    return dict(
      stage='M76',status='M76_SCAN_BUDGET_PARTIAL' if truncated else 'M76_SOURCE_PREFLIGHT_COMPLETE',
      source_state=state,read_only=True,m75_input_verified=True,
      root_candidates_checked=len(roots),entries_examined=counts['visited'],scan_budget_exhausted=truncated,
      exe_filename_matches=counts['named_exes'],pe64_x64_header_candidates=counts['pe64_exes'],
      loose_asset_candidates=counts['loose_assets'],named_archive_candidates=counts['archive_names'],
      archive_signatures={x:counts['magic_'+x] for x in ('zip','rar','7z','unknown','unreadable')},
      zip_with_exe_name=counts['zip_exe_members'],
      zip_asset_member_candidates=counts['zip_asset_members'],
      zip_metadata_read_limit=counts['zip_listing_limit'],
      original_forza_asset_authenticated=False,pe_signature_cryptographically_verified=False,
      forza_format_decoded=False,geometry_decoded=False,game_port_complete=False,
      independent_model_holdout_authenticated=False,
      privacy={'publishes_paths':False,'publishes_game_bytes':False,'publishes_hashes':False},
      next_gate=('Extract the complete, legally owned game to a Termux-visible folder, then rerun M76'
        if state=='ARCHIVE_ONLY_EXTRACT_BEFORE_PARSER' else
        'Verify independent source provenance and versioned container field; file names and PE headers alone do not authenticate assets'
        if counts['pe64_exes'] else
        'Check Termux storage permissions and game location; rerun with --game-path if outside default directories'))

class Tests(unittest.TestCase):
    def test_hint(self):self.assertTrue(hint('Forza Horizon 5'))
    def test_no_probe_confusion(self):self.assertTrue(is_probe('FH5_M75_REPORTS.zip'))
    def test_pe64(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'ForzaHorizon5.exe';b=bytearray(512);b[:2]=b'MZ'
            struct.pack_into('<I',b,60,128);b[128:132]=b'PE\x00\x00'
            struct.pack_into('<H',b,132,0x8664);struct.pack_into('<H',b,152,0x20b);p.write_bytes(b)
            self.assertTrue(pe64(p))
    def test_invalid_pe(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'ForzaHorizon5.exe';p.write_bytes(b'MZ'+bytes(510))
            self.assertFalse(pe64(p))
    def test_zip_names(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'ForzaHorizon5.zip'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('game/ForzaHorizon5.exe','a');z.writestr('media/test.modelbin','b')
            self.assertTrue(zip_names_only(p)['exe'])
            self.assertEqual(zip_names_only(p)['assets'],1)
    def test_rar(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x.rar';p.write_bytes(b'Rar!\x1a\x07\x01\x00')
            self.assertEqual(archive_magic(p),'rar')
    def test_7z(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x.7z';p.write_bytes(b'7z\xbc\xaf\x27\x1c')
            self.assertEqual(archive_magic(p),'7z')
    def test_prior_reject(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'prior.json';p.write_text('{"stage":"M75","status":"BAD"}')
            self.assertFalse(m75_gate(p))
    def test_prior_good(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'prior.json'
            p.write_text(json.dumps({'stage':'M75','status':'M75_WINDOW_DISTRIBUTION_COMPLETE_NO_FORMAT_CLAIM',
              'm74_full_revalidation_passed':True,'same_m72_m73_members_reverified':8,
              'original_forza_asset_authenticated':False,'error_counts':{}}))
            self.assertTrue(m75_gate(p))
    def test_archive_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'Forza Horizon 5.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('test','x')
            d=inspect([p])
            self.assertEqual(d['source_state'],'ARCHIVE_ONLY_EXTRACT_BEFORE_PARSER')
            self.assertFalse(d['original_forza_asset_authenticated'])
    def test_empty_root(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(inspect([t])['source_state'],'NO_GAME_COPY_FOUND_IN_SCANNED_ROOTS')
    def test_report_no_private_paths(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'ForzaHorizon5.7z';p.write_bytes(b'7z\xbc\xaf\x27\x1c')
            report=json.dumps(inspect([p]))
            self.assertNotIn(t,report)
            self.assertNotIn(str(p.name),report)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--game-path',action='append',default=[])
    opts=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    log=io.StringIO();res=unittest.TextTestRunner(stream=log,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    (OUT/'M76_LOCAL_TESTS.txt').write_text(log.getvalue(),encoding='utf8')
    if not res.wasSuccessful():report={'stage':'M76','status':'M76_SELFTEST_FAILED'}
    elif not m75_gate(PRIOR):
        report={'stage':'M76','status':'M76_REQUIRES_VERIFIED_M75_REPORT',
                'next_gate':'Run M75 first on this same device'}
    else:report=inspect(list(ROOTS)+opts.game_path)
    (OUT/'M76_SOURCE_REPORT.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
    (OUT/'M76_STATUS.txt').write_text(report['status']+'\n'+report.get('source_state','')+'\n',encoding='utf8')
    dest=OUT.parent/'FH5_M76_REPORTS.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED) as z:
        for p in OUT.glob('M76_*'):
            if p.is_file() and p.suffix in ('.txt','.json'):z.write(p,'FH5_M76/'+p.name)
    print('[M76]',report['status'],report.get('source_state',''))
    print('[M76] Public report:',dest)
    return 0 if report['status']=='M76_SOURCE_PREFLIGHT_COMPLETE' else 17

if __name__=='__main__':raise SystemExit(main())
