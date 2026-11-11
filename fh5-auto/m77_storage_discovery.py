#!/usr/bin/env python3
"""FH5 M77: read-only discovery of locally accessible game/archive sources.

Public report contains only aggregate counts. Paths stay in a private Termux file.
No game asset format interpretation or claim of authenticated source.
"""
from __future__ import annotations
import argparse, io, json, os, re, struct, time, unittest, zipfile
from collections import Counter, deque
from pathlib import Path

OUT = Path('/sdcard/Download/FH5_M77')
PRIOR = Path('/sdcard/Download/FH5_M76/M76_SOURCE_REPORT.json')
PRIVATE = Path.home()/'.fh5_m77'/'PRIVATE_SOURCE_CANDIDATES.json'
MAX_ENTRIES = 30000
MAX_SECONDS = 110
MAX_DEPTH = 7
ARCHIVE_MIN = 256 * 1024 * 1024
SNIFF_LIMIT = 48
ZIP_LIMIT = 10
META_MAX_ENTRIES = 40000
GAME_TOKENS = ('forza', 'horizon', 'playgroundgames', 'fh5')
ARCHIVE_EXTS = ('.zip', '.7z', '.rar', '.iso', '.001', '.z01', '.part1', '.bin', '.arc')
ASSET_EXTS = ('.modelbin', '.carbin', '.shaderbin', '.materialbin')
SKIP = ('dcim', 'pictures', 'movies', 'music', 'audiobooks', 'podcasts',
        'notifications', 'ringtones', 'alarms', 'thumbnails', 'cache', '.thumbnails')


def game_hint(name):
    norm = re.sub(r'[^a-z0-9]', '', name.lower())
    return any(t in norm for t in GAME_TOKENS) and not re.match(r'^fh5m\d', norm)


def archive_guess(name):
    low = name.lower()
    return low.endswith(ARCHIVE_EXTS) or bool(re.search(r'\.part\d+\.rar$', low))


def magic(p):
    try:
        with p.open('rb') as f: head = f.read(8)
    except (OSError, ValueError): return 'unreadable'
    if head.startswith((b'PK\x03\x04', b'PK\x05\x06')): return 'zip'
    if head.startswith(b'7z\xbc\xaf\x27\x1c'): return '7z'
    if head.startswith((b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00')): return 'rar'
    if head.startswith(b'MZ'): return 'mz'
    if head.startswith(b'\x1f\x8b'): return 'gzip'
    return 'unknown'


def valid_m76(path):
    try:
        if not path.is_file() or path.stat().st_size > 30000: return False
        v = json.loads(path.read_text(encoding='utf8'))
    except (OSError, ValueError, UnicodeError): return False
    return (v.get('stage') == 'M76'
            and v.get('status') == 'M76_SOURCE_PREFLIGHT_COMPLETE'
            and v.get('m75_input_verified') is True
            and v.get('read_only') is True)


def find_roots():
    candidates = [Path('/sdcard'), Path('/storage/emulated/0'),
                  Path.home()/'storage'/'shared']
    storage = Path('/storage')
    try:
        if storage.is_dir():
            for item in storage.iterdir():
                if item.name not in ('emulated', 'self') and item.is_dir():
                    candidates.append(item)
    except OSError: pass
    result = []
    seen = set()
    for path in candidates:
        try:
            if not path.is_dir(): continue
            resolved = str(path.resolve())
            if resolved in seen: continue
            seen.add(resolved)
            result.append(path)
        except OSError: continue
    return result


def zip_census(path):
    try:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > META_MAX_ENTRIES:
                return {'limited': True, 'exe': False, 'assets': 0}
            exe, assets = False, 0
            for member in archive.infolist():
                if member.is_dir(): continue
                low = member.filename.lower()
                exe |= low.endswith('/forzahorizon5.exe') or low == 'forzahorizon5.exe'
                assets += low.endswith(ASSET_EXTS)
            return {'limited': False, 'exe': bool(exe), 'assets': assets}
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, MemoryError):
        return {'error': True, 'exe': False, 'assets': 0}


def discover(roots, limit=MAX_ENTRIES, deadline_s=MAX_SECONDS):
    started = time.monotonic()
    q = deque()
    seen = set()
    counts = Counter()
    candidates = []
    archive_pool = []
    access = 0
    for root in roots:
        try:
            if not root.is_dir(): continue
            real = str(root.resolve())
            if real in seen: continue
            seen.add(real)
            with os.scandir(root) as it: next(it, None)
            access += 1
            q.append((root, 0, game_hint(root.name)))
        except (OSError, PermissionError): counts['root_errors'] += 1

    def remember(path, kind, size, priority):
        candidates.append({'path': str(path), 'kind': kind, 'size': int(size), 'priority': priority})

    while q and counts['entries'] < limit and time.monotonic()-started < deadline_s:
        path, depth, inherited = q.popleft()
        try:
            with os.scandir(path) as scan: entries = list(scan)
        except (PermissionError, OSError):
            counts['denied_dirs'] += 1
            continue
        # Game/Downloads folders first; never open a file's data except short headers.
        entries.sort(key=lambda e: (not game_hint(e.name), e.name.lower() not in
                                    ('download', 'downloads', 'games', 'pcgames', 'steam'), e.name.lower()))
        for e in entries:
            if counts['entries'] >= limit or time.monotonic()-started >= deadline_s: break
            counts['entries'] += 1
            name = e.name
            if name.startswith('.') or re.match(r'^FH5_M\d+_', name, re.I): continue
            try:
                if e.is_symlink(): continue
                isdir = e.is_dir(follow_symlinks=False)
                isfile = e.is_file(follow_symlinks=False)
            except OSError: continue
            marked = inherited or game_hint(name)
            if isdir:
                if depth >= MAX_DEPTH: continue
                low = name.lower()
                if low in SKIP: continue
                if low == 'android' and not marked:
                    counts['android_tree_skipped'] += 1
                    continue
                try:
                    real = str(Path(e.path).resolve())
                    if real not in seen:
                        seen.add(real)
                        q.append((Path(e.path), depth+1, marked))
                except OSError: counts['denied_dirs'] += 1
                continue
            if not isfile: continue
            try: size = e.stat(follow_symlinks=False).st_size
            except OSError: continue
            low = name.lower()
            if low == 'forzahorizon5.exe':
                counts['exe_named'] += 1
                remember(e.path, 'game_executable_name', size, 100)
            if marked and low.endswith(ASSET_EXTS):
                counts['game_named_assets'] += 1
                if counts['game_named_assets'] <= 20:
                    remember(e.path, 'named_game_asset', size, 85)
            if archive_guess(name):
                counts['archives_by_extension'] += 1
            if size >= ARCHIVE_MIN:
                counts['files_over_256mb'] += 1
            possible = archive_guess(name) or marked or (size >= ARCHIVE_MIN)
            if possible:
                score = (70 if marked else 0) + (25 if archive_guess(name) else 0) + (5 if size>=ARCHIVE_MIN else 0)
                archive_pool.append((score, size, Path(e.path)))

    archive_pool.sort(key=lambda a: (-a[0], -a[1]))
    archive_pool = archive_pool[:SNIFF_LIMIT]
    zip_checked = 0
    for priority, size, p in archive_pool:
        kind = magic(p)
        counts['magic_'+kind] += 1
        if kind in ('rar', '7z', 'zip'):
            remember(p, 'archive_'+kind, size, priority)
            counts['archive_magic_confirmed'] += 1
        elif priority >= 70 and size > 0:
            remember(p, 'game_named_nonarchive', size, priority)
        if kind == 'zip' and zip_checked < ZIP_LIMIT:
            zip_checked += 1
            result = zip_census(p)
            counts['zip_game_exes'] += bool(result.get('exe'))
            counts['zip_asset_entries'] += result.get('assets', 0)
            counts['zip_census_limits'] += bool(result.get('limited'))
            counts['zip_census_errors'] += bool(result.get('error'))
    candidates.sort(key=lambda d:(-d['priority'], -d['size']))
    if counts['exe_named']:
        decision = 'NAMED_EXE_FOUND_NEEDS_VERIFICATION'
    elif counts['zip_game_exes']:
        decision = 'ZIP_LISTS_FORZA_EXE_NEEDS_EXTRACTION'
    elif counts['archive_magic_confirmed']:
        decision = 'POSSIBLE_ARCHIVES_FOUND_NEED_IDENTIFICATION'
    elif counts['files_over_256mb']:
        decision = 'LARGE_FILES_FOUND_UNIDENTIFIED'
    elif access == 0:
        decision = 'STORAGE_NOT_ACCESSIBLE'
    else:
        decision = 'NO_SOURCE_IDENTIFIED_IN_ACCESSIBLE_STORAGE'
    budget = bool(q and (counts['entries'] >= limit or time.monotonic()-started >= deadline_s))
    public = {
        'stage':'M77', 'status': 'M77_SCAN_PARTIAL' if budget else 'M77_STORAGE_DISCOVERY_COMPLETE',
        'source_state':decision, 'm76_input_verified':True,
        'roots_accessible':access, 'root_open_errors':counts['root_errors'],
        'entries_examined':counts['entries'], 'unreadable_directories':counts['denied_dirs'],
        'scan_budget_exhausted':budget, 'android_tree_skipped':counts['android_tree_skipped'],
        'forza_executable_filename_matches':counts['exe_named'],
        'game_named_asset_matches':counts['game_named_assets'],
        'archive_extensions_seen':counts['archives_by_extension'],
        'files_over_256mb':counts['files_over_256mb'],
        'large_or_named_files_magic_probed':len(archive_pool),
        'confirmed_archive_signatures':counts['archive_magic_confirmed'],
        'zip_archives_with_forza_exe_member':counts['zip_game_exes'],
        'zip_model_asset_name_matches':counts['zip_asset_entries'],
        'zip_metadata_limits':counts['zip_census_limits'],
        'zip_metadata_errors':counts['zip_census_errors'],
        'private_candidates_count':len(candidates),
        'scan_read_only':True, 'game_bytes_uploaded':False,
        'original_forza_asset_authenticated':False,'forza_format_decoded':False,
        'game_port_complete':False,
        'next_gate':'Identify actual game path from the PRIVATE local candidate report; do not upload that private report.'}
    return public, {'stage':'M77','private_only':True,'source_locations':candidates[:60],
                    'warning':'Contains local file paths. Do NOT upload.'}

class Tests(unittest.TestCase):
    def test_hint(self): self.assertTrue(game_hint('Forza Horizon 5'))
    def test_hint_no_report(self): self.assertFalse(game_hint('FH5_M76_REPORTS.zip'))
    def test_archive(self): self.assertTrue(archive_guess('some.part21.rar'))
    def test_archive_no(self): self.assertFalse(archive_guess('image.png'))
    def test_m76_good(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'m76.json'
            p.write_text(json.dumps({'stage':'M76','status':'M76_SOURCE_PREFLIGHT_COMPLETE',
                         'm75_input_verified':True,'read_only':True}))
            self.assertTrue(valid_m76(p))
    def test_m76_bad(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'m76.json';p.write_text('{}')
            self.assertFalse(valid_m76(p))
    def test_zip_census(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x.zip'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('ForzaHorizon5.exe',b'x')
                z.writestr('Data/car.modelbin',b'y')
            self.assertTrue(zip_census(p)['exe'])
            self.assertEqual(zip_census(p)['assets'],1)
    def test_magic_rar(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'x.bin';p.write_bytes(b'Rar!\x1a\x07\x01\x00')
            self.assertEqual(magic(p),'rar')
    def test_magic_zip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'no_extension';p.write_bytes(b'PK\x03\x04')
            self.assertEqual(magic(p),'zip')
    def test_empty_scan(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            public,_=discover([Path(t)])
            self.assertEqual(public['source_state'],'NO_SOURCE_IDENTIFIED_IN_ACCESSIBLE_STORAGE')
    def test_privacy(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'Forza Horizon 5';p.mkdir()
            (p/'ForzaHorizon5.exe').write_bytes(b'MZ')
            public,private=discover([Path(t)])
            self.assertNotIn(t,json.dumps(public))
            self.assertIn(t,json.dumps(private))
    def test_unknown_big_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'unknown.dat'
            with p.open('wb') as f:f.truncate(ARCHIVE_MIN+1)
            public,_=discover([Path(t)])
            self.assertEqual(public['source_state'],'LARGE_FILES_FOUND_UNIDENTIFIED')
    def test_missing_roots(self):
        public,_=discover([Path('/definitely/not/an/actual/root/m77')])
        self.assertEqual(public['source_state'],'STORAGE_NOT_ACCESSIBLE')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--extra-root',action='append',default=[])
    args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    stream=io.StringIO()
    res=unittest.TextTestRunner(stream=stream,verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    (OUT/'M77_LOCAL_TESTS.txt').write_text(stream.getvalue(),encoding='utf8')
    if not res.wasSuccessful():
        public={'stage':'M77','status':'M77_SELFTEST_FAILED'}
    elif not valid_m76(PRIOR):
        public={'stage':'M77','status':'M77_REQUIRES_VERIFIED_M76',
                'next_gate':'Run M76 first on the same phone.'}
    else:
        roots=find_roots()
        for extra in args.extra_root:
            p=Path(extra)
            if p.is_dir() and p not in roots: roots.append(p)
        public,private=discover(roots)
        PRIVATE.parent.mkdir(parents=True,exist_ok=True)
        PRIVATE.write_text(json.dumps(private,indent=2)+'\n',encoding='utf8')
        try: PRIVATE.chmod(0o600)
        except OSError: pass
    (OUT/'M77_STORAGE_REPORT.json').write_text(json.dumps(public,indent=2)+'\n',encoding='utf8')
    (OUT/'M77_STATUS.txt').write_text(public['status']+'\n'+public.get('source_state','')+'\n',encoding='utf8')
    dest=OUT.parent/'FH5_M77_REPORTS.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED) as z:
        for f in sorted(OUT.glob('M77_*')):
            if f.is_file() and f.suffix in ('.txt','.json'):z.write(f,'FH5_M77/'+f.name)
    print('[M77]',public['status'],public.get('source_state',''))
    print('[M77] Public report:',dest)
    print('[M77] Private local paths:',PRIVATE, '(DO NOT UPLOAD)')
    return 0 if public['status']=='M77_STORAGE_DISCOVERY_COMPLETE' else 17

if __name__=='__main__':raise SystemExit(main())
