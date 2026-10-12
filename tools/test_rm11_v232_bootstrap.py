#!/usr/bin/env python3
"""Pure source contract for V2.3.2 bootstrapping; DOES NOT prove Wine startup."""
from pathlib import Path
p=Path(__file__).resolve().parent.parent
runner=(p/'app/src/main/java/com/rm11/wincore/WineFirstExeV22.java').read_text()
pack=(p/'tools/package_wine_exe_v22.py').read_text()
gradle=(p/'app/build.gradle.kts').read_text()
for s in ('RM11_SOURCE_V2_3_5','rm11-v235-wineprefix','[PREFIX STATUS]',
          '[WINE BOOT COMPONENT]', '[SERVER SPAWN]', '[SERVER CTYPE]',
          'XDG_RUNTIME_DIR', 'TMPDIR', '+process'):
    assert s in runner, f'Missing V2.3.2 runtime diagnostic: {s}'
assert 'versionCode = 41' in gradle and 'versionName = "2.3.5"' in gradle
assert 'RM11_WINESERVER_BRIDGE_PREFLIGHT_OK' in runner
for s in ('services.exe','explorer.exe','winedevice.exe','plugplay.exe','rpcss.exe'):
    assert s in pack, f'Missing Wine bootstrap component staging option: {s}'
assert 'android:allowNativeHeapPointerTagging="false"' not in (p/'app/src/main/AndroidManifest.xml').read_text()
print('PASS: V2.3.2 isolated wineprefix, bootstrap component staging and process/server diagnostics; real Android execution unverified')
