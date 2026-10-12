#!/usr/bin/env python3
"""V2.3.4 source checks; offline and not proof of successful Android Wine boot."""
from pathlib import Path
p = Path(__file__).resolve().parent.parent
wine=(p/'app/src/main/java/com/rm11/wincore/WineFirstExeV22.java').read_text()
ui=(p/'app/src/main/java/com/rm11/wincore/MainActivity.java').read_text()
config=(p/'app/build.gradle.kts').read_text()
manifest=(p/'app/src/main/AndroidManifest.xml').read_text()
for token in (
 'RM11_SOURCE_V2_3_4', 'rm11-v234-wineprefix', 'rm11-v234-boot-ready.ok',
 'private static final int BOOT_TIMEOUT_SECONDS = 120',
 'bootstrapOnly ? BOOT_TIMEOUT_SECONDS : TIMEOUT_SECONDS',
 'env.put("BOX64_DYNAREC", mode == ProbeMode.NORMAL ? "1" : "0")',
 'env.put("WINEDEBUG","-all,err+all,warn+all,+process")',
 '"-k"', '[PRIVATE SERVER CLEANUP]', '[IPC OBSERVATIONS]',
 '[IPC LIMIT]', '[PREFIX STATUS]', '[BOOT READY]', '[BOOT TIMEOUT]',
 'if (!bootstrapOnly && mode == ProbeMode.NORMAL && !prefixInitialized(prefix))',
 'if (finished && code == 0 && sysReg && userReg)',
 'bootStamp.getFD().sync()', '[EXE SKIPPED]'):
    assert token in wine, token
assert 'versionCode = 40' in config and 'versionName = "2.3.4"' in config
assert 'rm11-v234-wineprefix' in wine and 'rm11-v233-wineprefix' not in wine
assert 'V2.3.4' in ui and 'WineFirstExeV22.runBootstrap' in ui
assert 'android:allowNativeHeapPointerTagging="false"' not in manifest
assert wine.index('if (!bootstrapOnly && mode == ProbeMode.NORMAL && !prefixInitialized(prefix))') < wine.index('process=pb.start()')
print('PASS: V2.3.4 unique Wine prefix, bounded timeout, Dynarec trial, reduced Wine debug, server cleanup, strict success gate')
