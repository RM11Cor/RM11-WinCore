#!/usr/bin/env python3
"""V2.3.3 source-contract test. Not proof of Wine bootstrap on Android."""
from pathlib import Path
root=Path(__file__).resolve().parent.parent
java=(root/'app/src/main/java/com/rm11/wincore/WineFirstExeV22.java').read_text()
ui=(root/'app/src/main/java/com/rm11/wincore/MainActivity.java').read_text()
conf=(root/'app/build.gradle.kts').read_text()
for needle in ('RM11_SOURCE_V2_3_5','rm11-v235-wineprefix','rm11-v235-boot-ready.ok',
               'public static String runBootstrap(Context ctx)',
               'new ProcessBuilder(box.getAbsolutePath(), wine.getAbsolutePath(), "wineboot.exe", "--init")',
               'if (!bootstrapOnly && mode == ProbeMode.NORMAL && !prefixInitialized(prefix))',
               '[EXE SKIPPED]', '[BOOT READY]', '[BOOT NOT READY]', '[BOOT TIMEOUT]',
               '[PREFIX STATUS]', '[IPC OBSERVED]', '[PHASE] WINE_BOOT_ONLY',
               'wineboot exited 0 and created both registry files',
               'bootStamp.getFD().sync()', 'if (!bootstrapOnly) report.append(classify('):
    assert needle in java, f'Missing bootstrap gate: {needle}'
for needle in ('wineV233BootButton', 'runWineV233Boot()',
               'WineFirstExeV22.runBootstrap(getApplicationContext())',
               '1 — تهيئة Wine V2.3.5', '2 — اختبار أول Windows EXE'):
    assert needle in ui, f'Missing phone UI: {needle}'
assert 'versionCode = 41' in conf and 'versionName = "2.3.5"' in conf
assert 'android:allowNativeHeapPointerTagging="false"' not in (root/'app/src/main/AndroidManifest.xml').read_text()
assert java.index('if (!bootstrapOnly && mode == ProbeMode.NORMAL && !prefixInitialized(prefix))') < java.index('ProcessBuilder pb = bootstrapOnly')
assert java.index('if (finished && code == 0 && sysReg && userReg)') < java.index('bootStamp.getFD().sync()')
print('PASS: V2.3.3 Wine boot separate invocation, success receipt, EXE gate, bounded report and UI source contract')
