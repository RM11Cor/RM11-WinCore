#!/usr/bin/env python3
"""Idempotently connect the read-only runtime audit to RM11 MainActivity.
Safe: edits only the indicated file and never changes build version/signing.
Run from the repository root AFTER copying this package's files into it.
"""
from pathlib import Path
src=Path('app/src/main/java/com/rm11/autocore/MainActivity.java')
if not src.is_file():
    raise SystemExit('Not in RM11-WinCore repository root; MainActivity.java not found')
s=src.read_text(encoding='utf-8')
if 'runtimeIntegrationAuditButton' in s:
    print('Already integrated: no changes')
    raise SystemExit(0)
anchor='        // Transactional, non-destructive ImageFs + Wine Prefix provisioner.'
if s.count(anchor)!=1:
    raise SystemExit('Unsupported version of MainActivity: anchor missing/ambiguous. No file modified.')
block='''        // First-source integration: read-only ELF loader / runtime boundaries audit.
        Button runtimeIntegrationAuditButton = action("RM11: تدقيق دمج Wine وFEX وBox64");
        TextView runtimeIntegrationAuditView = label("فحص الاعتماديات والبيئات فقط؛ لا يشغّل الألعاب.",
                14, 0xFFD1E0F5, false);
        runtimeIntegrationAuditView.setTextIsSelectable(true);
        runtimeIntegrationAuditButton.setOnClickListener(v -> {
            runtimeIntegrationAuditButton.setEnabled(false);
            scanExecutor.execute(() -> {
                String report;
                try {
                    com.rm11.autocore.runtime.RuntimeLayout layout =
                            new com.rm11.autocore.runtime.RuntimeLayout(
                                    getFilesDir().toPath(),
                                    new File(getApplicationInfo().nativeLibraryDir).toPath());
                    report = com.rm11.autocore.integration.RuntimeIntegrationAudit.report(layout);
                } catch (Exception e) {
                    report = "INTEGRATION AUDIT FAILED: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                }
                final String result = report;
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    runtimeIntegrationAuditView.setText(result);
                    runtimeIntegrationAuditButton.setEnabled(true);
                });
            });
        });
        body.addView(runtimeIntegrationAuditButton, margins(0, 0, 0, 8));
        body.addView(runtimeIntegrationAuditView, margins(0, 0, 0, 14));

'''
# Always validate all source anchors and build metadata before writing anything.
config=Path('app/build.gradle')
checker=Path('scripts-check.py')
bionic=Path('app/src/main/java/com/rm11/autocore/runtime/BionicLaunchEnvironment.java')
if not config.is_file() or not checker.is_file() or not bionic.is_file():
    raise SystemExit('Build configuration, scripts-check or Bionic env missing; no changes applied.')
old_bionic=bionic.read_text(encoding='utf-8')
if old_bionic.count('env.put("HODLL", "libwow64fex.dll");') != 1 or 'HODLL64' in old_bionic:
    raise SystemExit('Bionic emulator env differs from expected v2.5.3, no changes applied.')

old_gradle=config.read_text(encoding='utf-8')
old_check=checker.read_text(encoding='utf-8')
for old, label, source in [
    ("versionCode 28",'Gradle version code',old_gradle),
    ("versionName '2.5.3-wine-ipc'",'Gradle version name',old_gradle),
    ("'versionCode 28'",'CI version code check',old_check),
    ("\"versionName '2.5.3-wine-ipc'\"",'CI version name check',old_check),
    ('v2.5.3 • WineServer + اختبار Windows EXE','MainActivity subtitle',s),
]:
    if source.count(old)!=1:
        raise SystemExit('Unexpected or missing '+label+'; no changes applied.')
s=s.replace(anchor,block+anchor,1).replace('v2.5.3 • WineServer + اختبار Windows EXE',
                                       'v2.5.4 • تكامل مبدئي وفحص بيئة Wine/FEX',1)
new_bionic=old_bionic.replace('env.put("HODLL", "libwow64fex.dll");',
    'env.put("HODLL64", "libarm64ecfex.dll");\n        env.put("HODLL", "libwow64fex.dll");',1)
new_gradle=old_gradle.replace('versionCode 28','versionCode 29',1).replace(
    "versionName '2.5.3-wine-ipc'", "versionName '2.5.4-runtime-integration'",1)
new_check=old_check.replace("'versionCode 28'","'versionCode 29'",1).replace(
    "\"versionName '2.5.3-wine-ipc'\"", "\"versionName '2.5.4-runtime-integration'\"",1)
required_sources=[
    'app/src/main/java/com/rm11/autocore/integration/RuntimeCatalog.java',
    'app/src/main/java/com/rm11/autocore/integration/RuntimeIntegrationAudit.java',
    'app/src/main/java/com/rm11/autocore/integration/Elf64Inspection.java',
    'app/src/main/java/com/rm11/autocore/integration/WineDriveMapper.java',
    'app/src/test/java/com/rm11/autocore/integration/IntegrationContractTest.java',
]
for path in required_sources:
    if not Path(path).is_file():
        raise SystemExit('Required integration file absent: '+path+'; no changes applied.')
new_check+='''
# v2.5.4 runtime integration audit, ABI/profile gates and safe drive mapping.
for path in ''' + repr(required_sources)+''':
    if not Path(path).is_file() or not Path(path).stat().st_size:
        raise SystemExit('MISSING RUNTIME INTEGRATION FILE: ' + path)
print('RM11 v2.5.4 integration source present; native game startup NOT proven.')
'''
src.write_text(s,encoding='utf-8')
config.write_text(new_gradle,encoding='utf-8')
checker.write_text(new_check,encoding='utf-8')
bionic.write_text(new_bionic,encoding='utf-8')
print('Integrated Runtime v2.5.4 audit UI, HODLL64 FEX selection, source checks and versionCode=29.')
