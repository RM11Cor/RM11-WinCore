from pathlib import Path
from xml.etree import ElementTree as ET

root = Path(__file__).resolve().parent
manifest = ET.parse(root / 'app/src/main/AndroidManifest.xml').getroot()
assert manifest.tag == 'manifest'
java = (root / 'app/src/main/java/com/rm11/wincore/MainActivity.java').read_text()
catalog = (root / 'app/src/main/java/com/rm11/wincore/LauncherCatalog.java').read_text()
native = (root / 'app/src/main/cpp/VulkanProbe.cpp').read_text()
for term in ('steam', 'ubisoft', 'ea', 'rockstar'):
    assert f'new Launcher("{term}"' in catalog
assert 'ACTION_OPEN_DOCUMENT' in java and 'ACTION_CREATE_DOCUMENT' in java
assert 'RuntimeGateway.currentStatusArabic()' in java
assert 'vkEnumeratePhysicalDevices' in native
assert 'ACCESS_ALL_FILES' not in str(manifest.attrib)
print('PASS: project files, manifest, official launcher IDs, Vulkan native probe and report actions present')

ready = (root / 'app/src/main/java/com/rm11/wincore/RuntimeReadiness.java').read_text()
assert 'RuntimeReadiness.inspect' in java
assert 'NOT INTEGRATED' in ready and 'NX809J' in ready
assert 'vkGetPhysicalDeviceFeatures2' in native
print('PASS: V0.2 preflight and Vulkan feature bits are present')

# V0.3 source checks: read-only PE header, private workspace, native Android subprocess.
pe=(root/'app/src/main/java/com/rm11/wincore/PeInspector.java').read_text()
boot=(root/'app/src/main/java/com/rm11/wincore/RuntimeBootstrap.java').read_text()
assert 'MAX_HEADER = 1024 * 1024' in pe and "case 0x8664" in pe
assert 'process.waitFor(8, TimeUnit.SECONDS)' in boot and 'correctDevice()' in boot
assert 'rm11-runtime' in boot and 'wine-prefix-placeholder' in boot
assert 'new Thread' in java and 'PeInspector.inspect' in java
assert 'versionName = "2.3.8"' in (root/'app/build.gradle.kts').read_text()
print('PASS: inherited V0.3 workspace, bounded PE inspection and native subprocess checks')

# V0.4: streaming bundle audit with bounded data and no process execution.
bundle=(root/'app/src/main/java/com/rm11/wincore/EngineBundleVerifier.java').read_text()
assert 'MAX_TOTAL' in bundle and 'MessageDigest.getInstance("SHA-256")' in bundle
assert 'ZipInputStream' in bundle and 'RuntimeBootstrap.correctDevice()' in bundle
assert 'EngineBundleVerifier.verify' in java and 'VERIFY_ENGINE_BUNDLE' in java
assert 'NOT READY' in bundle and 'does NOT' not in bundle  # status does not claim executable Wine
print('PASS: V0.4 read-only streaming runtime bundle audit and device restrictions')

# V0.5: static graphics API hints and balanced *suggestions*, no claim of runnable Windows games.
import subprocess
import tempfile
assert 'WindowsExecutableAnalyzer.analyze' in java
assert 'SmartGameProfile.recommend' in java
assert 'GAME_PROFILE_PICK' in java and 'GAME_PROFILE_EXPORT' in java
assert 'no EXE execution' in (root/'app/src/main/java/com/rm11/wincore/SmartGameProfile.java').read_text()
print('PASS: V0.5 read-only EXE advisor UI and explicit no-execution status')
with tempfile.TemporaryDirectory(prefix='rm11-tests-') as tmp:
    src = root/'app/src/main/java/com/rm11/wincore'
    subprocess.run(['javac', '-encoding', 'UTF-8', '-d', tmp,
                    str(src/'WindowsExecutableAnalyzer.java'),
                    str(src/'SmartGameProfile.java'),
                    str(root/'tests/CompatibilityAnalysisTest.java')], check=True)
    subprocess.run(['java', '-cp', tmp, 'CompatibilityAnalysisTest'], check=True)

# V0.6-A native ELF metadata audit, never execute components.
elf=(root/'app/src/main/java/com/rm11/wincore/ElfRuntimeInspector.java').read_text()
assert 'ELF_RUNTIME_PICK' in java and 'ElfRuntimeInspector.analyze' in java
assert 'MAX_PREFIX = 256 * 1024' in elf and 'DT_NEEDED' in elf
assert 'Nothing installed, loaded, or executed' in elf
with tempfile.TemporaryDirectory(prefix='rm11-elf-') as tmp:
    src = root/'app/src/main/java/com/rm11/wincore'
    subprocess.run(['javac', '-encoding', 'UTF-8', '-d', tmp,
                    str(src/'ElfRuntimeInspector.java'),
                    str(root/'tests/ElfRuntimeInspectorTest.java')], check=True)
    subprocess.run(['java', '-cp', tmp, 'ElfRuntimeInspectorTest'], check=True)
print('PASS: V0.6-A bounded ARM64 ELF loader and library audit; no executable engine')

# V0.7: test a *packaged* Android ARM64 JNI library and host linker path.
# This is not a test of Windows emulation or third-party binary execution.
bridge_cpp=(root/'app/src/main/cpp/RuntimeNativeBridge.cpp').read_text()
bridge_java=(root/'app/src/main/java/com/rm11/wincore/NativeRuntimeBridge.java').read_text()
cmake=(root/'app/src/main/cpp/CMakeLists.txt').read_text()
assert 'Java_com_rm11_wincore_NativeRuntimeBridge_nativeSelfTest' in bridge_cpp
assert 'dlopen("libc.so"' in bridge_cpp and 'dlsym(libc, "getpid")' in bridge_cpp
assert 'RuntimeNativeBridge.cpp' in cmake and ' dl)' in cmake
assert 'NativeRuntimeBridge.inspect()' in java and 'NativeRuntimeBridge' in bridge_java
assert 'System.loadLibrary("rm11probe")' in bridge_java
assert '[NOT INTEGRATED]' in bridge_cpp and 'versionName = "2.3.8"' in (root/'app/build.gradle.kts').read_text()
print('PASS: V0.7 JNI Android/Bionic host smoke test wired to UI; no Wine/Box64 claims')


# V0.8: a real second NDK .so module, dlopen/dlsym C ABI handshake.
# This proves Android intra-APK native integration, NOT Box64/Wine execution.
import shutil
adapter = (root/'app/src/main/cpp/RuntimePluginAdapter.cpp').read_text()
contract = (root/'app/src/main/cpp/RuntimeAdapterContract.h').read_text()
assert 'add_library(rm11runtime_adapter SHARED RuntimePluginAdapter.cpp)' in cmake
assert 'dlopen("librm11runtime_adapter.so"' in bridge_cpp
assert 'RM11_ADAPTER_ABI_VERSION' in bridge_cpp and 'dlsym(module' in bridge_cpp
assert 'NativeRuntimeBridge.inspectAdapter()' in java
assert 'versionCode = 42' in (root/'app/build.gradle.kts').read_text()
assert 'RM11_ADAPTER_ABI_VERSION 1u' in contract
assert 'rm11_adapter_self_test' in adapter
assert '[NOT INTEGRATED]' in bridge_cpp
compiler = shutil.which('g++')
if compiler:
    with tempfile.TemporaryDirectory(prefix='rm11-adapter-') as tmp:
        cpp = root/'app/src/main/cpp'
        shared = Path(tmp)/'librm11runtime_adapter.so'
        exe = Path(tmp)/'adapter-contract-test'
        subprocess.run([compiler,'-std=c++17','-Wall','-Wextra','-Werror','-fPIC',
                        '-shared',str(cpp/'RuntimePluginAdapter.cpp'),'-o',str(shared)],check=True)
        subprocess.run([compiler,'-std=c++17','-Wall','-Wextra','-Werror',
                        '-I',str(cpp),str(root/'tests/NativeAdapterContractTest.cpp'),
                        '-ldl','-o',str(exe)],check=True)
        subprocess.run([str(exe),str(shared)],check=True)
else:
    print('WARN: g++ not available; native dynamic module test omitted')
print('PASS: V0.8 native adapter module, interface and Java binding wired')

# V0.9: stage verified inert bundle bytes to application private storage, never execute.
stager = (root / 'app/src/main/java/com/rm11/wincore/EngineBundleStager.java').read_text()
assert 'EngineBundleStager.stage' in java and 'STAGE_ENGINE_BUNDLE' in java
assert 'new AlertDialog.Builder(this)' in java and 'runOnUiThread' in java
assert 'MessageDigest.getInstance("SHA-256")' in stager and 'getUsableSpace()' in stager
assert 'spec.id + ".blob"' in stager and 'new File(stage, spec.path)' not in stager
assert 'MAX_TOTAL' in stager and 'renameTo(active)' in stager
assert 'NO ENGINE EXECUTION' in stager and 'NOT RUNNABLE' in stager
assert 'Runtime.getRuntime().exec' not in stager and 'ProcessBuilder' not in stager
print('PASS: V0.9 inert engine bundle staging, checksum validation, rollback and UI consent')

subprocess.run(['python3', str(root/'tools/test_stager_host.py')], check=True)

# V1.0-A: read-only audit of staged bundles with fresh SHA256 plus bounded ELF details.
inventory = (root / 'app/src/main/java/com/rm11/wincore/StagedEngineInventory.java').read_text()
binary_audit = (root / 'app/src/main/java/com/rm11/wincore/RuntimeBinaryAudit.java').read_text()
assert 'StagedEngineInventory.inspect' in java and 'runStagedInventory()' in java
assert 'RuntimeBinaryAudit.inspect' in inventory and 'ElfRuntimeInspector.analyze' in binary_audit
assert 'SHA256 is NOT proof of origin' in inventory
assert '[NOT RUNNABLE]' in inventory and '[MISSING]' in inventory
assert 'ProcessBuilder' not in inventory and 'Runtime.getRuntime().exec' not in inventory
with tempfile.TemporaryDirectory(prefix='rm11-inventory-') as tmp:
    src = root/'app/src/main/java/com/rm11/wincore'
    subprocess.run(['javac', '-encoding','UTF-8','-d',tmp,
                    str(src/'ElfRuntimeInspector.java'),
                    str(src/'RuntimeBinaryAudit.java'),
                    str(root/'tests/RuntimeBinaryAuditTest.java')],check=True)
    subprocess.run(['java','-cp',tmp,'RuntimeBinaryAuditTest'],check=True)
print('PASS: V1.0 staged bundle inventory/re-hash and native ELF classification; no EXE claims')

# V1.1: real Android ARM64 PIE *process*, built by NDK into APK native lib directory.
# Unlike V0.3 shell test, this executes our own compiled ARM64 ELF in a new OS process.
exec_java=(root/'app/src/main/java/com/rm11/wincore/PackagedNativeProcess.java').read_text()
exec_c=(root/'app/src/main/cpp/PackagedExecProbe.c').read_text()
gradle=(root/'app/build.gradle.kts').read_text()
assert 'PackagedNativeProcess.runSelfTest' in java and 'runPackagedNativeProcess()' in java
assert 'ProcessBuilder(executable.getAbsolutePath(), "--self-test")' in exec_java
assert 'process.waitFor(7, TimeUnit.SECONDS)' in exec_java
assert 'RM11_ANDROID_ELF_EXEC_OK' in exec_c
assert 'useLegacyPackaging = true' in gradle
assert '[NOT INTEGRATED]' in exec_java
subprocess.run(['python3',str(root/'tools/test_exec_host.py')], check=True)
# The default GitHub Actions ZIP workflow already calls scripts-check.py before Gradle:
# build the executable here, avoiding another manual workflow-file edit per release.
command=['python3',str(root/'tools/build_native_exec.py')]
if __import__('os').environ.get('CI'):
    command.append('--required')
subprocess.run(command,check=True)
print('PASS: V1.1 first-party APK executable launch path; Wine/Box64 remain absent')

# V1.2: pin the debug signing certificate across ephemeral GitHub Action runners.
# This development key is public to anyone with the source; NOT for publication.
assert 'signingConfigs.getByName("rm11PrototypeDebug")' in gradle
assert 'versionName = "2.3.8"' in gradle and 'versionCode = 42' in gradle
subprocess.run(['python3', str(root/'tools/check_debug_signing.py')], check=True)
assert '[DEV SIGNING]' in java and '[ONE-TIME]' in java
print('PASS: V1.2 development debug key identity pinned; update version incremented')

# V1.3: attempt to build real upstream Box64, on CI only, from pinned MIT source.
# The legacy Android test executable still builds even when experimental Box64 fails.
box64_probe=(root/'app/src/main/java/com/rm11/wincore/OfficialBox64Probe.java').read_text()
box64_builder=(root/'tools/build_official_box64.py').read_text()
assert 'OfficialBox64Probe.inspect' in java and 'runOfficialBox64Probe()' in java
assert 'new ProcessBuilder(binary.getAbsolutePath(), "--version")' in box64_probe
assert '[NOT BUILT]' in box64_probe and 'Box64 --version success is NOT evidence' in box64_probe
assert '2f130fab1d6e1a4ee8a71dc60cfdfcc839ad192a' in box64_builder
assert '-DANDROID=ON' in box64_builder and 'verify_android_pie(binary)' in box64_builder
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3',str(root/'tools/test_box64_errno_patch.py')],check=True)
assert 'patch_android_errno_bridge(source)' in box64_builder and 'GOM(__errno_location, pFEv)' in box64_builder
subprocess.run(['python3',str(root/'tools/test_box64_builder.py')],check=True)
subprocess.run(['python3',str(root/'tools/test_box64_probe_host.py')],check=True)
if __import__('os').environ.get('CI') and not __import__('os').environ.get('RM11_SKIP_BOX64'):
    # Experimental compilation errors cannot break the proven RM11 Android probe.
    subprocess.run(['python3',str(root/'tools/build_official_box64.py'), '--required'],check=True)
else:
    print('SKIP: optional upstream Box64 build (CI only); no Box64 executable bundled locally')
print('PASS: V1.3 upstream Box64 build path, pinned revision, bounded version probe and fallback')

# V1.4: freestanding Linux x86-64 ELF is compiled on x86-64 CI (not Android ELF),
# packaged as *data* and handed only to genuine Android ARM64 Box64 by fixed path.
# Local/CI host program run proves its assembly output; Box64 execution remains
# unverified until the end-user presses the section 14 test button.
guest_builder = (root/'tools/build_x86_guest.py').read_text()
guest_runner = (root/'app/src/main/java/com/rm11/wincore/Box64GuestSmokeTest.java').read_text()
assert 'Box64GuestSmokeTest.run' in java and 'runBox64GuestSmokeTest()' in java
assert 'new ProcessBuilder(box64.getAbsolutePath(), guest.getAbsolutePath())' in guest_runner
assert 'process.waitFor(18, TimeUnit.SECONDS)' in guest_runner
assert 'process.exitValue()' in guest_runner and 'stdout.contains(SUCCESS)' in guest_runner
assert 'verifyGuest(contents)' in guest_runner and 'guest.delete()' in guest_runner
assert '-nostdlib' in guest_builder and '-static' in guest_builder
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3', str(root/'tools/build_x86_guest.py')], check=True)
subprocess.run(['python3', str(root/'tools/test_box64_guest_host.py')], check=True)
assert 'guest.setExecutable(true, true)' in guest_runner and 'guest.canExecute()' in guest_runner
print('PASS: V1.4 x86-64 freestanding guest data built, ELF validated, host smoke-tested, Java control logic tested')
print('LIMIT: No Android APK or Box64 translation was tested locally; on-device feedback required')

# V1.5: real x86-64 Linux glibc-linked executable; the Android APK does NOT bundle glibc.
# Local compilation/host execution and mocked Java test are not on-device Box64 proof.
dynamic_guest = (root/'app/src/main/java/com/rm11/wincore/Box64DynamicGlibcTest.java').read_text()
assert 'Box64DynamicGlibcTest.run' in java and 'runBox64DynamicGlibcTest()' in java
assert 'DT_NEEDED: ' in dynamic_guest and 'libc.so.6' in dynamic_guest
assert 'No Linux/glibc rootfs' in dynamic_guest and '[DEPENDENCY BLOCKED]' in dynamic_guest
assert 'process.exitValue() == 0 && log.contains(MARKER)' in dynamic_guest
assert 'new ProcessBuilder(executable.getAbsolutePath(), guest.getAbsolutePath())' in dynamic_guest
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3', str(root/'tools/build_dynamic_glibc_guest.py')],check=True)
subprocess.run(['python3', str(root/'tools/test_box64_dynamic_host.py')],check=True)
print('PASS: V1.5 dynamic glibc guest PT_INTERP/DT_NEEDED; host Linux exec; mocked Android result diagnostics')
print('LIMIT: Dynamic glibc guest translation on Android is UNKNOWN until section 15 on-device test')

# V1.6: evidence-based Dynarec ON/OFF diagnosis. Does not claim glibc integration.
new_runner=(root/'app/src/main/java/com/rm11/wincore/Box64DynarecDiagnostic.java').read_text()
assert 'runBox64V16Diagnostic()' in java and 'Box64DynarecDiagnostic.run' in java
assert 'BOX64_DYNAREC' in new_runner and '"1" : "0"' in new_runner
assert 'Box64DynamicGlibcTest.verifyGuest(data)' in new_runner
assert 'on.passed() && off.passed()' in new_runner and '[FAIL BOTH]' in new_runner
assert 'process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)' in new_runner
assert 'versionName = "2.3.8"' in gradle and 'versionCode = 42' in gradle
subprocess.run(['python3',str(root/'tools/test_box64_dynarec_host.py')],check=True)
print('PASS: V1.6 two isolated Dynarec modes, bounded log, audit and diagnosis with offline mocks')
print('LIMIT: Actual Android Box64 behavior requires section 16 device test')

# V1.7: isolate glibc CRT startup from a genuine libc write@PLT relocation.
libc_trial=(root/'app/src/main/java/com/rm11/wincore/Box64LibcStartupTrial.java').read_text()
assert 'Box64LibcStartupTrial.run(getApplicationContext())' in java
assert 'NO CRT + libc write@PLT' in libc_trial and 'BOX64_DYNAREC' in libc_trial
assert '__libc_start_main' in libc_trial and '[ISOLATED]' in libc_trial
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3',str(root/'tools/build_no_crt_libc_guest.py')],check=True)
subprocess.run(['python3',str(root/'tools/test_no_crt_libc_host.py')],check=True)
print('PASS: V1.7 dynamic libc write relocation, x86-64 host smoke test, mocked differential analysis')
print('LIMIT: On-device Box64 translation is unverified; no general glibc/Wine fix claimed')

# V1.8: pinned Box64 Android startup source fix, checked before optional CI build.
# Host tests verify build-time preprocessing and Java classification only.
assert 'runBox64V18Trial()' in java
assert 'Box64LibcStartupTrial.runV18Regression(getApplicationContext())' in java
trial = (root/'app/src/main/java/com/rm11/wincore/Box64LibcStartupTrial.java').read_text()
assert '[STILL BROKEN]' in trial and '[PASS CRT]' in trial
assert 'PATCH_RECEIPT' in box64_builder and 'patch_android_glibc_startup(source)' in box64_builder
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3',str(root/'tools/test_box64_startup_patch.py')],check=True)
print('PASS: V1.8 dual-entry patched Box64 source contract, compiler smoke-test and Android UI wiring')
print('LIMIT: actual patched Box64 NDK build and normal glibc CRT execution require GitHub and device validation')

# V1.9: four genuine dynamic x86-64 Linux glibc subprocess ABI probes.
v19 = (root/'app/src/main/java/com/rm11/wincore/Box64AbiCompatibilityV19.java').read_text()
assert 'Box64AbiCompatibilityV19.run(getApplicationContext())' in java
assert '[SUMMARY]' in v19 and '[PASS FOUR]' in v19 and 'BOX64_DYNAREC' in v19
assert 'guest.setExecutable(true, true)' in v19 and 'process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)' in v19
assert 'containsExactLine(log, PREFIX + marker + "_OK")' in v19
assert '"malloc/calloc/realloc/free"' in v19 and '"pthread_create/join"' in v19
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3', str(root/'tools/build_v19_compat_guest.py')], check=True)
subprocess.run(['python3', str(root/'tools/test_v19_compat_host.py')], check=True)
print('PASS: V1.9 four-mode host smoke tests, APK UI, Java fault classification and version identity')
print('LIMIT: Real Android Box64 execution is only confirmed by the user on-device')

# GitHub workflows already call scripts-check.py BEFORE Gradle; place the genuine
# Wine package step here so merely uploading a newer ZIP works with the EXISTING
# repository workflow. Fail CI if the authentic Wine package is unavailable.
if __import__('os').environ.get('CI'):
    subprocess.run(['sudo', 'apt-get', 'update', '-qq'], check=True)
    subprocess.run(['python3', str(root/'tools/package_wine_loader.py'), '--required'], check=True)
    subprocess.run(['python3', str(root/'tools/package_wine_runtime_v21.py'), '--required'], check=True)
    subprocess.run(['python3', str(root/'tools/package_wine_exe_v22.py'), '--required'], check=True)
else:
    print('SKIP: Ubuntu Wine APT download (GitHub CI only); no Wine binary packaged locally')

# V2.0: optional genuine x86-64 Linux Wine loader ELF + Box64 --version launch.
# This does NOT imply Wine prefix, Windows program support, graphics or a bundled userland.
wine_java = (root/'app/src/main/java/com/rm11/wincore/WineLoaderV20.java').read_text()
wine_tool = (root/'tools/package_wine_loader.py').read_text()
assert 'WineLoaderV20.run(getApplicationContext())' in java
assert 'wineV20Button' in java and 'wineV20StatusView' in java
assert 'new ProcessBuilder(box.getAbsolutePath(), guest.getAbsolutePath(), "--version")' in wine_java
assert '[WINE NOT PACKAGED]' in wine_java and '[PASS WINE VERSION]' in wine_java
assert 'versionSeen(log)' in wine_java and 'code == 0' in wine_java
assert 'MessageDigest.getInstance("SHA-256")' in wine_java
assert 'apt-get' in wine_tool and 'download' in wine_tool and "pkg != 'wine64'" in wine_tool
assert 'versionName = "2.3.8"' in gradle and 'versionCode = 42' in gradle
subprocess.run(['python3', str(root/'tools/test_wine_v20_host.py')], check=True)
print('PASS: V2.0 real distro Wine launcher build path, bounded Box64 --version subprocess and result classification')
print('LIMIT: Wine launcher may not be packaged; no libwine, wineserver, Windows EXE or games integrated')

# V2.1: staged path tree for genuine matched Linux Wine loader/ntdll from distro.
wine_v21=(root/'app/src/main/java/com/rm11/wincore/WineRuntimeV21.java').read_text()
pack_v21=(root/'tools/package_wine_runtime_v21.py').read_text()
assert 'WineRuntimeV21.run(getApplicationContext())' in java
assert 'wineV21Button' in java and 'wineV21StatusView' in java
assert 'ntdll.so' in wine_v21 and 'WINEDLLPATH' in wine_v21 and 'BOX64_LD_LIBRARY_PATH' in wine_v21
assert 'MessageDigest.getInstance("SHA-256")' in wine_v21 and '[PASS WINE VERSION]' in wine_v21
assert 'wine64' in pack_v21 and 'libwine' in pack_v21 and 'Mismatched Wine versions' in pack_v21
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3',str(root/'tools/test_wine_v21_host.py')],check=True)
print('PASS: V2.1 matched Wine package staging contract; ntdll path layout; asset integrity; Java host diagnostics')
print('LIMIT: Android Wine --version startup with libwine/ntdll remains unverified until actual device test')

# V2.1.2: fail-closed package inventory for actual missing libunwind8 and liblzma.
assert "libunwind.so.8" in wine_v21 and "liblzma.so.5" in wine_v21
assert "libunwind8" in pack_v21 and "liblzma5" in pack_v21
assert "BOX64_LD_LIBRARY_PATH" in wine_v21 and "supportLibs" in wine_v21
print("PASS: V2.1.2 libunwind/lzma paths included and verified; device execution unverified")

# V2.1.3: Android Box64 shim for wrapped x86-64 glibc errno symbol.
assert 'rm11-wine-v214' in wine_v21
assert 'V2.1.4 / Box64 Android glibc compatibility bridges' in wine_v21
assert 'test_box64_errno_patch.py' in box64_builder or 'patch_android_errno_bridge(source)' in box64_builder
print('PASS: V2.1.3 errno wrapper source validation; Wine --version on Android NOT YET proven')

# V2.1.4: wrappers for GNU glibc assert/line reader ABI on Android.
assert 'patch_android_glibc_misc_bridges(source)' in box64_builder
assert 'my___assert_fail' in box64_builder and 'my___getdelim' in box64_builder
assert 'vFEppup' in box64_builder and 'lFEppiS' in box64_builder
subprocess.run(['python3', str(root/'tools/test_box64_glibc_misc_patch.py')], check=True)
print('PASS: V2.1.4 GNU glibc symbol shims checked on host; Android/Wine runtime unverified')

# V2.2 first Windows EXE experiment: a genuine Windows x86-64 PE, not Linux ELF.
pe_runner = (root/'app/src/main/java/com/rm11/wincore/WineFirstExeV22.java').read_text()
pe_builder = (root/'tools/build_v22_pe_guest.py').read_text()
pe_packer = (root/'tools/package_wine_exe_v22.py').read_text()
bridge_src = (root/'app/src/main/cpp/WineServerBridge.c').read_text()
assert 'WineFirstExeV22.run(getApplicationContext())' in java and 'runWineV22Exe()' in java
assert 'WineRuntimeV21.stageTo(ctx,root)' in pe_runner
assert 'CreateFileA' in pe_runner and 'WriteFile' in pe_runner
assert 'written' in pe_runner and 'exitCode==0 && markerOk' in pe_runner
assert 'WINESERVER' in pe_runner and 'RM11_WINESERVER64_PATH' in pe_runner
assert 'rm11-v235-wineprefix' in pe_runner and 'WINEARCH' in pe_runner
assert 'librm11box64.so' in bridge_src and 'execv(box, args)' in bridge_src
assert 'Mismatched Wine versions' in pack_v21 and 'does not match V2.1.4' in pe_packer
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
subprocess.run(['python3',str(root/'tools/build_v22_pe_guest.py')],check=True)
subprocess.run(['python3',str(root/'tools/test_wine_v22_host.py')],check=True)
cmd=['python3',str(root/'tools/build_wineserver_bridge_v22.py')]
if __import__('os').environ.get('CI'):cmd.append('--required')
subprocess.run(cmd,check=True)
print('PASS: V2.2 Win64 PE32+ first-party probe, Wine PE module package contract, ARM64 server bridge')
print('LIMIT: Windows EXE, Wine prefix and wineserver operation require on-device test. No games support claimed.')

# V2.2.1 Wine language data and Android heap tagging mitigation diagnostic.
manifest_xml=(root/'app/src/main/AndroidManifest.xml').read_text()
assert 'android:allowNativeHeapPointerTagging="false"' not in manifest_xml
assert 'WINEDATADIR' in pe_runner and 'env.put("LC_ALL","C")' in pe_runner
assert 'share/wine/' in pe_runner and 'NLS_REQUIRED' in pe_packer
assert 'wine.inf' in pe_packer and 'l_intl.nls' in pe_runner
print('PASS: V2.2.3 Win32 NLS/data path checks and manifest size fix enabled')

# V2.2.3: The previous app rejected the real PE/NLS manifest after 10,000 bytes.
assert 'MAX_MANIFEST_BYTES = 1024 * 1024' in pe_runner
assert 'ASSET+"WINDOWS-COMPONENTS.tsv",MAX_MANIFEST_BYTES' in pe_runner
assert 'MAX_MANIFEST_BYTES=1024*1024' in pe_packer
print('PASS: V2.2.3 on-device Wine manifest read cap aligned with packer')

# V2.2.3: Bionic nl_langinfo numeric ABI must not turn CODESET into Saturday.
assert 'patch_android_nl_langinfo_codeset(source)' in box64_builder
assert 'GOM(nl_langinfo, pFEi)' in box64_builder
subprocess.run(['python3',str(root/'tools/test_box64_langinfo_bridge.py')],check=True)
assert 'versionCode = 42' in gradle and 'versionName = "2.3.8"' in gradle
print('PASS V2.2.3 CODESET ABI bridge host test; tagged-heap crash still requires on-device diagnosis')

# V2.2.4: baseline preserves tagged-heap protection; optional explicit subprocess A/B probe.
assert 'patch_box64_child_heap_isolation(source)' in box64_builder
assert 'RM11_TEST_DISABLE_BIONIC_HEAP_TAGS' in box64_builder
assert 'M_BIONIC_SET_HEAP_TAGGING_LEVEL' in box64_builder
assert 'runWineV22HeapDiagnostic()' in java and 'wineV22HeapButton' in java
assert 'runHeapDiagnostic(Context ctx)' in pe_runner
assert 'if (isolateHeap) env.put("RM11_TEST_DISABLE_BIONIC_HEAP_TAGS","1")' in pe_runner
assert 'else env.remove("RM11_TEST_DISABLE_BIONIC_HEAP_TAGS")' in pe_runner
assert 'isolateHeap?"rm11-v224-heap-isolation-prefix"' in pe_runner
assert 'isolateHeap?"rm11-v224-heap-isolation-work"' in pe_runner
subprocess.run(['python3',str(root/'tools/test_box64_heap_isolation.py')],check=True)
print('PASS: V2.2.4 restricted opt-in Box64 malloc tagging test; security reduced ONLY when explicitly requested')

# V2.2.5: tracked mmap/free diagnostic (no lowering Android tagging) and reliable crash tail capture.
assert 'runMallocTrackingDiagnostic(Context ctx)' in pe_runner
assert 'env.put("BOX64_MALLOC_HACK", "2")' in pe_runner
assert 'env.remove("BOX64_MALLOC_HACK")' in pe_runner
assert 'mallocTracking?"rm11-v225-malloc-tracking-prefix"' in pe_runner
assert 'mallocTracking?"rm11-v225-malloc-tracking-work"' in pe_runner
assert 'wineV22MallocButton' in java and 'runWineV22MallocDiagnostic()' in java
assert '[LOG TRUNCATED: middle omitted; crash tail preserved]' in pe_runner
assert 'HeadTailLog bounded=new HeadTailLog()' in pe_runner
print('PASS: V2.2.5 opt-in malloc/free tracking with tagging kept on, separate prefix, tail-preserving logs')

# V2.3: cross-process ownership guard and secure Wine server path.
assert 'versionName = "2.3.8"' in gradle and 'versionCode = 42' in gradle
assert 'patch_rm11_owned_environment_snapshot(source)' in box64_builder
assert 'RM11_ENV_SNAPSHOT_CREATED' in box64_builder
assert 'GOM(free, vFEp)' in box64_builder
assert 'GOM(secure_getenv, pFEp)' in box64_builder
assert 'RM11_ENV_BORROWED_FREE_PREVENTED' in box64_builder
assert 'RM11_SOURCE_V2_3_5' in pe_runner
assert 'installWineServerLink(wineServerEntry, bridge)' in pe_runner
assert 'RM11_WINESERVER_BRIDGE_PREFLIGHT_OK' in pe_runner and 'RM11_WINESERVER_BRIDGE_ENTERED' in bridge_src
assert 'android:allowNativeHeapPointerTagging="false"' not in manifest_xml
subprocess.run(['python3', str(root/'tools/test_rm11_v23.py')], check=True)
subprocess.run(['python3', str(root/'tools/test_rm11_v23_server.py')], check=True)
print('PASS: V2.3 original V2.2.5 based ownership and wineserver bridge source checks')

# V2.3.2: previously missing GNU ctype ABI needed by wineserver64.
assert 'patch_android_glibc_ctype_loc(source)' in box64_builder
assert 'RM11_CTYPE_BRIDGE_V231' in box64_builder
assert 'my___ctype_b_loc' in box64_builder and 'my___ctype_tolower_loc' in box64_builder
assert 'my___ctype_toupper_loc' in box64_builder
assert 'pthread_once(&rm11_ctype_once' in box64_builder
subprocess.run(['python3',str(root/'tools/test_rm11_v231_ctype.py')],check=True)
print('PASS: V2.3.2 glibc ctype pointer-to-pointer ABI bridge and C/POSIX 384-entry tables checked on Linux host; Wine on Android still unverified')

# V2.3.2: isolate stale wineprefix and report server/bootstrap readiness without claiming success.
subprocess.run(['python3',str(root/'tools/test_rm11_v232_bootstrap.py')],check=True)
print('PASS: V2.3.2 Wine bootstrap source diagnostics present; on-device outcome not proven')

# V2.3.3: staged, separately gated prefix bootstrap and Win32 PE execution.
subprocess.run(['python3',str(root/'tools/test_rm11_v233_bootstrap.py')],check=True)
subprocess.run(['python3',str(root/'tools/test_rm11_v235_bootstrap.py')],check=True)
print('PASS: V2.3.4 isolated Wine boot gate, immutable native helper and native tag protection source validation')
