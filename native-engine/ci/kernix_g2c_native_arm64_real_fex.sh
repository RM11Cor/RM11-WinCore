#!/usr/bin/env bash
# KERNIX G2-C: Linux ARM64 original FEX dynamic x86_64 PIE direct-entry proof.
# This deliberately bypasses ld-linux; it does not execute glibc or Wine.
set -euo pipefail
test "$(uname -m)" = aarch64
mkdir -p dist
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  clang lld cmake ninja-build git python3 pkg-config \
  binutils-x86-64-linux-gnu gcc-x86-64-linux-gnu libc6-dev-amd64-cross gdb

# Guest ELF has real interpreter and actual DT_NEEDED libc.so.6.
x86_64-linux-gnu-gcc -nostartfiles -nodefaultlibs -fPIE -pie \
  -Wl,-z,max-page-size=0x1000 -Wl,-z,noexecstack -Wl,--no-as-needed \
  native-engine/android-guest/kernix_g2c_dynamic_pie_direct_entry_witness.S \
  -lc -o dist/kernix-g2c-x86-dynamic-pie.elf
readelf -h dist/kernix-g2c-x86-dynamic-pie.elf \
  | grep -Fq 'Advanced Micro Devices X86-64'
readelf -l dist/kernix-g2c-x86-dynamic-pie.elf \
  | grep -Fq 'Requesting program interpreter: /lib64/ld-linux-x86-64.so.2'
readelf -d dist/kernix-g2c-x86-dynamic-pie.elf \
  | grep -Fq 'Shared library: [libc.so.6]'
! readelf -d dist/kernix-g2c-x86-dynamic-pie.elf \
  | grep -Eq '\((RPATH|RUNPATH)\)'
readelf -h -l -d -W dist/kernix-g2c-x86-dynamic-pie.elf \
  > dist/kernix-g2c-guest-elf-evidence.txt

# Source binaries from the cross compiler's distro-managed x86 sysroot.
# Never copy Wine/glibc to the ARM64 host's /usr/lib.
LIBC=/usr/x86_64-linux-gnu/lib/libc.so.6
LOADER=/usr/x86_64-linux-gnu/lib/ld-linux-x86-64.so.2
test -f "$LIBC" && test -f "$LOADER"
mkdir -p dist/rootfs/bin dist/rootfs/lib/x86_64-linux-gnu dist/rootfs/lib64
cp dist/kernix-g2c-x86-dynamic-pie.elf dist/rootfs/bin/kernix-dynamic-app
cp -L "$LIBC" dist/rootfs/lib/x86_64-linux-gnu/libc.so.6
cp -L "$LOADER" dist/rootfs/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
ln -s /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  dist/rootfs/lib64/ld-linux-x86-64.so.2
for file in dist/rootfs/lib/x86_64-linux-gnu/*.so*; do
  readelf -h "$file" | grep -Fq 'Advanced Micro Devices X86-64'
done
sha256sum dist/rootfs/bin/kernix-dynamic-app \
  dist/rootfs/lib/x86_64-linux-gnu/libc.so.6 \
  dist/rootfs/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  > dist/g2c-guest-elf-sha256.txt
echo KERNIX_G2C_REAL_DYNAMIC_PIE_INTERP_AND_GLIBC_DEPENDENCY_STATIC_GATE_PASS

# Diagnose PT_LOAD/ld-linux/stack rejection directly on ARM64 BEFORE
# the expensive pinned FEXCore source build. No guest code is executed here.
clang++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror \
  -Inative-engine/android-host \
  native-engine/android-host/tests/kernix_g2c_linux_arm64_preflight.cpp \
  -o dist/kernix-g2c-arm64-elf-staging-preflight
timeout -k 3s 20s dist/kernix-g2c-arm64-elf-staging-preflight "$PWD/dist/rootfs"
echo KERNIX_G2C_ORIGINAL_GUEST_ELF_AND_AUXV_ARM64_PREFLIGHT_READY

# Independent MIT-only dynamic ELF: genuine PT_INTERP and DT_NEEDED but
# *no* libc.so.6, ld-linux or external guest runtime. Actual original
# FEX JIT runs its main _start later in this job; test-only placeholder
# interpreter is never entered and does not implement ELF relocation.
MIT_ROOT=dist/g2c-mit-only-rootfs
bash native-engine/ci/kernix_g2c_build_mit_guest_fixture.sh "$MIT_ROOT"
timeout -k 3s 20s dist/kernix-g2c-arm64-elf-staging-preflight \
  "$PWD/$MIT_ROOT" --mit-no-glibc
# No implicit host fallback when MIT dependency is missing.
mkdir -p dist/g2c-mit-bad-rootfs
cp -a "$MIT_ROOT"/. dist/g2c-mit-bad-rootfs/
rm -f dist/g2c-mit-bad-rootfs/lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1
if timeout -k 2s 10s dist/kernix-g2c-arm64-elf-staging-preflight \
    "$PWD/dist/g2c-mit-bad-rootfs" --mit-no-glibc; then
  echo "::error::G2-C MIT-only PT_INTERP dependency plan accepted absent DSO"
  exit 1
fi
echo KERNIX_G2C_MIT_NO_GLIBC_THREE_ELF_CLOSURE_PTLOAD_STACK_ARM64_PREFLIGHT_PASS


# Build exactly the same unmodified FEXCore source that passed G1.
git clone --quiet --filter=blob:none --no-checkout \
  https://github.com/FEX-Emu/FEX.git /tmp/kernix-g2c-fex-upstream
git -C /tmp/kernix-g2c-fex-upstream checkout --quiet --detach \
  02e24ca5c01ed0c864466ed573db347336f70170
git -C /tmp/kernix-g2c-fex-upstream submodule update --init --recursive --quiet
test "$(git -C /tmp/kernix-g2c-fex-upstream rev-parse HEAD)" = \
  02e24ca5c01ed0c864466ed573db347336f70170
cp /tmp/kernix-g2c-fex-upstream/LICENSE dist/FEX-LICENSE.txt
python3 - <<'PY'
from pathlib import Path
root=Path('/tmp/kernix-g2c-fex-upstream')
path=root/'CMakeLists.txt'
content=path.read_text()
needle='add_subdirectory(Source/)'
assert content.count(needle)==1
path.write_text(content.replace(needle,'# CI: only build pinned FEXCore',1))
path=root/'FEXCore/Source/CMakeLists.txt'
content=path.read_text()
needle='AddLibrary('+chr(36)+'{PROJECT_NAME}_shared SHARED)'
assert needle in content
content+='\ntarget_link_libraries(FEXCore_shared PRIVATE FEXCore_Base softfloat_3e)\n'
path.write_text(content)
PY

timeout 240 cmake -S /tmp/kernix-g2c-fex-upstream \
  -B /tmp/kernix-g2c-fex-native -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=OFF \
  -DENABLE_CCACHE=OFF -DBUILD_THUNKS=OFF -DBUILD_FEXCONFIG=OFF \
  -DBUILD_FEX_LINUX_TESTS=OFF -DBUILD_TESTING=OFF \
  -DENABLE_FEX_ALLOCATOR=ON -DENABLE_JEMALLOC_GLIBC_ALLOC=OFF \
  -DENABLE_OFFLINE_TELEMETRY=OFF -DENABLE_GDB_SYMBOLS=OFF \
  -DENABLE_WERROR=OFF -DCMAKE_DISABLE_FIND_PACKAGE_fmt=TRUE \
  -DTUNE_CPU=generic > dist/g2c-fex-configure.log 2>&1 || {
    tail -n 90 dist/g2c-fex-configure.log; exit 1;
  }
timeout 960 cmake --build /tmp/kernix-g2c-fex-native \
  --target FEXCore_shared --parallel 3 \
  > dist/g2c-fex-build.log 2>&1 || {
    tail -n 90 dist/g2c-fex-build.log; exit 1;
  }
CORE="$(find /tmp/kernix-g2c-fex-native -type f -name libFEXCore.so | head -n 1)"
test -s "$CORE"
CORE_DIR="$(dirname "$CORE")"
echo KERNIX_G2C_PINNED_ORIGINAL_FEXCORE_ARM64_COMPILED_PASS

clang++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror \
  -fPIE -pie -DKERNIX_G2C_NATIVE_ARM64_CI \
  -Inative-engine/android-host \
  -isystem /tmp/kernix-g2c-fex-upstream/FEXCore/include \
  -isystem /tmp/kernix-g2c-fex-upstream/External/fmt/include \
  -isystem /tmp/kernix-g2c-fex-upstream/External/unordered_dense/include \
  -isystem /tmp/kernix-g2c-fex-upstream/External/xxhash \
  -isystem /tmp/kernix-g2c-fex-native/include \
  -isystem /tmp/kernix-g2c-fex-native/generated \
  native-engine/android-host/kernix_g2c_fex_dynamic_pie_direct_entry_probe.cpp \
  -L"$CORE_DIR" -lFEXCore -Wl,-rpath,"$CORE_DIR" \
  -o dist/kernix-g2c-actual-fex-guest \
  >dist/g2c-fex-driver-compile.log 2>&1 || {
    cat dist/g2c-fex-driver-compile.log; exit 1;
  }
echo KERNIX_G2C_REAL_GUARDED_DYNAMIC_PIE_ORIGINAL_FEX_DRIVER_LINK_PASS

set +e
timeout -k 3s 20s env LD_LIBRARY_PATH="$CORE_DIR" \
  dist/kernix-g2c-actual-fex-guest "$PWD/dist/rootfs" \
  >dist/g2c.stdout 2>dist/g2c.stderr
rc=$?
set -e
cat dist/g2c.stdout
cat dist/g2c.stderr
RC="$rc" python3 - <<'PY'
import json,os
from pathlib import Path
stdout=Path('dist/g2c.stdout').read_text(errors='replace')
stderr=Path('dist/g2c.stderr').read_text(errors='replace')
rc=int(os.environ['RC'])
marker='KERNIX_G2C_REAL_X86_DYNAMIC_PIE_DIRECT_ENTRY_STACK_AUXV_FEX_ARM64_PASS_NOT_GLIBC'
passed=(rc==0 and stdout.count(marker)==1 and
    'KERNIX_G2C_STAGE=real_x86_PIE_DT_NEEDED_and_PT_INTERP_metadata__direct_entry_bypasses_loader' in stderr and
    'KERNIX_G2C_FEX_RETURNED_RAX=0x4b45524e49584732' in stderr and
    'KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL_REJECTED' not in stderr)
result={
  'schema':'kernix.g2c.real-arm64-fex-direct-entry-dynamic-pie.v1',
  'source_git_sha':os.environ['GITHUB_SHA'],
  'upstream_fex_sha':'02e24ca5c01ed0c864466ed573db347336f70170',
  'host':'Ubuntu ARM64 Linux, not Android/Bionic',
  'guest':'real x86_64 PT_INTERP dynamic PIE with libc.so.6 DT_NEEDED',
  'guest_entrypoint':'main executable _start bypassing ld-linux',
  'guarded_host_elf_stack_bytes':True,
  'guest_code_executed_under_fex':passed,
  'glibc_loader_executed':False,
  'wine_pe_executed':False,
  'android_device_executed':False,
  'exit_code':rc,'pass':passed,
  'stdout':stdout[-1800:],'stderr':stderr[-5000:]
}
Path('dist/g2c-result.json').write_text(json.dumps(result,indent=2)+'\n')
print('KERNIX_G2C_SOURCE_PROVEN_NATIVE_ARM64_FEX_RESULT',json.dumps(result))
if not passed: raise SystemExit(1)
PY
echo KERNIX_G2C_REAL_DYNAMIC_PIE_DIRECT_ENTRY_FEX_ARM64_PASS_NOT_GLIBC

# G2-C next gate: freeze exactly the independently executed fixed x86 guest
# into an immutable, versioned Android *input* bundle, not an Android APK.
# This path is reached ONLY after the real Ubuntu ARM64 FEX JIT proof passed.
# No Wine or ld-linux execution is claimed. No phone-side execution occurs.
BUNDLE="dist/g2c-android-fixed-fixture-v1"
mkdir -p "$BUNDLE/bin" "$BUNDLE/lib/x86_64-linux-gnu" "$BUNDLE/lib64"
install -m 0444 dist/rootfs/bin/kernix-dynamic-app "$BUNDLE/bin/kernix-dynamic-app"
install -m 0444 dist/rootfs/lib/x86_64-linux-gnu/libc.so.6 "$BUNDLE/lib/x86_64-linux-gnu/libc.so.6"
install -m 0444 dist/rootfs/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  "$BUNDLE/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
# Android's verified app-private extractor will not need to create symlinks:
# freeze the original interpreter path as an identical regular file.
install -m 0444 dist/rootfs/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
  "$BUNDLE/lib64/ld-linux-x86-64.so.2"

python3 - <<'PY'
import hashlib, json, os, pathlib, stat, struct
bundle=pathlib.Path("dist/g2c-android-fixed-fixture-v1")
allowed=(
 "bin/kernix-dynamic-app",
 "lib/x86_64-linux-gnu/libc.so.6",
 "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
 "lib64/ld-linux-x86-64.so.2",
)
files={}
for name in allowed:
    f=bundle / name
    st=f.lstat()
    assert stat.S_ISREG(st.st_mode) and not f.is_symlink(), name
    data=f.read_bytes()
    assert 64 < len(data) < 16 * 1024 * 1024, name
    assert data[:4]==b'\x7fELF' and data[4]==2 and data[5]==1, name
    assert struct.unpack_from("<H",data,18)[0] == 62, name
    files[name]={"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}
assert files["lib64/ld-linux-x86-64.so.2"]["sha256"]==files[
 "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"]["sha256"]
assert files["bin/kernix-dynamic-app"]["sha256"]==hashlib.sha256(
    pathlib.Path("dist/rootfs/bin/kernix-dynamic-app").read_bytes()).hexdigest()
manifest={
 "schema":"kernix.g2c.android-fixed-guest-inputs.v1",
 "source_git_sha":os.environ["GITHUB_SHA"],
 "host_proven":"Ubuntu ARM64; original upstream FEX JIT actually executed the PIE _start",
 "intended_device":"Android ARM64/Bionic; NOT EXECUTED",
 "fixture":"fixed x86-64 PT_INTERP+DT_NEEDED PIE with distro x86 libc/ld-linux",
 "guest_dynamic_loader_executed":False,
 "android_device_executed":False,
 "wine_or_games_tested":False,
 "files":files,
 "extraction_allowlist":list(allowed),
}
(bundle/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
print("KERNIX_G2C_IMMUTABLE_X86_GUEST_INPUTS_CHECKSUMS_READY_NOT_DEVICE_RUN")
PY
# Repeat the existing authentic ARM64 G2-C preflight against the portable
# regular-file bundle. This catches missing interpreter/closure/AUXV paths
# before it can be proposed as a signed Android test input.
timeout -k 3s 20s dist/kernix-g2c-arm64-elf-staging-preflight "$PWD/$BUNDLE"
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 \
  --numeric-owner -C "$BUNDLE" -cf - . | gzip -n \
  > dist/g2c-android-fixed-fixture-v1.tar.gz
sha256sum dist/g2c-android-fixed-fixture-v1.tar.gz \
  > dist/g2c-android-fixed-fixture-v1.sha256
echo KERNIX_G2C_ANDROID_GUEST_BUNDLE_ARM64_PREFLIGHT_PASS_NOT_DEVICE_EXECUTION

# Second independent real FEX JIT run in an isolated Linux ARM64 child.
# Unlike the baseline above, PT_LOAD and final FEX RX bytes MUST originate
# from exactly the four digest-pinned anonymous snapshot images, not a
# pathname reopened by the host PT_LOAD installer. Metadata/stack planning
# still reads the checked rootfs, so this is not full pathless glibc/Wine.
G2C_APP_PRIVATE="dist/g2c-snapshot-test-app-private"
G2C_GUEST="$G2C_APP_PRIVATE/kernix/runtime-v1/guest-rootfs/g2c-fixed-v1"
mkdir -p "$(dirname "$G2C_GUEST")"
cp -a "$BUNDLE" "$G2C_GUEST"
set +e
timeout -k 3s 20s env LD_LIBRARY_PATH="$CORE_DIR" \
  dist/kernix-g2c-actual-fex-guest "$PWD/$G2C_GUEST" "$PWD/$G2C_APP_PRIVATE" \
  >dist/g2c-snapshot-fex.stdout 2>dist/g2c-snapshot-fex.stderr
snapshot_rc=$?
set -e
cat dist/g2c-snapshot-fex.stdout
cat dist/g2c-snapshot-fex.stderr
G2C_SNAPSHOT_RC="$snapshot_rc" python3 - <<'PY'
import json,os
from pathlib import Path
stdout=Path('dist/g2c-snapshot-fex.stdout').read_text(errors='replace')
stderr=Path('dist/g2c-snapshot-fex.stderr').read_text(errors='replace')
code=int(os.environ['G2C_SNAPSHOT_RC'])
pass_marker='KERNIX_G2C_REAL_X86_DYNAMIC_PIE_DIRECT_ENTRY_STACK_AUXV_FEX_ARM64_PASS_NOT_GLIBC'
snapshot_marker='KERNIX_G2C_STAGE=RX_PTLOAD_FROM_VERIFIED_ANONYMOUS_SNAPSHOTS_NO_PATH_REOPEN'
metadata_marker='KERNIX_G2C_STAGE=PT_INTERP_TRANSITIVE_NEEDED_PHDR_AUXV_FROM_SNAPSHOT_ONLY'
rax='KERNIX_G2C_FEX_RETURNED_RAX=0x4b45524e49584732'
passed=(code==0 and stdout==pass_marker+'\n' and
        snapshot_marker in stderr and metadata_marker in stderr and rax in stderr and
        'KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL_REJECTED' not in stderr and
        'KERNIX_G2C_SNAPSHOT_INPUT_REJECTED' not in stderr)
result={
 'schema':'kernix.g2c.real-linux-arm64-fex-from-pinned-anon-ptload.v1',
 'source_git_sha':os.environ['GITHUB_SHA'],
 'upstream_fex_sha':'02e24ca5c01ed0c864466ed573db347336f70170',
 'host':'Ubuntu ARM64 Linux, NOT Android',
 'fex_executes_verified_snapshot_main_ptload':passed,
 'fex_executes_verified_snapshot_interpreter_ptload':False,
 'closure_phdr_and_initial_stack_from_snapshot':passed,
 'note':'Full fixed PT_INTERP and transitive DT_NEEDED dependency audit, PHDR, stack AUXV and main x86 RX PT_LOAD originate from pinned byte snapshots. Interpreter is staged but not executed: _start main is entered directly.',
 'guest_dynamic_interpreter_executed':False,
 'wine_or_games_executed':False,
 'android_device_executed':False,
 'exit_code':code,
 'pass':passed,
 'stdout':stdout[-1800:],
 'stderr':stderr[-5000:],
}
Path('dist/g2c-snapshot-fex-result.json').write_text(json.dumps(result,indent=2)+'\n')
print('KERNIX_G2C_REAL_FEX_X86_PTLOAD_FROM_SNAPSHOT_RESULT',json.dumps(result))
if not passed:raise SystemExit(1)
PY
echo KERNIX_G2C_ORIGINAL_ARM64_FEX_FROM_VERIFIED_SNAPSHOT_PTLOAD_PASS_NOT_ANDROID

# Third, distinct REAL source-built original FEXCore JIT proof: no Ubuntu
# guest glibc or ld-linux required. Still bypasses the MIT placeholder
# interpreter and executes ONLY main x86_64 _start, returning exact RAX.
set +e
timeout -k 3s 20s env LD_LIBRARY_PATH="$CORE_DIR" \
  dist/kernix-g2c-actual-fex-guest "$PWD/$MIT_ROOT" --mit-no-glibc \
  >dist/g2c-mit-original-fex.stdout 2>dist/g2c-mit-original-fex.stderr
mit_guest_rc=$?
set -e
cat dist/g2c-mit-original-fex.stdout
cat dist/g2c-mit-original-fex.stderr
G2C_MIT_RC="$mit_guest_rc" python3 - <<'PY'
import json,os
from pathlib import Path
stdout=Path('dist/g2c-mit-original-fex.stdout').read_text(errors='replace')
stderr=Path('dist/g2c-mit-original-fex.stderr').read_text(errors='replace')
rc=int(os.environ['G2C_MIT_RC'])
expected='KERNIX_G2C_ORIGINAL_FEX_ARM64_MIT_ONLY_DYNAMIC_PIE_DIRECT_ENTRY_PASS_NO_GLIBC'
rax='KERNIX_G2C_FEX_RETURNED_RAX=0x4b45524e49584732'
passed=(rc==0 and stdout==expected+'\n' and rax in stderr and
        'KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL_REJECTED' not in stderr and
        'KERNIX_G2C_BOUNDED_GUEST_PLAN_REJECTED' not in stderr)
out={
 'schema':'kernix.g2c.original-FEX-linux-arm64-MIT-only-dynamic-PIE-direct-entry.v1',
 'source_revision':os.environ['GITHUB_SHA'],
 'upstream_original_fex':'02e24ca5c01ed0c864466ed573db347336f70170',
 'host':'Ubuntu ARM64, NOT Android/Bionic device',
 'guest':'owned MIT x86_64 ET_DYN with PT_INTERP and DT_NEEDED no glibc',
 'guest_source_license':'MIT',
 'real_original_fex_x86_jit_executed':passed,
 'same_G2C_guarded_PTLOAD_stack_AUXV_route':passed,
 'x86_main_start_entered_directly':passed,
 'test_only_interpreter_implemented':False,
 'test_only_interpreter_executed':False,
 'dynamic_relocations_or_symbols_resolved':False,
 'glibc_or_ld_linux_executed':False,
 'android_guest_executed':False,
 'wine_games_executed':False,
 'exit_code':rc,'stdout':stdout[-1800:],'stderr':stderr[-4500:],
}
Path('dist/g2c-mit-original-fex-result.json').write_text(
 json.dumps(out,indent=2,sort_keys=True)+'\n')
print('KERNIX_G2C_MIT_ORIGINAL_FEX_REAL_X86_DIRECT_DYNAMIC_PIE_RESULT',json.dumps(out))
if not passed:raise SystemExit(1)
PY
echo KERNIX_G2C_ORIGINAL_FEX_MIT_NO_GLIBC_DYNAMIC_PIE_REAL_ARM64_EXEC_PASS_NOT_ANDROID

# Fourth real original-FEX Linux ARM64 execution: the MIT-only 3-ELF
# fixture comes exclusively from O_NOFOLLOW/SHA256 pinned ANONYMOUS
# read-only snapshots. No PT_LOAD, metadata or AUXV path reopen.
MIT_APP_PRIVATE=dist/g2c-mit-snapshot-app-files
mkdir -p "$MIT_APP_PRIVATE/kernix/runtime-v1/guest-rootfs"
cp -a "$MIT_ROOT" \
  "$MIT_APP_PRIVATE/kernix/runtime-v1/guest-rootfs/g2c-mit-v1"
find "$MIT_APP_PRIVATE" -type f -exec chmod 0444 {} +
set +e
timeout -k 3s 20s env LD_LIBRARY_PATH="$CORE_DIR" \
  dist/kernix-g2c-actual-fex-guest "$PWD/$MIT_ROOT" \
    --mit-no-glibc "$PWD/$MIT_APP_PRIVATE" \
  >dist/g2c-mit-snapshot-fex.stdout 2>dist/g2c-mit-snapshot-fex.stderr
mit_snapshot_rc=$?
set -e
cat dist/g2c-mit-snapshot-fex.stdout
cat dist/g2c-mit-snapshot-fex.stderr
G2C_MIT_SNAPSHOT_RC="$mit_snapshot_rc" python3 - <<'PY'
import json,os
from pathlib import Path
stdout=Path('dist/g2c-mit-snapshot-fex.stdout').read_text(errors='replace')
stderr=Path('dist/g2c-mit-snapshot-fex.stderr').read_text(errors='replace')
rc=int(os.environ['G2C_MIT_SNAPSHOT_RC'])
pass_marker='KERNIX_G2C_ORIGINAL_FEX_ARM64_MIT_ONLY_DYNAMIC_PIE_DIRECT_ENTRY_PASS_NO_GLIBC'
needed=(
 'KERNIX_G2C_FEX_RETURNED_RAX=0x4b45524e49584732',
 'KERNIX_G2C_STAGE=RX_PTLOAD_FROM_VERIFIED_ANONYMOUS_SNAPSHOTS_NO_PATH_REOPEN',
 'KERNIX_G2C_STAGE=PT_INTERP_TRANSITIVE_NEEDED_PHDR_AUXV_FROM_SNAPSHOT_ONLY',
 'KERNIX_G2C_STAGE=MIT_ONLY_THREE_SHA256_PINNED_ELFS_NO_GLIBC'
)
passed=(rc==0 and stdout==pass_marker+'\n' and all(x in stderr for x in needed) and
        'KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL_REJECTED' not in stderr and
        'KERNIX_G2C_SNAPSHOT_INPUT_REJECTED' not in stderr)
result={
 'schema':'kernix.g2c.real-FEX-linux-ARM64-MIT-only-SHA-pinned-anon-snapshots.v1',
 'source_revision':os.environ['GITHUB_SHA'],
 'upstream_original_fex':'02e24ca5c01ed0c864466ed573db347336f70170',
 'host':'Ubuntu ARM64 Linux; Android device not executed',
 'MIT_only_original_guest_ELF_files':3,
 'immutable_guest_ELF_sha256_verified_before_JIT':passed,
 'FEX_executes_main_guest_x86_from_verified_anon_PTLOAD':passed,
 'FEX_reads_guest_dependency_PHDR_AUXV_from_same_snapshots':passed,
 'dynamic_interpreter_implemented_or_executed':False,
 'glibc_or_ld_linux_required':False,
 'guest_relocations_applied':False,
 'android_device_executed':False,
 'wine_or_games_executed':False,
 'exit_code':rc,'pass':passed,
 'stdout':stdout[-1200:],'stderr':stderr[-4800:],
}
Path('dist/g2c-mit-snapshot-fex-result.json').write_text(
 json.dumps(result,indent=2,sort_keys=True)+'\n')
print('KERNIX_G2C_MIT_ORIGINAL_FEX_PINNED_SNAPSHOT_REAL_X86_JIT_RESULT',json.dumps(result))
if not passed:raise SystemExit(1)
PY
echo KERNIX_G2C_MIT_ORIGINAL_FEX_IMMUTABLE_SNAPSHOT_DYNAMIC_PIE_ARM64_PASS_NOT_ANDROID

# Fifth original-FEX ARM64 run. The 16KiB page-separated v2 MIT-only
# ELF trio is not the older 4KiB v1 fixture, and its independent exact
# hashes, host-page PT_LOAD safety and frozen anonymous images must pass.
MIT16K_ROOT=dist/g2c-mit-16k-guest-v2
bash native-engine/ci/kernix_g2c_build_mit_guest_fixture.sh \
  "$MIT16K_ROOT" --host-16k-safe
python3 tools/kernix_g2c_mit_16k_ptload_gate.py \
  "$MIT16K_ROOT/bin/kernix-mit-dynamic-app" \
  "$MIT16K_ROOT/lib64/ld-kernix-g2c-mit-placeholder.so.1" \
  "$MIT16K_ROOT/lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1"
python3 - <<'PY'
import hashlib
from pathlib import Path
checks={
 'bin/kernix-mit-dynamic-app':'814944a2ff2580e6d2c65b84de8086e74f1f8f3a654b6ed4bda15542058efac6',
 'lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1':'0c2ef465de4222c5e63dcd3bd15587d649e1fbb23590d949dce917cc1bde34a3',
 'lib64/ld-kernix-g2c-mit-placeholder.so.1':'a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2',
}
for filename,digest in checks.items():
    path=Path('dist/g2c-mit-16k-guest-v2')/filename
    assert hashlib.sha256(path.read_bytes()).hexdigest()==digest, filename
print('KERNIX_G2C_16K_MIT_V2_FIXED_SHA256_TRIPLE_SOURCE_AUTHENTICATED')
PY
MIT16K_APP=dist/g2c-mit16k-snapshot-test-files
mkdir -p "$MIT16K_APP/kernix/runtime-v1/guest-rootfs"
cp -a "$MIT16K_ROOT" \
  "$MIT16K_APP/kernix/runtime-v1/guest-rootfs/g2c-mit16k-v1"
find "$MIT16K_APP" -type f -exec chmod 0444 {} +
set +e
timeout -k 3s 20s env LD_LIBRARY_PATH="$CORE_DIR" \
  dist/kernix-g2c-actual-fex-guest "$PWD/$MIT16K_ROOT" \
    --mit-no-glibc-16k "$PWD/$MIT16K_APP" \
  >dist/g2c-mit16k-snapshot-fex.stdout \
  2>dist/g2c-mit16k-snapshot-fex.stderr
mit16k_rc=$?
set -e
cat dist/g2c-mit16k-snapshot-fex.stdout
cat dist/g2c-mit16k-snapshot-fex.stderr
G2C_MIT16K_RC="$mit16k_rc" python3 - <<'PY'
import json,os
from pathlib import Path
stdout=Path('dist/g2c-mit16k-snapshot-fex.stdout').read_text(errors='replace')
stderr=Path('dist/g2c-mit16k-snapshot-fex.stderr').read_text(errors='replace')
rc=int(os.environ['G2C_MIT16K_RC'])
expected='KERNIX_G2C_ORIGINAL_FEX_ARM64_MIT_ONLY_DYNAMIC_PIE_DIRECT_ENTRY_PASS_NO_GLIBC'
markers=[
  'KERNIX_G2C_STAGE=RX_PTLOAD_FROM_VERIFIED_ANONYMOUS_SNAPSHOTS_NO_PATH_REOPEN',
  'KERNIX_G2C_STAGE=PT_INTERP_TRANSITIVE_NEEDED_PHDR_AUXV_FROM_SNAPSHOT_ONLY',
  'KERNIX_G2C_STAGE=MIT_ONLY_THREE_SHA256_PINNED_ELFS_NO_GLIBC',
  'KERNIX_G2C_STAGE=MIT_GUEST_16K_HOST_RX_RW_PTLOAD_ISOLATION_VERIFIED',
  'KERNIX_G2C_FEX_RETURNED_RAX=0x4b45524e49584732',
]
passed=rc==0 and stdout==expected+'\n' and all(p in stderr for p in markers)
proof={
 'schema':'kernix.g2c.original-FEX-arm64-MIT-v2-16k-page-WX-separated-snapshots.v1',
 'source_revision':os.environ['GITHUB_SHA'],
 'upstream_original_fex':'02e24ca5c01ed0c864466ed573db347336f70170',
 'host':'Ubuntu ARM64 Linux with 4KiB physical host pages; 16KiB PT_LOAD-safe guest checked statically',
 'guest_binary_triple_separates_RX_and_RW_on_16KiB_pages':True,
 'real_original_FEX_x86_JIT_from_verified_anonymous_ELF':passed,
 'fixed_guest_SHA256_triple_verified':True,
 'glibc_or_ld_linux_used':False,
 'real_guest_PT_INTERP_loader_executed':False,
 'android_16k_page_device_executed':False,
 'android_guest_executed':False,
 'wine_or_games_executed':False,
 'exit_code':rc,'pass':passed,
 'stdout':stdout[-1500:],'stderr':stderr[-4200:],
}
Path('dist/g2c-mit16k-snapshot-fex-result.json').write_text(
    json.dumps(proof,indent=2,sort_keys=True)+'\n')
print('KERNIX_G2C_16K_MIT_ORIGINAL_FEX_REAL_X86_JIT_SNAPSHOT_RESULT',json.dumps(proof))
if not passed:raise SystemExit(1)
PY
echo KERNIX_G2C_MIT_16K_PAGE_LAYOUT_REAL_FEX_ARM64_JIT_PASS_NOT_ANDROID

# G2-D is deliberately a SECOND, Linux ARM64-only original-FEX probe:
# genuine imported x86 function in an independent x86 ELF DSO, one exact
# R_X86_64_JUMP_SLOT patch under temporary RW followed by GOT read-only.
# Absolutely no Android G2-D candidate, glibc, ld-linux, PE or Wine here.
G2D_ROOT=dist/g2d-original-mit-import-v1
bash native-engine/ci/kernix_g2d_build_mit_import_fixture.sh "$PWD/$G2D_ROOT"
G2D_PRIVATE=dist/g2d-fex-ci-app-files
mkdir -p "$G2D_PRIVATE/kernix/runtime-v1/guest-rootfs"
cp -a "$G2D_ROOT" "$G2D_PRIVATE/kernix/runtime-v1/guest-rootfs/g2d-import-v1"
find "$G2D_PRIVATE" -type f -exec chmod 0444 {} +
clang++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror \
  -fPIE -pie -DKERNIX_G2D_NATIVE_ARM64_CI \
  -Inative-engine/android-host \
  -isystem /tmp/kernix-g2c-fex-upstream/FEXCore/include \
  -isystem /tmp/kernix-g2c-fex-upstream/External/fmt/include \
  -isystem /tmp/kernix-g2c-fex-upstream/External/unordered_dense/include \
  -isystem /tmp/kernix-g2c-fex-upstream/External/xxhash \
  -isystem /tmp/kernix-g2c-fex-native/include \
  -isystem /tmp/kernix-g2c-fex-native/generated \
  native-engine/android-host/kernix_g2d_real_fex_import_probe.cpp \
  -L"$CORE_DIR" -lFEXCore -Wl,-rpath,"$CORE_DIR" \
  -o dist/kernix-g2d-real-fex-external-x86-import \
  >dist/g2d-real-fex-compile.log 2>&1 || {
    tail -n 130 dist/g2d-real-fex-compile.log; exit 1;
  }
echo KERNIX_G2D_ORIGINAL_FEX_REAL_EXTERNAL_X86_GOT_IMPORT_DRIVER_CROSSLINK_PASS

set +e
timeout -k 3s 20s env LD_LIBRARY_PATH="$CORE_DIR" \
  dist/kernix-g2d-real-fex-external-x86-import \
  "$PWD/$G2D_PRIVATE" --g2d-fixed-mit-x86-import-only \
  >dist/g2d-original-fex-import.stdout \
  2>dist/g2d-original-fex-import.stderr
g2d_rc=$?
set -e
cat dist/g2d-original-fex-import.stdout
cat dist/g2d-original-fex-import.stderr
# A failure is a blocker; save the FIRST real ARM64 SIGSEGV fault register
# and stack trace before anyone proposes random FEX/ELF configuration changes.
# GDB runs only inside the bounded throwaway Linux CI process and never
# ships to a signed APK or to the REDMAGIC phone.
if [ "$g2d_rc" -eq 139 ]; then
  timeout -k 3s 15s env LD_LIBRARY_PATH="$CORE_DIR" \
    gdb -q -batch -ex 'set pagination off' \
      -ex 'handle SIGSEGV stop print nopass' \
      -ex 'run' -ex 'info registers' -ex 'thread apply all bt 16' \
      -ex 'p $_siginfo._sifields._sigfault.si_addr' \
      --args dist/kernix-g2d-real-fex-external-x86-import \
      "$PWD/$G2D_PRIVATE" --g2d-fixed-mit-x86-import-only \
    >dist/g2d-arm64-sigsegv-gdb.txt 2>&1 || true
  tail -n 105 dist/g2d-arm64-sigsegv-gdb.txt
  echo KERNIX_G2D_REAL_ARM64_FEX_GUEST_CALL_SIGSEGV_CAPTURED_AND_EXEC_GATED
fi
G2D_RC="$g2d_rc" python3 - <<'PY'
import os,json
from pathlib import Path
stdout=Path('dist/g2d-original-fex-import.stdout').read_text(errors='replace')
stderr=Path('dist/g2d-original-fex-import.stderr').read_text(errors='replace')
rc=int(os.environ['G2D_RC'])
marker='KERNIX_G2D_ORIGINAL_FEX_X86_64_REAL_PLT_JUMP_SLOT_CROSS_DSO_CALL_RETURN_PASS_NO_GLIBC'
expected=[
    'KERNIX_G2D_STAGE=MIT_THREE_GUEST_ELFS_SHA256_PINNED_ANONYMOUS_SNAPSHOTS',
    'KERNIX_G2D_STAGE=REAL_GNU_LD_JUMP_SLOT_GOT_BOUND_TO_EXTERNAL_X86_PROVIDER_AND_REPROTECTED_READONLY',
    'KERNIX_G2D_STAGE=MAIN_AND_PROVIDER_TEXT_RX_STACK_RW_GUARDS_NONE_NO_GLIBC',
    'KERNIX_G2D_FEX_REAL_EXTERNAL_X86_FUNCTION_RAX=0x4b45524e49584731',
]
passed=rc==0 and stdout==marker+'\n' and all(x in stderr for x in expected) and (
    'KERNIX_G2D_UNEXPECTED_X86_SYSCALL_REJECTED' not in stderr)
evidence={
 'schema':'kernix.g2d.real-original-fex-arm64-fixed-MIT-x86-imported-function.v1',
 'git_commit':os.environ['GITHUB_SHA'],
 'original_upstream_fex_sha':'02e24ca5c01ed0c864466ed573db347336f70170',
 'host':'Ubuntu native ARM64 Linux, NOT Android',
 'main_guest':'g2d MIT x86_64 ELF64 with external PLT imported symbol',
 'imported_symbol':'kernix_g2d_imported_value',
 'actual_imported_function_resolved_from_external_x86_DSO':passed,
 'actual_x86_R_X86_64_JUMP_SLOT_written_to_GOT':passed,
 'main_and_provider_x86_text_rx':passed,
 'guest_stack_rw_not_executable':passed,
 'actual_original_fex_x86_call_to_external_DSO_and_ret':passed,
 'exact_final_RAX':'0x4b45524e49584731',
 'real_guest_ELF_interpreter_executed':False,
 'general_dynamic_relocations_supported':False,
 'glibc_used':False,
 'Android_device_executed':False,
 'Wine_or_games_executed':False,
 'return_code':rc,'pass':passed,
 'stdout':stdout[-1400:],'stderr':stderr[-4800:],
}
Path('dist/G2D-ORIGINAL-FEX-REAL-X86-DYNAMIC-IMPORT-EXEC-RESULT.json').write_text(
 json.dumps(evidence,indent=2,sort_keys=True)+'\n')
print('KERNIX_G2D_SOURCE_BUILT_ORIGINAL_FEX_X86_IMPORTED_DSO_GOT_JUMP_SLOT_RESULT',
      json.dumps(evidence))
if not passed:raise SystemExit(1)
PY
echo KERNIX_G2D_REAL_SOURCE_BUILT_FEX_X86_EXTERNAL_DSO_FUNCTION_CALL_RETURN_PASS_LINUX_ARM64_ONLY
