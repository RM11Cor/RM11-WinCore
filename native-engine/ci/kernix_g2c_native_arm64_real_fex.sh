#!/usr/bin/env bash
# KERNIX G2-C: Linux ARM64 original FEX dynamic x86_64 PIE direct-entry proof.
# This deliberately bypasses ld-linux; it does not execute glibc or Wine.
set -euo pipefail
test "$(uname -m)" = aarch64
mkdir -p dist
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  clang lld cmake ninja-build git python3 pkg-config \
  binutils-x86-64-linux-gnu gcc-x86-64-linux-gnu

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
  -I/tmp/kernix-g2c-fex-upstream/FEXCore/include \
  -I/tmp/kernix-g2c-fex-upstream/External/fmt/include \
  -I/tmp/kernix-g2c-fex-upstream/External/unordered_dense/include \
  -I/tmp/kernix-g2c-fex-upstream/External/xxhash \
  -I/tmp/kernix-g2c-fex-native/include \
  -I/tmp/kernix-g2c-fex-native/generated \
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
