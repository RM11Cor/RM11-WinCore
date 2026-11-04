#!/usr/bin/env bash
# G2-C real dynamically declared x86 PIE made only of KERNIX-owned MIT code.
# No glibc, ld-linux, external DSOs or user-controlled ELF enters this fixture.
# The PT_INTERP placeholder is DATA-ONLY and never runs in direct-entry FEX.
set -euo pipefail
test "${1:-}" != ""
ROOT="$1"
SRC=native-engine/android-guest
mkdir -p "$ROOT/bin" "$ROOT/lib64" "$ROOT/lib/x86_64-linux-gnu" dist
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
AS=x86_64-linux-gnu-as
LD=x86_64-linux-gnu-ld
command -v "$AS" >/dev/null
command -v "$LD" >/dev/null
"$AS" --64 "$SRC/kernix_g2c_dynamic_pie_direct_entry_witness.S" -o "$TMP/main.o"
"$AS" --64 "$SRC/kernix_g2c_mit_interpreter_placeholder.S" -o "$TMP/interpreter.o"
"$AS" --64 "$SRC/kernix_g2c_mit_needed_placeholder.S" -o "$TMP/needed.o"

"$LD" -shared --build-id=none -z max-page-size=0x1000 \
  -soname libkernix-g2c-mit-placeholder.so.1 \
  -o "$ROOT/lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1" "$TMP/needed.o"
"$LD" -shared --build-id=none -z max-page-size=0x1000 \
  -e _start -o "$ROOT/lib64/ld-kernix-g2c-mit-placeholder.so.1" "$TMP/interpreter.o"
"$LD" -pie --build-id=none -z max-page-size=0x1000 \
  -e _start --dynamic-linker=/lib64/ld-kernix-g2c-mit-placeholder.so.1 \
  -o "$ROOT/bin/kernix-mit-dynamic-app" "$TMP/main.o" \
  --no-as-needed -L"$ROOT/lib/x86_64-linux-gnu" \
  -l:libkernix-g2c-mit-placeholder.so.1

MAIN="$ROOT/bin/kernix-mit-dynamic-app"
INTERP="$ROOT/lib64/ld-kernix-g2c-mit-placeholder.so.1"
NEEDED="$ROOT/lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1"
test "$(find "$ROOT" -type f | wc -l)" -eq 3
test "$(find "$ROOT" -type l | wc -l)" -eq 0
for file in "$MAIN" "$INTERP" "$NEEDED";do
  readelf -h "$file" | grep -Fq 'Advanced Micro Devices X86-64'
  readelf -h "$file" | grep -Fq 'DYN ('
  readelf -l "$file" | grep -Fq 'DYNAMIC '
  ! readelf -l "$file" | grep -Eq 'GNU_STACK.*RWE'
  ! readelf -d "$file" | grep -Eq '\((RPATH|RUNPATH)\)'
done
readelf -l "$MAIN" | grep -Fq 'Requesting program interpreter: /lib64/ld-kernix-g2c-mit-placeholder.so.1'
readelf -d "$MAIN" | grep -Fq 'Shared library: [libkernix-g2c-mit-placeholder.so.1]'
! readelf -d "$MAIN" | grep -Fq 'libc.so.6'
! readelf -d "$INTERP" | grep -Fq 'Shared library'
! readelf -d "$NEEDED" | grep -Fq 'Shared library'
# The placeholder is NOT Linux's loader; code enters the main's _start.
readelf -h -l -d -W "$MAIN" >dist/g2c-mit-only-main-elf-abi.txt
sha256sum "$MAIN" "$INTERP" "$NEEDED" >dist/g2c-mit-only-three-elf-sha256.txt
python3 - "$ROOT" <<'PY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])
files=[
'bin/kernix-mit-dynamic-app',
'lib64/ld-kernix-g2c-mit-placeholder.so.1',
'lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1']
record={
 'schema':'kernix.g2c.mit-only-direct-entry-dynamic-pie-fixture.v1',
 'guest_abi':'x86_64 ELF64 ET_DYN',
 'main_pt_interp':'/lib64/ld-kernix-g2c-mit-placeholder.so.1',
 'main_dt_needed':['libkernix-g2c-mit-placeholder.so.1'],
 'source_witness':'native-engine/android-guest/kernix_g2c_dynamic_pie_direct_entry_witness.S',
 'sources_license':'MIT',
 'source_only_dependencies':True,
 'no_glibc_or_distro_guest_libraries':True,
 'guest_dynamic_interpreter_implemented':False,
 'guest_dynamic_interpreter_executed':False,
 'guest_relocations_or_imports_executed':False,
 'android_guest_code_executed':False,
 'wine_or_games_executed':False,
 'files':{str(p):{'size':(root/p).stat().st_size,
                 'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()}
          for p in files}
}
Path('dist/g2c-mit-only-source-and-elf-manifest.json').write_text(
 json.dumps(record,indent=2,sort_keys=True)+'\n')
print('KERNIX_G2C_MIT_ONLY_THREE_REAL_X86_DYNAMIC_ELF_WITHOUT_GLIBC_CI_PASS_NO_GUEST_EXEC')
PY
