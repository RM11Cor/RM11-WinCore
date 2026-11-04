#!/usr/bin/env bash
# Fixed G2-D real MIT-only x86_64 dynamic PLT/DSO witness, 16KiB PT_LOAD.
# Does NOT use glibc, ld-linux, Wine, external packages or guest syscalls.
# Files are data only until an independent bounded relocator proves integrity.
set -euo pipefail
if [ "$#" -ne 1 ] || [[ "$1" != /* ]]; then
  echo "G2-D demands one absolute output directory" >&2
  exit 2
fi
OUT="$1"
SRC=native-engine/android-guest
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
for cmd in x86_64-linux-gnu-as x86_64-linux-gnu-ld readelf; do
  command -v "$cmd" >/dev/null
done
mkdir -p "$OUT/bin" "$OUT/lib64" "$OUT/lib/x86_64-linux-gnu"
x86_64-linux-gnu-as --64 "$SRC/kernix_g2d_mit_import_main.S" -o "$TMP/main.o"
x86_64-linux-gnu-as --64 "$SRC/kernix_g2d_mit_import_provider.S" -o "$TMP/provider.o"
x86_64-linux-gnu-as --64 "$SRC/kernix_g2c_mit_interpreter_placeholder.S" -o "$TMP/placeholder.o"
x86_64-linux-gnu-ld -shared --build-id=none -z max-page-size=0x4000 \
  -soname libkernix-g2d-mit-import.so.1 \
  -o "$OUT/lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1" \
  "$TMP/provider.o"
x86_64-linux-gnu-ld -shared --build-id=none -z max-page-size=0x4000 \
  -e _start -o "$OUT/lib64/ld-kernix-g2d-mit-import-test.so.1" "$TMP/placeholder.o"
x86_64-linux-gnu-ld -pie --build-id=none -z max-page-size=0x4000 \
  -e _start \
  --dynamic-linker=/lib64/ld-kernix-g2d-mit-import-test.so.1 \
  -o "$OUT/bin/kernix-g2d-import-app" "$TMP/main.o" \
  --no-as-needed -L"$OUT/lib/x86_64-linux-gnu" \
  -l:libkernix-g2d-mit-import.so.1
MAIN="$OUT/bin/kernix-g2d-import-app"
DSO="$OUT/lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1"
INTERP="$OUT/lib64/ld-kernix-g2d-mit-import-test.so.1"
test "$(find "$OUT" -type f | wc -l)" -eq 3
test "$(find "$OUT" -type l | wc -l)" -eq 0
for path in "$MAIN" "$DSO" "$INTERP"; do
  readelf -h "$path" | grep -Fq 'Advanced Micro Devices X86-64'
  readelf -h "$path" | grep -Fq 'DYN ('
  readelf -l -W "$path" | grep -Eq 'LOAD .*0x4000$'
  ! readelf -l "$path" | grep -Eq 'GNU_STACK.*RWE'
  ! readelf -d "$path" | grep -Eq '\((RPATH|RUNPATH)\)'
done
readelf -l "$MAIN" | grep -Fq 'Requesting program interpreter: /lib64/ld-kernix-g2d-mit-import-test.so.1'
readelf -d "$MAIN" | grep -Fq 'Shared library: [libkernix-g2d-mit-import.so.1]'
! readelf -d "$MAIN" | grep -Fq 'libc.so.6'
readelf -r -W "$MAIN" | grep -Eq 'R_X86_64_JUMP_SLOT.*kernix_g2d_imported_value'
readelf -s -W "$DSO" | grep -Eq 'FUNC.*GLOBAL.*kernix_g2d_imported_value'
! readelf -d "$DSO" | grep -Fq 'Shared library'
! readelf -d "$INTERP" | grep -Fq 'Shared library'
mkdir -p dist
readelf -h -l -d -r -W "$MAIN" >dist/G2D-MIT-X86-MAIN-REAL-PLT-RELA-ABI.txt
sha256sum "$MAIN" "$DSO" "$INTERP" >dist/G2D-MIT-X86-3-ELF-SHA256.txt
python3 - "$OUT" <<'PY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])
files=[
  'bin/kernix-g2d-import-app',
  'lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1',
  'lib64/ld-kernix-g2d-mit-import-test.so.1'
]
record={
  "schema":"kernix.g2d.MIT-x86-real-PLT-JUMP_SLOT-16k-fixture.v1",
  "guest_abi":"x86_64 little-endian ET_DYN 16KiB PT_LOAD aligned",
  "license":"MIT",
  "sources":[
    'native-engine/android-guest/kernix_g2d_mit_import_main.S',
    'native-engine/android-guest/kernix_g2d_mit_import_provider.S',
    'native-engine/android-guest/kernix_g2c_mit_interpreter_placeholder.S'
  ],
  "actual_main_DT_NEEDED":["libkernix-g2d-mit-import.so.1"],
  "actual_main_DT_JMPREL":"R_X86_64_JUMP_SLOT",
  "actual_imported_symbol":"kernix_g2d_imported_value",
  "provider_is_separate_ELF_DSO":True,
  "expected_RAX_after_imported_call":"0x4b45524e49584731",
  "interpreter_implemented":False,
  "interpreter_executed":False,
  "relocation_applied":False,
  "x86_guest_executed":False,
  "android_device_executed":False,
  "wine_or_games_executed":False,
  "files":{name:{"size":(root/name).stat().st_size,
                 "sha256":hashlib.sha256((root/name).read_bytes()).hexdigest()}
           for name in files}
}
Path("dist/G2D-MIT-X86-IMPORT-3-ELF-MANIFEST.json").write_text(
 json.dumps(record,indent=2,sort_keys=True)+"\n")
print("KERNIX_G2D_MIT_X86_REAL_IMPORTED_PLT_DSO_AND_16K_ELF_BUILT_NOT_EXECUTED")
PY
