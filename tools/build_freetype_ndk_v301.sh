#!/usr/bin/env bash
# RM11 v3.0.1: deterministic upstream-tag-pinned Android NDK FreeType.
# No optional bz2/png/zlib/brotli/harfbuzz runtime closure.
set -euo pipefail
NDK="$ANDROID_HOME/ndk/27.2.12479018"
ROOT="$RUNNER_TEMP/rm11-freetype-core-v301"
SRC="$ROOT/freetype"
OUT="app/src/main/jniLibs/arm64-v8a/librm11_freetype_core.so"
MANIFEST="app/src/main/assets/runtime/rm11-freetype-ndk-v301.json"
EXPECTED="42608f77f20749dd6ddc9e0536788eaad70ea4b5"
mkdir -p "$ROOT" "$(dirname "$OUT")" "$(dirname "$MANIFEST")" app/src/main/assets/licenses
git clone --quiet --depth 1 --branch VER-2-13-3 https://github.com/freetype/freetype.git "$SRC"
ACTUAL="$(git -C "$SRC" rev-parse HEAD)"
test "$ACTUAL" = "$EXPECTED" || { echo "UPSTREAM_FREETYPE_PIN_MISMATCH: $ACTUAL"; exit 66; }
cp "$SRC/LICENSE.TXT" app/src/main/assets/licenses/FreeType-2.13.3-LICENSE.TXT
cmake -S "$SRC" -B "$ROOT/build" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
  -DFT_DISABLE_ZLIB=ON -DFT_DISABLE_BZIP2=ON \
  -DFT_DISABLE_PNG=ON -DFT_DISABLE_BROTLI=ON \
  -DFT_DISABLE_HARFBUZZ=ON \
  -DCMAKE_C_FLAGS="-O2" \
  -DCMAKE_INSTALL_PREFIX="$ROOT/install"
cmake --build "$ROOT/build" --parallel 4

export RM11_FT_BUILD_ROOT="$ROOT/build"
export RM11_FT_TARGET="$OUT"
export RM11_FT_MANIFEST="$MANIFEST"
export RM11_FT_COMMIT="$EXPECTED"
python3 - <<'PY'
import json,os,hashlib,subprocess
from pathlib import Path
root=Path(os.environ['RM11_FT_BUILD_ROOT'])
target=Path(os.environ['RM11_FT_TARGET'])
candidates=sorted(x for x in root.rglob('libfreetype.so*')
                  if x.is_file() and x.read_bytes()[:4]==b'\x7fELF')
assert candidates,'Pinned NDK FreeType built no shared ELF'
src=max(candidates,key=lambda p:p.stat().st_size)
payload=src.read_bytes()
assert len(payload)>100000
target.write_bytes(payload)
# Device ELF audit (run 40102564782) proved the genuine Wine win32u.so
# calls dlopen("libfreetype.so"), while v4.0.3 packages ONLY a differently
# named librm11_freetype_core.so. Give Bionic's native APK namespace the exact
# SONAME; no LD_PRELOAD/dlopen hijack and no rewrite of Wine's ELF.
wine_soname_target=target.with_name('libfreetype.so')
assert wine_soname_target != target
wine_soname_target.write_bytes(payload)
assert wine_soname_target.read_bytes()==target.read_bytes()
readelf=Path(os.environ['ANDROID_HOME'])/'ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf'
header=subprocess.check_output([str(readelf),'-h',str(target)],text=True)
assert 'AArch64' in header,header
dynamic=subprocess.check_output([str(readelf),'-d',str(target)],text=True)
needed=[]
for line in dynamic.splitlines():
    if '(NEEDED)' in line:
        needed.append(line.split('Shared library: [',1)[-1].split(']')[0])
allowed={'libc.so','libm.so','libdl.so','liblog.so','libandroid.so'}
assert set(needed)<=allowed,f'Unexpected native FreeType dependency {needed}'
symbols=subprocess.check_output([str(readelf),'--dyn-syms',str(target)],text=True)
for x in ('FT_Init_FreeType','FT_New_Face','FT_Load_Glyph','FT_Render_Glyph','FT_Done_FreeType'):
    assert x in symbols,'Missing glyph API '+x
manifest={'wine_required_soname':'libfreetype.so',
          'wine_native_soname_sha256':hashlib.sha256(wine_soname_target.read_bytes()).hexdigest(),
          'wine_font_loader_audit_run':40102564782,
          'v404_wine_font_runtime_proven':False,
          'version':'2.13.3','upstream_commit':os.environ['RM11_FT_COMMIT'],
          'target':target.name,'bytes':len(payload),
          'sha256':hashlib.sha256(payload).hexdigest(),
          'dt_needed':needed,
          'features':['TrueType outline','OpenType outline','CFF outlines'],
          'disabled_optional_deps':['zlib','bzip2','libpng','brotli','harfbuzz'],
          'scope':'opt-in selected embedded Wine GUI only',
          'Android_NDK':'27.2.12479018','Android_API':26,
          'signed_APK':True,'device_gui_success_proven':False}
Path(os.environ['RM11_FT_MANIFEST']).write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print('RM11_V301_NDK_FREETYPE_CORE_VERIFIED',len(payload),manifest['sha256'],needed)
PY
