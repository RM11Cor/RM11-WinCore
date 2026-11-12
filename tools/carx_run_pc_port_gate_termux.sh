#!/data/data/com.termux/files/usr/bin/bash
# CarX Street PC PortLab: optional one-command local source dependency probe.
# Never changes or uploads game files. No DRM, bypass or game execution.
set -Eeuo pipefail
export LC_ALL=C

if ! command -v python3 >/dev/null 2>&1; then
  echo 'Python3 not installed. Run: pkg install python -y' >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo 'curl not installed. Run: pkg install curl -y' >&2
  exit 2
fi

OUT="$HOME/storage/downloads/CarX_Street_Native_Port_Source_Gate.json"
if [ ! -d "$HOME/storage/downloads" ]; then
  OUT="/sdcard/Download/CarX_Street_Native_Port_Source_Gate.json"
fi
ROOT=""
if [ "$#" -ge 1 ]; then
  ROOT="$1"
else
  for p in \
    "$HOME/storage/downloads/CarX Street" \
    "/sdcard/Download/CarX Street" \
    "/sdcard/Games/CarX Street" \
    "/storage/emulated/0/Download/CarX Street"; do
    if [ -f "$p/GameAssembly.dll" ]; then ROOT="$p"; break; fi
  done
fi
if [ -z "$ROOT" ] || [ ! -f "$ROOT/GameAssembly.dll" ]; then
  echo 'ما لكيت ملف GameAssembly.dll بالمواقع المعتادة.' >&2
  echo 'حدد مجلد اللعبة بشكل مباشر، مثال:' >&2
  echo "bash carx_run_pc_port_gate_termux.sh '/sdcard/Download/CarX Street'" >&2
  exit 3
fi

mkdir -p "$HOME/.local/share/carx-portlab"
SCRIPT="$HOME/.local/share/carx-portlab/carx_windows_gamecode_port_gate.py"
URL="https://raw.githubusercontent.com/RM11Cor/RM11-WinCore/carx-street-pc-port-v1/tools/carx_windows_gamecode_port_gate.py"
curl --fail --location --show-error --silent --retry 3 --connect-timeout 10 \
     --max-time 120 "$URL" -o "$SCRIPT.tmp"
test -s "$SCRIPT.tmp"
mv -f "$SCRIPT.tmp" "$SCRIPT"
echo 'بدء فحص ملفات Windows الأصلية وفهرس Addressables بدون أي تعديل...'
python3 "$SCRIPT" "$ROOT" --out "$OUT"
test -s "$OUT"
python3 - "$OUT" <<'PY'
from pathlib import Path
import json,sys
p=Path(sys.argv[1])
d=json.loads(p.read_text(encoding="utf-8"))
assert d["schema"]=="rm11carx.winpc-gamecode-and-addressables-to-android-gate.v1"
for label in ("game_il2cpp","unity_player"):
    item=d["game_code_inputs"][label]
    print(label, "architecture=",item.get("architecture","unknown"),
          "imports=",len(item.get("import_dll_names",[])))
a=d["assets"]
print("Addressables catalog reference count:",a.get("internal_id_count","unknown"))
print("Windows64 references:",a.get("windows64_reference_count","unknown"))
print("Android-named references:",a.get("android_named_reference_count","unknown"))
print("Native Android gameplay proven:",d["native_pc_to_android_port_proven"])
PY
echo "التقرير محفوظ محلياً: $OUT"
echo 'ارفع تقرير JSON فقط إلى المحادثة (مو ملفات اللعبة).'
