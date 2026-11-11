#!/data/data/com.termux/files/usr/bin/bash
# FH5 Android graphics test stage downloader -- no manually downloaded ZIP required.
set -Eeuo pipefail
BASE='https://raw.githubusercontent.com/RM11Cor/RM11-WinCore/fh5-android-auto-tests/fh5-auto'
OUT='/sdcard/Download/FH5_AUTO'
WORK="$HOME/fh5_auto"
mkdir -p "$WORK" "$OUT"

fail(){ echo "[FH5] ERROR: $*" >&2; exit 1; }
command -v pkg >/dev/null || fail 'Run this script inside Termux.'
command -v curl >/dev/null || pkg install -y curl
command -v unzip >/dev/null || pkg install -y unzip
command -v sha256sum >/dev/null || pkg install -y coreutils
command -v base64 >/dev/null || pkg install -y coreutils
command -v python >/dev/null || pkg install -y python

tmp=$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/fh5-auto.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT
printf '[FH5] Checking latest stage...\n'
curl -fL --retry 3 --connect-timeout 15 -sS "$BASE/latest.txt" -o "$tmp/latest.txt" || fail 'Could not reach the FH5 source on GitHub. Check your connection.'
mapfile -t cfg < "$tmp/latest.txt"
((${#cfg[@]} == 4)) || fail 'Invalid stage manifest.'
STAGE="${cfg[0]}"
PAYLOAD="${cfg[1]}"
EXPECTED="${cfg[2]}"
ENTRY="${cfg[3]}"
[[ "$STAGE" =~ ^M[0-9]{2,4}$ ]] || fail 'Invalid stage id.'
[[ "$PAYLOAD" =~ ^[a-zA-Z0-9_.-]+\.(b64|py)$ ]] || fail 'Unsafe package name.'
[[ "$ENTRY" =~ ^[a-zA-Z0-9_.-]+\.(sh|py)$ ]] || fail 'Unsafe entry script name.'
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid SHA256 in manifest.'
printf '[FH5] Downloading %s...\n' "$STAGE"
STAGEDIR="$WORK/$STAGE"
mkdir -p "$STAGEDIR"
if [[ "$PAYLOAD" == *.b64 ]]; then
  curl -fL --retry 3 --connect-timeout 15 -sS "$BASE/$PAYLOAD" -o "$tmp/package.b64" || fail 'Download failed.'
  base64 -d "$tmp/package.b64" > "$tmp/package.zip" || fail 'Package decode failed.'
  ACTUAL=$(sha256sum "$tmp/package.zip")
  ACTUAL=${ACTUAL%% *}
  [[ "$ACTUAL" == "$EXPECTED" ]] || fail 'SHA256 mismatch. The package will NOT run.'
  unzip -oq "$tmp/package.zip" -d "$STAGEDIR" || fail 'Cannot unpack the package.'
else
  [[ "$ENTRY" == "$PAYLOAD" && "$ENTRY" == *.py ]] || fail 'Python entry must match package name.'
  curl -fL --retry 3 --connect-timeout 15 -sS "$BASE/$PAYLOAD" -o "$tmp/package.py" || fail 'Download failed.'
  ACTUAL=$(sha256sum "$tmp/package.py")
  ACTUAL=${ACTUAL%% *}
  [[ "$ACTUAL" == "$EXPECTED" ]] || fail 'SHA256 mismatch. The Python script will NOT run.'
  cp -f "$tmp/package.py" "$STAGEDIR/$ENTRY"
fi
[[ -f "$STAGEDIR/$ENTRY" ]] || fail 'Missing package entry script.'
cp "$tmp/latest.txt" "$OUT/FH5_LAST_MANIFEST.txt"
printf '[FH5] Package verified: %s\n' "$EXPECTED"
printf '[FH5] Building and running %s...\n' "$STAGE"
set +e
(
 cd "$STAGEDIR"
 if [[ "$ENTRY" == *.py ]]; then python "./$ENTRY"; else bash "./$ENTRY"; fi
) 2>&1 | tee "$OUT/FH5_${STAGE}_AUTO_LOG.txt"
RC=${PIPESTATUS[0]}
set -e

# A separate hand-off bundle for the next analysis stage. Retain evidence on failures.
python - "$OUT" "$STAGE" "$RC" <<'PY'
from pathlib import Path
import sys,zipfile
out,stage,code=Path(sys.argv[1]),sys.argv[2],int(sys.argv[3])
source=out.parent/f'FH5_{stage}_REPORTS.zip'
summary=out/'FH5_AUTO_STATUS.txt'
summary.write_text(f'stage={stage}\nexit_code={code}\nreport_present={source.is_file()}\n',encoding='utf-8')
with zipfile.ZipFile(out/'FH5_NEXT_STAGE_INPUT.zip','w',zipfile.ZIP_DEFLATED) as z:
    for f in (summary,out/'FH5_LAST_MANIFEST.txt',out/f'FH5_{stage}_AUTO_LOG.txt',source):
        if f.is_file():z.write(f,arcname=f.name)
print('[FH5] Next-stage evidence bundle:',out/'FH5_NEXT_STAGE_INPUT.zip')
PY
if ((RC==0)); then
  printf '[FH5] Finished %s successfully. Evidence: %s/FH5_NEXT_STAGE_INPUT.zip\n' "$STAGE" "$OUT"
else
  printf '[FH5] %s exited with code %s. Upload %s/FH5_NEXT_STAGE_INPUT.zip for diagnosis.\n' "$STAGE" "$RC" "$OUT" >&2
  exit "$RC"
fi