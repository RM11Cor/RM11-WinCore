#!/data/data/com.termux/files/usr/bin/bash
# FH5 Runtime R2: verify downloads, stage original EXE only, optional sanitizing.
set -Eeuo pipefail
BASE='https://raw.githubusercontent.com/RM11Cor/RM11-WinCore/fh5-android-auto-tests/fh5-runtime'
HOME_DIR="$HOME/fh5_runtime"
DEST='/sdcard/Download/FH5_RUNTIME_SMOKE_R2'
fail(){ printf '[FH5 R2] ERROR: %s\n' "$*" >&2; exit 17; }
command -v pkg >/dev/null || fail 'This launcher requires Termux.'
for c in curl python sha256sum; do
  if ! command -v "$c" >/dev/null; then
    case "$c" in
      curl) pkg install -y curl;;
      python) pkg install -y python;;
      sha256sum) pkg install -y coreutils;;
    esac
  fi
done
[[ -w /sdcard/Download ]] || fail 'Termux storage permission required: termux-setup-storage'
mkdir -p "$HOME_DIR"
TMP=$(mktemp -d "$PREFIX/tmp/fh5-r2.XXXXXXXX")
trap 'rm -rf "$TMP"' EXIT
curl -fL --retry 3 -sS "$BASE/manifest_r2.txt" -o "$TMP/manifest_r2.txt" || fail 'Could not get verified content manifest.'
STAGE=$(sed -n '1p' "$TMP/manifest_r2.txt")
EXP_PY=$(sed -n '2p' "$TMP/manifest_r2.txt")
EXP_BAT=$(sed -n '3p' "$TMP/manifest_r2.txt")
[[ "$(wc -l < "$TMP/manifest_r2.txt")" -eq 3 ]] || fail 'Wrong manifest shape.'
[[ "$STAGE" == R2 && "$EXP_PY" =~ ^[0-9a-f]{64}$ && "$EXP_BAT" =~ ^[0-9a-f]{64}$ ]] || fail 'Unexpected manifest.'
curl -fL --retry 3 -sS "$BASE/boot_r2_stage.py" -o "$TMP/boot_r2_stage.py" || fail 'Python download failed.'
curl -fL --retry 3 -sS "$BASE/R2_BOOT_TEST.bat" -o "$TMP/R2_BOOT_TEST.bat" || fail 'BAT download failed.'
GOT_PY=$(sha256sum "$TMP/boot_r2_stage.py" | cut -d' ' -f1)
GOT_BAT=$(sha256sum "$TMP/R2_BOOT_TEST.bat" | cut -d' ' -f1)
[[ "$GOT_PY" == "$EXP_PY" && "$GOT_BAT" == "$EXP_BAT" ]] || fail 'SHA256 mismatch; refused to execute.'
cp -f "$TMP/boot_r2_stage.py" "$HOME_DIR/boot_r2_stage.py"
if [[ "$*" == '--collect' ]]; then
  python "$HOME_DIR/boot_r2_stage.py" --collect
  exit $?
fi
python "$HOME_DIR/boot_r2_stage.py" || fail 'Could not stage minimal game executable; upload FH5_BOOT_R2_REPORTS.zip.'
[[ -d "$DEST" && ! -L "$DEST" ]] || fail 'Destination directory is unsafe.'
if [[ -e "$DEST/R2_BOOT_TEST.bat" || -L "$DEST/R2_BOOT_TEST.bat" ]]; then
  cmp -s "$TMP/R2_BOOT_TEST.bat" "$DEST/R2_BOOT_TEST.bat" || fail 'Different existing BAT; refusing overwrite.'
else
  cp "$TMP/R2_BOOT_TEST.bat" "$DEST/R2_BOOT_TEST.bat"
fi
printf '\n[FH5 R2] Smoke folder: %s\n' "$DEST"
printf '[FH5 R2] Test file: %s/R2_BOOT_TEST.bat\n' "$DEST"
printf '[FH5 R2] No automatic execution. Open the BAT from your legitimate Wine/Bannerlator container.\n'
printf '[FH5 R2] Then collect sanitized results: bash ~/fh5_runtime_r2.sh --collect\n'
