#!/data/data/com.termux/files/usr/bin/bash
# Forza Horizon 5 runtime R1. No game file upload, patch or automatic extraction.
set -Eeuo pipefail
BASE='https://raw.githubusercontent.com/RM11Cor/RM11-WinCore/fh5-android-auto-tests/fh5-runtime'
SRC="$HOME/fh5_runtime"
OUT='/sdcard/Download'
fail(){ echo "[FH5 R1] $*" >&2; exit 17; }
command -v pkg >/dev/null || fail 'Run inside Termux.'
for cmd in curl python sha256sum; do
  if ! command -v "$cmd" >/dev/null; then
    case "$cmd" in
      curl) pkg install -y curl;;
      python) pkg install -y python;;
      sha256sum) pkg install -y coreutils;;
    esac
  fi
done
[[ -d "$OUT" && -w "$OUT" ]] || fail 'Allow Termux storage access: termux-setup-storage'
mkdir -p "$SRC"
tmp=$(mktemp -d "$PREFIX/tmp/fh5-boot-r1.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT
curl -fL --retry 3 --connect-timeout 15 -sS "$BASE/manifest.txt" -o "$tmp/manifest.txt" || fail 'Cannot get runtime manifest.'
STAGE=$(sed -n '1p' "$tmp/manifest.txt")
EXPECTED_SCRIPT=$(sed -n '2p' "$tmp/manifest.txt")
EXPECTED_BAT=$(sed -n '3p' "$tmp/manifest.txt")
[[ "$(wc -l < "$tmp/manifest.txt")" -eq 3 ]] || fail 'Invalid manifest lines.'
[[ "$STAGE" == 'R1' ]] || fail 'Unexpected runtime stage.'
[[ "$EXPECTED_SCRIPT" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid script checksum.'
[[ "$EXPECTED_BAT" =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid batch checksum.'
curl -fL --retry 3 --connect-timeout 15 -sS "$BASE/boot_r1.py" -o "$tmp/boot_r1.py" || fail 'Cannot download R1 probe.'
curl -fL --retry 3 --connect-timeout 15 -sS "$BASE/FH5_BOOT_TEST.bat" -o "$tmp/FH5_BOOT_TEST.bat" || fail 'Cannot download boot diagnostic.'
SCRIPT_SHA=$(sha256sum "$tmp/boot_r1.py" | cut -d' ' -f1)
BAT_SHA=$(sha256sum "$tmp/FH5_BOOT_TEST.bat" | cut -d' ' -f1)
[[ "$SCRIPT_SHA" == "$EXPECTED_SCRIPT" ]] || fail 'Script checksum mismatch. Nothing executed.'
[[ "$BAT_SHA" == "$EXPECTED_BAT" ]] || fail 'BAT checksum mismatch. Nothing executed.'
cp "$tmp/boot_r1.py" "$SRC/boot_r1.py"
cp "$tmp/FH5_BOOT_TEST.bat" "$OUT/FH5_BOOT_TEST.bat"
echo '[FH5 R1] Verified both files; inspecting game EXE only, no full extraction.'
set +e
python "$SRC/boot_r1.py"
rc=$?
set -e
echo '[FH5 R1] Public report: /sdcard/Download/FH5_BOOT_R1_REPORTS.zip'
echo '[FH5 R1] For later Wine runtime test: /sdcard/Download/FH5_BOOT_TEST.bat'
exit "$rc"
