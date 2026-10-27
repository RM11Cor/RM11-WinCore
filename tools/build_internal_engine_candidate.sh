#!/usr/bin/env bash
# Sign an INTERNAL APK candidate from the SHA-pinned prior release and an
# NDK-built AArch64 supervisor. Validate then DISCARD the APK; no release.
set -euo pipefail
umask 077
test -n "$GITHUB_WORKSPACE"
test -n "$RUNNER_TEMP"
test -n "$ANDROID_HOME"
test -n "$RM11_RELEASE_KEYSTORE_B64"
test -n "$RM11_RELEASE_PASSWORD"
test -n "$GH_TOKEN"

cd "$GITHUB_WORKSPACE"
ROOT="$RUNNER_TEMP/rm11-engine-internal-candidate"
rm -rf "$ROOT"
mkdir -p "$ROOT/stage/lib/arm64-v8a" audit
trap 'rm -rf "$ROOT"' EXIT

NDK="$ANDROID_HOME/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin"
BT="$ANDROID_HOME/build-tools/36.0.0"
test -x "$NDK/aarch64-linux-android29-clang"
test -x "$BT/apksigner"
test -x "$BT/zipalign"
test -x "$BT/aapt"

# PIE dynamic ELF can live under APK nativeLibraryDir with lib*.so naming.
# It is a standalone executable, not a dlopen()-compatible JNI library.
NATIVE="$ROOT/stage/lib/arm64-v8a/librm11_engine_supervisor.so"
"$NDK/aarch64-linux-android29-clang" \
  -std=c11 -Wall -Wextra -Werror -O2 -fPIE -pie \
  -Wl,--build-id=sha1 -Wl,-z,max-page-size=16384 \
  -o "$NATIVE" tools/engine_native_session_supervisor.c
python3 tools/verify_android_native_supervisor.py "$NATIVE" \
  --out audit/engine-candidate-supervisor-abi.json

gh release download v4.0.89-native-wine-activity \
  --repo RM11Cor/RM11-WinCore --pattern app-release.apk --dir "$ROOT"
mv "$ROOT/app-release.apk" "$ROOT/baseline.apk"
printf '%s\n' \
  '1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8  '"$ROOT"'/baseline.apk' \
  | sha256sum -c -

cp "$ROOT/baseline.apk" "$ROOT/un-aligned.apk"
if unzip -Z1 "$ROOT/baseline.apk" | grep -Fxq \
  'lib/arm64-v8a/librm11_engine_supervisor.so'; then
  echo "RM11_ENGINE_ALREADY_PRESENT_IN_BASELINE" >&2
  exit 41
fi
(
  cd "$ROOT/stage"
  zip -q -X -0 "$ROOT/un-aligned.apk" \
    lib/arm64-v8a/librm11_engine_supervisor.so
)
"$BT/zipalign" -f -p 4 "$ROOT/un-aligned.apk" "$ROOT/aligned.apk"

# No keystore or password is printed or persisted in a workflow artifact.
printf '%s' "$RM11_RELEASE_KEYSTORE_B64" | base64 --decode \
  > "$ROOT/signing.p12"
chmod 600 "$ROOT/signing.p12"
keytool -list -keystore "$ROOT/signing.p12" \
  -storetype PKCS12 -storepass "$RM11_RELEASE_PASSWORD" \
  -alias rm11-autocore >/dev/null
"$BT/apksigner" sign \
  --ks "$ROOT/signing.p12" --ks-type PKCS12 \
  --ks-key-alias rm11-autocore \
  --ks-pass env:RM11_RELEASE_PASSWORD \
  --key-pass env:RM11_RELEASE_PASSWORD \
  --min-sdk-version 29 \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --v4-signing-enabled false \
  --out "$ROOT/internal-signed.apk" "$ROOT/aligned.apk"

"$BT/apksigner" verify --verbose --min-sdk-version 29 \
  --max-sdk-version 36 --print-certs "$ROOT/baseline.apk" \
  > "$ROOT/legacy-cert.txt"
"$BT/apksigner" verify --verbose --min-sdk-version 29 \
  --max-sdk-version 36 --print-certs "$ROOT/internal-signed.apk" \
  > "$ROOT/new-cert.txt"
"$BT/zipalign" -c -p 4 "$ROOT/internal-signed.apk"
"$BT/aapt" dump badging "$ROOT/baseline.apk" \
  | grep '^package:' > "$ROOT/legacy-identity.txt"
"$BT/aapt" dump badging "$ROOT/internal-signed.apk" \
  | grep '^package:' > "$ROOT/new-identity.txt"
diff -u "$ROOT/legacy-identity.txt" "$ROOT/new-identity.txt"

python3 tools/verify_engine_candidate_apk.py \
  "$ROOT/baseline.apk" "$ROOT/internal-signed.apk" "$NATIVE" \
  --abi-report audit/engine-candidate-supervisor-abi.json \
  --out audit/engine-candidate-signed-closure.json

python3 - "$ROOT/legacy-cert.txt" "$ROOT/new-cert.txt" <<'PY'
import json
import re
import sys
from pathlib import Path
pattern=r"Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]{64})"
a=re.search(pattern,Path(sys.argv[1]).read_text())
b=re.search(pattern,Path(sys.argv[2]).read_text())
if not a or not b or a.group(1).lower()!=b.group(1).lower():
    raise SystemExit("RM11_ENGINE_SIGNER_CERT_CHANGED")
path=Path("audit/engine-candidate-signed-closure.json")
result=json.loads(path.read_text())
assert result["original_resources_preserved"] is True
assert result["candidate_may_be_released"] is False
assert result["activation_flag"] == "OFF"
result["release_signer_identity_matches"]=True
result["android_package_identity_matches"]=True
result["internal_apk_deleted_after_audit"]=True
result["published_release"]=False
path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
print("RM11_ENGINE_CANDIDATE_CERT_AND_PACKAGE_VERIFIED_ONLY")
PY
# Candidate APK and signing material removed by EXIT trap.
# Only JSON gate reports uploaded by CI.
