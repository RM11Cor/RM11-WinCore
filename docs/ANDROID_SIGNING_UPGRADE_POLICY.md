# CarX Street PortLab — Android in-place upgrade signing contract

## Permanent release identity, effective from v0.3.0

- Application ID: com.rm11cor.carxstreet.portlab (must never change).
- Android package versionCode: 3 for v0.3.0; **4 or greater** for the next release, and strictly increasing for each later release.
- Permanent CarX-only certificate SHA256:
  73759b890548a1cc52cc513ce859013e0e2c0884258f66ee19da45e59b30e2bc
- Private PKCS#12 signing identity: encrypted ciphertext in
  carx-signing/carx-release.p12.enc.b64 (public repository ciphertext ONLY).
- Encryption/password supplied by existing protected repository secret
  RM11_RELEASE_PASSWORD. Do not print the secret, add plaintext key files to Git,
  rebootstrap/rotate a working signing identity, or publish debug-signed APKs.
- Gradle release signer alias: carx-release. Uses Android APK Signature Scheme v3
  (or v2 if the toolchain produces it); CI verifies Android apksigner, certificate
  fingerprint, application ID and versionCode before publishing.

## One-time legacy debug-signer migration

CarX PC PortLab v0.1.0 and v0.2.0 APKs used random GitHub-hosted build
runner debug signing keys. Their old private keys were not retained.
Android WILL NOT allow a differently signed v0.3.0 APK to update them
in place. A certificate cannot be converted into its missing private key.

User must export any JSON report from old inspector, uninstall ONLY the
old inspector ONCE, then install the permanent v0.3.0 from GitHub Releases.
The user-owned PC game files in shared storage are not removed. Selecting
the same game folder again may be necessary.

From the permanent-signed v0.3.0 forward, the next v0.4/1.0 version can
install over it if (1) same application ID, (2) same signing certificate,
(3) strictly larger versionCode, and (4) device remains compatible.
Do not ask the user to uninstall for future normal updates.

## Verified evidence

- Dedicated CarX signing bootstrap Actions #43181230185 SUCCESS. Permanent
  certificate fingerprint above, encrypted keystore committed.
- v0.3.0 build-and-sign Actions #43182076967: APK compile/assemble and
  apksigner signature+package/version verification succeeded. The **workflow
  overall** failed ONLY in its now-removed GitHub Release publish step
  (403). Do not label that entire run successful.
- Separate immutable artifact publishing Actions #43182594661 SUCCESS,
  rechecked original signed build SHA manifest and published release:
  https://github.com/RM11Cor/RM11-WinCore/releases/tag/carx-street-portlab-v0.3.0-permanent-signing-20261112
- Historical v0.2.0 asset restored to its exact original signed debug APK
  SHA256 0bbc2622e0e499da2db4e455115bb9868a3a6cf166d3167f114154ce3c4fb014
  via Actions #43182114613 SUCCESS. Never accidentally relabel a
  versionCode 3 debug build as v0.2.0 again.
- Build and publication are separated. New version's builder must
  explicitly check its new versionCode and pinned original CarX signer
  fingerprint, then release a new tag, not overwrite old release assets.

**Port functionality:** This signing change does NOT create or execute an
Android-native CarX Street game port. The APK remains the read-only original
Unity / IL2CPP / Windows64 assets inspector.
