# KERNIX: permanent APK update signing (v0.8+)

## Problem identified

Past public APK versions (v0.2–v0.7) were generated with the standard Android
`assembleDebug` task on disposable GitHub Actions runners. Each runner can
generate an independent random debug signing key, so `org.kernix.host`
packages with the same package name but different signing certificates
cannot be installed over each other. Increasing `versionCode` does not repair
a signing certificate mismatch.

**You cannot silently re-sign v0.7 to match the new private identity**:
Android does not let two unrelated signing keys update an existing installation.
Users upgrading from an old debug-signed preview must uninstall that preview
**once**, after preserving any preview-specific data. Do not uninstall other
emulators or games. Starting with the first stable-signed v0.8, later v0.9+
APK updates can install in place, if the original signing key is retained.

## Fixed release identity

- Package name (must remain constant): `org.kernix.host`.
- Certificate SHA-256 (public and pinned in CI):
  `A7:47:35:BC:30:B5:3E:59:05:89:D8:FF:5C:23:3F:72:DC:0E:4D:DF:6E:31:29:39:D6:68:AE:30:C4:6B:6F:8E`.
- Keystore type: `PKCS12`, alias: `kernix-update`.
- Exact PRIVATE keystore SHA-256 (safe for CI comparison):
  `fc4fcce82a85df0cb87d6f1cf3f9fce57555353ce9f2d05d7940c645e86e16e6`.
- First fixed-signing version: `versionCode 8`; `versionName 0.8-stable-update-signing`.
- Each future **published** version must use a strictly greater `versionCode` than the installed version; e.g. v0.9 should be 9, v0.10 should be 10.
- Releases use `:app:assembleRelease`, NEVER `assembleDebug`. Internal debug APKs are not distributable upgrade files.

## Secure GitHub Actions setup — one time

The repo is public. **Do not commit the keystore, base64 key, password, or a
password-containing config file**. Make one encrypted offline backup of the
permanent identity. Repository administrators must add **two GitHub Actions
repository secrets** at
https://github.com/RM11Cor/RM11-WinCore/settings/secrets/actions:

1. `KERNIX_SIGNING_KEYSTORE_BASE64` — the entire base64-encoded contents
   of the private `KERNIX-UPDATE-PRIVATE.p12` file.
2. `KERNIX_APK_SIGNING_PASSWORD` — the keystore's private password; this
   keystore uses the same password for its private key.

The private keystore and password have been provided separately to the repo
owner as a secure **conversation attachment**, **not committed to GitHub**.

Once both secrets are configured, run
`KERNIX independent Android host preview APK` in Actions on branch
`kernix-native-engine-v1`. The workflow will:

- fail if either secret is missing, decoded keystore SHA is unexpected,
  alias is absent, password is incorrect or public cert hash differs;
- compile and sign the release APK with that one private key;
- verify the signed APK using Android `apksigner` and compare the exact
  signer fingerprint; reject mismatched `org.kernix.host` identity/version;
- preserve existing FEXCore and x86 guest-runner static checks, hashes,
  upstream license notices, Android ABI and classes;
- upload only the validated signed release APK as an internal build artifact.
  Direct GitHub Releases still require a separate verified publish workflow.

### Direct GitHub Release for v0.8 and future stable updates

After the source APK workflow succeeds, go to GitHub Actions and run
`KERNIX permanently signed update APK publisher (v0.8+)` with both inputs:

- `source_run_id`: the successful source APK workflow run ID.
- `source_commit_sha`: the exact 40-character commit SHA shown for that run.

The publisher verifies the SHA and branch, APK checksum, Android signing
certificate, package name, native host/guest proof binaries, and versionCode.
It checks ALL previous `kernix-update-vN-...` release tags for a higher
versionCode, then creates an immutable direct-download `KERNIX-Update.apk`
GitHub Release. Do not publish APKs from older `v0.2`–`v0.7` debug-key
release workflows as replacement update builds.

A separate `KERNIX APK stable signing Gradle contract smoke` workflow
checks that a production build **fails closed without secrets**. Its optional
v0.8/v0.9 rebuild proof uses a disposable test-only signing key; no APK from
this smoke test is published, because its key is NOT the permanent one.

**Verification alone cannot prove an update on the user's installed phone**.
After the first v0.8 is signed, install it (a one-time removal of old v0.7
may be required), then build v0.9 with the SAME key and greater versionCode
and install it over v0.8 without uninstalling. Never rotate the key silently.

## Security and rotation

The backup bundle contains a private Android signing key. Do not disclose it
in GitHub Issues, comments, Pull Requests, terminal logs, chat screenshots,
or public release assets. Treat compromise as serious: an adversary with the
private key can sign an app with the same package identity. If GitHub secrets
are lost, restore them from the secure offline backup — **do not generate a new
key for each run**. Public key fingerprints can be checked in logs; private key
bytes must never be printed. Any intentional key rotation needs a separate
Android signing lineage/migration design and cannot be treated as a routine APK
build change.


## Verified CI outcome (2026-11-03)

[Signed-APK update contract run 41618947343](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41618947343) **completed successfully**. It actually built two local non-distributable release APKs using the **same disposable smoke key**, checked that versionCode increased from 8 to 9 while the signing certificate fingerprint and package identity stayed identical, and deliberately deleted both test APKs. It also verified that a release build without a persistent private signing key is rejected. This is direct build/signing-system verification, not a claim that either APK was distributed or installed on a phone.

The production APK workflow currently **cannot publish v0.8** until the repo owner adds both private Actions secrets described above. This intentional failure protects users from another randomly signed GitHub Actions APK. Do not use the smoke APK as a real download.


## v0.8 stable-signature build: success; GitHub Releases permission: blocked (2026-11-03)

- **Actual successful fixed-key source run:** [GitHub Actions #41625468319](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41625468319), attempt 2, source commit `251af8b1422f788a51c0af6890aad48a81f2f452`. Passed Android private signing-keystore SHA, password, release Gradle build, APK signing certificate fingerprint, native FEXCore binary/guest probe SHA, native arm64 and third-party license gates.
- Artifact `KERNIX-Host-Preview-APK`, artifact ID `13226570404`, contains exact `KERNIX-Host-Preview.apk` (994,925 bytes), SHA-256 `e7ca70cfb0ac78547efc468ac0e0f0d86a97fc7e730995f8680dfb36d8fcdd0d`. Package `org.kernix.host`, versionCode 8, versionName `0.8-stable-update-signing`, signing scheme v2, permanent certificate fingerprint `a74735bc30b53e590589d8ff5c233f72dc0e4ddf6e312939d668ae30c46b6f8e`. This build is real, but x86/Wine/game compatibility has not advanced beyond the v0.7 user-reported fixed getpid gate.
- **Release publishing blocked by permissions, NOT compilation or signing:** [release attempt #41626610196](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41626610196) and [#41626738163](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41626738163) passed source provenance, APK checksum/signature/identity and increasing version checks, then both failed at `gh release create` with `HTTP 403: Resource not accessible by integration`. The first tried `KERNIX_RELEASE_TOKEN` or `github.token`; the second explicitly `github.token`. No GitHub Release was published.
- **Next action for the repository owner:** GitHub `RM11Cor/RM11-WinCore` > **Settings > Actions > General > Workflow permissions > Read and write permissions**; Save. Also check any account/organization policy. This allows the repository's `GITHUB_TOKEN` with the workflow's explicit `contents: write` permission to create a GitHub Release. If owner cannot change this setting, configure a narrowly scoped personal access token with `Contents: write` for this exact repository as `KERNIX_RELEASE_TOKEN`, and use that token after verifying it was granted appropriate access. Never expose signing secrets in logs.
- After permissions change, start a **fresh** publisher job, not a previous attempt that may retain a read-only token context. The publisher is pinned to source run `41625468319` and source commit `251af8b1422f788a51c0af6890aad48a81f2f452`, with planned immutable tag `kernix-update-v8-251af8b1` and asset `KERNIX-Update.apk`. A successful release must be verified via its actual returned assets before a download link is shared.
- Android update rule remains: old v0.7 debug-signed APK cannot be updated in place with new v0.8 signer, requiring a single migration removal of `org.kernix.host` after saving its data. v0.9+ must preserve the exact v0.8 signing certificate and use increasing versionCode. Never uninstall other game emulators.
