# KERNIX G2-C MIT16K — first user-observed Android x86 guest execution PASS

**Date:** 2026-11-04  
**Device:** REDMAGIC 11 Pro (Android 16, ARM64)  
**Evidence class:** user-supplied screenshot of the actual installed Android
app's post-test UI. This is **not** independent developer device capture
or GitHub-hosted Android emulator execution. Original screenshot is held
only in the user's ChatGPT conversation; **not** distributed in this
repository because it includes unrelated third-party overlay content.

## Exact screenshot evidence

The user installed the signed
`KERNIX-G2C-MIT16K-OptIn-v0.22.apk` and activated the explicit G2-C
MIT16K eight-second fixed-x86 test button. The screenshot visibly shows
the button disabled after testing and these exact result markers
(line wrapping is due to the Android text layout):

```text
KERNIX_G2C_MIT_16K_SIGNED_ASSET_SHA256_STAGED_NO_GUEST_EXEC
KERNIX_G2C_ANDROID_MIT16K_FEX_CHILD_VERIFIED_EXACT_RAX
```

The first marker means the Java staging function accepted exactly the
three SHA-256-pinned MIT ELF inputs from the signed APK, and installed
them under the app-owned directory. By itself it does **not** prove
guest execution.

The **second marker** is returned only by
`G2CAndroidChildSupervisor.superviseMit16k` for its actual Android
subprocess when all of the following held:

1. The Process completed within the bounded 8-second wait.
2. The child exit code was **0**.
3. Entire stdout was *exactly*:
   ```text
   KERNIX_G2C_ANDROID_FEX_MIT_ONLY_PINNED_DYNAMIC_PIE_EXEC_PASS_V1
   GUEST_RAX=0x4b45524e49584732
   ```
4. stderr contained no `KERNIX_G2C_UNEXPECTED_GUEST_SYSCALL`
   or `KERNIX_G2C_FATAL`.
5. In the native original FEXCore driver the RAX success lines occur
   **only after** `context->ExecuteThread(thread)` returned and
   the actual guest state RAX equaled
   `0x4b45524e49584732`, otherwise exit 25.

The separate Java `G2CMit16kAndroidSupervisor` pins the exact
signed APK original FEXCore library SHA256
`f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d`,
native original-FEX Android MIT candidate SHA256
`62eee7a6344956d41bf3b1c0070c7f6c3b68d2a72f379f059f72da57557e2462`,
and the three exact MIT guest ELF hashes, before invoking a fixed
child binary/flag. The child itself independently opens and SHA-checks
the three guest files with no-symlink and immutable anonymous
snapshot handoff.

## Signed release gate identity

[GitHub Actions signed APK build 41825392908](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41825392908):
**SUCCESS**, retaining the same Android update signing certificate;
`versionCode=22` and `versionName=0.22-g2c-mit16k-opt-in`.
APK SHA256 from signed release evidence:
`0fd4cb2a953d14a43eaecda16b75b2ab001e3a30aa95c3ddd2678611c9663219`.

## What this establishes / what it does not

**User-observed on-device PASS:** KERNIX's first SHA-pinned,
MIT-only, bounded genuine x86-64 ELF64 direct-entry guest instruction
sequence executed through the source-built original FEXCore in the
signed Android host app, with exact post-execution guest register
check. The user-provided screenshot is stronger evidence than prior
Linux ARM64-only CI and NDK cross-compilation alone.

**NOT established:** functioning `PT_INTERP` interpreter;
relocations, TLS, imported symbol binding, `glibc` or other distro
library startup; arbitrary Linux x86 applications; Windows PE;
Wine/Proton; DirectX, DXVK, VKD3D; graphics or any Windows game.
The special ELF PT_INTERP placeholder was never executed, and the
witness deliberately directly enters main `_start`.

There is **no** independent detailed device stderr or timestamped
native trace attached to the screenshot, and no device GPU
performance/thermal study has been done. Do not generalize this
single result to all devices or extended workloads.

## Next targeted engineering gate

Proceed to a second fixed, MIT-only on-device witness that validates
a genuine x86 imported-function call plus relocations/linker entry
without `glibc`, still under the same SHA-pinned private assets,
original FEXCore and 8-second child safety boundary. It requires
independent on-device proof before broadening beyond a tiny guest.
Keep the verified `v0.22` test APK as a stable rollback point.
