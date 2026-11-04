# G2-C Android original FEXCore fixed guest candidate — CI link PASS

- Date: 2026-11-04
- Branch: `kernix-native-engine-v1`
- CI: [original FEXCore Android ARM64 NDK run 41809470149](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41809470149) — **SUCCESS**
- Security policy CI: [run 41809470038](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41809470038) — **SUCCESS**

## What actually passed

Original pinned, source-built FEXCore linked successfully on Android ARM64/Bionic to a **new candidate** for direct-entry execution of the one fixed x86-64 dynamic PIE. GitHub also separately linked the older `KERNIX_G2C_ANDROID_BIONIC_BUILD_ONLY` binary, which always exits 126.

The candidate's exact `--kernix-g2c-execute-fixed-snapshot-direct-entry-v1` command, app-private path restriction, and native four-ELF size/SHA-256 verified anonymous byte snapshots are mandatory before a future JIT run. Positive and negative host tests reject external storage, arbitrary commands, traversal and other packages.

Android ELF auditor confirmed AArch64, `/system/bin/linker64`, original `libFEXCore.so`, Android `libc.so`, and no unintended glibc or shared libc++ dependency. The candidate executable was **deleted from /tmp after its digest and ABI audit**, and was neither uploaded nor packaged in the signed APK. Only the build audit text/log and SHA digest are retained.

## Explicit limits

This was **NOT Android device execution** of G2-C x86 guest code, and not glibc, guest PT_INTERP interpreter boot, Wine, PE/DirectX or game compatibility. Earlier G1 on-phone original FEXCore x86 ELF64 probes are separate evidence. The signed APK has `G2CAndroidChildSupervisor.QUALIFIED_RUNNER_SHA256 = ""` and does not expose the future G2-C runner to UI. The default Android build-only mode remains hard-blocked.

## Next release gate

Securely source and license the original fixed four x86 ELF fixture; package only after separate provenance/license check, pin candidate runner SHA to **identical bytes inside a persistently signed APK**, preserve the eight-second child watchdog, then obtain an actual user-initiated REDMAGIC Android 16 result before opening any broader guest runtime or Wine gate.
