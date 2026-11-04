# KERNIX G2-C MIT-only 16 KiB-safe direct-entry signed Android opt-in APK v0.22

**2026-11-04 release-gate evidence (signed APK ready for a single device test; NOT Android execution proof).**

## Signed package actually built

- **GitHub Actions:** [SUCCESS 41825392908](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41825392908)
- **GitHub artifact:** `KERNIX-G2C-MIT16K-Signed-OptIn-v0.22-APK`.
- **APK filename:** `KERNIX-G2C-MIT16K-OptIn-v0.22.apk`
- **Size:** 1,287,130 bytes.
- **APK SHA-256:** `0fd4cb2a953d14a43eaecda16b75b2ab001e3a30aa95c3ddd2678611c9663219`.
- **Package:** `org.kernix.host`.
- **Version:** `versionCode=22`, `versionName=0.22-g2c-mit16k-opt-in`.
- **Expected, verified stable update signer cert SHA256:** `a74735bc30b53e590589d8ff5c233f72dc0e4ddf6e312939d668ae30c46b6f8e`.

The signed APK's **actual member bytes** were checked against their exact independent hashes, and `apksigner verify --verbose --print-certs` + `aapt dump badging` passed on CI. The downloaded CI artifact was separately unpacked; its APK SHA, package/versions, and actual exact embedded member bytes were rechecked before sharing.

### Embedded MIT x86 guest (three exact SHA-pinned 16KiB W^X-separated ELF assets)

- `bin/kernix-mit-dynamic-app`: SHA256 `814944a2ff2580e6d2c65b84de8086e74f1f8f3a654b6ed4bda15542058efac6`.
- `lib/x86_64-linux-gnu/libkernix-g2c-mit-placeholder.so.1`: SHA256 `0c2ef465de4222c5e63dcd3bd15587d649e1fbb23590d949dce917cc1bde34a3`.
- `lib64/ld-kernix-g2c-mit-placeholder.so.1`: SHA256 `a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2`.

Each is MIT-only; `assets/third-party-notices/KERNIX-MIT-GUEST.txt` SHA256 `cce39d8733871191985c975c8a6a2454201c3665482027a25731b4090303e250` is shipped in addition to all original FEXCore/third-party notices. The exact original Android `libFEXCore.so` is SHA256 `f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d` and the Android/Bionic MIT-only JIT candidate is SHA256 `62eee7a6344956d41bf3b1c0070c7f6c3b68d2a72f379f059f72da57557e2462`.

### User-initiated on-device execution criteria

The UI versionCode 22 path, and only this path, shows the single-use G2-C MIT16K test button. A confirmation dialog states that the runner has an 8-second watchdog. Java stages exactly the three trusted, verified original MIT ELF asset bytes into app-private `kernix/runtime-v1/guest-rootfs/g2c-mit16k-v1`, rejects unexpected files and symlinks and rehashes before launch. The native child independently pins originals with O_NOFOLLOW, checks file owner/immutable mode/hash, freezes anonymous read-only copies before FEX guest RX and uses the exact single original x86 _start direct entry; no user-provided guest input, Wine or installed game is consulted. The original-FEX 16KiB guest layout had previously proved real x86 execution on **Ubuntu ARM64** in [run 41821444577](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41821444577), and the original Bionic ELF candidate was cross-linked in [run 41822169402](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41822169402).

**What is not yet proven:** This precise v0.22 APK has not yet been executed on REDMAGIC or any Android device. Its first test may still fail from Bionic dynamic loading, guest execution, FEX JIT, actual 16KiB host page details or device-specific behavior. Do not claim it boots Linux loaders, resolves dynamic relocations, runs glibc, Wine or any Windows games. The test interpreter is a deliberate **nonfunctional PT_INTERP placeholder**; the direct entry bypasses it. The standard signed v0.21 host preview remains the independent non-G2-C-runner mode.

**Device trial safety:** one user confirmation per run; exit/timeout/fatal output and failed SHA must be reported separately. Stop testing if abnormal heating, freeze or system instability appears; do not retry repeatedly. Preserve the exact diagnostic/marker output from the first Android test to determine the next engineering change rather than speculative rebuilds.
