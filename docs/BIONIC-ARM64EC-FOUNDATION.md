# RM11-WinCore — Bionic ARM64EC Runtime Foundation

**Status:** source-only foundation prepared offline on 2026-10-21. **NOT integrated into `main`, not an APK, not proof that Windows EXE runs.**

## Evidence reviewed

- User's GitHub repository `RM11Cor/RM11-WinCore`, current branch `main` (`43c91ae85961fb2c77c38f3c069680c1a65a024c` at review): `WineSmokeV2417.java`, `WineIpcProbeV2423.java`, Gradle, manifest and `apply-v2424-wineserver-nls.yml`.
- GameNative's `BionicProgramLauncherComponent.java` and `BasePrefix.java` show a managed `ImageFs`, a coherently built prefix, Wine/FEX paths, Bionic shared libraries, and optional execution redirection.
- FEX's ARM64EC documentation states that both the 64-bit ARM64EC and 32-bit WOW64 translator modules are required for their respective Windows ABI pathways.
- Android's API 29+ behavior explicitly disallows direct `execve()` of code from writable app home.

Sources:
- https://github.com/utkarshdalal/GameNative/blob/master/app/src/main/java/com/winlator/xenvironment/components/BionicProgramLauncherComponent.java
- https://github.com/utkarshdalal/GameNative/blob/master/app/src/main/java/com/winlator/container/BasePrefix.java
- https://wiki.fex-emu.com/index.php/Development:ARM64EC
- https://developer.android.com/about/versions/10/behavior-changes-10

## Known v2.4.24 failure

`wine --version` succeeded, but the foreground wineserver process returned 1 on startup; the device's latest captured output ends with a nonfatal `/etc/machine-id` complaint. The code in `server/token.c` returns after printing that message. **The cause of the server exit remains unproven** without the complete process log or controlled source-level evidence. Do not claim an unrelated bug is fixed by the foundation below.

## This package supplies

- `RuntimeLayout`: coherent per-app ImageFs directory convention and APK-native entrypoint locations.
- `RuntimeAssessment`: fail-closed preflight of Wine, NLS, FEX and a *fully materialized* Windows prefix; checks the APK-native launchers' AArch64 ELF headers. Returns `STRUCTURALLY_READY`, not `EXECUTION_READY`.
- `BionicLaunchEnvironment`: base environment for a matching Wine ARM64EC/FEX runtime, excluding unverified Android redirectors and display services.
- `PrefixInstaller`: atomic, non-destructive install of an **already unpacked and validated** prefix directory. Refuses to overwrite the user's prefix; refuses unsafe symlinks and partial prefixes.
- `NativeProcessPolicy`: enforces the Android target-29+ boundary: Wine and wineserver start **only** from APK-native-library entrypoints, not writable app files.
- `FoundationSelfTest`: deterministic Java 17 host-side checks (not a phone trial).

## Integration required before any new APK

1. **Bundle manifest**: pin Wine source SHA, FEX source SHA, compiler/ABI, 4K/16K page assumptions, and SHA-256 for each native executable and PE/DLL; package NLS and dependencies in the same release. Reject mixed artifacts at build time.
2. **ImageFs unpacking**: map the existing `runtime-v2417` archive to `/imagefs/opt/wine` while keeping only data and shared libraries in app-writable folders. No `execve()` of `imagefs/opt/wine/bin/wine` on Android 16.
3. **Prefix materialization**: inspect the actual `prefixPack.txz` format/paths, unpack it with a known-supported decompressor preserving Unix symlinks and registry entries, and call `PrefixInstaller` using a prepared directory. Do not assume `.txz` is `.zip`. Do not call `mkdir WINEPREFIX` a successful initialization.
4. **Native execution & re-exec**: integrate a *verified* Android-native process launching/redirector adapter. Current `libwineprobe.so` + `libwineserverrm11.so` allow initial launch but do not prove child re-exec, libredirect, or Wine process IPC. Do not set `WINELOADERNOEXEC` globally to disguise the missing bridge.
5. **Lifecycle**: implement one process supervisor for wineserver, Wine, graceful termination, exact environment, isolated per-game prefix, bounded logs, and state transitions. Host process must outlive its guests; don't interpret process being alive after 1 second as proof of Win32 success.
6. **Display**: integrate working X11/Wayland service and real shared-memory facilities; only set `DISPLAY`, `LD_PRELOAD`, and IPC paths when those components are installed and active.
7. **FEX bridge**: keep `libarm64ecfex.dll` and `libwow64fex.dll` in `aarch64-windows`; use `HODLL=libwow64fex.dll` for the documented WOW64 pathway. Verify ABI matching of the Wine and FEX binaries, not mere filenames.
8. **Android package**: compile and statically inspect the completed integration in a feature branch, preserve the existing keystore and applicationId, then only produce one signed candidate when all offline checks pass. No extra experiments or changing the existing release on `main`.

These remaining steps are **not silently implemented by this package**. Copying this foundation alone will not make RM11 run games.

## How to run host-only checks

```bash
mkdir -p out
javac --release 17 -encoding UTF-8 -d out src/com/rm11/autocore/runtime/*.java test/com/rm11/autocore/runtime/*.java
java -cp out com.rm11.autocore.runtime.FoundationSelfTest
```

## Why this is a separate deliverable

A GitHub branch creation attempt returned HTTP 403 `Resource not accessible by integration`; writes are not authorized through the connected GitHub App. This package is staged locally instead of pretending it was committed. `main` and the current installed APK have not been modified.

No GameNative GPL source files are copied into this foundation; the implementation is independently written, informed by published architectural details. Review upstream licenses if implementing copied components in a future complete integration.
