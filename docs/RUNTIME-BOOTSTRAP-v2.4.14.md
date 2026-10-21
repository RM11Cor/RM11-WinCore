# RM11-WinCore: Android ARM64 Runtime Bootstrap (v2.4.14-alpha)

This change begins an **in-APK native execution host**, not a complete Windows emulator.

- Adds an NDK JNI `.so` shipped and executed **from the APK's native library path**.
- Tests ARM64 W^X-compatible JIT memory flow: mmap(RW), ARM64 MOV/RET, cache flush,
  mprotect(RX), execution returning 42, and unmap.
- Reports Android/SELinux/JIT compatibility transparently. A blocked result is NOT
  proof the GPU or CPU lacks the power to run Windows games.
- Shows that FEXCore, Wine/Proton, DXVK/Turnip and safe game-file mapping are
  **not yet embedded or verified** in RM11-WinCore. No false EXE-ready badge.
- No Android root, native code downloaded from the internet, DRM bypass, game copy,
  installation of executables to writable app data, or change to the signing key.

## Why this foundation?

Android 10+ forbids executing binaries directly from an app's writable home
folder for target SDK >= 29. The eventual engine must package executable
components in the APK and comply with Android's executable-memory policy.
FEX-Emu Linux binaries are not drop-in Android executables; FEXCore + Wine
ARM64EC/WoW64 requires deliberate platform adaptation and matching libraries.

## Next integration stages

1. Package and license-audit an ARM64-compatible, JNI-loadable CPU translator
   as an APK native library (FEXCore or a compatible runtime).
2. Add a matched Wine/Proton ARM64EC/WoW64 backend, Android-compliant Linux
   runtime syscall compatibility, process/session lifecycle and X11/Wayland display.
3. Add Vulkan driver plumbing and verified DXVK/VKD3D DLLs; validate actual
   D3D11/D3D12 device creation, presentation and executable launches.
4. Add user-granted game-directory access without modifying the source games;
   prefer Android SAF permissions and avoid copying large game data.
5. Measure sustained frame times/thermal status in Balance; only expose
   supported Android performance hints, never claim Diablo-level performance.

Upstreams: https://github.com/FEX-Emu/FEX ; https://gitlab.winehq.org/wine/wine ;
https://github.com/doitsujin/dxvk ; https://github.com/HansKristian-Work/vkd3d-proton

Upstream license terms and dynamic/runtime redistribution need separate review
before bundling third-party binaries. This change introduces none of them.
