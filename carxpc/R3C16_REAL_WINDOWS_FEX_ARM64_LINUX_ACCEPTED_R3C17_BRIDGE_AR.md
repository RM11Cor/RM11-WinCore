# CarX R3-C16 — real Windows PE64 under pinned FEX on ARM64 Linux: ACCEPTED

Date: 2026-11-14. Exact accepted GitHub Actions evidence: https://github.com/RM11Cor/RM11-WinCore/actions/runs/43601491216

## Source-pinned inputs
- FEX source commit: `02e24ca5c01ed0c864466ed573db347336f70170` (genuine Linux ARM64 FEX ELF, NOT Android Bionic)
- Wine x86-64 guest: signed Ubuntu Noble distro Wine packages, version from `wine-guest-distro-package-manifest.txt` (not the separate Wine11 custom build)
- Guest Ubuntu Wine rootfs archive SHA256: `86fafa2f5072aa2c47b7025ca591d945007584ecda37ae92eee208a95283f4b0`
- Independent real Win64 PE source: `carxpc/r3c16/win64_vmem_tls_stdout_smoke.c`, built with MinGW x86-64 PE32+.
- Wine Prefix originally prepared under actual Wine x64, verified to have `system.reg`, then staged fully under **guest** `/opt/carx-r3c16-wine-prefix`. The parent `/opt` itself must be user-owned for Wine; copying just a root-owned parent fails. Guest-owned SHA-verified files remain unmodified except ownership/mount path and the added exact Win64 smoke EXE within prefix.
- Wine host binaries remain Linux x86-64 guest code; Android host is **not** yet used.

## Passing hardware-backed Linux ARM64 proof
The genuine FEX ARM64 ELF launched x86 Linux `stat` successfully against all:
1. `/usr/share/wine/wine.inf`
2. `/opt/carx-r3c16-wine-prefix/system.reg`
3. `/opt/carx-r3c16-wine-prefix/drive_c/CarX_R3C16_Win64_Smoke.exe`

The subsequent genuine Wine x86-64 guest execution ran `/tmp/kernix-real-win32-smoke.exe` under FEX. Native Windows code verified `GetCurrentProcessId`, `GetCurrentThreadId`, `VirtualAlloc`, full-page content readback, Windows TLS allocation/write/read/free, `VirtualProtect` writable→read-only→restore, `VirtualFree`, and `GetStdHandle/WriteFile`. Actual proof line:
`CARX_R3C16_REAL_WIN64_PE_WINAPI_VMEM_TLS_STDOUT_PASS`.
**Process exit code = 0**, no missing kernel32, no wine.inf unavailability. CI job conclusion SUCCESS.

A separate **C: path** variant printed the same marker but exit code **137** (SIGKILL / possible resource termination), so it is **NOT accepted as clean exit**. Do not treat a marker without exit0 as proven.

## Root cause isolated by failed controls
- Native Linux x64 custom-built Wine11 exited 53 loading kernel32, while Ubuntu distro Wine natively passed the *same* PE; therefore the custom Wine11 build still needs separate repair (run 43598386045).
- FEX + guest distro Wine with freshly created host-side prefix: exit53/c0000135 despite rootfs DLL presence (run 43598239873).
- Confirmed all three files exist AND are readable from genuine x86 FEX stat with exit0; host /usr/share/wine/wine.inf is absent (run 43600893527). Wine filename resolution was not identical to direct guest stat.
- Once the full Prefix was stored within FEX guest RootFS with user-owned parent, Win64 PE worked cleanly under Wine+FEX (run 43601491216).

## Next non-skippable gates
R3C17: run this **identical actual Win64 PE under Android/Bionic ARM64** with FEXCore's Android-native host, guest x86_64 glibc rootfs and Wine process execution. Requirements:
1. Prove Android Bionic caller and genuine ARM64 FEX + x86-64 Linux guest with separate, source-pinned host/guest dependencies and correct user-owned guest prefix.
2. Prove guest process creation, exit, TLS/FS handling, Windows `ntdll`/`kernel32`, and Win64 PE marker **and exit0** in a real Android child.
3. Prove no accidental host Bionic TLS override, W+X mappings, guest syscall forwarding to host with untrusted pointers, or fake guest thread features.
4. Only after this, test DXVK D3D11 → Android Vulkan WSI Surface swapchain acquire/submit/present/verified triangle; then user-provided CarX game and gamepad.

The already accepted R3C15 bounded original GNU x86 ELF 12/12 batch is NOT a proof of generalized Wine guest process execution. Reuse its regression witness, not its fixed ELF sample as a Wine substitute.

**No new APK from R3C16**: Linux ARM64 execution is not Android app execution. R3C15 versionCode22 signed APK is last device-validated.
