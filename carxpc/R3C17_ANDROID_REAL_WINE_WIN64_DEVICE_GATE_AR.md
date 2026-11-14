# R3-C17 — Android ARM64 Bionic Wine/Win64 evidence gate

## Grounded result inherited from R3-C16
- **PASS on GitHub Actions Linux ARM64**: genuine FEX SHA `02e24ca5c01ed0c864466ed573db347336f70170` and Ubuntu Noble x86_64 Wine guest, native-prepared Wine Prefix inside guest RootFS with user-owned parent, ran a real Windows x64 PE /tmp/EXE fixture, printed `CARX_R3C16_REAL_WIN64_PE_WINAPI_VMEM_TLS_STDOUT_PASS`, and exited 0. Run: https://github.com/RM11Cor/RM11-WinCore/actions/runs/43601491216.
- Tested Windows APIs: process/thread identity, VirtualAlloc, full-page R/W, Windows TlsAlloc/TlsGetValue/TlsSetValue/TlsFree, VirtualProtect, VirtualFree, WriteFile.
- The second `C:` launch variant showed the marker but process exit 137; **not accepted** as complete clean execution.
- The full Windows x64 execution milestone is for **Linux ARM64, not Android Bionic ARM64**. This distinction is mandatory.

## Executable future device gate
`carxpc/r3c17/accept_android_win64_wine_device.py` is a strict report-consistency checker only:
- Requires Android/Bionic ARM64 device host, pinned real original FEX native Android binary, x86_64 Linux guest Wine, exact rootfs provenance SHA, owned guest prefix.
- Requires guest Linux ldso boot, Windows ntdll/kernel32 load, actual approved x64 PE image SHA, Windows API marker and guest child exit code 0, observed in one ordered native child transcript.
- Refuses unsupported guest x86 syscall, SIGSEGV/SIGBUS/SIGKILL, accidental Bionic host TLS override, or unsafe host guest-pointer forwarding.
- Prevents conflating Win64 fixture with game boot or graphics by requiring `carx_game_boot_proven=false` and `vulkan_triangle_presented=false`.
- A JSON report is not a cryptographic or independent attestation of device execution. CI synthetic selftests must NEVER be presented as device evidence.

## Current implementation boundary
- The existing signed Android APK R3C15 is a bounded `GNU ld-linux/libc/ELF` test runner, not a generic process-aware Linux x86_64 FEX rootfs + Wine runtime.
- No real Android Wine/Win64 PE has yet booted on device; R3C17 gate script does not create a working Android Wine host by itself.
- No new APK is released until the host-side Bionic-compatible FEX guest process executor, guest rootfs path/FD mapping, guest Wine initialization, and child output capture exist and pass Android tests.
- Source-built Wine11 custom artifact still had independent kernel32 failure even on native Linux x64 and is not quietly substituted into accepted Wine source stream; Ubuntu distro guest is the **Linux control**.

## Next native Android integration increment
1. Prepare Android app-owned x86_64 Wine guest rootfs installation without root/system bind mounts, with metadata/provenance SHA and owned prefix; free-space checks, rollback, and no path escapes.
2. Implement Android Bionic-hosted actual FEX guest process entry, supporting Wine child processes and guest syscalls without forwarding raw guest x86 pointers into Bionic, while retaining original R3C15 guest TLS safety invariants.
3. First Android on-device test `wine --version` (not a claimed Windows API pass). Then `ntdll/kernel32`, then exact Win64 PE fixture marker+exit0. Record failure isolation by subsystem in one report.
4. Only after a real Win64 PE pass on Android start the graphics gate: Android Vulkan native surface, DXVK D3D11, shader pipeline, acquire/submit/present, verified triangle, then game folder and controller.

## Tests
- CI run https://github.com/RM11Cor/RM11-WinCore/actions/runs/43602220828 confirms Python syntax, 16 synthetic negative-control rejection cases and cross-platform false-positive checks.
- CI tests are **not** proof of Android Wine process execution.
