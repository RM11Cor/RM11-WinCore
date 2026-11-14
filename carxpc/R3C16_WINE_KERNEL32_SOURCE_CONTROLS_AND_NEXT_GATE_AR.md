# CarX R3-C16 — Source-grounded Win64 kernel32 discrepancy, 14 November 2026

## On-device accepted baseline (R3C15)
- REDMAGIC NX809J Android SDK36 report `CarX_PC_R3C_Diagnostics (16).json`: original x86 GNU loader/ELF sample passed **12/12** checkpoints in one process; `exit_code=0`, `auto_batch_terminal_original_guest_exit_group0_proven=true`.
- A bounded guest ELF/ld-linux/glibc sample is demonstrated, **not** general `Wine`, `DXVK`, `CarX`, full IFUNC relocation proof or Android graphics.
- Do not rerun R3C15 milestone for each Windows experiment.

## Genuine Win64 PE64 proof candidate
- Source: `carxpc/r3c16/win64_vmem_tls_stdout_smoke.c`. Built with MinGW Windows-target x64, imports `kernel32.dll`, tests GetCurrentProcessId/GetCurrentThreadId, VirtualAlloc/VirtualProtect/VirtualFree, Windows TLS, WriteFile and exit0.
- Verified PE AMD64 import audit + Wine11 Linux x86_64 artifact provenance: GitHub run **43596982241** SUCCESS. Fixture SHA256 `7a3b6d182d892d3ac4f3af4f5c5b56789e64beb2868fcf40993a752ab84306bf`.
- This is a *newly compiled Windows fixture*, not CarX Street or a game binary.

## Experimental A: native x86-64 Linux Wine, no FEX (run 43598386045)
- Wine 11.0 source-compiled Wine archive at pinned commit `db11d0fe6a169c457e23d007e20404643d067aa8`: `wine --version exit0` but PE `exit53`, fails to load kernel32.dll (`c0000135`).
- Ubuntu distro Wine same native x64 host + same exact SHA PE: `wine --version exit0`, PE `exit0` with exact real WinAPI stdout marker.
- **Grounded inference:** the custom-built Wine11 runtime is already problematic without FEX. Its source packaging/toolchain/runtime, not FEX alone, needs independent repair. Do not claim that Ubuntu's installed Wine version is the required final runtime.

## Experimental B: Linux ARM64 FEX with Wine (runs 43597505621, 43598239873)
- FEX upstream SHA `02e24ca5c01ed0c864466ed573db347336f70170`, genuine source-built native AArch64 Linux ELF.
- Custom Wine11 under FEX: authentic x86 `true exit0`, `wine --version exit0`, but PE `exit53 kernel32 c0000135`.
- Ubuntu distro Wine under same FEX and rootfs: `true exit0`, `wine --version exit0`, PE `exit53 kernel32 c0000135` despite source real DLL present.
- **Interpretation:** independent Wine/FEX guest process setup mismatch exists; not yet isolated to a CPU/JIT bug, guest rootfs path mapping, guest syscall, subprocess exec, or Wine bootstrapping.

## Experimental C: FEX Wine guest-path isolation (run 43598777493)
- Exact distro Wine guest immutable package archive SHA verified. Three same PE runs:
  - standard Wine guest ROOTFS: `exit53`, kernel32 missing
  - explicitly set DLL and system DLL directories: `exit53`, kernel32 missing
  - Wine host-side copy outside FEX rootfs: `exit139`, no kernel32-missing marker; **not success** (segmentation fault)
- Therefore copying DLLs outside guest rootfs is insufficient and risks a different memory crash. Do not promote host-side layout.

## Experimental D: official pinned FEX `binfmt_misc` rule (run 43599165536)
- Pinned FEX source `Source/Tools/FEXInterpreter/CMakeLists.txt` uses `FEX` binary and flags `POCF` for x86_64 binfmt, rather than generic emulator replacement.
- Host binfmt rule registered but initial direct x86_64 `true` returned 255. Manual FEX true returned 0; Wine PE still exit53. A follow-up run retests original executable basename and exposes diagnostic output. No claims of binfmt success yet.
- Test and verify guest subprocess exec and Wine-service state separately before any Windows acceptance.

## Actions that follow from this evidence
1. For host Wine 11 archive, use native x64 **real PE smoke** gate on each rebuild. Fail before FEX/Android if `kernel32` cannot load.
2. For FEX, verify direct binfmt x64 true and Wine **multiprocess** kernel32 startup on Linux ARM64 with source-pinned ELF, including access/signal diagnostics; do not silently substitute older Wine runtime in final KERNIX.
3. Only when Win64 PE executes under FEX Linux may the Android Bionic guest-process layer be adapted. It must handle x86 Linux syscalls, guest TLS and virtual memory rights at scale, not copy Linux ELF into Android `jniLibs` as native ARM64.
4. After Wine Win64 PE on Android, connect actual DXVK D3D11 to Vulkan WSI/Surface to render and present a triangle, followed by selected CarX Street user files and measurable frames.

**No Android APK released for R3C16**. Prior signed Android R3C15 versionCode22 remains latest device-validated milestone. The Wine source study does not mean the CarX native ARM64 port project has been accomplished; it is a Windows runtime integration task.
