# CarX R3-C19 — Win64/Wine guest ELF source preflight and Android gate

**Verified source milestone:** GitHub Actions R3C19 test https://github.com/RM11Cor/RM11-WinCore/actions/runs/43605765603 passed, including full original archive streaming SHA-256, real ELF64 Wine layout, DT_NEEDED and kernel32 PE64 and five negative corruption controls. This is a source/host test, not on-device or Wine-execution proof.

## Real source bytes (not invented)
Original Ubuntu Noble Wine x86_64 guest rootfs source archive SHA-256:
`86fafa2f5072aa2c47b7025ca591d945007584ecda37ae92eee208a95283f4b0`
- `/usr/lib/wine/wine64` exact ELF x86-64 PIE hash: `f86e46a5fe46e92783ac42fcf03a84f0287c2fbc7d620a5521b3341b1a032e03`.
- Wine actual PT_INTERP: `/lib64/ld-linux-x86-64.so.2`. SHA-256 of resolved linker ELF: `1d7133d7b9f94465978b2ae8d21ca3751c8dfaaecaa2d462aeaf1ec50e5c3a90`.
- Original `wine64` PT_LOAD count: 4; original linker PT_LOAD count: 4.
- Wine64 immediate DT_NEEDED is `libc.so.6`, present in the guest filesystem. This does **not** prove closure of all transitive libraries or Wine startup.
- Wine Windows-built `kernel32.dll` PE64 SHA-256 `b4d6464d6c56d08a939564adcafa59822a3957df5ab13de24edf29de4795f5e5`.
- Source provenance: https://github.com/RM11Cor/RM11-WinCore/actions/runs/43605206286

## R3C19 Android implementation
`carxpc/r3c19/android/WineGuestElfPreflight.java`:
- Strict app-private rootfs receipt and path resolution with symlinks confined to app root; no device root privileges.
- Read-only ELF64 header, x86_64 architecture, program headers, PT_INTERP, PT_LOAD bounds and W/X, stack-executable rejection, DT_DYNAMIC, DT_NEEDED backed by PT_LOAD, correct Linux guest interpreter.
- Verifies original Wine64 / loader / kernel32 SHA-256 independently; checks kernel32 MZ/PE32+/AMD64 and optional header.
- Rejects host ARM64 guest spoof, W+X load, PE MZ forgery, forged rootfs receipt, host-symlink escape. Five mutated-binary negative controls on original extracted rootfs in Linux CI.
- Android code integrates as new button08 and JSON `wine_elf_preflight`, while preserving button07 Wine rootfs import and original GNU 12/12 test06.
- Reports `android_wine_executed=false`, `wine64_linux_guest_process_executed=false`, `win64_pe_android_executed=false`, `carx_game_boot_proven=false`. Real on-device metadata preflight requires user's phone test.

## Next R3C20 native execution boundary
1. Android-native FEX host guest-process entrypoint that uses rootfs binary as guest **data**, not a Bionic `execve` of Linux x86_64 code. Reuse original FEX SHA and Android guest-owned virtual memory, FS guest TLS, segment protection and syscall boundaries from original R3C15/KERNIX.
2. Build generic (not fixed 3 ELF) x86_64 guest dynamic loader/syscall ABI including guest `fork/clone/execve` and Wine/wineserver subprocess semantics with owned guest FD/path mapping, no host pointer leak or host TLS override.
3. First real REDMAGIC 11 Pro Android16 run: `wine --version` from genuine Wine64 user-private rootfs, with process startup/exit evidence. Then Win64 PE VM/TLS/WriteFile real marker and exit0, and only after this D3D11/DXVK Vulkan triangle and CarX main executable.
4. Do not claim Wine/Windows/CarX run from source-only APK build or Linux ARM64 FEX control. Don't repeat the accepted GNU 12/12 regressions as manual phone tests unnecessarily.
