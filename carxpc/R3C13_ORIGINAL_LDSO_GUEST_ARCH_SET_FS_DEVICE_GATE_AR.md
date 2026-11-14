# CarX PC Runtime R3-C13 — original GNU ld.so guest ARCH_SET_FS (TLS)

## REDMAGIC NX809J evidence from report (13)
- Android SDK 36, ARM64; R3-C12 bounded gate `success=true`, `exit_code=117`.
- Original x86 `libc` source maps and virtual fd100 close remain preserved.
- The original GNU ld.so `mmap(9)` after close allocates 8,192 bytes RW anonymous and zeroed, guest base `0x7ef34c1000`.
- Immediately afterward: original `arch_prctl` syscall 158, `operation=0x1002 (ARCH_SET_FS)`, `addr=0x7ef34c20c0`, `rip=0x80102013b`; address is exact +0x10c0 within 8KiB.
- The report does not prove full guest glibc initialization, Wine, DXVK or CarX launch.

## R3-C13 bounded gate
Use existing upstream source-authenticated `KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY` macro.
No original guest ELF rewrite, no host Bionic TLS mutation and no host `arch_prctl` call.

Device proof criteria:
1. Preserve all prior actual device markers and SHA-pinned original FEX, loader, libc, APK native libs.
2. Require original post-close `mmap(9)` 8KiB zero-filled RW VMA marker before original `arch_prctl(158,0x1002,FSBase)`.
3. Verify source-authenticated guest FSBase in the 8KiB owner VMA at offset 0x10c0, valid old FS provenance and unchanged GS, update FEX X86State `fs_cached`, return RAX=0.
4. Require marker `KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_PRCTL158_ARCH_SET_FS1002_OWNED_8K_TCB_PLUS_0x10c0_FEX_FS_CACHED_GUEST_ONLY_PASS fs=... NO_HOST_TLS`.
5. Exit 117 at first next original unsupported x86 syscall, report its authentic number/args. `success=true` only for R3-C13 bounded gate.
6. Signed APK `com.r4.carxpc` `versionCode=20`; only run test06, export diagnostic JSON.

`full_dynamic_interpreter_complete`, `guest_glibc_initialized`, `wine_executed`, `carx_game_boot_proven` must remain false until direct separate proofs.
