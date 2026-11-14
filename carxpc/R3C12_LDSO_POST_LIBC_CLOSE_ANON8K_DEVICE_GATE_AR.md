# CarX PC Runtime R3-C12 — GNU ld.so anonymous 8KiB after libc close

## Evidence from REDMAGIC NX809J
Input: `CarX_PC_R3C_Diagnostics (12).json`, Android SDK36 / arm64-v8a.
- R3-C11 bounded gate `success=true`, `exit_code=117` within 45 s.
- Original FEX x86 guest libc opened, read/pread/fstat, mapped 5 original ELF portions including zero BSS; virtual `close(3)` of guest fd100 returned zero with mapped RX/RO/RW/BSS preserved.
- First unsupported syscall after close: `mmap(9)`, RIP=0x801025d2a, `addr=0, len=0x2000, prot=0x3, flags=0x22, fd=-1, offset=0`.
- Not proof of full dynamic loader, glibc initialization, Wine, DXVK or CarX game boot.

## R3-C12 scope
Source already has independently guarded `KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY` in KERNIX original loader continuation source.
Do **not** alter original x86 GNU guest ELF or the pinned upstream FEXCore SHA.

This gate must prove:
1. Same original guest x86 syscall request; 8192-byte anonymous, zero initialized, guest-owned VMA, 4KiB pages, actual RW pages in Bionic (no W+X).
2. No forwarded guest fd, host untrusted syscall or host path; all earlier libc mappings and original zero BSS preserved after guest fd100 close.
3. On-device authentic marker `KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_POST_LIBC_CLOSE_ANONYMOUS_RW_8K_OWNED_ZERO_SOURCE_VM_PASS`, *after* close3, *before* first subsequent unsupported syscall.
4. Bounded stop `exit_code=117` (unless the kernel reports a real error), report contains following syscall number and register arguments.
5. Signed `com.r4.carxpc`, versionCode19 update existing installation; run test button 06 only and export diagnostics JSON.

Do not reclassify a compile pass or a source-only marker as an Android runtime pass. `full_dynamic_interpreter_complete`, `guest_glibc_initialized`, `wine_executed`, `carx_game_boot_proven` remain false until separately proven.
