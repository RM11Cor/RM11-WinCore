# CarX PC Runtime R3-C14 — original GNU ldso set_tid_address(218) on guest TLS

## Accepted Android REDMAGIC report (14)
- Guest: original unmodified GNU x86_64 ld-linux from SHA-pinned triad, FEX upstream `02e24ca5c01ed0c864466ed573db347336f70170`, ARM64 Android SDK36.
- All source verified libc RO/RX/RO/RW/BSS maps, synthetic fd100 virtual close3, post-close anonymous guest RW zero 8KiB and original `arch_prctl(158, ARCH_SET_FS=0x1002)` proved on-device with exit117.
- Guest FSBase `0x7a740070c0`; next original x86 `set_tid_address(218)` RIP `0x801014f30`, requested guest pointer `0x7a74007390` = FSBase + 0x2d0.
- No evidence yet of full guest glibc initialization, Wine or CarX launch.

## Device acceptance gate
- Preserve all previous original source markers and fixed pinned ABI/ELF provenance. Use existing native `KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY` macro; no changes to guest loader code.
- Assert valid 4-byte pointer in guest-owned RW 8KiB TLS region and FEX guest FS unchanged.
- Authenticate exact guest `set_tid_address(218)`, register the guest clear-child-tid address without modifying the memory word at registration or calling host Linux/Android set_tid_address; diagnostic return guest TID=1 only (not general threading support).
- Require hardware marker `KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_SET_TID_ADDRESS218_AFTER_ARCH_SET_FS_CLEAR_CHILD_TID_POINTER_IN_OWNED_GUEST_8K_TLS_NO_HOST_TID_SYSCALL_PASS ptr=... tid=1` after FS marker.
- Stop on NEXT unsupported original x86 syscall exit117; record x86 syscall number + RIP/args. Build-only status must not become on-device success.
- Build signed `com.r4.carxpc` versionCode21 stable upgrade. Run test 06 and export diagnostics.

All `full_dynamic_interpreter_complete`, `guest_glibc_initialized`, `wine_executed`, `carx_game_boot_proven` stay false until separately demonstrated.
