# KERNIX G0 physical Android ELF execution PASS — 2026-11-05

## Device-observed promotion

**PASS within the exact scoped test**: the user submitted Android phone
screenshot `116584.jpg` showing a separately installed, signed
`org.kernix.g0elfdevice` APK displaying:

- `G0_ANDROID_ELF_DEVICE_PASS=1`
- `REAL_GNU_X86_ELF_FEX_EXEC=1`
- `REAL_GUEST_WRITE=1`, `REAL_GUEST_GETPID=1`
- `EXIT_CODE=0`
- `KERNIX_X86_REGISTER_RAX=25288`
- original GNU x86_64 ELF PT_LOAD mapping with W^X, real FEXCore
  thread/context creation, the actual guest message, authentic
  `write` / `getpid` bridge callback markers and native child
  completion.

This is **physical Android user-screenshot observation**, not a signed
hardware attestation. Package asset and APK hashes, CI source lineage
and pinned original FEX source separately verified in:

- GitHub Android NDK compile run 42070029837 (source only)
- GitHub Linux ARM64 real original FEX ELF execution run 42070029933
- GitHub original-signed Android APK release build run 42072051825
- Immutable APK prerelease
  `kernix-g0-real-elf-android-64827af0`
- Machine-readable evidence
  `evidence/g0-real-gnu-x86-elf-fex-android-device-screenshot-pass-20261105.json`

**Clear distinction:** fixed, independently GNU-as/ld assembled
relocation-free glibc-free x86_64 ELF **actually executed via FEX on
Android** and its real guest `write`/`getpid` dispatched and verified.
A bounded guest HLT ended execution and the native process returned 0.
The x86 Linux **exit syscall** was not invoked by this guest, and a
full `PT_INTERP` / `ld-linux-x86-64.so.2` / `libc.so.6` process
has **not** completed startup on Android. Wine/Proton/Windows PE and
games remain **NOT EXECUTED**.

## Next functional integration gate — source-pinned ELF files, not opcodes

Do not make longer numbered 29/30/31-opcode probes nor re-test
the successful tiny ELF on the phone. Next guest process milestone:

1. Reuse the three SHA256-pinned original Linux x86_64 files
   (main, authentic `ld-linux`, authentic glibc) under an owner-only,
   `O_NOFOLLOW` app-private root. No arbitrary paths, root or external
   game storage. Keep the fixed G0 signed APK independent of stable
   KERNIX v0.27.
2. Implement an authenticated guest file table and bounded Linux
   guest syscall surface that returns *real* bytes to genuine guest
   VM, preserving x86 ABI register order and W^X. A new
   `pread64(3, guest_writable_ptr, n, off)` primitive is included in
   `android-host/kernix_g0_guest_syscall_dispatch.h`.
   - Requires an owner-held, source-SHA256-verified, `O_NOFOLLOW`
     read-only regular host FD with exact size, maps **only guest FD 3**,
     at most 4096 bytes per call, writes only inside an attested
     guest-writable region, uses actual POSIX pread, preserves file
     cursor, and returns x86 Linux -errno on failure.
   - Linux POSIX live-file + guest RW VM/negative boundary suite PASS
     and Android/Bionic ARM64 cross-compile PASS in CI
     **42073972812**. This is **not FEX execution of pread** and **not
     phone proof of dynamic ldso**.
   - Keep `openat`, `mmap`, `mprotect`, `futex`, signals and other
     unresolved Linux guest APIs denied (`-ENOSYS`) until ownership
     mapping and full guest syscall contracts exist.
3. Build a genuinely runnable x86_64 initial process stack / auxv
   from original ELF `PT_INTERP`, bring up authentic guest FS/TCB,
   relocations/IFUNC and glibc, and emit a marker from original guest
   libc before using a real Linux exit syscall. Require full child
   result on Android and safe release of guest mappings.
4. Only after dynamic Linux guest process PASS, integrate Wine/Proton
   into the Android host, with actual Windows PE execution, then use
   the previously verified bounded G1 Vulkan WSI groundwork for
   DXVK graphics. No claims of a production graphics backend or game.

## Regression and release controls

- Preserve G0 `write`/`getpid` physical on-device pass and the 4/48/180
  G1 bounded WSI passes. Do not extrapolate renderer FPS or game support.
- Existing G0 pread dispatcher is an **additive** C++ overload/default
  argument; previously proven FEX `write`/`getpid` calls remain
  unchanged.
- No new APK was published for the pread functionality. Its tests are
  source/native Linux and Bionic compile only.
- No game files or existing KERNIX prefixes were changed.
