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

## G0 original ELF/ld-linux/libc immutable guest source table (2026-11-05)

**Functional new source:** `android-host/kernix_g0_original_guest_snapshot_table.h`.
The runtime boundary now has a deliberately narrow guest file-descriptor
3/4/5 table for the exact SHA256-pinned original x86 Linux main,
`ld-linux-x86-64.so.2` and `libc.so.6`. This is **not** an unrestricted
filesystem or a guest `openat()` implementation.

- The production entry `MountVerifiedAppPrivateOriginalRoot(rootfd)`
  calls the existing G2-E preflight directly, requiring an actual private
  root, no-follow original path resolution, exact pinned size/SHA256,
  verified ELF closure and three original read-only snapshots.
- Copies those sources to **table-owned, mprotect(PROT_READ) anonymous
  memory**. The original root file descriptors and preflight memory
  can be released before any guest reads, preventing a later mutable
  disk-file edit from changing the guest's source bytes during execution.
- Interprets authenticated x86 guest `read(0)`, `pread64(17)`, and
  `close(3)` via virtual descriptors 3, 4, 5 and guest-writable VM
  attestation. Limits each operation to 4096 bytes; validates the full
  requested guest destination; tracks sequential read cursors; pread
  preserves cursor; EOF and closure work without host syscalls.
- Rejects unsupported guest `openat`, external file descriptors,
  out-of-bounds offsets, read-only or unverified destination memory
  and stale/forged syscall provenance. No guest path, root privilege,
  host FD pass-through, RWX or game folder access.

**Verification scope:** `tests/kernix_g0_original_guest_snapshot_table_test.cpp`
uses a **test-only synthetic** three-file constructor compiled only
under `KERNIX_G0_SNAPSHOT_TABLE_UNIT_TEST_ONLY` to exercise byte
copying, tamper isolation, cursor, EOF, Linux ABI register order and
malicious/invalid accesses. A separate native/Linux and Android/Bionic
compile gate runs in the existing G0 workflow. The source-specific,
SHA-attested production mount of the real three pinned ELF bytes has
**not** run end-to-end in FEX or on the physical Android device.

**Next executable handoff:** Attach the table to a genuine original FEX
`CpuStateFrame` syscall callback, then execute the dynamic guest
`PT_INTERP` entry with original loader relocations, TLS and remaining
syscalls. **Do not** issue a new G0 phone APK just to increase a counter:
only package once a new complete functional guest milestone is met.

## Actual original three guest ELF files mounted on Linux ARM64 — PASS

Source-specific `MountVerifiedAppPrivateOriginalRoot` now has a successful
native ARM64 gate with **the original real, SHA256-pinned x86_64 main,
ld-linux and glibc files**, not a synthetic guest file. It reproduced
the exact files from GitHub source-proven artifact 41846530666,
verified all three full SHA256 and ELF headers, placed them in a
0700 app-private-style owned directory with 0400 files, and called
the production verifier to build independently held PROT_READ
anonymous snapshots for guest fd3/4/5.

The Linux ARM64 run executed the native guest-vfile `read`,
`pread64` (independent cursor) and `close` operations on all three
actual pinned ELFs and negative permission/path checks. The separate
**Android/Bionic ARM64 cross-compile** used the exact same
implementation. Both jobs PASSED at
[CI #42075931685](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42075931685).

Evidence:
`evidence/g0-original-verified-x86-guest-triad-immutable-table-linux-arm64-and-bionic-compile-pass-20261105.json`.

**Truth boundary:** these are native Linux/Android build tests with
authenticated **synthetic x86 syscall register states**. No original FEX
guest `read`, `pread64` or `close` was actually executed by an x86
guest in this gate; no Android phone test or original glibc/ldso
execution is claimed. The earlier separate on-phone fixed ELF
`write`+`getpid` PASS remains valid.

**Next accepted gate:** wire the source-verified immutable file table
to authentic *live* FEX CpuStateFrame callbacks and a real
`PT_INTERP` guest loader path with FS/TCB/TLS, relocations/IFUNC,
required guest mmap/arch_prctl/futex/signal handling and real guest
`exit`; only claim dynamic glibc once its marker comes from original
guest libc and exit code is observed on Android. Do not issue another
standalone instruction/frame-count-only APK.
