# G0: one original FEX process with SHA-locked ELF PT_LOAD, AUXV and x86 mmap/munmap

## Why this gate exists

The user's Android phone already proved two separate source-backed,
bounded original FEX Linux x86 guest syscall pathways:

- Original \`ld-linux-x86-64.so.2\` bytes read as data through authentic
  x86 \`pread64\`, consumed by a genuine x86 byte-load instruction,
  Android screenshot PASS.
- Authentic x86 \`mmap(9)\`, guest memory store/load \`0x5a\`,
  \`munmap(11)\` of the owner-held native page, Android screenshot PASS.

Neither proves both syscalls and **original executable page/initial
Linux process stack ownership** coexist safely inside a single native
FEX process. A standalone syscall probe cannot be treated as the
original ELF guest runtime.

## This integrated gate

This new test reuses the existing source-verified C3-D7B
\`NativeChosenPIEGuestLayout\` and C3-D7G original \`PT_LOAD\` W^X
permission implementation, **not** a second ELF loader. One real
upstream FEXCore (source commit
\`02e24ca5c01ed0c864466ed573db347336f70170\`) context then:

1. Opens only an exact verified original x86 main, ld-linux and libc
   private root from trusted GH Actions artifact run \`41846530666\`.
   Exact file sizes and SHA256 hashes are required before memory
   staging.
2. Stages three real ET_DYN original ELF \`PT_LOAD\` images at
   kernel-chosen canonical guest/native VMAs, plus a genuine rebased
   \`argc=1\` Linux x86 initial \`AUXV\` stack: **four owned windows**.
3. Applies native per-original-page RX/RW/RO/PROT_NONE via C3-D7G,
   denies every W+X page and the stack guard page. Explicit
   native-page requirement: 4096 bytes; 16K host pages fail closed
   until a distinct source-authenticated shadow-page implementation.
4. Creates a separately owned RX page containing an independently
   assembled GNU x86 guest integration fixture. **This fixture is NOT
   original ld-linux source instructions.** FEX starts at this
   fixture's RIP; original PT_INTERP/ld-linux RIP is checked but
   deliberately never entered.
5. Actual x86 guest \`MOV\` loads a word from **the verified main ELF
   PT_LOAD** into R12 and reads \`argc\` from the **actual initial
   guest stack RSP** into R14.
6. The very same original FEX \`CpuStateFrame\` invokes genuine x86
   Linux \`mmap(9)\` with flags sourced from the R10 register and
   strict x86 call ABI. A native owner-held RW-only heap page is
   returned, never a raw forwarded guest syscall.
7. Genuine x86 instructions store the source main-ELF word into the
   allocated guest heap and load it back into R15. The same FEX
   context invokes \`munmap(11)\` and safely releases exactly this
   anonymous heap page.
8. An attempted in-process guest \`munmap\` of the original loader
   executable mapping MUST return guest \`-EINVAL\` and leave all four
   original ELF/stack windows intact. The original source file-backed
   PT_LOAD segments must remain byte-for-byte equal to the
   source-pinned images after FEX exits.
9. FEX context is released before source-root memory windows.
   Final acceptance requires zero anonymous heap pages, release
   of **all four source-owned windows**, bounded host child exit code
   zero and no original dynamic-linker execution.

## Test implementation

- \`android-guest/kernix_g0_original_elf_owned_fex_process_integration.S\`
- \`android-host/tests/kernix_g0_original_elf_fex_combined_process_arm64.cpp\`
- \`.github/workflows/kernix-g0-original-fex-elf-auxv-heap-integrated-arm64.yml\`

CI: https://github.com/RM11Cor/RM11-WinCore/actions/runs/42090766519

At the time this document was authored, CI was **IN PROGRESS**.
Do not mark this gate PASS until exact source original FEX/native
Linux ARM64 execution and the final scripted marker validation both
finish successfully. A compiler's PASS alone is not an execution PASS.

## Not proved here

- No original \`PT_INTERP\` / \`ld-linux\` x86 instruction execution in
  this new combined test. The earlier independent 28 original
  instruction bounded gate does not constitute full loader startup.
- No actual original glibc/TLS/TCB/FS start, relocations/IFUNC,
  versioned symbol lookup, runtime \`mprotect\`/RELRO or x86 guest
  \`exit_group\` handling.
- No external game paths, Wine/Proton, Windows PE, graphics,
  DXVK/VKD3D or any playable PC game.
- No Android-device execution of **this combined** source-backed
  process; a Linux ARM64 CI PASS would be separate from phone proof.
  Older Android device successes for standalone syscalls remain
  valid, but don't imply integrated-process Android support.

## Following gate (only after CI functional PASS)

Cross-link the *same* runtime source and upstream FEX for Android
ARM64/Bionic while preserving source hashes, private original guest
root, original certificate, fixed package isolation, watchdog and
all guest-vs-native protections. A single user-initiated on-device
combined proof should precede any attempt to move FEX's RIP to
the real source-verified \`ld-linux\` interpreter entry.

Original \`ld-linux\` full startup will require a virtual guest kernel
capable of serving genuinely requested \`mmap\`, \`mprotect\`,
\`arch_prctl\`/FS TLS, file mapping and symbol relocation under a single
ownership model. Do not fake a loader PASS from a bounded fixture.

Stable KERNIX v0.27, prefixes and the user's installed games must
remain unchanged.
