# KERNIX G0 authentic FEX x86 guest mmap / munmap, native VM and device gates

## Confirmed completed functional results — 2026-11-05

**Physical Android screen PASS (previous subsystem):**
\`org.kernix.g0preaddevice\` user-screenshot fields show actual original FEX
x86 guest \`pread64(17)\` loading 64 bytes from source-SHA-pinned original
\`ld-linux-x86-64.so.2\`, and original guest x86 \`movzbl\` loading
\`0x7f\` from the returned guest RW memory. Source:
\`evidence/g0-original-fex-pread-source-ldso-android-device-screenshot-pass-20261105.json\`.
This is a bounded guest ELF read, not executing original ld-linux instructions.

**Native guest VM allocator + syscall ABI PASS:**
\`android-host/kernix_g0_guest_owned_anonymous_vm_kernel.h\` and
\`tests/kernix_g0_guest_owned_anonymous_vm_kernel_test.cpp\`
were built on genuine Linux ARM64, made real owner-held native anonymous
RW mappings, stored/loaded bytes and exact owner-verified unmapping,
rejected all forged trap provenance, guest file-backed mappings, any
\`MAP_FIXED\`, guest PROT_EXEC, wrong address/length and arbitrary
\`mprotect\`, \`openat\`, etc. Android/Bionic ARM64 cross-compilation also
passed, [CI #42084831961](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42084831961).
A production mapping is allocated by the native kernel with **advisory
guest-canonical address hints only**, NEVER MAP_FIXED. At most eight
simultaneous mappings, 2 MiB per request, 8 MiB requested total.

**Actual source-pinned FEX guest mmap -> guest store/load -> munmap
on Linux ARM64 PASS:** The genuine independently GNU-as assembled x86_64
test program
\`android-guest/kernix_g0_original_fex_real_guest_mmap_munmap.S\`
was run by unmodified original FEXCore (pinned source commit
\`02e24ca5c01ed0c864466ed573db347336f70170\`).
The real original FEX \`CpuStateFrame\` callback decoded both guest
Linux x86 syscall numbers (\`mmap(9)\`, \`munmap(11)\`) with fourth argument
in **R10**, allocated real host-owner-held guest RW memory, returned the
x86 guest VA; actual guest instructions stored and reloaded \`0x5a\`,
then original x86 \`munmap(11)\` released the exact owned VMA.
The guest ended via bounded HLT, not a full Linux process guest exit.
[**CI #42085473700 PASS**](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42085473700).
Machine evidence:
\`evidence/g0-original-fex-x86-guest-mmap-store-load-munmap-linux-arm64-actual-execution-pass-20261105.json\`.

**16K Android host-page safety:** Without a tested x86 4K software
subpage protection model, never expose 12K of additional writable native
data by fulfilling a 4K guest \`mmap\` on a 16K host. Requests must match
host-page multiples, otherwise return guest Linux \`-ENOSYS\`. See
\`NativePageGuestLengthSafe\` compile-time regression checks. This is a
safe compatibility gate, not a claim of all 16K host subpage support.

## Current remaining gates

- Android ARM64 *source-pinned original FEX mmap bridge* compiled and
  linked against \`libFEXCore.so\`: separate Bionic native CI required;
  a native \`libc.so\` dependency check is not device execution.
- **Real REDMAGIC Android phone execution of the new mmap bridge:** not
  proven. A new isolated signed APK is only justified after complete
  source/native integrity checks, distinct app ID, bounded child process
  and user-initiated operation. Do not replace KERNIX v0.27 or games.
- Original real Linux dynamic loader **whole-process runtime**:
  source-mapped \`PT_LOAD\`, host/guest guest-map ownership, real
  \`PT_INTERP\` FEX RIP/RSP with genuine AUXV, guest TLS/TCB/FS,
  \`arch_prctl\`, \`mmap/mprotect/munmap\` including real ELF backing,
  relocations/IFUNC/RELRO, dynamic symbol versioning, controlled
  errors/signals/guest \`exit_group\` and cleanup. None of these are
  implied by the two successful bounded syscalls.
- No real Wine/Proton Windows PE, game rendering, DXVK/VKD3D runtime,
  complete loader, original glibc startup, or all-games compatibility.

## Engineering decision

Keep **one guest syscall/memory subsystem** and reuse the pre-existing
C3-D7B native source-verified original ELF PT_LOAD ownership and C3-D7G
permission contracts; do not create a second incompatible PT_LOAD memory
loader. Preserve prior genuine 28-source-opcode and G1 bounded Vulkan
device passes, but do not increase probe opcode/frame counters as a
substitute for this whole-process guest runtime.

**Evidence classifications:** original FEX Linux ARM64 actual guest
execution PASS; native Android/Bionic build != phone execution; physical
screen PASS only for the separate earlier source-verified x86 \`pread64\`
subsystem.


## UPDATE: Android signed independent FEX x86 mmap phone trial shipped (PHONE PENDING)

November 5, 2026. Source-pinned original FEXCore and the GNU-as
x86-64 mmap(9) -> native guest-RW page -> x86 store/load 0x5A ->
munmap(11) FEX child cross-compiled and linked for Android/Bionic ARM64:
[original source FEX CI #42088103679](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42088103679)
PASS, native runner/source SHA256 and ELF interpreter checked.

Built a **separate** Android app:
- Package: \`org.kernix.g0mmapdevice\`, no external storage permissions.
- APK: \`KERNIX-G0-Original-FEX-Real-X86-MMAP-Android-Signed.apk\`.
- Immutable release: \`kernix-g0-original-fex-real-mmap-android-59aa9081\`.
- SHA256: \`ae54ae528c4fa65b2d0f80b214614c3618a0564f28cae658ee23d8020a407676\`.
- [Signed Android release CI #42088742328](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42088742328)
  PASS. Verified original project signing cert SHA256,
  \`libFEXCore.so\`, native guest child, genuine GNU x86 guest
  machine-code source, asset digests, Bionic dependencies and no
  unbundled libc++.
- A user-initiated, bounded native child runs after SHA256 asset checks,
  with output cap and 24s watchdog. On host native page size 16KB,
  the 4KB guest mmap fails closed rather than exposing a host subpage.
- **Physical Android phone execution of this new syscall bridge is NOT
  evidenced yet.** Only a phone result can advance this gate:
  \`G0_ANDROID_FEX_REAL_GUEST_MMAP_MUNMAP_PASS=1\`,
  \`GUEST_BYTE_5A_STORED_AND_LOADED=1\`,
  \`NATIVE_PAGE_RELEASED=1\`, \`EXIT_CODE=0\`.
- The prior separate original ld-linux \`pread64\` photo PASS still
  stands. This new APK does NOT run original ld-linux or glibc
  instructions, Wine/Proton/Windows games, or the Vulkan renderer.

Next after **actual** device evidence: integrate the **existing**
source-pinned C3-D7B PT_LOAD-owned ELF mappings / C3-D7G page policies
and real guarded Linux x86 initial AUXV stack with a single FEX guest
process runtime, followed by validated TLS/FS, relocations/IFUNC,
and all required syscalls, full ld-linux entry/exit and cleanup.


## 2026-11-05 — physical Android guest mmap/store/load/munmap PASS (gate CLOSED)

The separate, original-certificate-signed
\`org.kernix.g0mmapdevice\` APK was user-tested on an Android phone.
The user-supplied app screenshot showed the exact native child markers,
plus all of these fields:

\`\`\`text
G0_ANDROID_FEX_REAL_GUEST_MMAP_MUNMAP_PASS=1
ORIGINAL_FEX_X86_GUEST_MMAP_EXECUTED=1
GUEST_BYTE_5A_STORED_AND_LOADED=1
ORIGINAL_FEX_X86_GUEST_MUNMAP_EXECUTED=1
NATIVE_PAGE_RELEASED=1
GUEST_DYNAMIC_LDSO_EXECUTED=0
GUEST_GLIBC_INITIALIZED=0
WINE_PROTON_GAME_EXECUTED=0
EXIT_CODE=0
\`\`\`

- Immutable signed APK: \`kernix-g0-original-fex-real-mmap-android-59aa9081\`.
- APK SHA256 \`ae54ae528c4fa65b2d0f80b214614c3618a0564f28cae658ee23d8020a407676\`.
- Original-FEX Bionic compile PASS #42088103679, signature release CI
  PASS #42088742328, and **physical Android device PASS by screenshot**.
- Machine-readable screenshot observation:
  \`evidence/g0-original-fex-real-x86-mmap-store-load-munmap-android-physical-screen-pass-20261105.json\`.
- Original FEX actually executed real x86 Linux
  \`mmap(9)\` -> store/load \`0x5a\` -> \`munmap(11)\` and the Android
  child exited 0. Proof is bounded, not a whole guest Linux process.
- Device screenshot is user-submitted observational evidence, not a
  cryptographic device attestation.

**The bounded heap syscall gate is now CLOSED.** Do not revisit the
individual syscall/opcode counter or repeat simple native-memory tests
without an actual regression. The separate original GNU x86
\`pread64\` source-backed ELF read screenshot gate is already CLOSED.

### Single next functional integration gate: original ELF interpreter process

1. Reuse **C3D7B** SHA256-pinned private original main/ld-linux/libc
   \`PT_LOAD\` pages in host-owned source-validated kernel-selected guest
   VAs, and **C3D7G** exact W^X per-module permissions, non-PT_LOAD
   holes and stack guard. There must be **one owner** of these mappings:
   do not create a parallel overlapping guest ELF loader.
2. Reuse the real rebased Linux x86 initial stack
   \`argc, argv, envp, AUXV\` (AT_PHDR/AT_BASE/AT_ENTRY/AT_RANDOM and
   user IDs) with the FEX RIP set to the **original source-verified
   \`PT_INTERP\` entry**, not the executable's main entry.
3. Join the **already phone-proven** guest \`pread64\`, \`mmap\` and
   \`munmap\` authenticated FEX CpuStateFrame adapters in that **same
   owner-held guest runtime**. Deny unknown syscalls. Add only the
   guest Linux syscalls the original interpreter demonstrably needs,
   preserve x86 argument ABI (especially R10), no unrestricted host
   syscall forwarding, and do not allow MAP_FIXED to overwrite
   host memory.
4. Implement actual guest FS/TCB/TLS and \`arch_prctl\` handling without
   changing Android host TLS; apply original ELF relocations and
   RELRO/IFUNC with explicit ownership and permission transitions.
   Maintain separate 4K guest versus 16K host subpage protections.
5. Use bounded watchdog/process isolation and verified guest exit/
   signal cleanup. First acceptance must be source-authentic original
   dynamic \`ld-linux\` instruction execution, no synthetic replacement
   code at interpreter RIP; full startup later requires source-authentic
   libc and program handoff. Do not claim a working game from the
   mere first instruction.
6. Build Linux ARM64 original FEX functional integration before a
   separately signed Android trial. Require real device screenshot
   for any Android runtime PASS. Protect existing KERNIX v0.27
   and user game data throughout.

**No new APK is necessary for this phone-proven bounded mmap gate.**
The next APK, when ready, belongs to the **integrated original
PT_INTERP loader runtime**, not another one-syscall diagnostic.
