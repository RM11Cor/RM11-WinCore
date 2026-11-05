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
