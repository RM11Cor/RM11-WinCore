# G0: source-original ld-linux first instruction after real FEX heap in the SAME guest session

## Proven starting point

2026-11-05: Android user screenshot verified the standalone
\`org.kernix.g0integrateddevice\` application, which runs authentic
GNU x86 guest reads from the verified original main ELF, real
Linux x86 AUXV initial stack, and mmap(9) -> store/load ->
munmap(11) inside one source-original FEXCore guest context.
Exact observed fields and native marker order are preserved in:
\`evidence/g0-original-elf-auxv-fex-heap-android-physical-screen-pass-20261105.json\`.
The bounded combined process **PHONE PASS is CLOSED**; don't
retest the previous device gate unless a real regression is detected.

## Current next development boundary

The single next functional question is not whether a synthetic test
guest works (already proven). We need to show that after actual x86
memory syscalls, the **same original FEX context** can enter the
source-verified **PT_INTERP ld-linux e_entry** at original
kernel-selected, W^X-protected, source-backed ELF virtual address,
with the authentic Linux x86 initial \`argc/argv/envp/AUXV\` stack.

The first bounded handoff test here is intentionally narrower than
full ld-linux startup:

1. Reuse exact source SHA256 original main, ld-linux and libc images
   from run 41846530666, existing \`C3-D7B\` four owner-held VMAs and
   \`C3-D7G\` W^X permissions. No second ELF loader and no MAP_FIXED.
2. In one genuine upstream FEXCore 02e24ca5... context, source-assemble
   GNU x86 fixture that reads original main ELF and stack and performs
   real x86 \`mmap(9)\`, guest source byte copy/load and \`munmap(11)\`.
3. **Without leaving that FEX context**, branch to the **original**
   ELF source \`PT_INTERP\` entry RIP, preserving initial guest RSP.
4. Verify the original source bytes are exact \`48 89 e7 e8\`:
   the first authentic x86 instruction is \`mov %rsp,%rdi\`,
   the second authentic source instruction starts \`CALL rel32\`.
   Temporarily replace **only** byte #4 with a bounded HLT in the
   guest-owned executable mapping, using RW->RX transitions (never
   RWX). Original source files and immutable SHA256 snapshots are
   untouched; no synthetic instruction replaces the first MOV.
5. FEX must actually execute the original MOV and reach the HLT
   after the prior real mmap/syscall sequence, proving RDI equals the
   original initial RSP and RIP is the original entry+3 or +4.
6. Destroy FEX context, restore the exact original fourth byte,
   enforce RX, verify all original source \`PT_LOAD\` bytes against
   pinned file snapshots, release all native heap and ELF/stack VMAs.
7. Entire runtime remains host-page-size=4096 only. On 16 KiB hosts,
   no guest subpage-execute alias is granted: fail closed.

**No uncontrolled dynamic-linker startup or syscall forwarding is
permitted in this gate.** The following original CALL is not executed.
This does not prove original ld-linux relocations, TLS/FS, glibc, a
full Linux process, Wine/Proton, Vulkan or a PC game.

## Test implementation

- \`android-guest/kernix_g0_original_elf_heap_to_ldso_entry_handoff.S\`
- \`android-host/tests/kernix_g0_original_elf_heap_to_ldso_entry_handoff_arm64.cpp\`
- \`.github/workflows/kernix-g0-one-process-original-ldso-entry-after-heap-arm64.yml\`
- [CI #42094456275](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42094456275)

The Linux ARM64 functional run was **in progress** at the moment
this plan was committed. Do not call this new handoff PASS until the
precise native source proof and real original FEX user-x86 execution
steps conclude successfully; a green compiler step is insufficient.

## Gate after actual functional PASS

Cross-link the identical exact original pinned FEX+guest ELF runtime
to Android/Bionic ARM64, preserving deterministic source SHA256,
original KERNIX signing certificate, independent application package,
bounded child execution, and original-source license notices.
Only then request a single new phone screenshot. The **following**
functional gate will be controlled source-original entry -> genuine
CALL and loader function initialization, with real Linux x86 guest
file IO, TLS/FS, relocations and safe process exit as needed.
Avoid the historical loop of one arbitrary instruction test per
release; prefer real functional integration and an explicit bounded
kernel contract over opcode counters.

Never modify stable KERNIX v0.27, game paths or existing Wine prefixes.
