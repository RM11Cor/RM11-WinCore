# G0 exact real GNU x86 ELF on original FEX / Linux ARM64

Uses the SAME existing Android `kernix_fexcore_elf64_exec_probe.cpp`
with an explicit Linux ARM64 CI-only define, not a second implementation.
Authentic GNU x86_64 assembler+linker rebuild the original immutable
`kernix_elf64_guest_write_getpid.S` ELF64 fixture. Hash and strict opcode
audits run before use. The original FEX source is Git SHA-pinned.

The real FEX JIT invokes guest x86 Linux `write` from its actual ELF
read-only message pointer and `getpid`; each syscall is decoded
through the source-pinned C1/C2 FEX CpuStateFrame mapping and dispatched
by the shared G0 layer. Acceptance requires exact actual stdout bytes,
both FEX callbacks and final PID + bytecount RAX witness after HLT.

Scope: fixed glibc-free x86 ELF on Ubuntu ARM64. No guest `exit`
syscall yet; HLT remains bounded test stop. NOT an Android phone
execution, NOT the original `ld-linux`+glibc whole dynamic process,
NOT Wine/Proton/game.

## Failure diagnosis and conservative low-canonical host VM fix (2026-11-05)

The ARM64 CI run `42068499021` built original FEXCore and the exact GNU x86 ELF,
then invoked a **real** FEX SYSCALL but stopped with
`KERNIX_G0_ACTUAL_FEX_CPUSTATE_GUEST_STACK_OR_ABI_REJECTED`.
This was an ABI-boundary rejection, not a FEX compiler failure. The initial
`loadFixedGuestELF` and guest stack used native `mmap(nullptr)`, which on
Linux ARM64 can select a host VA **outside** x86's low 47-bit canonical user
address range. C1 correctly rejects such `RIP`/`RSP` pointers.

Fix: use non-fixed, documented low x86 canonical address **hints** for both
native-owned fixture ELF and guest stack; validate the actual kernel-returned
mappings before allowing original FEX execution. Keep every C1/C2 canonical
pointer/stack check; never bypass provenance or translate a fake result.
Additional structured boolean diagnostics distinguish RIP range, stack range,
RSP bounds, syscall next RIP and register match if the failure persists.
The regression test also validates non-fixed low-hint ELF allocation on
the Linux host. This is a candidate fix pending full end-to-end run.
