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
