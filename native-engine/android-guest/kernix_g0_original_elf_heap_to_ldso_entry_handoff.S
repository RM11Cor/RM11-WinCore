# SPDX-License-Identifier: MIT
# Same original FEX guest session: exact original x86 ELF PT_LOAD/AUXV reads,
# mmap/store/load/munmap, then INDIRECT HANDOFF to SOURCE-AUTHENTIC original
# PT_INTERP ld-linux entry. Only the FIRST unchanged original MOV executes;
# the following original CALL is replaced in owned VM with bounded HLT.
# Source ELF files never edited. This is not full dynamic linker startup.
.text
.globl _start
_start:
    mov (%r13), %r12
    mov (%rsp), %r14
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    mov %rax, %rbx
    mov %r12, (%rbx)
    mov (%rbx), %r15
    mov $11, %eax
    mov %rbx, %rdi
    mov $4096, %esi
    syscall
    jmp *%rbp
    hlt
