# SPDX-License-Identifier: MIT
# Bounded explicit x86 guest RELA writer. This IS NOT glibc/ld-linux's
# relocation implementation and MUST NOT be reported as such.
# Host source preflight authorizes R8 = pointer to one original unchanged
# main ELF Elf64_Rela with r_info == R_X86_64_RELATIVE (symbol 0).
# R13 = original main ELF load bias (source-verified equal chosen image VA).
# Only the target from source r_offset in original owned RW PT_LOAD may change.
# This is executed in the SAME original FEX context as real x86 mmap,
# source-authentic ld-linux MOV/CALL and bounded callee RW/stack writes.
.text
.globl _start
_start:
    mov (%r13), %r12
    mov (%rsp), %r14
    mov %r8, %r15
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
    # Genuine x86 instructions operate on an exact SHA-verified
    # source ELF RELATIVE record (not a hardcoded synthetic addend).
    mov 8(%r15), %rax
    cmp $8, %rax
    jne .Lreject
    mov (%r15), %r11
    add %r13, %r11
    mov 16(%r15), %rax
    add %r13, %rax
    mov %rax, (%r11)
    # Preserve original historical heap/ldso witness registers.
    mov (%rbx), %r15
    mov $11, %eax
    mov %rbx, %rdi
    mov $4096, %esi
    syscall
    jmp *%rbp
.Lreject:
    hlt
