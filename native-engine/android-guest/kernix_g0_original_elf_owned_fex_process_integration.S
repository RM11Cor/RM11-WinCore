# SPDX-License-Identifier: MIT
# Integration fixture: actual original SHA256 ELF PT_LOAD and Linux initial
# stack reads in the SAME original FEXCore guest that performs the true
# Linux x86_64 mmap(9), guest RW byte store/load, and munmap(11).
# The instructions here are GNU-as test source, NOT original ld-linux code.
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
    hlt
