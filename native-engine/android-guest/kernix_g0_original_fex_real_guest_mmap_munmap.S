# SPDX-License-Identifier: MIT
# Functional two-syscall Linux x86-64 guest heap allocation and release
# under original upstream FEXCore, not a dynamic ld-linux process.
.text
.globl _start
_start:
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    mov %rax, %rbx
    movb $0x5a, (%rbx)
    movzbl (%rbx), %r12d
    mov $11, %eax
    mov %rbx, %rdi
    mov $4096, %esi
    syscall
    hlt
