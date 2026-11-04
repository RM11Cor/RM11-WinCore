/*
 * KERNIX G2-C: actual x86-64 dynamic PIE guest entry stack/AUXV witness.
 * Linked with real PT_INTERP + DT_NEEDED libc.so.6, but FEX enters
 * THIS executable's _start directly. Not glibc/ld-linux execution!
 * Fixed argc=2, envc=1, exactly 14 prescribed AUXV entries.
 * No syscalls, no guest reads outside declared stack, no root.
 * SPDX-License-Identifier: MIT
 */
.text
.globl _start
.type _start, @function
_start:
    movq (%rsp), %rax
    cmpq $2, %rax
    jne .Lbad
    movq 8(%rsp), %rdi
    testq %rdi, %rdi
    je .Lbad
    cmpb $'/', (%rdi)
    jne .Lbad
    movq 16(%rsp), %rdi
    testq %rdi, %rdi
    je .Lbad
    cmpb $'-', (%rdi)
    jne .Lbad
    cmpq $0, 24(%rsp)
    jne .Lbad
    movq 32(%rsp), %rdi
    testq %rdi, %rdi
    je .Lbad
    cmpb $'L', (%rdi)
    jne .Lbad
    cmpq $0, 40(%rsp)
    jne .Lbad
    leaq 48(%rsp), %rsi
    cmpq $3, (%rsi)    /* AT_PHDR */
    jne .Lbad
    cmpq $4, 16(%rsi) /* AT_PHENT */
    jne .Lbad
    cmpq $5, 32(%rsi) /* AT_PHNUM */
    jne .Lbad
    cmpq $6, 48(%rsi) /* AT_PAGESZ */
    jne .Lbad
    cmpq $4096, 56(%rsi)
    jne .Lbad
    cmpq $7, 64(%rsi) /* AT_BASE */
    jne .Lbad
    movq 72(%rsi), %rdi
    testq %rdi, %rdi
    je .Lbad
    cmpq $9, 96(%rsi) /* AT_ENTRY */
    jne .Lbad
    leaq _start(%rip), %rax
    cmpq %rax, 104(%rsi)
    jne .Lbad
    cmpq $25, 192(%rsi) /* AT_RANDOM */
    jne .Lbad
    movq 200(%rsi), %rdi
    testq %rdi, %rdi
    je .Lbad
    cmpb $1, (%rdi)
    jne .Lbad
    cmpq $31, 208(%rsi) /* AT_EXECFN */
    jne .Lbad
    movq 216(%rsi), %rdi
    testq %rdi, %rdi
    je .Lbad
    cmpb $'/', (%rdi)
    jne .Lbad
    cmpq $0, 224(%rsi) /* AT_NULL */
    jne .Lbad
    movabsq $0x4b45524e49584732, %rax /* KERNIXG2 */
    hlt
.Lbad:
    xorl %eax, %eax
    hlt
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
