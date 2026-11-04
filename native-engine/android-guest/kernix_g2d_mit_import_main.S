/*
 * KERNIX G2-D: genuine x86-64 ELF64 PLT imported function witness.
 * The only call crosses to a DIFFERENT shared-object x86 .text.
 * The PLT slot must be resolved as R_X86_64_JUMP_SLOT before running;
 * otherwise guest code must not be executed. This is NOT Wine or glibc.
 * SPDX-License-Identifier: MIT
 */
.text
.globl _start
.type _start,@function
_start:
    call kernix_g2d_imported_value@PLT
    addq $17,%rax
    hlt
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
