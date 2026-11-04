/*
 * KERNIX G2-C: tiny OWNED MIT test-only PT_INTERP metadata placeholder.
 * This is NOT a Linux dynamic loader. It NEVER processes relocations,
 * symbol lookups, ELF dependencies or TLS. No guest interpreter is executed
 * in the direct-entry proof. No glibc, Wine or game compatibility is claimed.
 * SPDX-License-Identifier: MIT
 */
.text
.globl _start
.type _start,@function
_start:
    xorl %eax,%eax
    hlt
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
