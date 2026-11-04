/*
 * KERNIX G2-D: fixed MIT-only x86 shared DSO provider.
 * Genuine external function returns fixed expected value before
 * ELF R_X86_64_JUMP_SLOT-imported main adds +17 and halts.
 * SPDX-License-Identifier: MIT
 */
.text
.globl kernix_g2d_imported_value
.type kernix_g2d_imported_value,@function
kernix_g2d_imported_value:
    movabsq $0x4b45524e49584720,%rax
    ret
.size kernix_g2d_imported_value,.-kernix_g2d_imported_value
.section .note.GNU-stack,"",@progbits
