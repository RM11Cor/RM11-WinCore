/*
 * KERNIX G2-C: owned MIT-only DT_NEEDED leaf shared object.
 * Provides a real ELF64 ET_DYN PT_DYNAMIC/SONAME, without relying on
 * glibc. No relocation/import or interpreter execution is claimed.
 * SPDX-License-Identifier: MIT
 */
.text
.globl kernix_g2c_test_dependency_only
.type kernix_g2c_test_dependency_only,@function
kernix_g2c_test_dependency_only:
    ret
.size kernix_g2c_test_dependency_only,.-kernix_g2c_test_dependency_only
.section .note.GNU-stack,"",@progbits
