# SPDX-License-Identifier: MIT
# GNU as x86-64 guest: REAL FEX pread64 of SHA256-original ld-linux fd4.
# RSI is initialized to a current owner-attested writable guest VMA.
# After SYSCALL guest reads *returned bytes* and puts 0x7f ELF into EAX.
# This is not dynamic ELF interpreter execution, glibc or Android.
.text
.globl _start
_start:
    mov $17, %eax
    mov $4, %edi
    mov $64, %edx
    xor %r10d, %r10d
    syscall
    movzbl (%rsi), %eax
    hlt
