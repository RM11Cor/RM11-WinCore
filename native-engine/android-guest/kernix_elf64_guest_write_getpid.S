/* KERNIX original, intentionally tiny real x86-64 Linux ELF64 program.
 * Guest compiled with GNU as/ld, not handwritten machine-code array.
 * SPDX-License-Identifier: MIT. No libc, relocations, file/network access.
 */
.intel_syntax noprefix
.global _start
.section .text
_start:
    mov eax, 1                     /* Linux x86-64 SYS_write */
    mov edi, 1                     /* stdout only */
    lea rsi, [rip + kernix_message] /* true ELF program .rodata */
    mov edx, kernix_message_end - kernix_message
    syscall
    mov ebx, eax                   /* actual bytes written */
    mov eax, 39                    /* Linux x86-64 SYS_getpid */
    syscall
    add rax, rbx                   /* expected PID + message length */
    hlt                            /* app-private ExitOnHLT test only */
.section .rodata
kernix_message:
    .ascii "KERNIX_ELF64_GUEST_RUN_PASS\n"
kernix_message_end:
.section .note.GNU-stack,"",@progbits
