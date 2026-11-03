/* KERNIX v0.11 original ELF64 x86-64 writable guest memory gate.
 * GNU as/ld-built Linux guest copies a message from ELF .rodata into
 * ELF .data using REP MOVSB, and passes the writable pointer to write(1).
 * No external files, dynamic libraries, glibc or user-supplied programs.
 * SPDX-License-Identifier: MIT.
 */
.intel_syntax noprefix
.global _start
.section .text
_start:
    lea rsi, [rip + message_template]
    lea rdi, [rip + writable_message]
    mov ecx, message_end - message_template
    rep movsb
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + writable_message]
    mov edx, message_end - message_template
    syscall
    mov ebx, eax
    mov eax, 39
    syscall
    add rax, rbx
    hlt
.section .rodata
message_template:
    .ascii "KERNIX_ELF_RW_MEMORY_PASS\n"
message_end:
.section .data
writable_message:
    .zero message_end - message_template
.section .note.GNU-stack,"",@progbits
