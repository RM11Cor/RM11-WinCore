/* Original KERNIX bounded ELF64 x86-64 mmap/write/getpid/munmap proof.
 * SPDX-License-Identifier: MIT. Program uses only private anonymous RW mapping. */
.intel_syntax noprefix
.global _start
.section .text
_start:
    mov eax, 9
    xor edi, edi
    mov esi, 16384
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    // Copy real x86 guest high GPRs into low GPRs before SYSCALL.
    // Never substitute these snapshots for the genuine syscall inputs.
    mov rbp, r10
    mov rbx, r8
    syscall
    mov r12, rax
    // Make both guest snapshots observable after SYSCALL, preventing
    // dead-store elimination before the FEXCore syscall callback.
    xor ebp, 0x22
    inc rbx
    or rbp, rbx
    lea rsi, [rip + message_template]
    mov rdi, r12
    mov ecx, message_end - message_template
    rep movsb
    mov eax, 1
    mov edi, 1
    mov rsi, r12
    mov edx, message_end - message_template
    syscall
    mov ebx, eax
    mov eax, 39
    syscall
    mov r13, rax
    mov eax, 11
    mov rdi, r12
    mov esi, 16384
    syscall
    mov rax, r13
    add rax, rbx
    // Correct R10/R8 imply a zero shadow checksum; wrong values fail RAX.
    add rax, rbp
    hlt
.section .rodata
message_template:
    .ascii "KERNIX_ELF_RW_MEMORY_PASS\n"
message_end:
.section .data
kernix_data_reserved:
    .quad 0
.section .note.GNU-stack,"",@progbits
