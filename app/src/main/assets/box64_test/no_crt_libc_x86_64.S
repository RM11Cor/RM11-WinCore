/* RM11 v1.7: A real dynamically linked x86-64 Linux ELF without glibc CRT.
 * Calls the libc write wrapper via PLT; uses Linux exit syscall to terminate.
 * This tests whether Box64's libc wrapper can resolve a symbol OTHER THAN
 * __libc_start_main. Does not fix that missing symbol in other programs.
 */
.section .rodata
message:
    .ascii "RM11_X86_64_LIBC_WRITE_OK\n"
.set message_len, .-message
.section .text
.globl _start
.type _start, @function
_start:
    andq $-16, %rsp
    movl $1, %edi
    leaq message(%rip), %rsi
    movl $message_len, %edx
    call write@PLT
    cmpl $message_len, %eax
    jne exit_failure
    xorl %edi, %edi
    jmp exit_now
exit_failure:
    movl $17, %edi
exit_now:
    movl $60, %eax
    syscall
    ud2
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
