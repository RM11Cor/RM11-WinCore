/* RM11 WinCore V1.4: freestanding Linux x86-64 guest smoke test.
 * Built on the x86-64 GitHub Actions runner, with no libc dependencies.
 * The guest is DATA for Box64, never executed directly by Android.
 * x86-64 Linux syscall ABI: write=1, exit=60.
 * No third-party code; tests basic x86-64 arithmetic, branch, and syscalls.
 */
.section .text
.globl _start
.type _start, @function
_start:
    mov $1234567, %rax
    imul $13, %rax, %rax
    sub $16049360, %rax
    cmp $11, %rax
    jne failure

    mov $1, %rax                    /* SYS_write */
    mov $1, %rdi                    /* STDOUT */
    lea success_message(%rip), %rsi
    mov $success_length, %rdx
    syscall
    cmp $success_length, %rax
    jne failure

    xor %rdi, %rdi                  /* exit(0) */
    mov $60, %rax                   /* SYS_exit */
    syscall
failure:
    mov $31, %rdi                   /* exit(31) means failed arithmetic/write */
    mov $60, %rax
    syscall
.section .rodata
success_message:
    .ascii "RM11_X86_64_GUEST_EXEC_OK\n"
.set success_length, . - success_message
.section .note.GNU-stack,"",@progbits
