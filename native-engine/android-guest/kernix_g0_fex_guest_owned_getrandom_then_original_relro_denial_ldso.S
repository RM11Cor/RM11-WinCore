# SPDX-License-Identifier: MIT
# One real original FEX x86 session:
# source ELF/AUXV -> Linux x86 arch_prctl(ARCH_SET_FS) -> actual x86 FS:0,
# FS:8 / DTV[1] and FS:-136 reads from original libc PT_TLS initializer
# -> guest mmap -> 2x real getrandom(318) guest RW writes and x86 reads
# -> source-attested main ELF RELA RELATIVE guest fixture store
# -> x86 mprotect(PROT_READ) on original real ELF RELRO: reject -EINVAL
# -> x86 mprotect(PROT_READ) on exact owned anonymous page -> guest RO load
# -> munmap -> original PT_INTERP ld-linux MOV/CALL and bounded callee.
# This is NOT a complete glibc TLS/TCB/DTV or ld-linux relocation startup.
# Host passes R8 = exclusively owned guest TCB/FS base and R9 = exact original
# source ELF R_X86_64_RELATIVE record in source owned ELF staging.
.text
.globl _start
_start:
    mov (%r13), %r12
    mov (%rsp), %r14
    mov %r9, %r15
    # RAX initially carries one exact source-verified main PT_GNU_RELRO
    # writable FULL page, saved only on our owned guest stack.
    push %rax
    mov $158, %eax
    mov $0x1002, %edi
    mov %r8, %rsi
    syscall
    # The native host syscall adapter must update ONLY x86 guest
    # CPUState.fs_cached, not host AArch64 or Android thread TLS.
    mov %fs:0, %rax
    mov %rax, 32(%r8)
    mov %fs:8, %rax
    mov 16(%rax), %rax
    mov (%rax), %rax
    mov %rax, 40(%r8)
    mov %fs:-136, %rax
    mov %rax, 48(%r8)
    mov %fs:16, %rax
    mov %rax, 56(%r8)
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    mov %rax, %rbx
    mov %r12, (%rbx)
    # Two REAL Linux x86 getrandom(318) syscalls into disjoint 32-byte
    # regions of ONE native-owned guest anonymous RW page. No host fd,
    # pathname or user pointer is exposed to x86. Host checks real
    # entropy provenance; x86 checks both Linux syscall return values.
    mov $318, %eax
    lea 64(%rbx), %rdi
    mov $32, %esi
    xor %edx, %edx
    syscall
    cmp $32, %rax
    jne .Lreject
    mov $318, %eax
    lea 96(%rbx), %rdi
    mov $32, %esi
    xor %edx, %edx
    syscall
    cmp $32, %rax
    jne .Lreject
    # Real x86 guest reads both kernel-supplied independently generated
    # outputs and refuses a duplicated first qword.
    mov 64(%rbx), %rax
    cmp %rax, 96(%rbx)
    je .Lreject
    # Guest fixture consumes original SHA-pinned main ELF DT_RELA entry.
    mov 8(%r15), %rax
    cmp $8, %rax
    jne .Lreject
    mov (%r15), %r11
    add %r13, %r11
    mov 16(%r15), %rax
    add %r13, %rax
    mov %rax, (%r11)
    # Attempt to prematurely seal the TRUE original main ELF source
    # PT_GNU_RELRO page from actual guest syscall 10. Fail closed:
    # the KERNIX guest kernel cannot seal original ELF without a
    # proven genuine dynamic-linker relocation-completion witness.
    pop %rdi
    mov $10, %eax
    mov $4096, %esi
    mov $1, %edx
    syscall
    cmp $-22, %rax
    jne .Lreject
    # Authentic x86 Linux mprotect(10): change ONE exact owner-held
    # guest anonymous VMA to READ ONLY. This is a guest-kernel
    # protection prerequisite, NOT GNU ld-linux's PT_GNU_RELRO.
    mov $10, %eax
    mov %rbx, %rdi
    mov $4096, %esi
    mov $1, %edx
    syscall
    # This is now an actual guest x86 load from native RO memory.
    mov (%rbx), %r15
    mov $11, %eax
    mov %rbx, %rdi
    mov $4096, %esi
    syscall
    jmp *%rbp
.Lreject:
    hlt
