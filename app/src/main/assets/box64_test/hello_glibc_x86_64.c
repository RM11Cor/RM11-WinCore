/* RM11 WinCore V1.5 x86-64 ELF guest: ordinary glibc-linked Linux program.
 * Compiled on CI (x86-64 Linux), packaged as DATA in APK assets, and only
 * passed to Box64. This is NOT a Windows EXE and glibc is NOT bundled. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    if (printf("RM11_X86_64_GLIBC_DYNAMIC_OK pid=%ld\n", (long)getpid()) < 0)
        return 7;
    return fflush(stdout) == 0 ? 0 : 8;
}
