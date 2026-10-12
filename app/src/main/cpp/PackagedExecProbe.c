/*
 * RM11 WinCore V1.1: first-party Android executable, not Wine or Box64.
 * Compile as a PIE executable with the Android NDK, name it lib*.so solely
 * so Android's native-libraries packager extracts it into nativeLibraryDir.
 * Do not link it as a shared library: a runnable executable needs PT_INTERP.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--self-test") != 0) {
        fputs("RM11: only --self-test is supported\n", stderr);
        return 2;
    }
    struct utsname kernel;
    if (uname(&kernel) != 0) return 3;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 4;
    puts("RM11_ANDROID_ELF_EXEC_OK");
#if defined(__aarch64__)
    puts("ARCH=aarch64");
#else
    puts("ARCH=non-aarch64 (host test only)");
#endif
    printf("KERNEL=%s\nPAGE_SIZE=%ld\n", kernel.machine, page_size);
    return 0;
}
