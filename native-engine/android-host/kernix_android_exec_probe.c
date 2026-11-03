/*
 * KERNIX Android native process exec proof (NOT FEX, Wine, or a game).
 * SPDX-License-Identifier: MIT
 * Packaged as a fixed-name ELF PIE in the APK's extracted nativeLibraryDir.
 * This app-controlled Bionic executable never reads arbitrary paths.
 */
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error KERNIX native process proof requires Android ARM64
#endif

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 3;
    struct utsname info;
    if (uname(&info) != 0) return 4;
    if (strcmp(info.machine, "aarch64") != 0) return 5;
    if (puts("KERNIX_ANDROID_BIONIC_PIE_PROCESS_PROOF_V1 arch=aarch64") == EOF)
        return 6;
    if (fflush(stdout) != 0) return 7;
    return 0;
}
