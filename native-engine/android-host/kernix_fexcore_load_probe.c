/*
 * KERNIX independent Android ARM64 FEXCore dynamic-link proof.
 * Original KERNIX code, SPDX-License-Identifier: MIT.
 *
 * Loads ONLY a verified APK native-library path provided by KERNIX itself.
 * FEXCore symbol lookup does not execute x86 code or Wine.
 */
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error KERNIX native FEXCore loader requires Android ARM64
#endif

int main(int argc, char **argv) {
    if (argc != 2 || argv[1] == NULL) return 2;
    const char *path = argv[1];
    size_t n = strlen(path);
    const char suffix[] = "/libFEXCore.so";
    if (n <= sizeof(suffix) - 1 || n >= PATH_MAX ||
        strcmp(path + n - (sizeof(suffix) - 1), suffix) != 0 ||
        path[0] != '/') return 3;
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        const char *error = dlerror();
        fprintf(stderr, "KERNIX_FEXCORE_DLOPEN_FAILED: %.240s\n",
                error ? error : "unknown Android linker error");
        return 4;
    }
    /*
     * Real pinned upstream FEXCore::Config::Initialize() Itanium ABI symbol.
     * DO NOT invoke this symbol before allocator, guest-memory and lifecycle
     * bootstrap is qualified; presence + dlopen is the only current gate.
     */
    void *symbol = dlsym(library, "_ZN7FEXCore6Config10InitializeEv");
    if (symbol == NULL) {
        fprintf(stderr, "KERNIX_FEXCORE_PINNED_PUBLIC_SYMBOL_MISSING\n");
        dlclose(library);
        return 5;
    }
    puts("KERNIX_REAL_FEXCORE_ANDROID_DLOPEN_SYMBOL_PROOF_V1");
    if (fflush(stdout) != 0) return 6;
    dlclose(library);
    return 0;
}
