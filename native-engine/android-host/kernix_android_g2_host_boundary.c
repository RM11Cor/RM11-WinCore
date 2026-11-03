/*
 * KERNIX G2: Android/Bionic host boundary observation ONLY.
 * SPDX-License-Identifier: MIT
 * Runs as a signed-APK native PIE. No root, Wine, guest execution or
 * arbitrary binary loading. Opens only the verified FEXCore library path.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2 host boundary proof requires Android ARM64
#endif
static int valid_core_path(const char *name) {
    if (!name || name[0] != '/') return 0;
    const char *base = strrchr(name, '/');
    return base && strcmp(base + 1, "libFEXCore.so") == 0;
}
static void observe_status(int *seccomp, int *no_new_privs) {
    *seccomp = -1;
    *no_new_privs = -1;
    FILE *in = fopen("/proc/self/status", "r");
    if (!in) return;
    char line[256];
    while (fgets(line, sizeof(line), in)) {
        int value = -1;
        if (sscanf(line, "Seccomp: %d", &value) == 1 &&
            value >= 0 && value <= 2) *seccomp = value;
        else if (sscanf(line, "NoNewPrivs: %d", &value) == 1 &&
                 value >= 0 && value <= 1) *no_new_privs = value;
    }
    fclose(in);
}
static const char *display(int value, char *buffer, size_t size) {
    if (value < 0) return "unknown";
    return snprintf(buffer, size, "%d", value) >= 0 ? buffer : "unknown";
}
int main(int argc, char **argv) {
    if (argc != 2 || !valid_core_path(argv[1])) return 2;
    struct utsname host;
    if (uname(&host) != 0 || strcmp(host.machine, "aarch64") != 0) return 3;
    if (getpid() <= 1) return 4;
    const long page = sysconf(_SC_PAGESIZE);
    if (page != 4096 && page != 16384 && page != 65536) return 5;
    void *core = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!core) {
        fprintf(stderr, "KERNIX_G2_FAILURE stage=FEX_DLOPEN\n");
        return 6;
    }
    void *symbol = dlsym(core, "_ZN7FEXCore6Config10InitializeEv");
    if (!symbol) {
        fprintf(stderr, "KERNIX_G2_FAILURE stage=FEX_SYMBOL\n");
        dlclose(core);
        return 7;
    }
    int seccomp = -1, nnp = -1;
    observe_status(&seccomp, &nnp);
    if (dlclose(core) != 0) return 8;
    char secbuf[20], nnpbuf[20];
    const char *sec = display(seccomp, secbuf, sizeof(secbuf));
    const char *priv = display(nnp, nnpbuf, sizeof(nnpbuf));
    if (printf("KERNIX_G2_BIONIC_HOST_BOUNDARY_V1\n"
               "ABI=aarch64\nPAGE_BYTES=%ld\nSECCOMP_MODE=%s\n"
               "NO_NEW_PRIVS=%s\nFEX_CORE_LOAD=1\n"
               "FEX_CONFIG_SYMBOL=1\nWINE_PE_EXECUTED=0\n",
               page, sec, priv) < 0) return 9;
    return fflush(stdout) == 0 ? 0 : 10;
}
