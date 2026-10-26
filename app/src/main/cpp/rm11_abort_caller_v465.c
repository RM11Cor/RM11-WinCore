#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * v4.0.65: native abort() caller audit for the explicitly selected Windows
 * game Wine process ONLY, attached by an additional game-only LD_PRELOAD.
 *
 * The device's Wine handler mapped SIGABRT to EXCEPTION_WINE_ASSERTION,
 * whose RIP was Android Bionic libc.so abort+0xa0. That RIP is a callee,
 * not the origin. Capture the native caller before raising SIGABRT, then
 * delegate to the original Bionic abort() without suppressing the signal.
 *
 * Deliberately not linked into wineserver, X11, FEX, or normal desktop
 * launches; no signal-handler modification, no stack-frame patching.
 */
static __thread int rm11_abort_logging_active;

static void rm11_print_caller(const void *caller) {
    Dl_info image;
    memset(&image, 0, sizeof(image));
    const char *name = "UNKNOWN";
    unsigned long long offset = 0;
    if (caller && dladdr(caller, &image) && image.dli_fname) {
        name = strrchr(image.dli_fname, '/');
        name = name ? name + 1 : image.dli_fname;
        if (image.dli_fbase) {
            offset = (unsigned long long)
                ((uintptr_t)caller - (uintptr_t)image.dli_fbase);
        }
    }
    /* Only library basename and offset, no private storage path. */
    char basename[96];
    size_t n = 0;
    while (name[n] && n < sizeof(basename)-1) {
        char c = name[n];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '+') basename[n] = c;
        else basename[n] = '_';
        ++n;
    }
    basename[n] = 0;
    char buf[270];
    int len = snprintf(buf, sizeof(buf),
        "RM11_V465_NATIVE_ABORT_CALLER_SEEN=true\\n"
        "RM11_V465_NATIVE_ABORT_CALLER_IMAGE=%s\\n"
        "RM11_V465_NATIVE_ABORT_CALLER_ELF_OFFSET=0x%llx\\n",
        basename, offset);
    if (len > 0 && len < (int)sizeof(buf)) {
        (void)write(STDERR_FILENO, buf, (size_t)len);
    }
}

/*
 * Export symbol with normal ELF visibility; only loaded into the opted-in
 * Wine game launcher. __builtin_return_address(0) is the immediate caller.
 * Do not read deeper frames: guest/FEX frames aren't normal host unwind
 * frames and dereferencing arbitrary stack addresses would be unsafe.
 */
__attribute__((visibility("default"), noreturn))
void abort(void) {
    if (!rm11_abort_logging_active) {
        rm11_abort_logging_active = 1;
        const char *flag = getenv("RM11_V465_TRACE_ABORT_CALLER");
        if (flag && flag[0] == '1' && flag[1] == '\\0') {
            void *pc = __builtin_extract_return_addr(__builtin_return_address(0));
            rm11_print_caller(pc);
        }
    }
    typedef void (*abort_fn)(void);
    abort_fn real_abort = (abort_fn)dlsym(RTLD_NEXT, "abort");
    if (real_abort && real_abort != &abort)
        real_abort();
    /* Fail closed: if libc abort unexpectedly can't be resolved, retain
     * termination rather than allowing a corrupt process to continue. */
    (void)signal(SIGABRT, SIG_DFL);
    (void)raise(SIGABRT);
    _exit(134);
}
