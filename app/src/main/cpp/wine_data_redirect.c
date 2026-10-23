#define _GNU_SOURCE
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* Read-only compatibility shim for Wine ntdll loaded from Android APK JNI libs.
 * Wine 11 derives its NLS data path from the ntdll ELF's own installation path.
 * This redirects only absolute Wine NLS reads to the already provisioned ImageFs.
 * No writes or arbitrary executable redirects are permitted.
 */
static const char *adjust_nls_path(const char *source, char *out, size_t capacity) {
    static const char marker[] = "/share/wine/nls/";
    if (!source || source[0] != '/') return source;
    const char *part = strstr(source, marker);
    if (!part) return source;
    const char *filename = part + sizeof(marker) - 1;
    if (!*filename || strlen(filename) > 100 || strstr(filename, "..") || strchr(filename, '/')) return source;
    for (const char *p = filename; *p; ++p) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return source;
    }
    const char *datadir = getenv("RM11_WINE_DATADIR");
    if (!datadir || datadir[0] != '/' || strlen(datadir) >= PATH_MAX - 128) return source;
    size_t datalen = strlen(datadir);
    if (strncmp(source, datadir, datalen) == 0 && strcmp(source + datalen, part + sizeof("/share/wine") - 1) == 0)
        return source;
    int length = snprintf(out, capacity, "%s/nls/%s", datadir, filename);
    if (length < 0 || (size_t)length >= capacity) return source;
    static int reported;
    if (__atomic_exchange_n(&reported, 1, __ATOMIC_RELAXED) == 0) {
        static const char report[] = "RM11_NLS_REDIRECT_ACTIVE\n";
        ssize_t written = write(STDERR_FILENO, report, sizeof(report) - 1);
        (void)written;
    }
    return out;
}


/* The packaged ARM64 Wine ntdll ELF is loaded from Android's signed APK lib/arm64.
 * Wine 11 derives its Windows PE DLL directory from this ELF path, but the PE
 * aarch64-windows DLLs are held in the app-private, read-only Wine bundle.
 * Redirect only read-only queries for files under our APK-native library path
 * to the existing ImageFs PE directory. Never redirect writes, other packages,
 * user supplied paths, arbitrary executable binaries, or symlinks outside RM11.
 *
 * This is an experimental WineServer compatibility path, not proof of a fully
 * functioning Wine child launcher or Windows game execution.
 */
static const char *adjust_pe_path(const char *source, char *out, size_t capacity) {
    if (!source || source[0] != '/') return source;
    const char *native = getenv("RM11_APK_NATIVE_LIB_DIR");
    const char *pe_dir = getenv("RM11_WINE_PE_DIR");
    if (!native || !pe_dir || native[0] != '/' || pe_dir[0] != '/' ||
        strlen(native) > PATH_MAX - 100 || strlen(pe_dir) > PATH_MAX - 100)
        return source;

    size_t prefix_len = strlen(native);
    if (strncmp(source, native, prefix_len) || source[prefix_len] != '/') return source;
    const char *file = source + prefix_len + 1;
    static const char subdir[] = "aarch64-windows/";
    if (!strncmp(file, subdir, sizeof(subdir) - 1))
        file += sizeof(subdir) - 1;

    size_t file_len = strlen(file);
    if (file_len < 5 || file_len > 110 || strstr(file, "..") ||
        strchr(file, '/') || strchr(file, '\\')) return source;
    for (const char *c = file; *c; ++c) {
        if (!( (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
               (*c >= '0' && *c <= '9') || *c == '-' || *c == '_' || *c == '.'))
            return source;
    }
    /* PE builtins only; never route ELF .so or arbitrary paths. */
    if (strcmp(file + file_len - 4, ".dll") && strcmp(file + file_len - 4, ".exe") &&
        strcmp(file + file_len - 4, ".drv")) return source;
    int count = snprintf(out, capacity, "%s/%s", pe_dir, file);
    if (count <= 0 || (size_t)count >= capacity) return source;
    if (syscall(SYS_faccessat, AT_FDCWD, out, R_OK, 0) != 0) {
        static int missing;
        if (__atomic_exchange_n(&missing, 1, __ATOMIC_RELAXED) == 0) {
            static const char message[] = "RM11_PE_DLL_TARGET_MISSING\n";
            ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
        (void)written;
        }
        return source;
    }
    static int seen;
    if (__atomic_exchange_n(&seen, 1, __ATOMIC_RELAXED) == 0) {
        static const char message[] = "RM11_PE_DLL_REDIRECT_ACTIVE\n";
        ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
        (void)written;
    }
    return out;
}

static const char *adjust_read_path(const char *source, char *out, size_t capacity) {
    const char *pe = adjust_pe_path(source, out, capacity);
    if (pe != source) return pe;
    return adjust_nls_path(source, out, capacity);
}

static mode_t get_mode(int flags, va_list ap) {
    if (flags & O_CREAT) return (mode_t)va_arg(ap, int);
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE) return (mode_t)va_arg(ap, int);
#endif
    return 0;
}

static int redirected_openat(int dirfd, const char *path, int flags, mode_t mode) {
    char alternative[PATH_MAX];
    const char *used = path;
    /* Redirect ONLY reads. Creation, truncation and all writes use original paths. */
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        used = adjust_read_path(path, alternative, sizeof alternative);
    return (int)syscall(SYS_openat, dirfd, used, flags, mode);
}

int open(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = get_mode(flags, ap); va_end(ap);
    return redirected_openat(AT_FDCWD, path, flags, mode);
}
int open64(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = get_mode(flags, ap); va_end(ap);
    return redirected_openat(AT_FDCWD, path, flags, mode);
}
int openat(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = get_mode(flags, ap); va_end(ap);
    return redirected_openat(dirfd, path, flags, mode);
}
int openat64(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags);
    mode_t mode = get_mode(flags, ap); va_end(ap);
    return redirected_openat(dirfd, path, flags, mode);
}
int __open_2(const char *path, int flags) {
    return redirected_openat(AT_FDCWD, path, flags, 0);
}
int __openat_2(int dirfd, const char *path, int flags) {
    return redirected_openat(dirfd, path, flags, 0);
}

/* WineServer may query PE DLL existence through stat/fstatat before opening.
 * Use raw syscalls to avoid recursion into this preloaded shim.
 */
int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    char alt[PATH_MAX];
    const char *used = adjust_read_path(path, alt, sizeof alt);
    return (int)syscall(SYS_newfstatat, dirfd, used, buf, flags);
}
int stat(const char *path, struct stat *buf) {
    return fstatat(AT_FDCWD, path, buf, 0);
}
int lstat(const char *path, struct stat *buf) {
    return fstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}
int access(const char *path, int mode) {
    char alt[PATH_MAX];
    const char *used = adjust_read_path(path, alt, sizeof alt);
    return (int)syscall(SYS_faccessat, AT_FDCWD, used, mode, 0);
}


/*
 * RM11 v2.6.8 experimental Wine child re-exec bridge.
 *
 * Wine 11 ntdll/unix/loader.c calls execv(wineloader, argv) from its *child*
 * after setting WINELOADERNOEXEC=1. With our Android install, ntdll.so lives
 * in APK native libs; it derives a non-existent <nativeLibDir>/wine path.
 *
 * This interposer only replaces exactly that app-private Wine loader basename
 * with the SIGNED, already-executable APK-native libwineprobe.so. It never
 * changes argv, Windows PE files, application commands or any other exec path.
 *
 * It is opt-in per diagnostic process (RM11_CHILD_LOADER_BRIDGE=1); the known
 * working v2.6.7 smoke path remains unchanged.
 *
 * Do not equate a successful execv redirect with a functioning Wine child.
 */
static const char *rm11_child_loader_target(const char *path, char *result,
                                             size_t capacity) {
    const char *enabled = getenv("RM11_CHILD_LOADER_BRIDGE");
    const char *native = getenv("RM11_APK_NATIVE_LIB_DIR");
    if (!path || !enabled || strcmp(enabled, "1") != 0 ||
        !native || native[0] != '/') return path;
    const size_t dirlen = strlen(native);
    if (dirlen < 4 || dirlen > PATH_MAX - 120 ||
        strncmp(path, native, dirlen) != 0 || path[dirlen] != '/')
        return path;

    const char *base = path + dirlen + 1;
    if (strcmp(base, "wine") && strcmp(base, "wine64") &&
        strcmp(base, "wine-preloader") && strcmp(base, "wine64-preloader"))
        return path;

    const int n = snprintf(result, capacity, "%s/libwineprobe.so", native);
    if (n < 0 || (size_t)n >= capacity) return path;
    if (syscall(SYS_faccessat, AT_FDCWD, result, X_OK, 0) != 0)
        return path;
    return result;
}

/* Called by Wine's loader_exec() -> preloader_exec(), never by Java. */
int execv(const char *path, char *const argv[]) {
    char redirected[PATH_MAX];
    const char *target = rm11_child_loader_target(path, redirected,
                                                   sizeof redirected);
    if (target != path) {
        /* Wine itself sets WINELOADERNOEXEC prior to loader_exec; enforce it
         * for just the redirected native Wine loader to avoid exec loops.
         */
        if (setenv("WINELOADERNOEXEC", "1", 1) != 0) return -1;
        static const char marker[] = "RM11_CHILD_LOADER_REEXEC_ACTIVE\n";
        ssize_t written = write(STDERR_FILENO, marker, sizeof marker - 1);
        (void)written;
    }
    extern char **environ;
    return (int)syscall(SYS_execve, target, argv, environ);
}


/*
 * RM11 v2.6.9: Wine 11's ntdll PE/Unix loader derives the UnixLib path from
 * APK-hosted ntdll.so and dlopen()s <nativeLibDir>/aarch64-unix/ws2_32.so.
 * Android's linker disallows loading runtime ELF code from app-writable
 * ImageFs; preserve the identical pinned ELF from Wine runtime in signed APK
 * under libwine_ws2_32.so and route only that SINGLE Wine-internal name.
 *
 * Opt-in only for the experimental child-reexec test. Never redirect general
 * dlopen calls, other Wine modules, user executables or writable libraries.
 */
void *dlopen(const char *filename, int flags) {
    typedef void *(*open_fn)(const char *, int);
    open_fn original = (open_fn)dlsym(RTLD_NEXT, "dlopen");
    if (!original) return NULL;
    const char *target = filename;
    char replacement[PATH_MAX];
    const char *enabled = getenv("RM11_WS2_UNIXLIB_REDIRECT");
    const char *native = getenv("RM11_APK_NATIVE_LIB_DIR");
    if (filename && enabled && !strcmp(enabled, "1") && native &&
        native[0] == '/' && strlen(native) < PATH_MAX - 120) {
        char expected[PATH_MAX];
        const int n = snprintf(expected, sizeof expected,
                               "%s/aarch64-unix/ws2_32.so", native);
        if (n > 0 && (size_t)n < sizeof expected &&
            strcmp(filename, expected) == 0) {
            const int m = snprintf(replacement, sizeof replacement,
                                   "%s/libwine_ws2_32.so", native);
            if (m > 0 && (size_t)m < sizeof replacement &&
                syscall(SYS_faccessat, AT_FDCWD, replacement, R_OK, 0) == 0)
                target = replacement;
            else {
                static const char absent[] =
                        "RM11_WS2_UNIXLIB_SIGNED_TARGET_MISSING\n";
                ssize_t written=write(STDERR_FILENO, absent, sizeof absent - 1);
                (void)written;
            }
        }
    }
    void *handle = original(target, flags);
    if (target != filename) {
        static const char redirected[] = "RM11_WS2_UNIXLIB_DLOPEN_REDIRECTED\n";
        static const char failure[] = "RM11_WS2_UNIXLIB_DLOPEN_FAILED\n";
        const char *message = handle ? redirected : failure;
        ssize_t written=write(STDERR_FILENO, message, strlen(message));
        (void)written;
    }
    return handle;
}
