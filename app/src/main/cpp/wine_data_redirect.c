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
#include "wine_win32u_match_v408.h"

/*
 * v2.9.2: scoped native Wine loader installation-path correction.
 *
 * Wine 11 unix/loader.c calls dladdr(init_paths) and uses the returned ELF
 * location to derive native data_dir, which is inserted into the Windows
 * process environment as WINEDATADIR. In APK-hosted Wine this points to a
 * nonexistent Android APK-relative share/wine path. Redirect ONLY dladdr
 * queries whose actual ELF name is exactly our signed libwine_ntdll.so and
 * ONLY when the embedded-GUI launch supplies the verified app-private
 * native Wine installation ELF location.
 *
 * The interposer never changes the loaded ELF or reads/writes user files.
 * It does not claim the native Wine GUI stack has finished initializing.
 */
int dladdr(const void *addr, Dl_info *info) {
    typedef int (*real_dladdr_fn)(const void *, Dl_info *);
    real_dladdr_fn original = (real_dladdr_fn)dlsym(RTLD_NEXT, "dladdr");
    if (!original) return 0;  /* libc's dladdr ABI requires a nonnull info. */
    int result = original(addr, info);
    if (!result || !info->dli_fname) return result;
    const char *native = getenv("RM11_APK_NATIVE_LIB_DIR");
    const char *virtual_path = getenv("RM11_WINE_NTDLL_VIRTUAL_PATH");
    if (!native || !virtual_path || native[0] != '/' || virtual_path[0] != '/')
        return result;
    size_t len = strlen(native);
    if (len < 6 || len > PATH_MAX - 120) return result;
    if (strncmp(info->dli_fname, native, len) ||
        strcmp(info->dli_fname + len, "/libwine_ntdll.so")) return result;
    static const char tail[] = "/lib/wine/aarch64-unix/ntdll.so";
    size_t total = strlen(virtual_path);
    if (total <= sizeof tail || total >= PATH_MAX - 1 ||
        strcmp(virtual_path + total - (sizeof tail - 1), tail)) return result;
    /* Fail closed unless the supplied target is an actual regular file. */
    struct stat st;
    if (syscall(SYS_newfstatat, AT_FDCWD, virtual_path, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(st.st_mode) || st.st_size < 4096) return result;
    info->dli_fname = virtual_path;
    static int reported;
    if (__atomic_exchange_n(&reported, 1, __ATOMIC_RELAXED) == 0) {
        static const char msg[] = "RM11_V292_NTDLL_WINE_LAYOUT_DLADDR_REDIRECTED\n";
        ssize_t written = write(STDERR_FILENO, msg, sizeof msg - 1);
        (void)written;
    }
    return result;
}

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
    if (dirlen < 4 || dirlen > PATH_MAX - 120) return path;
    const char *base = NULL;
    if (!strncmp(path, native, dirlen) && path[dirlen] == '/') {
        base = path + dirlen + 1;
    } else {
        /* Wine's corrected ntdll installation layout also updates the
         * derived child-loader path. Allow only its exact aarch64-unix
         * sibling, never an arbitrary binary below writable ImageFs. */
        const char *virtual_ntdll = getenv("RM11_WINE_NTDLL_VIRTUAL_PATH");
        static const char suffix[] = "/ntdll.so";
        if (!virtual_ntdll || virtual_ntdll[0] != '/') return path;
        size_t nlen = strlen(virtual_ntdll);
        if (nlen <= sizeof suffix || nlen > PATH_MAX - 64 ||
            strcmp(virtual_ntdll + nlen - (sizeof suffix - 1), suffix))
            return path;
        size_t parent_len = nlen - (sizeof suffix - 1);
        if (!strncmp(path, virtual_ntdll, parent_len) &&
            path[parent_len] == '/') {
            base = path + parent_len + 1;
        } else {
            /*
             * v2.9.7: upstream Wine init_paths() uses
             * realpath_dirname(info.dli_fname) before constructing
             * wineloader = build_path(ntdll_dir, "wine").
             * RM11 WineRoot is an app-private symlink. Wine may therefore
             * execv() the canonical target's aarch64-unix/wine, not the
             * noncanonical path in RM11_WINE_NTDLL_VIRTUAL_PATH.
             *
             * Trust ONLY the parent of the real, already verified ntdll.so
             * and the same exact Wine loader basename. No arbitrary path
             * or user supplied EXE can be redirected.
             */
            char *canonical = realpath(virtual_ntdll, NULL);
            if (!canonical) return path;
            size_t cn = strlen(canonical);
            int accepted = 0;
            if (cn > sizeof suffix &&
                !strcmp(canonical + cn - (sizeof suffix - 1), suffix)) {
                size_t cp = cn - (sizeof suffix - 1);
                if (!strncmp(path, canonical, cp) && path[cp] == '/') {
                    base = path + cp + 1;
                    accepted = 1;
                }
            }
            free(canonical);
            if (!accepted) return path;
            static int canonical_reported;
            if (__atomic_exchange_n(&canonical_reported,1,__ATOMIC_RELAXED) == 0) {
                static const char marker[] =
                    "RM11_V297_CANONICAL_WINE_CHILD_PATH_MATCHED\n";
                ssize_t written=write(STDERR_FILENO,marker,sizeof marker-1);
                (void)written;
            }
        }
    }
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
    int result=(int)syscall(SYS_execve, target, argv, environ);
    /* Wine 11's spawn_process returns an NT status derived from a failed
     * loader re-exec; record only error code and whether our signed loader
     * path was actually used. Never disclose user-selected Windows paths. */
    if (result < 0 && getenv("RM11_CHILD_LOADER_BRIDGE")) {
        char report[160];
        int length=snprintf(report,sizeof report,
                "RM11_V297_WINE_CHILD_EXECVE_FAILED errno=%d signed=%d\n",
                errno,target!=path);
        if (length>0 && (size_t)length<sizeof report) {
            ssize_t written=write(STDERR_FILENO,report,(size_t)length);
            (void)written;
        }
    }
    return result;
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
static void rm11_native_diag(const char *text, size_t length) {
    ssize_t recorded = write(STDERR_FILENO,text,length);
    (void)recorded;
}

/* v4.0.7: read-only evidence in the EXPLICITLY opted-in Winefile
 * process. This does not affect Wine server or Explorer, which never
 * receive the RM11_WIN32U_ISOLATED_FONTCLIENT flag.
 */
__attribute__((constructor)) static void rm11_v407_scoped_client_started(void) {
    const char *flag=getenv("RM11_WIN32U_ISOLATED_FONTCLIENT");
    if(flag && !strcmp(flag,"1")) {
        static const char marker[]="RM11_V407_OPT_IN_FONTCLIENT_PROCESS_ENV_OBSERVED\n";
        ssize_t n=write(STDERR_FILENO,marker,sizeof marker-1);
        (void)n;
    }
}

/*
 * v4.4.4: Wine clients and wineserver can inherit environment variables.
 * A flag set in the selected EXE is NOT by itself proof of process isolation.
 *
 * Permit an experimental native FreeType redirect only when the *running*
 * process executable is exactly our signed APK Wine launcher. In particular,
 * wineserver (libwineserverrm11.so), the Android app process, shell tools and
 * Wine's unrelated child executables cannot use this path even if they inherit
 * RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT=1.
 *
 * /proc/self/exe is kernel supplied, not argv[0], so a caller cannot bypass
 * this check by spoofing a process title. No Wine processes are started here.
 */
static int rm11_v444_is_signed_wine_launcher(const char *native) {
    if (!native || native[0]!='/' || strlen(native)>PATH_MAX-64)
        return 0;
    char expected[PATH_MAX];
    int n=snprintf(expected,sizeof(expected),"%s/libwineprobe.so",native);
    if(n<=0 || (size_t)n>=sizeof(expected))return 0;
    char current[PATH_MAX];
    ssize_t length=readlink("/proc/self/exe",current,sizeof(current)-1);
    if(length<=0 || length>=(ssize_t)sizeof(current))return 0;
    current[length]='\0';
    return !strcmp(current,expected);
}

void *dlopen(const char *filename, int flags) {
    typedef void *(*open_fn)(const char *, int);
    open_fn original = (open_fn)dlsym(RTLD_NEXT, "dlopen");
    if (!original) return NULL;
    const char *target = filename;
    char replacement[PATH_MAX];
    const char *enabled = getenv("RM11_WS2_UNIXLIB_REDIRECT");
    const char *native = getenv("RM11_APK_NATIVE_LIB_DIR");
    const char *win32u_enabled = getenv("RM11_NATIVE_WIN32U_DLL_REDIRECT");
    /* v4.0.6: only Winefile's first test child receives this flag. */
    const char *fontclient = getenv("RM11_WIN32U_ISOLATED_FONTCLIENT");
    if(fontclient && !strcmp(fontclient,"1") && filename) {
        const size_t len=strlen(filename);
        static const char suffix[]="/win32u.so";
        if(!strcmp(filename,"win32u.so") ||
           (len>=sizeof suffix-1 &&
            !strcmp(filename+len-(sizeof suffix-1),suffix))) {
            static int observed;
            if(!__atomic_exchange_n(&observed,1,__ATOMIC_RELAXED)) {
                static const char marker[]=
                    "RM11_V407_FONTCLIENT_WIN32U_DLOPEN_REQUEST_REACHED_INTERPOSER\n";
                ssize_t n=write(STDERR_FILENO,marker,sizeof marker-1);
                (void)n;
            }
        }
    }
    const char *winex11_enabled = getenv("RM11_NATIVE_WINEX11_DLOPEN_REDIRECT");
    const char *font_enabled = getenv("RM11_NATIVE_FREETYPE_DLOPEN_REDIRECT");
    const char *virtual_ntdll = getenv("RM11_WINE_NTDLL_VIRTUAL_PATH");
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
    /* v4.0.8: Wine 11 may request native win32u.so by basename or the
     * canonical ntdll sibling, NOT just the symlink-derived virtual sibling.
     * Device v4.0.7 confirmed the opt-in request reached this interposer,
     * but did NOT observe either success or failure for the private client.
     *
     * Preserve the exact original v4.0.7 match for ALL normal GUI processes.
     * Accept additional forms ONLY in the user-clicked isolated font test;
     * redirect exclusively into the signed APK nativeLibraryDir.
     */
    if (filename && win32u_enabled && !strcmp(win32u_enabled, "1") &&
        native && virtual_ntdll && native[0] == '/' &&
        virtual_ntdll[0] == '/' && strlen(native) < PATH_MAX - 120) {
        int scoped_font = fontclient && !strcmp(fontclient, "1");
        static const char requested_suffix[] = "/win32u.so";
        size_t request_len = strlen(filename);
        int candidate = !strcmp(filename, "win32u.so") ||
                (request_len >= sizeof(requested_suffix) - 1 &&
                 !strcmp(filename + request_len - (sizeof(requested_suffix) - 1),
                         requested_suffix));
        if (candidate) {
            char *canonical_ntdll = scoped_font
                    ? realpath(virtual_ntdll, NULL) : NULL;
            int kind = rm11_v408_win32u_match(filename, virtual_ntdll,
                                                canonical_ntdll);
            free(canonical_ntdll);
            /* Baseline must remain byte-for-byte behaviorally equivalent:
             * accept ONLY the exact old virtual ntdll sibling path. */
            if (!scoped_font &&
                kind != RM11_WIN32U_VIRTUAL_NTDLL_SIBLING_MATCH) kind = 0;
            if (scoped_font) {
                const char *evidence =
                        kind == RM11_WIN32U_BASENAME_MATCH
                        ? "RM11_V408_SCOPED_WIN32U_MATCH_BASENAME\n"
                        : kind == RM11_WIN32U_VIRTUAL_NTDLL_SIBLING_MATCH
                        ? "RM11_V408_SCOPED_WIN32U_MATCH_VIRTUAL\n"
                        : kind == RM11_WIN32U_CANONICAL_NTDLL_SIBLING_MATCH
                        ? "RM11_V408_SCOPED_WIN32U_MATCH_CANONICAL\n"
                        : "RM11_V408_SCOPED_WIN32U_REQUEST_PATH_UNTRUSTED\n";
                rm11_native_diag(evidence, strlen(evidence));
            }
            if (kind != RM11_WIN32U_NO_MATCH) {
                const char *basename = scoped_font
                        ? "librm11_win32u_fontclient.so" : "libwine_win32u.so";
                int count = snprintf(replacement, sizeof(replacement), "%s/%s",
                                     native, basename);
                if (count > 0 && (size_t)count < sizeof(replacement) &&
                    syscall(SYS_faccessat, AT_FDCWD, replacement, R_OK, 0) == 0) {
                    target = replacement;
                } else {
                    static const char absent[] =
                        "RM11_V292_SIGNED_WIN32U_UNIXLIB_MISSING\n";
                    rm11_native_diag(absent, sizeof(absent) - 1);
                }
            }
        }
    }
    /*
     * v2.9.3: Android 16 disallows executable ELF from writable ImageFs.
     * The Wine-native X11 backend MUST run from signed APK nativeLibraryDir,
     * just as the previously integrated X11 client dependency closure does.
     *
     * Only enabled in the embedded-display Wine diagnostic process. Match
     * exact native original or app-private original Wine UnixLib location.
     * Also match realpath() of this package's verified ntdll sibling because
     * wineRoot is a symlink to the restored ImageFs Wine package.
     * Never change arbitrary application dlopen paths or arbitrary .so names.
     */
    if (filename && winex11_enabled && !strcmp(winex11_enabled, "1") &&
        native && virtual_ntdll && native[0]=='/' && virtual_ntdll[0]=='/' &&
        strlen(native)<PATH_MAX-120) {
        static const char driver[] = "/winex11.so";
        static const char ntdll_suffix[] = "/ntdll.so";
        size_t pathlen = strlen(filename), nlen = strlen(virtual_ntdll);
        /* Some Wine builds dlopen the UnixLib by basename rather than
         * its complete app-private Wine path; allow only this exact Wine
         * basename under the already opt-in embedded-GUI process flag.
         * Android's trusted signed nativeLibraryDir supplies the bytes. */
        int basename_request = !strcmp(filename, "winex11.so");
        if ((basename_request || (pathlen >= sizeof driver - 1 &&
             !strcmp(filename + pathlen - (sizeof driver - 1), driver))) &&
            nlen > sizeof ntdll_suffix &&
            !strcmp(virtual_ntdll + nlen - (sizeof ntdll_suffix - 1),
                    ntdll_suffix)) {
            static int observed;
            if (!__atomic_exchange_n(&observed,1,__ATOMIC_RELAXED)) {
                static const char msg[] =
                    "RM11_V293_NATIVE_WINEX11_LOAD_REQUEST_OBSERVED\n";
                rm11_native_diag(msg,sizeof msg-1);
            }
            char expected_native[PATH_MAX];
            int an = snprintf(expected_native,sizeof expected_native,
                              "%s/aarch64-unix/winex11.so",native);
            size_t parent = nlen - (sizeof ntdll_suffix - 1);
            int trusted = basename_request ||
                (an > 0 && (size_t)an < sizeof expected_native &&
                 !strcmp(filename,expected_native));
            if (!trusted && pathlen == parent + sizeof driver - 1 &&
                !strncmp(filename,virtual_ntdll,parent) &&
                !strcmp(filename+parent,driver))
                trusted=1;
            if (!trusted) {
                char *canonical = realpath(virtual_ntdll,NULL);
                if (canonical) {
                    size_t canonlen=strlen(canonical);
                    if (canonlen > sizeof ntdll_suffix &&
                        !strcmp(canonical+canonlen-(sizeof ntdll_suffix-1),
                                ntdll_suffix)) {
                        size_t cparent=canonlen-(sizeof ntdll_suffix-1);
                        if (pathlen == cparent+sizeof driver-1 &&
                            !strncmp(filename,canonical,cparent) &&
                            !strcmp(filename+cparent,driver))
                            trusted=1;
                    }
                    free(canonical);
                }
            }
            if (trusted) {
                int written=snprintf(replacement,sizeof replacement,
                                     "%s/libwine_winex11.so",native);
                if (written > 0 && (size_t)written < sizeof replacement &&
                    syscall(SYS_faccessat,AT_FDCWD,replacement,R_OK,0)==0) {
                    target=replacement;
                } else {
                    static const char msg[] =
                        "RM11_V293_SIGNED_WINEX11_DRIVER_MISSING\n";
                    rm11_native_diag(msg,sizeof msg-1);
                }
            } else {
                static const char msg[] =
                    "RM11_V293_WINEX11_LOAD_PATH_UNMATCHED\n";
                rm11_native_diag(msg,sizeof msg-1);
            }
        }
    }
    /*
     * v2.9.8: Wine win32u/freetype.c dynamically loads SONAME_LIBFREETYPE.
     * Android cannot use Termux's executable .so from app-writable ImageFs,
     * and the private platform FreeType may be inaccessible.
     * Our vetted official Bionic ARM64 ELF is signed in nativeLibraryDir.
     *
     * Match ONLY the exact FreeType SONAME (Wine builds may request .so.6 or
     * .so), and ONLY the embedded X11 launch that opted in explicitly.
     * No general library path rewriting, no interception of other fonts or
     * third-party programs, no root access, no registry modifications.
     */
    if (filename && font_enabled && !strcmp(font_enabled,"1") &&
        native && native[0]=='/' && strlen(native)<PATH_MAX-64 &&
        (!strcmp(filename,"libfreetype.so.6") ||
         !strcmp(filename,"libfreetype.so"))) {
        if (!rm11_v444_is_signed_wine_launcher(native)) {
            static const char blocked[]=
                    "RM11_V444_FREETYPE_REDIRECT_BLOCKED_NON_WINE_LAUNCHER\n";
            rm11_native_diag(blocked,sizeof(blocked)-1);
        } else {
        int n=snprintf(replacement,sizeof replacement,
                       "%s/librm11_freetype_core.so",native);
        if (n>0 && (size_t)n<sizeof replacement &&
            syscall(SYS_faccessat,AT_FDCWD,replacement,R_OK,0)==0) {
            target=replacement;
            static int seen;
            if (!__atomic_exchange_n(&seen,1,__ATOMIC_RELAXED)) {
                static const char mark[]="RM11_V301_NDK_FREETYPE_REQUEST_SEEN\n";
                rm11_native_diag(mark,sizeof mark-1);
            }
        } else {
            static const char mark[]="RM11_V301_SIGNED_NDK_FREETYPE_MISSING\n";
            rm11_native_diag(mark,sizeof mark-1);
        }
        }
    }
    /* v4.0.9: strictly opt-in, APK-signed Bionic Fontconfig for the test
     * Winefile only. Never redirect globally; never open a game-supplied ELF.
     */
    const char *fc_enabled = getenv("RM11_NATIVE_FONTCONFIG_DLOPEN_REDIRECT");
    if (filename && fc_enabled && !strcmp(fc_enabled,"1") &&
        fontclient && !strcmp(fontclient,"1") &&
        native && native[0]=='/' && strlen(native)<PATH_MAX-64 &&
        (!strcmp(filename,"libfontconfig.so") ||
         !strcmp(filename,"libfontconfig.so.1"))) {
        int n=snprintf(replacement,sizeof(replacement),
                       "%s/librm11_fc.so",native);
        if (n>0 && (size_t)n<sizeof(replacement) &&
            syscall(SYS_faccessat,AT_FDCWD,replacement,R_OK,0)==0)
            target=replacement;
        else {
            static const char missing[]="RM11_V409_PRIVATE_FONTCONFIG_SIGNED_ELF_MISSING\n";
            rm11_native_diag(missing,sizeof(missing)-1);
        }
    }
    void *handle = original(target, flags);
    if (target!=filename && strstr(target,"/librm11_fc.so")) {
        const char *msg=handle
             ? "RM11_V409_FONTCONFIG_NATIVE_DLOPEN_SUCCESS\n"
             : "RM11_V409_FONTCONFIG_NATIVE_DLOPEN_FAILED\n";
        rm11_native_diag(msg,strlen(msg));
    }
    if (target!=filename && strstr(target,"/librm11_freetype_core.so")) {
        const char *msg=handle ? "RM11_V301_NDK_FREETYPE_DLOPEN_SUCCEEDED\n"
                               : "RM11_V301_NDK_FREETYPE_DLOPEN_FAILED\n";
        rm11_native_diag(msg,strlen(msg));
    }
    if (target!=filename && strstr(target,"/libwine_winex11.so")) {
        static const char yes[]="RM11_V293_WINEX11_DLOPEN_SUCCEEDED\n";
        static const char no[]="RM11_V293_WINEX11_DLOPEN_FAILED\n";
        const char *msg=handle?yes:no;
        rm11_native_diag(msg,strlen(msg));
    }
    if (target != filename && strstr(target,"/librm11_win32u_fontclient.so")) {
        const char *msg=handle ?
            "RM11_V406_PATCHED_WIN32U_WINEFILE_DLOPEN_SUCCEEDED\n":
            "RM11_V406_PATCHED_WIN32U_WINEFILE_DLOPEN_FAILED\n";
        rm11_native_diag(msg,strlen(msg));
    }
    if (target != filename && strstr(target, "/libwine_win32u.so")) {
        static const char yes[] = "RM11_V292_NATIVE_WIN32U_DLOPEN_SUCCEEDED\n";
        static const char no[] = "RM11_V292_NATIVE_WIN32U_DLOPEN_FAILED\n";
        const char *message = handle ? yes : no;
        ssize_t written=write(STDERR_FILENO,message,strlen(message));
        (void)written;
    }
    if (target != filename && !strstr(target,"/librm11_freetype_core.so") &&
        !strstr(target,"/libwine_winex11.so") &&
        !strstr(target,"/libwine_win32u.so")) {
        static const char redirected[] = "RM11_WS2_UNIXLIB_DLOPEN_REDIRECTED\n";
        static const char failure[] = "RM11_WS2_UNIXLIB_DLOPEN_FAILED\n";
        const char *message = handle ? redirected : failure;
        ssize_t written=write(STDERR_FILENO, message, strlen(message));
        (void)written;
    }
    return handle;
}
