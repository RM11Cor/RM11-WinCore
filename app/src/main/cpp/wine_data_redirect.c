#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
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
        (void)write(STDERR_FILENO, report, sizeof(report) - 1);
    }
    return out;
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
        used = adjust_nls_path(path, alternative, sizeof alternative);
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
