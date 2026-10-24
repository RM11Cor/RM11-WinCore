#ifndef RM11_WINE_WIN32U_MATCH_V408_H
#define RM11_WINE_WIN32U_MATCH_V408_H

/* v4.0.8: strict, unit-tested matching for the opt-in Winefile client.
 * Basename requests are emitted by some Wine 11 loader paths; other requests
 * must exactly match the trusted virtual or canonical sibling of ntdll.so.
 * This helper performs no IO, no ELF loading, and no process-wide changes.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum {
    /* Android / Wine path buffer limit; never depend on host RM11_V408_PATH_LIMIT macros. */
    RM11_V408_PATH_LIMIT = 4096,
    RM11_WIN32U_NO_MATCH = 0,
    RM11_WIN32U_BASENAME_MATCH = 1,
    RM11_WIN32U_VIRTUAL_NTDLL_SIBLING_MATCH = 2,
    RM11_WIN32U_CANONICAL_NTDLL_SIBLING_MATCH = 3
};

static inline int rm11_v408_win32u_match(const char *request,
                                           const char *virtual_ntdll,
                                           const char *canonical_ntdll) {
    static const char suffix[] = "/ntdll.so";
    if (!request || !virtual_ntdll || virtual_ntdll[0] != '/') return 0;
    size_t len = strlen(virtual_ntdll);
    if (len <= sizeof(suffix) - 1 || len > RM11_V408_PATH_LIMIT - 64 ||
        strcmp(virtual_ntdll + len - (sizeof(suffix) - 1), suffix)) return 0;
    if (!strcmp(request, "win32u.so")) return RM11_WIN32U_BASENAME_MATCH;
    char sibling[RM11_V408_PATH_LIMIT];
    int count = snprintf(sibling, sizeof(sibling), "%.*s/win32u.so",
                         (int)(len - (sizeof(suffix) - 1)), virtual_ntdll);
    if (count > 0 && (size_t)count < sizeof(sibling) &&
        !strcmp(request, sibling))
        return RM11_WIN32U_VIRTUAL_NTDLL_SIBLING_MATCH;
    if (canonical_ntdll && canonical_ntdll[0] == '/') {
        len = strlen(canonical_ntdll);
        if (len > sizeof(suffix) - 1 && len <= RM11_V408_PATH_LIMIT - 64 &&
            !strcmp(canonical_ntdll + len - (sizeof(suffix) - 1), suffix)) {
            count = snprintf(sibling, sizeof(sibling), "%.*s/win32u.so",
                             (int)(len - (sizeof(suffix) - 1)), canonical_ntdll);
            if (count > 0 && (size_t)count < sizeof(sibling) &&
                !strcmp(request, sibling))
                return RM11_WIN32U_CANONICAL_NTDLL_SIBLING_MATCH;
        }
    }
    return RM11_WIN32U_NO_MATCH;
}
#endif
