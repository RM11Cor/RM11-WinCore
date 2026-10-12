/* RM11 V2.3.0 ARM64 wineserver bridge. The executable remains installed as
 * a genuine Android native ELF (librm11wineserverbridge.so). Wine may spawn
 * it using a symlink named <private-wine-root>/usr/lib/wine/wineserver.
 * Do NOT copy an executable to writable app storage (Android W^X).
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int resolve_paths(char *box, size_t box_cap, const char **server_out) {
    const char *server = getenv("RM11_WINESERVER64_PATH");
    if (!server || server[0] != '/' || !strstr(server, "/usr/lib/wine/wineserver64") ||
        strlen(server) >= PATH_MAX || strstr(server, "/../") || strstr(server, "/./")) {
        fputs("RM11_WINESERVER_BRIDGE_BAD_SERVER_PATH\n", stderr);
        return 91;
    }
    char own[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", own, sizeof(own) - 1);
    if (n <= 0 || n >= (ssize_t)sizeof(own)-1) return 92;
    own[n] = 0;
    char *slash = strrchr(own, '/');
    if (!slash) return 93;
    slash[1] = 0;
    int size = snprintf(box, box_cap, "%slibrm11box64.so", own);
    if (size < 0 || (size_t)size >= box_cap) return 94;
    if (access(box, X_OK) || access(server, R_OK)) {
        fprintf(stderr, "RM11_WINESERVER_BRIDGE_DEPENDENCY_FAIL: errno=%d\n", errno);
        return 95;
    }
    *server_out = server;
    return 0;
}

int main(int argc, char **argv) {
    char box[PATH_MAX];
    const char *server = NULL;
    int code = resolve_paths(box, sizeof(box), &server);
    if (code) return code;
    if (argc == 2 && strcmp(argv[1], "--rm11-self-test") == 0) {
        puts("RM11_WINESERVER_BRIDGE_PREFLIGHT_OK");
        fflush(stdout);
        return 0;
    }
    fputs("RM11_WINESERVER_BRIDGE_ENTERED\n", stderr);
    char **args = (char**)calloc((size_t)argc + 2, sizeof(char*));
    if (!args) return 96;
    args[0] = box;
    args[1] = (char*)server;
    for (int i = 1; i < argc; ++i) args[i + 1] = argv[i];
    execv(box, args);
    fprintf(stderr, "RM11_WINESERVER_BRIDGE_EXEC_FAIL: errno=%d: %s\n", errno, strerror(errno));
    return 97;
}
