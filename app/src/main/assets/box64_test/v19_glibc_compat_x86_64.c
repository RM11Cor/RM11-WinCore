/* RM11 WinCore V1.9: first-party dynamically linked Linux x86-64 ABI probes.
 * Each mode runs in a separate Box64 process. This is not Wine/Windows code.
 * Do not use third-party inputs; the file path is created by RM11 in cache. */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_memory(void) {
    const size_t count = 8192;
    unsigned char *p = (unsigned char *)malloc(count);
    if (!p) return 11;
    for (size_t i = 0; i < count; ++i) p[i] = (unsigned char)(i % 251);
    unsigned char *q = (unsigned char *)realloc(p, 2 * count);
    if (!q) { free(p); return 12; }
    for (size_t i = 0; i < count; ++i) if (q[i] != (unsigned char)(i % 251)) { free(q); return 13; }
    free(q);
    int *z = (int *)calloc(1024, sizeof(int));
    if (!z) return 14;
    for (int i = 0; i < 1024; ++i) if (z[i]) { free(z); return 15; }
    free(z);
    puts("RM11_V19_MEMORY_OK");
    return 0;
}

static int test_file(const char *path) {
    if (!path || !*path) return 21;
    const char payload[] = "RM11_V19_FILE_CONTENT_7B3";
    char buf[sizeof(payload)] = {0};
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 22;
    int status = 0;
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload)) status = 23;
    if (!status && lseek(fd, 0, SEEK_SET) != 0) status = 24;
    if (!status && read(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) status = 25;
    if (!status && memcmp(payload, buf, sizeof(payload))) status = 26;
    if (close(fd) != 0 && !status) status = 27;
    if (unlink(path) != 0 && !status) status = 28;
    if (!status) puts("RM11_V19_FILE_OK");
    return status;
}

struct ThreadJob { uint64_t total; };
static void *worker(void *arg) {
    struct ThreadJob *job = (struct ThreadJob *)arg;
    uint64_t sum = 0;
    for (uint64_t i = 1; i <= 20000; ++i) sum += i;
    job->total = sum;
    return arg;
}
static int test_thread(void) {
    pthread_t a, b;
    struct ThreadJob x = {0}, y = {0};
    if (pthread_create(&a, NULL, worker, &x)) return 31;
    if (pthread_create(&b, NULL, worker, &y)) { pthread_join(a, NULL); return 32; }
    void *ra = NULL, *rb = NULL;
    if (pthread_join(a, &ra)) return 33;
    if (pthread_join(b, &rb)) return 34;
    if (ra != &x || rb != &y || x.total != 200010000ULL || y.total != 200010000ULL) return 35;
    puts("RM11_V19_THREAD_OK");
    return 0;
}

static int test_dlopen(void) {
    void *handle = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "RM11_DLOPEN_ERROR: %s\n", dlerror()); return 41; }
    dlerror();
    void *symbol = dlsym(handle, "cos");
    const char *error = dlerror();
    if (error || !symbol) { fprintf(stderr, "RM11_DLSYM_ERROR: %s\n", error ? error : "null symbol"); dlclose(handle); return 42; }
    /* ISO C does not generally guarantee object-to-function pointer casts.
       POSIX dlsym defines this use case; memcpy avoids a pedantic cast warning. */
    double (*cos_fn)(double) = NULL;
    if (sizeof(cos_fn) != sizeof(symbol)) { dlclose(handle); return 43; }
    memcpy(&cos_fn, &symbol, sizeof(symbol));
    double value = cos_fn(0.0);
    if (value < 0.999999 || value > 1.000001) { dlclose(handle); return 44; }
    if (dlclose(handle) != 0) return 45;
    puts("RM11_V19_DLOPEN_OK");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) return 90;
    if (strcmp(argv[1], "memory") == 0 && argc == 2) return test_memory();
    if (strcmp(argv[1], "file") == 0 && argc == 3) return test_file(argv[2]);
    if (strcmp(argv[1], "thread") == 0 && argc == 2) return test_thread();
    if (strcmp(argv[1], "dlopen") == 0 && argc == 2) return test_dlopen();
    return 91;
}
