/* RM11 native runtime bootstrap: checks Android ARM64 JIT prerequisites.
 * This is NOT Wine, FEXCore, an EXE loader, or proof of a game runtime.
 * W^X: memory is never simultaneously writable and executable.
 */
#include <jni.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Test real AArch64 instructions: MOV W0, #42; RET. */
static int test_jit(int *error_code, int *returned_value) {
#if defined(__aarch64__)
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        *error_code = EINVAL;
        return 0;
    }
    void *mem = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        *error_code = errno;
        return 0;
    }
    const uint32_t opcodes[2] = {0x52800540u, 0xd65f03c0u};
    memcpy(mem, opcodes, sizeof(opcodes));
    __builtin___clear_cache((char *)mem, (char *)mem + sizeof(opcodes));
    if (mprotect(mem, (size_t)page, PROT_READ | PROT_EXEC) != 0) {
        *error_code = errno;
        munmap(mem, (size_t)page);
        return 0;
    }
    int (*entry)(void) = NULL;
    memcpy(&entry, &mem, sizeof(entry));
    *returned_value = entry();
    munmap(mem, (size_t)page);
    return *returned_value == 42;
#else
    *error_code = ENOTSUP;
    (void)returned_value;
    return 0;
#endif
}

JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_RuntimeNativeProbe_nativeProbe(JNIEnv *env, jclass unused) {
    (void)unused;
    struct utsname system_info;
    const char *machine = "unknown";
    if (uname(&system_info) == 0) {
        machine = system_info.machine;
    }
    int error_code = 0;
    int returned_value = 0;
    int ok = test_jit(&error_code, &returned_value);
    char json[512];
    snprintf(json, sizeof(json),
             "{\"stage\":\"native-arm64-jit\",\"machine\":\"%.96s\","
             "\"nativeLibraryLoaded\":true,\"jitOk\":%s,"
             "\"jitReturned\":%d,\"osError\":%d,"
             "\"windowsRuntimeIntegrated\":false}",
             machine, ok ? "true" : "false", returned_value, error_code);
    return (*env)->NewStringUTF(env, json);
}
