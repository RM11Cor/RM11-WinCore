#include "fex_bionic_shm_compat.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/memfd.h>

/*
 * FEX-2609 UnixLib's optional statistics use shm_open("fex-<pid>-stats").
 * Android Bionic has no POSIX named shm, so keep one process-local table of
 * memfd descriptors. This doesn't implement cross-process named-shm discovery.
 * It only supplies the same-process reopen semantics used in FEXUnixLib.cpp.
 * No device permissions, root or /dev/shm access required.
 */
namespace {
std::mutex gMutex;
std::unordered_map<std::string, int> gDescriptors;

bool valid_name(const char *name) {
    if (!name) return false;
    size_t n = strnlen(name, 96);
    if (n < 5 || n >= 96 || strncmp(name, "fex-", 4)) return false;
    for (size_t i = 4; i < n; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    return true;
}
}

extern "C" int rm11_fex_shm_open(const char *name, int flags, mode_t mode) {
    (void)mode;
    if (!valid_name(name)) {
        errno = EINVAL;
        return -1;
    }
    std::lock_guard<std::mutex> lock(gMutex);
    const std::string key(name);
    auto found = gDescriptors.find(key);
    if (found != gDescriptors.end()) {
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
            errno = EEXIST;
            return -1;
        }
        int fd = dup(found->second);
        if (fd >= 0 && (flags & O_TRUNC) && ftruncate(fd, 0) < 0) {
            const int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        return fd;
    }
    if (!(flags & O_CREAT)) {
        errno = ENOENT;
        return -1;
    }
    const int fd = static_cast<int>(
            syscall(SYS_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING));
    if (fd < 0) return -1;
    const int userFd = dup(fd);
    if (userFd < 0) {
        const int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    gDescriptors.emplace(key, fd);
    return userFd;
}

extern "C" int rm11_fex_shm_unlink(const char *name) {
    if (!valid_name(name)) {
        errno = EINVAL;
        return -1;
    }
    std::lock_guard<std::mutex> lock(gMutex);
    const auto iter = gDescriptors.find(std::string(name));
    if (iter == gDescriptors.end()) {
        errno = ENOENT;
        return -1;
    }
    close(iter->second);
    gDescriptors.erase(iter);
    return 0;
}
