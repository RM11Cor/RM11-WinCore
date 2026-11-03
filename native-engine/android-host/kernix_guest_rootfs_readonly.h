#pragma once
// KERNIX G2-B: read-only guest path resolution inside an app-owned rootfs.
// This is a host filesystem primitive, NOT an active FEX/Wine syscall bridge.
// SPDX-License-Identifier: MIT
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace kernix::g2b {
constexpr size_t kMaxGuestPath = 4096;
constexpr size_t kMaxComponent = 255;

// rootfd must be an already-open, trusted app-private root directory fd.
// Guest absolute paths are resolved relative to it, without following any
// symlink in any component. On success, returns a readable regular-file fd.
// Never creates files or writes to any host/system path.
inline int OpenReadOnlyGuestRegularFile(int rootfd, std::string_view guest) {
    if (rootfd < 0 || guest.size() < 2 || guest.size() > kMaxGuestPath || guest.front() != '/') {
        errno = EINVAL;
        return -1;
    }
    for (const char c : guest) {
        if (c == '\0' || c == '\\' || static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
            errno = EINVAL;
            return -1;
        }
    }
    // The caller's original rootfd is never closed or mutated.
    int parent = fcntl(rootfd, F_DUPFD_CLOEXEC, 0);
    if (parent < 0) return -1;
    size_t start = 1;
    while (start < guest.size()) {
        const size_t slash = guest.find('/', start);
        const size_t end = slash == std::string_view::npos ? guest.size() : slash;
        const std::string_view part = guest.substr(start, end - start);
        if (part.empty() || part.size() > kMaxComponent || part == "." || part == "..") {
            close(parent);
            errno = EINVAL;
            return -1;
        }
        char name[kMaxComponent + 1];
        std::memcpy(name, part.data(), part.size());
        name[part.size()] = '\0';
        const bool isLast = end == guest.size();
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
        if (!isLast) flags |= O_DIRECTORY;
        int fd = openat(parent, name, flags);
        const int open_error = errno;
        close(parent);
        if (fd < 0) {
            errno = open_error;
            return -1;
        }
        parent = fd;
        if (isLast) {
            struct stat info {};
            if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
                close(fd);
                errno = EINVAL;
                return -1;
            }
            return fd;
        }
        start = end + 1;
    }
    close(parent);
    errno = EINVAL; // trailing slash
    return -1;
}
}
