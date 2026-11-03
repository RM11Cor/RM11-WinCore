#pragma once
// KERNIX G2-B: bounded symlink-aware, read-only guest rootfs file resolution.
// A HOST filesystem primitive only. NOT wired to FEX, Wine, ELF loader or games.
// SPDX-License-Identifier: MIT
#include <cerrno>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <utility>

namespace kernix::g2b {
constexpr size_t kMaxSymlinkGuestPath = 4096;
constexpr size_t kMaxSymlinkName = 255;
constexpr size_t kMaxPendingParts = 256;
constexpr size_t kMaxDirectoryDepth = 128;
constexpr unsigned kMaxSymlinkExpansions = 40;

// Forbid NUL, backslash, ASCII controls, duplicate or trailing separators.
// The initial guest path MUST be absolute, with no "." or ".." components.
// Symbolic-link targets may have "." and ".."; they are interpreted against
// the descriptor stack, never against the Android/Linux host path namespace.
inline bool SplitGuestComponents(std::string_view input, bool initial,
                                  std::deque<std::string>& parts) {
    if (input.empty() || input.size() > kMaxSymlinkGuestPath)
        return false;
    if (initial && (input.size() < 2 || input.front() != '/'))
        return false;
    for (char c : input) {
        if (c == '\0' || c == '\\' || (unsigned char)c < 32 || c == 127)
            return false;
    }
    size_t start = input.front() == '/' ? 1 : 0;
    if (start == input.size()) return false;
    while (start < input.size()) {
        const size_t slash = input.find('/', start);
        const size_t end = slash == std::string_view::npos ? input.size() : slash;
        auto part = input.substr(start, end - start);
        if (part.empty() || part.size() > kMaxSymlinkName ||
            (initial && (part == "." || part == "..")))
            return false;
        if (parts.size() >= kMaxPendingParts) return false;
        parts.emplace_back(part);
        if (slash == std::string_view::npos) break;
        start = slash + 1;
        if (start == input.size()) return false;
    }
    return !parts.empty();
}

// Open a file exclusively within the caller's already-open, trusted app
// private rootfd. Each component is inspected with O_PATH|O_NOFOLLOW and
// each link target is read from THAT symlink fd via readlinkat(fd, "").
// Host absolute link destinations are NEVER followed: "/" refers to rootfd.
// Invalid or over-root "..", device files, sockets, loops and race-changed
// final inodes are rejected. Calls perform no writes.
// PRECONDITION: rootfs is owned by this app and has no concurrent untrusted
// mutator that can rename/mount directories between fd opens. This is NOT an
// openat2 RESOLVE_IN_ROOT replacement for adversarial mutable directory trees.
inline int OpenGuestFileWithScopedSymlinks(int rootfd, std::string_view guest) {
    std::deque<std::string> remaining;
    if (!SplitGuestComponents(guest, true, remaining)) {
        errno = EINVAL;
        return -1;
    }
    int root = fcntl(rootfd, F_DUPFD_CLOEXEC, 0);
    if (root < 0) return -1;
    struct stat rootstat {};
    if (fstat(root, &rootstat) != 0 || !S_ISDIR(rootstat.st_mode)) {
        close(root);
        errno = ENOTDIR;
        return -1;
    }
    std::vector<int> dirfds{root};
    auto closeAll = [&]() {
        for (int fd : dirfds) close(fd);
        dirfds.clear();
    };
    auto fail = [&](int code) -> int {
        closeAll();
        errno = code;
        return -1;
    };
    unsigned symlinks = 0;
    while (!remaining.empty()) {
        auto part = std::move(remaining.front());
        remaining.pop_front();
        if (part == ".") continue;
        if (part == "..") {
            if (dirfds.size() == 1) return fail(EACCES);
            close(dirfds.back());
            dirfds.pop_back();
            continue;
        }
        int node = openat(dirfds.back(), part.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (node < 0) return fail(errno);
        struct stat info {};
        if (fstat(node, &info) != 0) {
            const int error = errno;
            close(node);
            return fail(error);
        }
        if (S_ISLNK(info.st_mode)) {
            if (++symlinks > kMaxSymlinkExpansions) {
                close(node);
                return fail(ELOOP);
            }
            char target[kMaxSymlinkGuestPath + 1];
            const ssize_t n = readlinkat(node, "", target, sizeof(target));
            const int error = errno;
            close(node);
            if (n < 1 || n >= static_cast<ssize_t>(sizeof(target)))
                return fail(n < 0 ? error : ENAMETOOLONG);
            std::deque<std::string> prefix;
            if (!SplitGuestComponents(std::string_view(target, static_cast<size_t>(n)),
                                      false, prefix)) return fail(EINVAL);
            if (prefix.size() + remaining.size() > kMaxPendingParts)
                return fail(ENAMETOOLONG);
            if (target[0] == '/') {
                while (dirfds.size() > 1) {
                    close(dirfds.back());
                    dirfds.pop_back();
                }
            }
            prefix.insert(prefix.end(), remaining.begin(), remaining.end());
            remaining.swap(prefix);
            continue;
        }
        if (S_ISDIR(info.st_mode)) {
            if (remaining.empty()) {
                close(node);
                return fail(EISDIR);
            }
            if (dirfds.size() >= kMaxDirectoryDepth) {
                close(node);
                return fail(ENAMETOOLONG);
            }
            dirfds.push_back(node);
            continue;
        }
        if (!S_ISREG(info.st_mode) || !remaining.empty()) {
            close(node);
            return fail(S_ISREG(info.st_mode) ? ENOTDIR : EINVAL);
        }
        // Only the final regular file is opened for actual read access.
        // A last-component swap to another inode must not silently pass.
        int fd = openat(dirfds.back(), part.c_str(),
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        const int openError = errno;
        if (fd < 0) {
            close(node);
            return fail(openError);
        }
        struct stat finalstat {};
        if (fstat(fd, &finalstat) != 0 || !S_ISREG(finalstat.st_mode) ||
            finalstat.st_dev != info.st_dev || finalstat.st_ino != info.st_ino) {
            close(fd);
            close(node);
            return fail(EAGAIN);
        }
        close(node);
        closeAll();
        return fd;
    }
    return fail(EISDIR);
}
}
