// KERNIX G2-B Android/Bionic-facing read-only guest library closure gateway.
// Compile-time/external artifact proof ONLY; not packaged into APK or run
// on a device yet. No root, Wine, guest executable memory or syscalls.
// SPDX-License-Identifier: MIT
#include "kernix_guest_elf64_dependency_closure.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error This G2-B bridge must use the Android AArch64 NDK and Bionic ABI.
#endif

// The caller MUST provide a trusted, already-open, app-private rootfs FD.
// The rootfs must not be concurrently modified by an untrusted process.
// Linux guest files are inspected, never loaded as native Android code.
// A success indicates only that bounded on-disk ELF metadata is consistent.
extern "C" __attribute__((visibility("default")))
int kernix_g2b_android_verify_guest_elf_closure_readonly(
    int app_private_rootfd, const char* guest_executable,
    uint32_t* object_count, uint32_t* direct_edge_count) noexcept {
    if (object_count) *object_count = 0;
    if (direct_edge_count) *direct_edge_count = 0;
    if (app_private_rootfd < 0 || guest_executable == nullptr ||
        object_count == nullptr || direct_edge_count == nullptr) {
        return -EINVAL;
    }
    const size_t length = strnlen(guest_executable,
                                   kernix::g2b::kMaxSymlinkGuestPath + 1);
    if (length < 2 || length > kernix::g2b::kMaxSymlinkGuestPath ||
        guest_executable[0] != '/') return -EINVAL;
    try {
        kernix::g2b::GuestDependencyClosure closure;
        std::string failure;
        if (!kernix::g2b::AuditGuestELFDependencyClosure(
                app_private_rootfd, std::string_view(guest_executable, length),
                closure, failure) ||
            !closure.allDirectAndTransitiveFilesPresent ||
            closure.guestCodeExecuted || closure.androidWineTested ||
            closure.symbolVersionsResolved || closure.relocationsApplied ||
            closure.nodes.empty()) {
            return -ENOEXEC;
        }
        *object_count = static_cast<uint32_t>(closure.nodes.size());
        *direct_edge_count = static_cast<uint32_t>(closure.resolvedEdges);
        return 0;
    } catch (...) {
        return -EFAULT;
    }
}
