// KERNIX G2-B Android ARM64 standalone, build-only PT_LOAD staging proof.
// Never packages a Linux ELF as an Android native library; no guest exec.
// SPDX-License-Identifier: MIT
#include "kernix_guest_elf64_readonly_image.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error Expected original Android ARM64 NDK with Bionic, not Linux glibc
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2b_stage_scoped_x86_elf_ptloads_readonly(
    int private_root_dirfd, const char* guest_absolute_path,
    uint32_t* loaded_segment_count, uint64_t* readonly_image_size) noexcept {
    if (loaded_segment_count) *loaded_segment_count = 0;
    if (readonly_image_size) *readonly_image_size = 0;
    if (private_root_dirfd < 0 || guest_absolute_path == nullptr ||
        loaded_segment_count == nullptr || readonly_image_size == nullptr)
        return -EINVAL;
    const size_t n = strnlen(guest_absolute_path,
                            kernix::g2b::kMaxSymlinkGuestPath + 1);
    if (n < 2 || n > kernix::g2b::kMaxSymlinkGuestPath ||
        guest_absolute_path[0] != '/') return -EINVAL;
    try {
        kernix::g2b::GuestReadonlyImage image;
        std::string failure;
        const bool valid = kernix::g2b::StageReadOnlyGuestELFImage(
            private_root_dirfd, std::string_view(guest_absolute_path, n),
            image, failure);
        if (!valid || !image.hostView || image.segments.empty() ||
            !image.hostViewReadOnly || image.hostViewExecutable ||
            image.guestCodeExecuted || image.relocationsApplied ||
            image.androidWineTested)
            return -ENOEXEC;
        *loaded_segment_count = static_cast<uint32_t>(image.segments.size());
        *readonly_image_size = static_cast<uint64_t>(image.hostViewBytes);
        // Guest image is unmapped by its RAII object upon returning. It
        // must not be retained as an executable mapping or FEX guest stack.
        return 0;
    } catch (...) {
        return -EFAULT;
    }
}
