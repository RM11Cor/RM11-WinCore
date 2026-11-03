#pragma once
// KERNIX G2-B: read-only host-memory image of REAL x86-64 ELF PT_LOADs.
// Does not execute guest code, apply relocations or run an interpreter/Wine.
// SPDX-License-Identifier: MIT
#include "kernix_guest_elf64_dynamic_audit.h"
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace kernix::g2b {

constexpr uint64_t kMaxGuestReadonlyImageBytes = 32ULL * 1024 * 1024;
struct GuestReadonlySegment {
    uint64_t fileOffset = 0;
    uint64_t guestVaddr = 0;
    uint64_t fileBytes = 0;
    uint64_t memoryBytes = 0;
    uint32_t guestFlags = 0;
};

struct GuestReadonlyImage {
    void* hostView = nullptr;
    size_t hostViewBytes = 0;
    uint64_t guestPageAlignedBase = 0;
    uint64_t guestEntry = 0;
    std::vector<GuestReadonlySegment> segments;
    bool hostViewReadOnly = false;
    bool hostViewExecutable = false;
    bool guestCodeExecuted = false;
    bool relocationsApplied = false;
    bool androidWineTested = false;

    GuestReadonlyImage() = default;
    GuestReadonlyImage(const GuestReadonlyImage&) = delete;
    GuestReadonlyImage& operator=(const GuestReadonlyImage&) = delete;
    void release() noexcept {
        if (hostView) munmap(hostView, hostViewBytes);
        hostView = nullptr;
        hostViewBytes = 0;
        guestPageAlignedBase = 0;
        guestEntry = 0;
        segments.clear();
        hostViewReadOnly = false;
        hostViewExecutable = false;
        guestCodeExecuted = false;
        relocationsApplied = false;
        androidWineTested = false;
    }
    ~GuestReadonlyImage() { release(); }
};

// Only a pinned trusted app-private Linux guest filesystem may be passed.
// This maps the *bytes* of every PT_LOAD into an anonymous, nonexecutable host
// view for later inspection. Its address is NOT yet the guest address used by
// FEXCore; nor does this implement Linux ELF relocations/initial stack/AUXV.
// Requiring guest PT_LOAD p_align to be compatible with actual host page size
// prevents silently adopting 4KiB x86 assets on 16KiB Android pages.
inline bool StageReadOnlyGuestELFImage(int trustedRootFd,
                                       std::string_view guestPath,
                                       GuestReadonlyImage& output,
                                       std::string& failure,
                                       bool mainExecutable = true) {
    output.release();
    auto reject = [&](const char* reason) {
        failure = reason;
        return false;
    };
    const long actualHostPage = sysconf(_SC_PAGESIZE);
    if (actualHostPage != 4096 && actualHostPage != 16384)
        return reject("GUEST_IMAGE_HOST_PAGE_SIZE_UNSUPPORTED");
    const uint64_t page = static_cast<uint64_t>(actualHostPage);
    const int fd = OpenGuestFileWithScopedSymlinks(trustedRootFd, guestPath);
    if (fd < 0) return reject("GUEST_IMAGE_PATH_NOT_IN_TRUSTED_ROOTFS");
    std::vector<unsigned char> raw;
    const bool validFile = ReadFilePrefix(fd, raw, kMaxAuditedGuestBytes);
    close(fd);
    if (!validFile || raw.size() < sizeof(Elf64_Ehdr))
        return reject("GUEST_IMAGE_FILE_SIZE_REJECTED");
    Elf64_Ehdr h{};
    std::memcpy(&h, raw.data(), sizeof(h));
    if (!GuestElfHeader(h) ||
        h.e_phentsize != sizeof(Elf64_Phdr) || h.e_phnum == 0 ||
        h.e_phnum > 128 ||
        !ElfRange(h.e_phoff,
                  static_cast<uint64_t>(h.e_phnum) * sizeof(Elf64_Phdr),
                  raw.size()))
        return reject("GUEST_IMAGE_ELF_HEADER_REJECTED");
    std::vector<GuestReadonlySegment> segs;
    uint64_t minimum = UINT64_MAX, maximum = 0;
    bool entryInsideExecutable = false;
    bool seenExecutable = false;
    for (unsigned i = 0; i < h.e_phnum; ++i) {
        Elf64_Phdr ph{};
        std::memcpy(&ph, raw.data() + h.e_phoff +
                          static_cast<size_t>(i) * sizeof(ph), sizeof(ph));
        if (ph.p_type == PT_GNU_STACK && (ph.p_flags & PF_X))
            return reject("GUEST_IMAGE_EXECUTABLE_STACK_REJECTED");
        if (ph.p_type != PT_LOAD) continue;
        if (!ph.p_memsz || ph.p_filesz > ph.p_memsz ||
            !ElfRange(ph.p_offset, ph.p_filesz, raw.size()) ||
            ph.p_vaddr > UINT64_MAX - ph.p_memsz ||
            ph.p_align < page || (ph.p_align & (ph.p_align - 1)) ||
            (ph.p_offset % ph.p_align) != (ph.p_vaddr % ph.p_align) ||
            (ph.p_flags & ~(PF_R | PF_W | PF_X)) ||
            !(ph.p_flags & PF_R) ||
            ((ph.p_flags & PF_W) && (ph.p_flags & PF_X)))
            return reject("GUEST_IMAGE_INVALID_OR_WRITABLE_EXECUTABLE_LOAD");
        const uint64_t end = ph.p_vaddr + ph.p_memsz;
        for (const auto& previous : segs) {
            if (ph.p_vaddr < previous.guestVaddr + previous.memoryBytes &&
                previous.guestVaddr < end)
                return reject("GUEST_IMAGE_OVERLAPPING_LOAD_SEGMENTS");
        }
        if (ph.p_flags & PF_X) {
            if (seenExecutable)
                return reject("GUEST_IMAGE_MORE_THAN_ONE_EXECUTABLE_SEGMENT");
            seenExecutable = true;
            if (h.e_entry >= ph.p_vaddr && h.e_entry < end)
                entryInsideExecutable = true;
        }
        minimum = std::min<uint64_t>(minimum, static_cast<uint64_t>(ph.p_vaddr));
        maximum = std::max(maximum, end);
        segs.push_back({ph.p_offset, ph.p_vaddr, ph.p_filesz,
                        ph.p_memsz, ph.p_flags});
    }
    if (segs.empty() || segs.size() > 16 || minimum == UINT64_MAX ||
        maximum <= minimum || !seenExecutable ||
        (mainExecutable && !entryInsideExecutable))
        return reject("GUEST_IMAGE_SEGMENT_OR_ENTRY_POLICY_REJECTED");
    const uint64_t alignedMinimum = minimum & ~(page - 1);
    if (maximum > UINT64_MAX - (page - 1))
        return reject("GUEST_IMAGE_VADDR_OVERFLOW");
    const uint64_t alignedMaximum = (maximum + page - 1) & ~(page - 1);
    if (alignedMaximum <= alignedMinimum ||
        alignedMaximum - alignedMinimum > kMaxGuestReadonlyImageBytes)
        return reject("GUEST_IMAGE_SPAN_REJECTED");
    const size_t length = static_cast<size_t>(alignedMaximum - alignedMinimum);
    void* mapping = mmap(nullptr, length, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return reject("GUEST_IMAGE_ANONYMOUS_MMAP_FAILED");
    for (const auto& s : segs) {
        const size_t dstOffset = static_cast<size_t>(
            s.guestVaddr - alignedMinimum);
        const size_t count = static_cast<size_t>(s.fileBytes);
        if (count)
            std::memcpy(static_cast<char*>(mapping) + dstOffset,
                        raw.data() + s.fileOffset, count);
        // Anonymous mmap already zero-fills the BSS tail.
    }
    // Do not make the x86 text executable on the ARM64 host. FEX's JIT must
    // later own actual guest virtual addresses and access permissions.
    if (mprotect(mapping, length, PROT_READ) != 0) {
        munmap(mapping, length);
        return reject("GUEST_IMAGE_READONLY_MPROTECT_FAILED");
    }
    output.hostView = mapping;
    output.hostViewBytes = length;
    output.guestPageAlignedBase = alignedMinimum;
    output.guestEntry = h.e_entry;
    output.segments = std::move(segs);
    output.hostViewReadOnly = true;
    failure = "none";
    return true;
}
} // namespace kernix::g2b
