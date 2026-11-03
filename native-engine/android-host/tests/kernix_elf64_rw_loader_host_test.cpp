// Pure host-side mapping of original ELF writable data, no x86 guest code run.
// SPDX-License-Identifier: MIT
#include "kernix_elf64_loader.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <cstring>

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) return 2;
    std::vector<unsigned char> elf(
        std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{});
    kernix::GuestELF image{};
    const char* reason = nullptr;
    const auto rw = kernix::GuestLayout::WritableMemoryCopy;
    if (!kernix::loadFixedGuestELF(elf.data(), elf.size(), image, reason, rw)) {
        std::cerr << "real pinned ELF RW fixture rejected: " << reason << "\n";
        return 3;
    }
    constexpr char message[] = "KERNIX_ELF_RW_MEMORY_PASS\n";
    if (image.entry != image.executable || image.executableSize != 58 ||
        image.messageSize != 32 || !image.containsWritableMessage(image.writableData,26) ||
        std::memcmp(reinterpret_cast<const void*>(image.message),message,26) ||
        std::memcmp(reinterpret_cast<const void*>(image.writableData),
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",26)) return 4;
    image.release();
    // Reject wrong profile (v0.10 still takes exactly its original layout).
    if (kernix::loadFixedGuestELF(elf.data(), elf.size(), image, reason)) return 5;
    // Reject unexpected header, corrupt RW flag and truncated program header.
    for (size_t offset: {0UL, 4UL, 5UL, 16UL, 18UL, 24UL, 56UL}) {
        auto copy=elf;
        copy[offset]^=0x55;
        if (kernix::loadFixedGuestELF(copy.data(),copy.size(),image,reason,rw)) return 6;
    }
    auto copy=elf;
    constexpr size_t kRWFlagsAt = 64 + 3*56 + 4;
    copy[kRWFlagsAt]=7; // never permit RWX
    if (kernix::loadFixedGuestELF(copy.data(),copy.size(),image,reason,rw)) return 7;
    copy=elf;
    copy.resize(50);
    if (kernix::loadFixedGuestELF(copy.data(),copy.size(),image,reason,rw)) return 8;
    std::cout << "KERNIX_HOST_ELF64_ACTUAL_GUEST_RW_PROTECTION_AND_MUTATION_CHECKS_PASS\n";
    return 0;
}
