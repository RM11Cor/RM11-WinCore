// Host-only validator regression: mapping true ELF64 fixture without executing HLT.
// SPDX-License-Identifier: MIT.
#include "kernix_elf64_loader.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <cstring>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    std::ifstream source(argv[1], std::ios::binary);
    if (!source) return 2;
    std::vector<unsigned char> elf(
        (std::istreambuf_iterator<char>(source)),
        std::istreambuf_iterator<char>());
    kernix::GuestELF mapped{};
    const char *why = nullptr;
    if (!kernix::loadFixedGuestELF(elf.data(), elf.size(), mapped, why)) {
        std::cerr << "valid original GNU ELF rejected: " << (why ? why : "?") << "\n";
        return 3;
    }
    constexpr char msg[] = "KERNIX_ELF64_GUEST_RUN_PASS\n";
    if (mapped.messageSize != 32 ||
        !mapped.containsReadOnlyMessage(mapped.message, sizeof(msg)-1) ||
        std::memcmp(reinterpret_cast<void*>(mapped.message), msg, sizeof(msg)-1) != 0 ||
        !mapped.entry || mapped.entry != mapped.executable ||
        mapped.executableSize != 37) return 4;
    mapped.release();

    // Prove malformed/malicious ELF headers are rejected and never mapped.
    const auto original=elf;
    for (size_t off: {0UL, 4UL, 5UL, 16UL, 18UL, 24UL, 32UL, 54UL, 56UL}) {
        elf=original; elf[off] ^= 0x55;
        kernix::GuestELF rejected{};
        if (kernix::loadFixedGuestELF(elf.data(), elf.size(), rejected, why)) {
            rejected.release();
            std::cerr << "modified ELF accepted at offset " << off << "\n";
            return 5;
        }
    }
    elf=original;
    elf.resize(48); // truncated program headers
    if (kernix::loadFixedGuestELF(elf.data(),elf.size(),mapped,why)) return 6;
    std::cout << "KERNIX_HOST_ELF64_HEADER_SEGMENT_PROTECTION_AND_NEGATIVE_GATES_PASS\n";
    return 0;
}
