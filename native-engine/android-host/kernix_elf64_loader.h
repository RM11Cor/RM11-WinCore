// KERNIX original bounded in-memory ELF64/x86-64 image loader.
// SPDX-License-Identifier: MIT. A narrowly fixed trusted fixture only.
// No filesystem, PT_INTERP, relocations, guest libraries or arbitrary ELF.
#pragma once

#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace kernix {
struct GuestELF {
    void* base = nullptr;
    size_t size = 0;
    uintptr_t entry = 0;
    uintptr_t executable = 0;
    size_t executableSize = 0;
    uintptr_t message = 0;
    size_t messageSize = 0;

    // The caller runs in a bounded disposable process.
    void release() {
        if (base != nullptr) munmap(base, size);
        *this = {};
    }
    bool containsReadOnlyMessage(uint64_t address, uint64_t bytes) const {
        return message != 0 && address == message && bytes == 28 && messageSize >= bytes;
    }
};

// End exclusive. All pointer arithmetic happens after bounded ELF checks.
inline bool isBounded(uint64_t off, uint64_t count, uint64_t limit) {
    return off <= limit && count <= limit - off;
}

inline bool loadFixedGuestELF(const unsigned char* data, size_t length,
                              GuestELF& result, const char*& failure) {
    failure = "unknown";
    if (!data || length < sizeof(Elf64_Ehdr) || length > 131072) {
        failure = "bad ELF size"; return false;
    }
    Elf64_Ehdr eh{};
    std::memcpy(&eh, data, sizeof(eh));
    if (std::memcmp(eh.e_ident, ELFMAG, SELFMAG) ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_machine != EM_X86_64 || eh.e_type != ET_DYN ||
        eh.e_version != EV_CURRENT || eh.e_ehsize != sizeof(Elf64_Ehdr) ||
        eh.e_phentsize != sizeof(Elf64_Phdr) ||
        eh.e_phnum != 6 || eh.e_phnum == 0 ||
        !isBounded(eh.e_phoff, uint64_t(eh.e_phnum) * sizeof(Elf64_Phdr), length)) {
        failure = "ELF64 x86 PIE header rejected"; return false;
    }
    const long platformPage = sysconf(_SC_PAGESIZE);
    if (platformPage < 4096 || platformPage > 16384 ||
        (platformPage & (platformPage - 1))) {
        failure = "unsupported Android page size"; return false;
    }
    const uint64_t page = static_cast<uint64_t>(platformPage);
    // 16 KiB linker alignment works with both 4 KiB and 16 KiB devices.
    Elf64_Phdr ph[6]{};
    std::memcpy(ph, data + eh.e_phoff, sizeof(ph));
    uint64_t minAddress = UINT64_MAX, maxAddress = 0;
    unsigned loads = 0, textLoads = 0, dataLoads = 0, roLoads = 0;
    unsigned dynamicHeaders = 0;
    for (const auto& p : ph) {
        if (p.p_type == PT_INTERP || p.p_type == PT_TLS) {
            failure = "interpreter/TLS forbidden"; return false;
        }
        if (p.p_type == PT_GNU_STACK && (p.p_flags & PF_X)) {
            failure = "executable stack forbidden"; return false;
        }
        if (p.p_type == PT_DYNAMIC) {
            if (++dynamicHeaders > 1 ||
                !isBounded(p.p_offset, p.p_filesz, length) ||
                p.p_filesz % sizeof(Elf64_Dyn) != 0) {
                failure = "dynamic metadata out of bounds"; return false;
            }
            // The compiled fixture contains no relocations or dependencies.
            bool sawTerminator = false;
            for (uint64_t i = 0; i < p.p_filesz; i += sizeof(Elf64_Dyn)) {
                Elf64_Dyn dyn{};
                std::memcpy(&dyn, data + p.p_offset + i, sizeof(dyn));
                if (dyn.d_tag == DT_NULL) { sawTerminator = true; break; }
                if (dyn.d_tag == DT_NEEDED || dyn.d_tag == DT_RELA ||
                    dyn.d_tag == DT_RELASZ || dyn.d_tag == DT_REL ||
                    dyn.d_tag == DT_RELSZ || dyn.d_tag == DT_JMPREL ||
                    dyn.d_tag == DT_PLTRELSZ || dyn.d_tag == DT_TEXTREL ||
                    dyn.d_tag == DT_INIT || dyn.d_tag == DT_INIT_ARRAY) {
                    failure = "relocations or dynamic dependencies forbidden"; return false;
                }
            }
            if (!sawTerminator) {
                failure = "no DT_NULL in dynamic table"; return false;
            }
        }
        if (p.p_type != PT_LOAD) continue;
        ++loads;
        if (p.p_filesz > p.p_memsz || !p.p_memsz ||
            !isBounded(p.p_offset, p.p_filesz, length) ||
            p.p_vaddr >= 65536 || p.p_memsz > 65536 - p.p_vaddr ||
            p.p_align != 16384 ||
            (p.p_offset % page) != (p.p_vaddr % page) ||
            !(p.p_flags & PF_R) ||
            (p.p_flags & ~(PF_R | PF_W | PF_X)) ||
            ((p.p_flags & PF_W) && (p.p_flags & PF_X))) {
            failure = "invalid/unsafe PT_LOAD"; return false;
        }
        const uint64_t begin = p.p_vaddr & ~(page - 1);
        const uint64_t end = (p.p_vaddr + p.p_memsz + page - 1) & ~(page - 1);
        if (end > 65536) { failure = "guest span too large"; return false; }
        if (begin < minAddress) minAddress = begin;
        if (end > maxAddress) maxAddress = end;
        if (p.p_flags == (PF_R | PF_X)) ++textLoads;
        else if (p.p_flags == (PF_R | PF_W)) ++dataLoads;
        else if (p.p_flags == PF_R) ++roLoads;
        else { failure = "unsupported load flags"; return false; }
    }
    if (loads != 4 || textLoads != 1 || dataLoads != 1 || roLoads != 2 ||
        dynamicHeaders != 1 || minAddress != 0 || maxAddress != 65536 ||
        eh.e_entry != 0x4000) {
        failure = "not pinned four-segment 16KiB-aligned ELF"; return false;
    }

    void* mapped = mmap(nullptr, maxAddress, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mapped == MAP_FAILED) { failure = "mmap failed"; return false; }
    const uintptr_t base = reinterpret_cast<uintptr_t>(mapped);
    for (const auto& p : ph) {
        if (p.p_type != PT_LOAD) continue;
        std::memcpy(reinterpret_cast<void*>(base + p.p_vaddr),
                    data + p.p_offset, static_cast<size_t>(p.p_filesz));
        if (p.p_memsz > p.p_filesz)
            std::memset(reinterpret_cast<void*>(base + p.p_vaddr + p.p_filesz),
                        0, static_cast<size_t>(p.p_memsz - p.p_filesz));
    }
    if (mprotect(mapped, maxAddress, PROT_NONE) != 0) {
        munmap(mapped, maxAddress); failure = "mprotect reserve failed"; return false;
    }
    GuestELF output{};
    output.base = mapped;
    output.size = static_cast<size_t>(maxAddress);
    output.entry = base + static_cast<uintptr_t>(eh.e_entry);
    for (const auto& p : ph) {
        if (p.p_type != PT_LOAD) continue;
        int prot = PROT_READ;
        if (p.p_flags & PF_X) prot |= PROT_EXEC;
        if (p.p_flags & PF_W) prot |= PROT_WRITE;
        const uintptr_t begin = base + (p.p_vaddr & ~(page - 1));
        const uintptr_t end = base + ((p.p_vaddr + p.p_memsz + page - 1) & ~(page - 1));
        if (mprotect(reinterpret_cast<void*>(begin), end - begin, prot) != 0) {
            munmap(mapped, maxAddress); failure = "segment mprotect failed"; return false;
        }
        if (p.p_flags & PF_X) {
            output.executable = base + static_cast<uintptr_t>(p.p_vaddr);
            output.executableSize = static_cast<size_t>(p.p_memsz);
            if (output.entry < output.executable ||
                output.entry >= output.executable + output.executableSize) {
                munmap(mapped, maxAddress); failure = "entry outside executable"; return false;
            }
        }
        // For this compiled fixture .rodata is exactly the third PT_LOAD.
        if (p.p_flags == PF_R && p.p_vaddr == 32768) {
            output.message = base + static_cast<uintptr_t>(p.p_vaddr);
            output.messageSize = static_cast<size_t>(p.p_filesz);
        }
    }
    if (!output.executable || !output.message || output.messageSize != 32 ||
        output.entry != output.executable) {
        munmap(mapped, maxAddress); failure = "fixed executable/rodata not found"; return false;
    }
    result = output;
    failure = "none";
    return true;
}
} // namespace kernix
