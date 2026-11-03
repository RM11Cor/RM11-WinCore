#pragma once
// KERNIX G2-B: read-only inspection of PT_INTERP and direct DT_NEEDED from
// real guest x86_64 ELF in a trusted app-owned root. No guest execution.
// SPDX-License-Identifier: MIT
#include "kernix_guest_rootfs_symlinks.h"
#include <elf.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace kernix::g2b {
struct GuestDynamicAudit {
    std::string executable;
    std::string interpreter;
    std::vector<std::string> needed;
    std::vector<std::string> resolvedDirectLibraries;
    bool readOnly = false;
    bool executableLoaded = false;
    bool guestCodeExecuted = false;
    bool androidWineTested = false;
};
constexpr size_t kMaxAuditedGuestBytes = 16 * 1024 * 1024;
constexpr size_t kMaxDynamicEntries = 4096;
constexpr size_t kMaxNeeded = 96;

inline bool ElfRange(uint64_t off, uint64_t count, uint64_t limit) {
    return off <= limit && count <= limit - off;
}
inline bool GuestElfHeader(const Elf64_Ehdr& h) {
    return std::memcmp(h.e_ident, ELFMAG, SELFMAG) == 0 &&
           h.e_ident[EI_CLASS] == ELFCLASS64 &&
           h.e_ident[EI_DATA] == ELFDATA2LSB &&
           h.e_ident[EI_VERSION] == EV_CURRENT &&
           h.e_machine == EM_X86_64 && h.e_version == EV_CURRENT &&
           (h.e_type == ET_DYN || h.e_type == ET_EXEC) &&
           h.e_ehsize == sizeof(Elf64_Ehdr);
}
inline bool ReadFilePrefix(int fd, std::vector<unsigned char>& bytes, size_t cap) {
    struct stat st {};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        static_cast<uint64_t>(st.st_size) > cap) return false;
    bytes.resize(static_cast<size_t>(st.st_size));
    size_t done = 0;
    while (done < bytes.size()) {
        ssize_t n = pread(fd, bytes.data() + done, bytes.size() - done,
                          static_cast<off_t>(done));
        if (n <= 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}
inline bool IsValidNeededName(std::string_view s) {
    if (s.empty() || s.size() > 200 || s == "." || s == ".." ||
        s.front() == '.' || s.front() == '-') return false;
    for (char c : s) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '.' ||
              c == '-' || c == '+' || c == '@')) return false;
    }
    return true;
}
inline bool BoundedGuestELFIdentity(int root, std::string_view path) {
    int fd = OpenGuestFileWithScopedSymlinks(root, path);
    if (fd < 0) return false;
    Elf64_Ehdr hdr {};
    const ssize_t n = pread(fd, &hdr, sizeof(hdr), 0);
    close(fd);
    return n == static_cast<ssize_t>(sizeof(hdr)) && GuestElfHeader(hdr);
}

// Shared-library mode (requireInterpreter=false) accepts ET_DYN x86-64
// objects with PT_DYNAMIC and zero or one PT_INTERP. Real glibc libc.so.6
// has its own PT_INTERP and is also runnable to print version information.
// Every present interpreter must resolve inside the guest rootfs.
// Fixed default directories only. DT_RUNPATH/RPATH deliberately rejected:
// resolving $ORIGIN, symbol versions and transitive libraries requires the
// later genuine dynamic linker; these are not execution or import guarantees.
inline bool AuditGuestDynamicELF(int root, std::string_view guest,
                                 GuestDynamicAudit& out, std::string& error,
                                 bool requireInterpreter = true) {
    out = {};
    auto reject = [&](const char* reason) -> bool { error = reason; return false; };
    int fd = OpenGuestFileWithScopedSymlinks(root, guest);
    if (fd < 0) return reject("GUEST_ELF_NOT_FOUND_IN_ROOTFS");
    std::vector<unsigned char> bytes;
    const bool loaded = ReadFilePrefix(fd, bytes, kMaxAuditedGuestBytes);
    close(fd);
    if (!loaded || bytes.size() < sizeof(Elf64_Ehdr))
        return reject("BAD_GUEST_ELF_FILE_SIZE");
    Elf64_Ehdr head {};
    std::memcpy(&head, bytes.data(), sizeof(head));
    if (!GuestElfHeader(head) || head.e_phentsize != sizeof(Elf64_Phdr) ||
        head.e_phnum == 0 || head.e_phnum > 128 ||
        !ElfRange(head.e_phoff, static_cast<uint64_t>(head.e_phnum) *
                               sizeof(Elf64_Phdr), bytes.size()))
        return reject("BAD_ELF64_X86_HEADER_OR_PHDR");
    std::vector<Elf64_Phdr> phdrs(head.e_phnum);
    std::memcpy(phdrs.data(), bytes.data() + head.e_phoff,
                phdrs.size() * sizeof(Elf64_Phdr));
    std::string interpreter;
    Elf64_Phdr dynPh {};
    bool seenDynamic = false;
    unsigned interpCount = 0;
    for (const Elf64_Phdr& ph : phdrs) {
        if (ph.p_type == PT_LOAD &&
            (ph.p_filesz > ph.p_memsz ||
             !ElfRange(ph.p_offset, ph.p_filesz, bytes.size())))
            return reject("BAD_LOAD_SEGMENT_BOUNDS");
        if (ph.p_type == PT_INTERP) {
            if (++interpCount != 1 || ph.p_filesz < 3 || ph.p_filesz > 256 ||
                !ElfRange(ph.p_offset, ph.p_filesz, bytes.size()))
                return reject("INVALID_PT_INTERP");
            const char* base = reinterpret_cast<const char*>(
                bytes.data() + ph.p_offset);
            if (base[ph.p_filesz - 1] != '\0' ||
                std::memchr(base, '\0', ph.p_filesz - 1) != nullptr)
                return reject("INVALID_PT_INTERP_STRING");
            interpreter.assign(base, ph.p_filesz - 1);
            if (interpreter.empty() || interpreter.front() != '/')
                return reject("INTERP_NOT_ABSOLUTE_GUEST_PATH");
        }
        if (ph.p_type == PT_DYNAMIC) {
            if (seenDynamic || ph.p_filesz == 0 ||
                ph.p_filesz % sizeof(Elf64_Dyn) != 0 ||
                ph.p_filesz / sizeof(Elf64_Dyn) > kMaxDynamicEntries ||
                !ElfRange(ph.p_offset, ph.p_filesz, bytes.size()))
                return reject("INVALID_DYNAMIC_SEGMENT");
            seenDynamic = true;
            dynPh = ph;
        }
    }
    if ((requireInterpreter && interpCount != 1) || !seenDynamic)
        return reject("INTERPRETER_POLICY_OR_DYNAMIC_TABLE_MISMATCH");
    uint64_t strVaddr = 0, strSize = 0;
    bool seenStrVaddr = false, seenStrSize = false, seenEnd = false;
    std::vector<uint64_t> offsets;
    const size_t count = static_cast<size_t>(dynPh.p_filesz / sizeof(Elf64_Dyn));
    for (size_t i = 0; i < count; ++i) {
        Elf64_Dyn dyn {};
        std::memcpy(&dyn, bytes.data() + dynPh.p_offset + i * sizeof(dyn),
                    sizeof(dyn));
        if (dyn.d_tag == DT_NULL) { seenEnd = true; break; }
        if (dyn.d_tag == DT_STRTAB) {
            if (seenStrVaddr) return reject("DUPLICATE_DYNAMIC_STRTAB");
            seenStrVaddr = true; strVaddr = dyn.d_un.d_ptr;
        } else if (dyn.d_tag == DT_STRSZ) {
            if (seenStrSize) return reject("DUPLICATE_DYNAMIC_STRSZ");
            seenStrSize = true; strSize = dyn.d_un.d_val;
        } else if (dyn.d_tag == DT_NEEDED) {
            if (offsets.size() >= kMaxNeeded)
                return reject("TOO_MANY_DIRECT_DEPENDENCIES");
            offsets.push_back(dyn.d_un.d_val);
        } else if (dyn.d_tag == DT_RPATH || dyn.d_tag == DT_RUNPATH) {
            return reject("RUNPATH_NOT_YET_SUPPORTED_FOR_ISOLATED_ROOTFS");
        }
    }
    if (!seenEnd || !seenStrVaddr || !seenStrSize ||
        strSize == 0 || strSize > 1024 * 1024)
        return reject("BAD_DYNAMIC_STRING_TABLE");
    // DT_STRTAB holds an ELF *virtual address*, not a physical file offset.
    uint64_t strOffset = 0;
    bool strMapped = false;
    for (const Elf64_Phdr& ph : phdrs) {
        if (ph.p_type != PT_LOAD || strVaddr < ph.p_vaddr) continue;
        const uint64_t relative = strVaddr - ph.p_vaddr;
        if (!ElfRange(relative, strSize, ph.p_filesz)) continue;
        if (ph.p_offset > UINT64_MAX - relative) continue;
        const uint64_t candidate = ph.p_offset + relative;
        if (!ElfRange(candidate, strSize, bytes.size())) continue;
        if (strMapped) return reject("AMBIGUOUS_DYNAMIC_STRTAB_MAPPING");
        strOffset = candidate; strMapped = true;
    }
    if (!strMapped) return reject("UNMAPPED_DYNAMIC_STRING_TABLE");
    std::vector<std::string> names;
    for (uint64_t offset : offsets) {
        if (offset >= strSize) return reject("DT_NEEDED_OUT_OF_BOUNDS");
        const char* start = reinterpret_cast<const char*>(
            bytes.data() + strOffset + offset);
        const void* end = std::memchr(
            start, '\0', static_cast<size_t>(strSize - offset));
        if (!end) return reject("UNTERMINATED_NEEDED_NAME");
        const size_t len = static_cast<const char*>(end) - start;
        const std::string_view name(start, len);
        if (!IsValidNeededName(name)) return reject("BAD_DT_NEEDED_NAME");
        if (std::find(names.begin(), names.end(), name) != names.end())
            return reject("DUPLICATE_NEEDED_NAME");
        names.emplace_back(name);
    }
    if (interpCount != 0 && !BoundedGuestELFIdentity(root, interpreter))
        return reject("GUEST_DYNAMIC_INTERPRETER_MISSING_OR_WRONG_ARCH");
    std::vector<std::string> libraries;
    for (const auto& name : names) {
        std::string located;
        for (const char* directory : {"/lib/x86_64-linux-gnu/",
                                      "/usr/lib/x86_64-linux-gnu/",
                                      "/lib64/"}) {
            std::string path = std::string(directory) + name;
            if (BoundedGuestELFIdentity(root, path)) {
                located = std::move(path);
                break;
            }
        }
        if (located.empty())
            return reject("DIRECT_NEEDED_NOT_PRESENT_IN_ROOTFS");
        libraries.push_back(std::move(located));
    }
    out.executable.assign(guest);
    out.interpreter = std::move(interpreter);
    out.needed = std::move(names);
    out.resolvedDirectLibraries = std::move(libraries);
    out.readOnly = true;
    out.executableLoaded = false;
    out.guestCodeExecuted = false;
    out.androidWineTested = false;
    error = "none";
    return true;
}
}
