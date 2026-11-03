#pragma once
// KERNIX G2-B Linux x86-64 process-entry stack bytes (argc/argv/envp/AUXV).
// Pure bounded host-memory preparation. No guest mapping, FEX execution,
// Wine, ELF interpreter relocation, or Android runtime execution.
// SPDX-License-Identifier: MIT
#include <elf.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kernix::g2b {
constexpr uint64_t kLinuxGuestUserLimit = 0x0000800000000000ULL;
constexpr uint64_t kMaxLinuxStackBytes = 1024 * 1024;
constexpr size_t kMaxLinuxStartStrings = 24;
constexpr size_t kMaxLinuxStartStringBytes = 8192;

struct LinuxX86StackInput {
    // All addresses must come from an independently verified guest memory
    // plan. Zero-valued placeholder pointers are rejected.
    uint64_t guestStackBottom = 0;
    uint64_t guestStackBytes = 0;
    uint64_t guestPageBytes = 0;        // Linux x86 guest page size (not host)
    uint64_t guestMainProgramHeaders = 0; // AT_PHDR: runtime relocated PHDR
    uint64_t guestMainEntry = 0;       // AT_ENTRY: runtime relocated main entry
    uint64_t guestInterpreterBase = 0; // AT_BASE: runtime ld-linux load bias
    uint16_t programHeaderCount = 0;   // AT_PHNUM
    uint32_t uid = 0, euid = 0, gid = 0, egid = 0;
    std::array<uint8_t, 16> randomBytes{}; // supplied externally; never generated here
    std::vector<std::string> args;
    std::vector<std::string> environment;
};

struct LinuxX86StackImage {
    std::vector<uint8_t> bytes;
    uint64_t guestBottom = 0;
    uint64_t guestRSP = 0;
    uint64_t guestTop = 0;
    uint64_t guestRandomPointer = 0;
    uint64_t guestExecFnPointer = 0;
    size_t auxEntryCount = 0;
    bool initialStackLayoutValidated = false;
    bool guestMemoryMapped = false;
    bool guestCodeExecuted = false;
    bool androidWineTested = false;
    void clear() { *this = {}; }
};

inline bool ValidLinuxGuestPointer(uint64_t v) {
    return v >= 0x10000 && v < kLinuxGuestUserLimit;
}
inline bool ValidLinuxStartString(std::string_view str, bool env) {
    if (str.empty() || str.size() > 2048) return false;
    if (env && (str.front() == '=' || str.find('=') == std::string_view::npos))
        return false;
    for (char c : str) {
        if (c == '\0' || static_cast<unsigned char>(c) < 0x20 || c == 0x7f)
            return false;
    }
    return true;
}
inline bool PrepareLinuxX86InitialStack(const LinuxX86StackInput& input,
                                        LinuxX86StackImage& result,
                                        std::string& reason) {
    result.clear();
    const auto fail = [&](const char* e) -> bool {
        result.clear();
        reason = e;
        return false;
    };
    if (!ValidLinuxGuestPointer(input.guestStackBottom) ||
        input.guestStackBytes < 4096 ||
        input.guestStackBytes > kMaxLinuxStackBytes ||
        (input.guestStackBytes % 4096) != 0 ||
        (input.guestStackBottom % 4096) != 0 ||
        input.guestStackBytes > kLinuxGuestUserLimit-input.guestStackBottom)
        return fail("INVALID_GUEST_STACK_ADDRESS_OR_CAPACITY");
    const uint64_t top = input.guestStackBottom+input.guestStackBytes;
    if (top >= kLinuxGuestUserLimit)
        return fail("GUEST_STACK_ABOVE_CANONICAL_USER_LIMIT");
    if (input.guestPageBytes != 4096 && input.guestPageBytes != 16384)
        return fail("INVALID_LINUX_GUEST_PAGE_SIZE");
    if (!ValidLinuxGuestPointer(input.guestMainEntry) ||
        !ValidLinuxGuestPointer(input.guestMainProgramHeaders) ||
        !ValidLinuxGuestPointer(input.guestInterpreterBase) ||
        input.programHeaderCount == 0 || input.programHeaderCount > 128 ||
        input.guestMainProgramHeaders >
            kLinuxGuestUserLimit-static_cast<uint64_t>(input.programHeaderCount)*sizeof(Elf64_Phdr))
        return fail("GUEST_ELF_RUNTIME_ADDRESSES_UNVERIFIED");
    if (input.args.empty() || input.args.size() > kMaxLinuxStartStrings ||
        input.environment.size() > kMaxLinuxStartStrings ||
        input.args.size()+input.environment.size() > kMaxLinuxStartStrings)
        return fail("INVALID_ARGV_OR_ENV_COUNT");
    size_t total = 16;
    for (const auto& item : input.args) {
        if (!ValidLinuxStartString(item, false) ||
            total > kMaxLinuxStartStringBytes-item.size()-1)
            return fail("INVALID_ARGV_STRING_OR_TOTAL");
        total += item.size()+1;
    }
    for (const auto& item : input.environment) {
        if (!ValidLinuxStartString(item, true) ||
            total > kMaxLinuxStartStringBytes-item.size()-1)
            return fail("INVALID_ENV_STRING_OR_TOTAL");
        total += item.size()+1;
    }
    bool hasEntropy = false;
    for (uint8_t v : input.randomBytes) hasEntropy |= v != 0;
    if (!hasEntropy) return fail("AT_RANDOM_MUST_BE_SUPPLIED_BY_CALLER");

    // These keys and their order describe a partial Linux x86_64 process
    // initial stack, not a complete glibc AUXV contract. AT_HWCAP, TLS,
    // VDSO and AT_SYSINFO_EHDR require independent host/guest validation.
    constexpr uint64_t PHDR=3, PHENT=4, PHNUM=5, PAGESZ=6, BASE=7,
        FLAGS=8, ENTRY=9, UID=11, EUID=12, GID=13, EGID=14,
        SECURE=23, RANDOM=25, EXECFN=31, NULL_TAG=0;
    std::vector<uint8_t> buffer(static_cast<size_t>(input.guestStackBytes),0);
    uint64_t cursor = top;
    const auto pushBytes = [&](const void* data, size_t length) -> uint64_t {
        if (!length || cursor < input.guestStackBottom+length)
            return 0;
        cursor -= length;
        std::memcpy(buffer.data()+static_cast<size_t>(
            cursor-input.guestStackBottom), data, length);
        return cursor;
    };
    std::vector<uint64_t> argPointers(input.args.size(),0);
    std::vector<uint64_t> envPointers(input.environment.size(),0);
    for (size_t i = input.args.size(); i > 0; --i) {
        const auto& text = input.args[i-1];
        argPointers[i-1] = pushBytes(text.c_str(),text.size()+1);
        if (!argPointers[i-1]) return fail("ARGV_DATA_EXCEEDS_STACK");
    }
    for (size_t i = input.environment.size(); i > 0; --i) {
        const auto& text = input.environment[i-1];
        envPointers[i-1] = pushBytes(text.c_str(),text.size()+1);
        if (!envPointers[i-1]) return fail("ENV_DATA_EXCEEDS_STACK");
    }
    const uint64_t randomPointer = pushBytes(input.randomBytes.data(),16);
    if (!randomPointer) return fail("AUX_RANDOM_EXCEEDS_STACK");
    const std::array<std::pair<uint64_t,uint64_t>, 14> aux{{
        {PHDR,input.guestMainProgramHeaders},
        {PHENT,sizeof(Elf64_Phdr)},
        {PHNUM,input.programHeaderCount},
        {PAGESZ,input.guestPageBytes},
        {BASE,input.guestInterpreterBase},
        {FLAGS,0},
        {ENTRY,input.guestMainEntry},
        {UID,input.uid}, {EUID,input.euid},
        {GID,input.gid}, {EGID,input.egid},
        {SECURE,0},
        {RANDOM,randomPointer},
        {EXECFN,argPointers[0]}
    }};
    std::vector<uint64_t> words;
    words.reserve(1+argPointers.size()+1+envPointers.size()+1+aux.size()*2+2);
    words.push_back(argPointers.size());
    for (auto p : argPointers) words.push_back(p);
    words.push_back(0);
    for (auto p : envPointers) words.push_back(p);
    words.push_back(0);
    for (const auto& item : aux) {
        words.push_back(item.first);
        words.push_back(item.second);
    }
    words.push_back(NULL_TAG);
    words.push_back(0);
    const uint64_t wordBytes = static_cast<uint64_t>(words.size())*sizeof(uint64_t);
    if (cursor < input.guestStackBottom+wordBytes+16)
        return fail("AUXV_POINTERS_EXCEED_STACK");
    const uint64_t rsp = (cursor-wordBytes)&~15ULL;
    if (rsp < input.guestStackBottom || (rsp & 15) != 0)
        return fail("GUEST_RSP_ALIGNMENT_OR_BOUNDS_REJECTED");
    // Encode pointer-sized little-endian x86_64 words independent of
    // Android host endian or C++ vector storage alignment.
    size_t offset = static_cast<size_t>(rsp-input.guestStackBottom);
    for (uint64_t word : words) {
        for (unsigned i=0; i<8; ++i)
            buffer[offset++] = static_cast<uint8_t>(word>>(8*i));
    }
    result.bytes = std::move(buffer);
    result.guestBottom = input.guestStackBottom;
    result.guestRSP = rsp;
    result.guestTop = top;
    result.guestRandomPointer = randomPointer;
    result.guestExecFnPointer = argPointers[0];
    result.auxEntryCount = aux.size();
    result.initialStackLayoutValidated = true;
    reason = "none";
    return true;
}
} // namespace kernix::g2b
