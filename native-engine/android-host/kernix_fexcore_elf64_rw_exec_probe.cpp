/*
 * KERNIX isolated real x86-64 ELF64 PIE writable guest memory execution proof.
 * The guest is a GNU as/ld-built ELF with .text/.rodata/.data PT_LOADs.
 * This is NOT arbitrary external executable loading, glibc or Wine.
 * SPDX-License-Identifier: MIT.
 */
#include "kernix_elf64_loader.h"
#include "kernix_elf64_rw_guest_blob.h"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/fextl/memory.h>

#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error KERNIX actual FEXCore CPU probe must target Android ARM64
#endif

namespace {
constexpr uint64_t WRITE_SYSCALL = 1;
constexpr uint64_t GETPID_SYSCALL = 39;
constexpr uintptr_t WRITE_RIP = 43, WRITE_NEXT_RIP = 45;
constexpr uintptr_t GETPID_RIP = 52, GETPID_NEXT_RIP = 54;
constexpr size_t MESSAGE_LENGTH = 26;
constexpr char MESSAGE[] = "KERNIX_ELF_RW_MEMORY_PASS\n";
static_assert(sizeof(MESSAGE) - 1 == MESSAGE_LENGTH);
constexpr char PASS[] = "KERNIX_FEXCORE_ANDROID_ELF64_X86_RW_GUEST_MEMORY_PROOF_V1";
class FixedGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    explicit FixedGuestSyscalls(const kernix::GuestELF& image)
      : Code(image.entry), Length(image.executableSize),
        MessageAddress(image.writableData), MessageAvailable(image.writableSize) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        ++Count;
        auto &state = frame->State;
        const uint64_t number = state.gregs[FEXCore::X86State::REG_RAX];
        const uint64_t rip = state.rip;
        const uint64_t next = state.gregs[FEXCore::X86State::REG_RCX];
        const uintptr_t expectedRip = Code + (Count == 1 ? WRITE_RIP : GETPID_RIP);
        const uintptr_t expectedNext = Code + (Count == 1 ? WRITE_NEXT_RIP : GETPID_NEXT_RIP);
        const uint64_t expectedNumber = Count == 1 ? WRITE_SYSCALL : GETPID_SYSCALL;
        if (Count > 2 || number != expectedNumber ||
            rip != expectedRip || next != expectedNext ||
            next != rip + 2) {
            std::fprintf(stderr,
                "KERNIX_X86_SYSCALL_SEQUENCE_REJECTED number=%llu count=%u currentOffset=%lld nextOffset=%lld\n",
                static_cast<unsigned long long>(number), Count,
                static_cast<long long>(rip - Code),
                static_cast<long long>(next - Code));
            _exit(33);
        }
        if (Count == 1) {
            const auto fd = state.gregs[FEXCore::X86State::REG_RDI];
            const auto ptr = state.gregs[FEXCore::X86State::REG_RSI];
            const auto length = state.gregs[FEXCore::X86State::REG_RDX];
            // Only the exact guest-writable ELF .data buffer may be read.
            // No arbitrary pointers or user-controlled I/O.
            if (fd != STDOUT_FILENO || ptr != MessageAddress ||
                length != MESSAGE_LENGTH ||
                ptr < MessageAddress || length > MessageAvailable ||
                ptr - MessageAddress > MessageAvailable - length) {
                std::fprintf(stderr, "KERNIX_GUEST_WRITE_POINTER_OR_ARGUMENT_REJECTED\n");
                _exit(34);
            }
            const ssize_t n = ::write(STDOUT_FILENO,
                reinterpret_cast<const void*>(ptr), static_cast<size_t>(length));
            if (n != static_cast<ssize_t>(MESSAGE_LENGTH)) _exit(35);
            state.gregs[FEXCore::X86State::REG_RAX] = static_cast<uint64_t>(n);
            std::fprintf(stderr, "KERNIX_X86_WRITE_BRIDGE_GUEST_MEMORY_READ_OK\n");
        } else {
            state.gregs[FEXCore::X86State::REG_RAX] =
                static_cast<uint64_t>(getpid());
            std::fprintf(stderr, "KERNIX_X86_GETPID_SECOND_SYSCALL_OK\n");
        }
        // Pinned FEX dispatch reports current SYSCALL in RIP, next in RCX.
        state.rip = next;
    }
    unsigned Count = 0;
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*, uint64_t address) override {
        if (address >= Code && address < Code + Length)
            return {Code, Length, false};
        return {0, 0, false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*, uint64_t) override {
        return std::nullopt;
    }
private:
    uintptr_t Code;
    size_t Length;
    uintptr_t MessageAddress;
    size_t MessageAvailable;
};

int run() {
    std::fprintf(stderr, "KERNIX_ELF64_STAGE=validate_and_map_elf\n");
    kernix::GuestELF guest{};
    const char* reason = nullptr;
    if (!kernix::loadFixedGuestELF(KERNIX_ELF64_RW_BLOB, sizeof(KERNIX_ELF64_RW_BLOB),
                                   guest, reason, kernix::GuestLayout::WritableMemoryCopy)) {
        std::fprintf(stderr, "KERNIX_ELF64_LOAD_REJECTED=%s\n", reason);
        return 19;
    }
    if (!guest.containsWritableMessage(guest.writableData, MESSAGE_LENGTH) ||
        std::memcmp(reinterpret_cast<const void*>(guest.message),
                    MESSAGE, MESSAGE_LENGTH) != 0) {
        std::fprintf(stderr, "KERNIX_ELF64_MESSAGE_MISMATCH\n");
        return 20;
    }
    if (std::memcmp(reinterpret_cast<const void*>(guest.writableData),
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", MESSAGE_LENGTH) != 0) {
        std::fprintf(stderr, "KERNIX_RW_ELF_MEMORY_MUST_START_ZERO\n");
        return 21;
    }
    std::fprintf(stderr, "KERNIX_ELF64_RW_REAL_PT_LOAD_MAPPED_WX_SAFE\n");
    const long p = sysconf(_SC_PAGESIZE);
    if (p < 4096 || p > 16384) return 11;
    const size_t page = static_cast<size_t>(p);
    void* stack = mmap(nullptr, page * 2, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (stack == MAP_FAILED) return 13;
    const uintptr_t entry = guest.entry;

    std::fprintf(stderr, "KERNIX_X86_STAGE=core_config\n");
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
    FEXCore::Config::ReloadMetaLayer();

    FEXCore::HostFeatures host{};
    host.DCacheLineLog2 = 4;
    host.ProcessFeatures.HostType = FEXCore::HostFeatures::HostTypeEnum::Linux;
    host.ProcessFeatures.Is64BitMode = 1;
    host.ProcessPID = static_cast<uint32_t>(getpid());
    host.CPUMIDRs.push_back(0);

    std::fprintf(stderr, "KERNIX_X86_STAGE=context_create\n");
    auto ctx = FEXCore::Context::Context::CreateNewContext(host);
    if (!ctx) return 15;
    FEXCore::SignalDelegator signals{};
    FixedGuestSyscalls syscalls{guest};
    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&syscalls);
    ctx->EnableExitOnHLT();
    if (!ctx->InitCore()) return 16;

    std::fprintf(stderr, "KERNIX_X86_STAGE=thread_create\n");
    auto* thread = ctx->CreateThread();
    if (!thread || !thread->CurrentFrame) return 17;

    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& state = thread->CurrentFrame->State;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = gdt;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = gdt;
    state.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
    auto* segment = FEXCore::Core::CPUState::GetSegmentFromIndex(state, state.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(segment, 0);
    FEXCore::Core::CPUState::SetGDTLimit(segment, 0xFFFFF);
    segment->L = 1;
    segment->D = 0;
    state.cs_cached = 0;
    state.gregs[FEXCore::X86State::REG_RSP] =
        (reinterpret_cast<uintptr_t>(stack) + page * 2 - 16) & ~static_cast<uintptr_t>(15);
    state.gregs[FEXCore::X86State::REG_RAX] = 0;
    state.rip = entry;

    const uint64_t expected = static_cast<uint64_t>(getpid()) + MESSAGE_LENGTH;
    std::fprintf(stderr, "KERNIX_ELF64_STAGE=actual_rep_movsb_writable_guest_copy\n");
    ctx->ExecuteThread(thread);
    const uint64_t actual = thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    std::fprintf(stderr, "KERNIX_X86_REGISTER_RAX=%llu\n",
        static_cast<unsigned long long>(actual));
    if (syscalls.Count != 2 || actual != expected ||
        std::memcmp(reinterpret_cast<const void*>(guest.writableData),
                    MESSAGE, MESSAGE_LENGTH) != 0) return 18;
    std::puts(PASS);
    std::fflush(stdout);
    // Process exits immediately; isolated child reclaims native JIT allocations.
    return 0;
}
}

int main(int argc, char**) {
    if (argc != 1) return 2;
    return run();
}
