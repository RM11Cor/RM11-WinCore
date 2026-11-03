/*
 * KERNIX proof gate: x86-64 guest memory pointer + two Linux syscalls.
 * Original KERNIX code. SPDX-License-Identifier: MIT.
 *
 * A fixed, immutable guest executes write(1, guest_code_message, length),
 * then getpid(), adds the number of written bytes, then HLT.
 * The real Android Bionic host bridges TWO Linux guest syscall traps,
 * confirms guest RIP and RCX after each trap, validates guest pointer
 * bounds and arguments, reads real read-only guest memory, and verifies
 * the final translated guest RAX.
 *
 * NO arbitrary EXE or ELF, Wine, file access, network access, root or
 * guest library load. Opt-in isolated Android APK native child only.
 */
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
constexpr uint8_t GUEST_X86_64[] = {
    0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 
    0x00, 0x00, 0x48, 0x8d, 0x35, 0x14, 0x00, 0x00, 
    0x00, 0xba, 0x16, 0x00, 0x00, 0x00, 0x0f, 0x05, 
    0x89, 0xc3, 0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 
    0x05, 0x48, 0x01, 0xd8, 0xf4, 0x4b, 0x45, 0x52, 
    0x4e, 0x49, 0x58, 0x5f, 0x47, 0x55, 0x45, 0x53, 
    0x54, 0x5f, 0x57, 0x52, 0x49, 0x54, 0x45, 0x5f, 
    0x4f, 0x4b, 0x0a
};
constexpr uint64_t WRITE_SYSCALL = 1;
constexpr uint64_t GETPID_SYSCALL = 39;
constexpr uintptr_t WRITE_RIP = 22, WRITE_NEXT_RIP = 24;
constexpr uintptr_t GETPID_RIP = 31, GETPID_NEXT_RIP = 33;
constexpr uintptr_t MESSAGE_OFFSET = 37;
constexpr size_t MESSAGE_LENGTH = 22;
constexpr char PASS[] = "KERNIX_FEXCORE_ANDROID_X86_64_GUEST_WRITE_GETPID_MEMORY_PROOF_V1";
static_assert(sizeof(GUEST_X86_64) == MESSAGE_OFFSET + MESSAGE_LENGTH);
static_assert(sizeof(GUEST_X86_64) < 4096);
class FixedGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    FixedGuestSyscalls(uintptr_t code, size_t length)
      : Code(code), Length(length) {}
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
            // Only the packaged, read-only guest message may be read.
            // No arbitrary pointers or user-controlled I/O.
            if (fd != STDOUT_FILENO || ptr != Code + MESSAGE_OFFSET ||
                length != MESSAGE_LENGTH ||
                ptr < Code || length > Length ||
                ptr - Code > Length - length) {
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
};

int run() {
    std::fprintf(stderr, "KERNIX_X86_STAGE=allocate\n");
    const long p = sysconf(_SC_PAGESIZE);
    if (p < 4096 || p > 65536) return 11;
    const size_t page = static_cast<size_t>(p);
    void* code = mmap(nullptr, page, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (code == MAP_FAILED) return 12;
    void* stack = mmap(nullptr, page * 2, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (stack == MAP_FAILED) return 13;
    std::memcpy(code, GUEST_X86_64, sizeof(GUEST_X86_64));
    if (mprotect(code, page, PROT_READ | PROT_EXEC) != 0) return 14;
    const uintptr_t entry = reinterpret_cast<uintptr_t>(code);

    std::fprintf(stderr, "KERNIX_X86_STAGE=core_config\n");
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    // The meta reload clears ad-hoc mode overrides. Apply guest x86-64 mode
    // afterwards, so unchanged upstream FEXCore uses the x64 SRA mapping.
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
    const bool guest64 = FEXCore::Config::GetConv<bool>(
        FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false);
    std::fprintf(stderr, "KERNIX_G1_ANDROID_CONFIG_AFTER_RELOAD x86_64_mode=%u\n",
                 guest64 ? 1U : 0U);
    if (!guest64) return 46;

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
    FixedGuestSyscalls syscalls{entry, sizeof(GUEST_X86_64)};
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
    std::fprintf(stderr, "KERNIX_X86_STAGE=actual_guest_write_getpid_execute\n");
    ctx->ExecuteThread(thread);
    const uint64_t actual = thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    std::fprintf(stderr, "KERNIX_X86_REGISTER_RAX=%llu\n",
        static_cast<unsigned long long>(actual));
    if (syscalls.Count != 2 || actual != expected) return 18;
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
