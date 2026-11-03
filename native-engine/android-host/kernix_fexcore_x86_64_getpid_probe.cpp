/*
 * KERNIX fixed x86-64 FEXCore execution probe for Android ARM64/Bionic.
 * Original KERNIX code. SPDX-License-Identifier: MIT.
 *
 * A fixed guest performs Linux x86-64 getpid syscall (39), adds 7, then HLT.
 * A pass is printed ONLY if the genuine FEXCore syscall handler was entered
 * exactly once with x86 RAX=39, RIP advances to after SYSCALL,\n * and CPUState RAX becomes host PID+7.
 *
 * No guest executable files, arbitrary code, root, cross-app data, Wine,
 * Vulkan or network access are involved. Run only as a bounded child process.
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
    0xb8,0x27,0x00,0x00,0x00, // mov eax, 39 = Linux x86-64 getpid
    0x0f,0x05,                // syscall (host handler must be called)
    0x48,0x83,0xc0,0x07,      // add rax, 7
    0xf4                     // hlt (FEXCore ExitOnHLT)
};
constexpr uint64_t EXPECTED_GUEST_SYSCALL = 39;
constexpr char PASS[] = "KERNIX_FEXCORE_ANDROID_X86_64_GETPID_SYSCALL_RAX_PROOF_V1";

class FixedGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    FixedGuestSyscalls(uintptr_t code, size_t length)
      : Code(code), Length(length) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        // Only the fixed, read-only guest sequence may invoke exactly ONE
        // Linux x86-64 getpid(39). No filesystem, network or user code.
        ++Count;
        const uint64_t guest_number =
            frame->State.gregs[FEXCore::X86State::REG_RAX];
        if (Count != 1 || guest_number != EXPECTED_GUEST_SYSCALL) {
            std::fprintf(stderr,
                "KERNIX_UNEXPECTED_GUEST_SYSCALL number=%llu count=%u\n",
                static_cast<unsigned long long>(guest_number), Count);
            _exit(33);
        }
        // In pinned upstream FEXCore::IR::OpDispatchBuilder::SyscallOp,
        // State.rip is set to the *current* SYSCALL instruction, while
        // RCX holds the instruction address *after* SYSCALL.
        // Linux syscall handlers must resume guest execution at next RIP.
        // Leaving RIP at current SYSCALL repeats the trap and makes the
        // returned PID look like a second syscall number (observed 125).
        constexpr uintptr_t SYSCALL_INSTRUCTION_OFFSET = 5;
        constexpr uintptr_t AFTER_SYSCALL_OFFSET = 7;
        const uint64_t currentRIP = frame->State.rip;
        const uint64_t nextRIP =
            frame->State.gregs[FEXCore::X86State::REG_RCX];
        if (currentRIP != Code + SYSCALL_INSTRUCTION_OFFSET ||
            nextRIP != Code + AFTER_SYSCALL_OFFSET) {
            std::fprintf(stderr,
                "KERNIX_SYSCALL_RESUME_RIP_REJECTED current_offset=%lld next_offset=%lld\n",
                static_cast<long long>(currentRIP - Code),
                static_cast<long long>(nextRIP - Code));
            _exit(34);
        }
        frame->State.gregs[FEXCore::X86State::REG_RAX] =
            static_cast<uint64_t>(getpid());
        frame->State.rip = nextRIP;
        std::fprintf(stderr, "KERNIX_X86_SYSCALL_BRIDGE_GETPID_CALLED_RIP_ADVANCED\n");
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

    const uint64_t expected = static_cast<uint64_t>(getpid()) + 7;
    std::fprintf(stderr, "KERNIX_X86_STAGE=actual_syscall_execute\n");
    ctx->ExecuteThread(thread);
    const uint64_t actual = thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    std::fprintf(stderr, "KERNIX_X86_REGISTER_RAX=%llu\n",
        static_cast<unsigned long long>(actual));
    if (syscalls.Count != 1 || actual != expected) return 18;
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
