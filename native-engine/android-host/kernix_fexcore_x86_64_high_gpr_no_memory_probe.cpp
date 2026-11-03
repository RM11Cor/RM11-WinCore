/*
 * KERNIX fixed x86-64 FEXCore execution probe for Android ARM64/Bionic.
 * Original KERNIX code. SPDX-License-Identifier: MIT.
 *
 * Minimal high-GPR register preservation control with NO guest syscall, NO memory writes.
 * A pass requires real guest R10=34, R8=-1, RBP=34 and RBX=-1 after HLT.
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

#if !defined(__aarch64__) || (!defined(__ANDROID__) && !defined(KERNIX_ARM64_CI_REGRESSION))
#error KERNIX GPR witness only on Android ARM64 or explicit native ARM64 CI
#endif

namespace {
constexpr uint8_t GUEST_X86_64[] = {
    0x41,0xba,0x22,0x00,0x00,0x00,      // mov r10d,0x22
    0x49,0xc7,0xc0,0xff,0xff,0xff,0xff, // mov r8,-1 (sign extended)
    0x4c,0x89,0xd5,                    // mov rbp,r10
    0x4c,0x89,0xc3,                    // mov rbx,r8
    0xf4                              // hlt (FEXCore ExitOnHLT)
};
constexpr char PASS[] = "KERNIX_FEXCORE_X86_HIGH_GPR_DIRECT_EXECUTION_PASS";

class FixedGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    FixedGuestSyscalls(uintptr_t code, size_t length)
      : Code(code), Length(length) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
        // The fixed test contains NO syscalls. Return an explicit failure.
        std::fputs("KERNIX_UNEXPECTED_GUEST_SYSCALL\n", stderr);
        _exit(33);
    }
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
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
#ifdef KERNIX_ARM64_CI_ONE_INST
    // A/B diagnostic only: keep each x86 instruction in a separate JIT
    // block to test whether GPR state loss depends on block lifetime.
    // Not enabled in the distributable Android build.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST, "1");
#endif
    FEXCore::Config::ReloadMetaLayer();
#if defined(KERNIX_ARM64_CI_REGRESSION) && defined(KERNIX_ARM64_CI_CORRECT_META_ORDER)
    // FEX MetaLayer::Load() clears programmatically set Meta options.
    // Therefore set guest architecture AFTER ReloadMetaLayer(), not before.
    // This is an isolated A/B proof; no changes to the original FEX source.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
#ifdef KERNIX_ARM64_CI_ONE_INST
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST, "1");
#endif
    const bool mode64 = FEXCore::Config::GetConv<bool>(
        FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false);
    std::fprintf(stderr, "KERNIX_G1_CONFIG_AFTER_RELOAD x86_64_mode=%u\n",
                 mode64 ? 1U : 0U);
    if (!mode64) return 46;
#endif

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

    std::fprintf(stderr, "KERNIX_X86_STAGE=actual_execute\n");
    ctx->ExecuteThread(thread);
    const auto& cpu=thread->CurrentFrame->State;
    const auto r10=cpu.gregs[FEXCore::X86State::REG_R10];
    const auto r8=cpu.gregs[FEXCore::X86State::REG_R8];
    const auto rbp=cpu.gregs[FEXCore::X86State::REG_RBP];
    const auto rbx=cpu.gregs[FEXCore::X86State::REG_RBX];
    std::fprintf(stderr,
       "KERNIX_X86_HIGH_GPR_NO_MEMORY r10=%llu r8_low=%llu r8_high=%llu rbp=%llu rbx_low=%llu rbx_high=%llu\n",
       (unsigned long long)r10,
       (unsigned long long)(r8 & 0xffffffffULL),
       (unsigned long long)(r8 >> 32),
       (unsigned long long)rbp,
       (unsigned long long)(rbx & 0xffffffffULL),
       (unsigned long long)(rbx >> 32));
    if (r10 != 34 || r8 != UINT64_MAX || rbp != 34 || rbx != UINT64_MAX)
      return 38;
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
