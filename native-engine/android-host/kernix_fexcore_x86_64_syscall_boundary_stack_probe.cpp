/*
 * KERNIX fixed x86-64 FEXCore execution probe for Android ARM64/Bionic.
 * Original KERNIX code. SPDX-License-Identifier: MIT.
 *
 * Bounded x86-64 SYSCALL boundary witness, with one guest getpid syscall (39).
 * Store RBP/RBX and R10/R8 to a fixed stack witness immediately before SYSCALL.
 * Independently check guest memory and CpuState inside the host syscall handler.
 * No actual Android/Linux host syscall is dispatched by this handler.
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
    0x48,0x89,0x6c,0x24,0xe0,         // mov qword [rsp-32], rbp
    0x48,0x89,0x5c,0x24,0xe8,         // mov qword [rsp-24], rbx
    0x4c,0x89,0x54,0x24,0xf0,         // mov qword [rsp-16], r10
    0x4c,0x89,0x44,0x24,0xf8,         // mov qword [rsp-8], r8
    0xb8,0x27,0x00,0x00,0x00,          // mov eax,39 (getpid)
    0x0f,0x05,                         // syscall
    0xf4                              // unreachable after host callback exits
};
constexpr char PASS[] = "KERNIX_X86_SYSCALL_BOUNDARY_STACK_CPUSTATE_PASS";

class FixedGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    FixedGuestSyscalls(uintptr_t code, size_t length, uintptr_t witness)
      : Code(code), Length(length), Witness(witness) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        // This test's only guest syscall is Linux x86-64 getpid (39).
        // Read x86 writes from an independent fixed, host-owned guest stack,
        // and check FEX's CpuState as seen at the actual syscall boundary.
        uint64_t mem[4]{};
        std::memcpy(mem, reinterpret_cast<const void*>(Witness), sizeof(mem));
        const auto& cpu=frame->State;
        const auto r10=cpu.gregs[FEXCore::X86State::REG_R10];
        const auto r8=cpu.gregs[FEXCore::X86State::REG_R8];
        const auto rbp=cpu.gregs[FEXCore::X86State::REG_RBP];
        const auto rbx=cpu.gregs[FEXCore::X86State::REG_RBX];
        const auto rax=cpu.gregs[FEXCore::X86State::REG_RAX];
        const auto rsp=cpu.gregs[FEXCore::X86State::REG_RSP];
        std::fprintf(stderr,
          "KERNIX_X86_SYSCALL_BOUNDARY mem_rbp=%llu mem_rbx_low=%llu mem_rbx_high=%llu mem_r10=%llu mem_r8_low=%llu mem_r8_high=%llu cpu_rax=%llu cpu_r10=%llu cpu_r8_low=%llu cpu_r8_high=%llu cpu_rbp=%llu cpu_rbx_low=%llu cpu_rbx_high=%llu cpu_rsp_matches=%u\n",
          (unsigned long long)mem[0],(unsigned long long)(mem[1]&0xffffffffULL),
          (unsigned long long)(mem[1]>>32),(unsigned long long)mem[2],
          (unsigned long long)(mem[3]&0xffffffffULL),(unsigned long long)(mem[3]>>32),
          (unsigned long long)rax,(unsigned long long)r10,(unsigned long long)(r8&0xffffffffULL),
          (unsigned long long)(r8>>32),(unsigned long long)rbp,
          (unsigned long long)(rbx&0xffffffffULL),(unsigned long long)(rbx>>32),
          rsp==Witness+32 ? 1U : 0U);
        std::fflush(stderr);
        if (mem[0]!=34 || mem[1]!=UINT64_MAX ||
            mem[2]!=34 || mem[3]!=UINT64_MAX) _exit(38);
        if (rax!=39 || r10!=34 || r8!=UINT64_MAX ||
            rbp!=34 || rbx!=UINT64_MAX || rsp!=Witness+32) _exit(39);
        std::puts(PASS);
        std::fflush(stdout);
        _exit(0);
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
    uintptr_t Witness;
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
    const uintptr_t guestSP =
      (reinterpret_cast<uintptr_t>(stack) + page * 2 - 16) & ~static_cast<uintptr_t>(15);

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
    FixedGuestSyscalls syscalls{entry, sizeof(GUEST_X86_64), guestSP-32};
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
    state.gregs[FEXCore::X86State::REG_RSP] = guestSP;
    // Poison the four expected RW memory slots, so skipped x86 stores fail.
    std::memset(reinterpret_cast<void*>(guestSP-32), 0xA5, 32);
    state.gregs[FEXCore::X86State::REG_RAX] = 0;
    state.rip = entry;

    std::fprintf(stderr, "KERNIX_X86_STAGE=actual_execute\n");
    ctx->ExecuteThread(thread);
    // The callback exits the bounded test process with a meaningful result;
    // returning normally means the fixed SYSCALL path did not complete.
    std::fputs("KERNIX_X86_SYSCALL_CALLBACK_NOT_REACHED\n",stderr);
    return 45;
}
}

int main(int argc, char**) {
    if (argc != 1) return 2;
    return run();
}
