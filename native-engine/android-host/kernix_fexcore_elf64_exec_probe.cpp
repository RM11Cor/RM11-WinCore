/*
 * KERNIX isolated real x86-64 ELF64 PIE executable proof on Android.
 * The guest is a GNU as/ld-built ELF with .text and .rodata PT_LOADs.
 * This is NOT arbitrary external executable loading, glibc or Wine.
 * SPDX-License-Identifier: MIT.
 */
#include "kernix_elf64_loader.h"
#include "kernix_elf64_guest_blob.h"
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
#include "kernix_g0_guest_syscall_dispatch.h"
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
constexpr uintptr_t WRITE_RIP = 22, WRITE_NEXT_RIP = 24;
constexpr uintptr_t GETPID_RIP = 31, GETPID_NEXT_RIP = 33;
constexpr size_t MESSAGE_LENGTH = 28;
constexpr char MESSAGE[] = "KERNIX_ELF64_GUEST_RUN_PASS\n";
static_assert(sizeof(MESSAGE) - 1 == MESSAGE_LENGTH);
constexpr char PASS[] = "KERNIX_FEXCORE_ANDROID_REAL_ELF64_X86_GUEST_EXEC_PROOF_V1";
class FixedGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    explicit FixedGuestSyscalls(const kernix::GuestELF& image,
                               uintptr_t trustedStackStart,
                               size_t trustedStackSize)
      : Code(image.entry), Length(image.executableSize),
        MessageAddress(image.message), MessageAvailable(image.messageSize),
        GuestStack{trustedStackStart,trustedStackStart+trustedStackSize,true},
        MessageRegion{image.message,image.message+image.messageSize,
                      true,false,false,true} {}
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
        // Decode the *live* upstream FEX CpuStateFrame. The shared C1 ABI
        // verifies x86-64 R10/RCX semantics and owner-held guest stack.
        kernix::g2e::c2::ActualFexTrapWitness frameWitness{};
        if (!kernix::g2e::c2::DecodePinnedFexCpuState(
                frame, GuestStack, frameWitness) ||
            !frameWitness.originalFexCpuStateFrameRead ||
            frameWitness.decoded.guestNumber != expectedNumber ||
            frameWitness.decoded.nextGuestRIP != expectedNext) {
            std::fputs("KERNIX_G0_ACTUAL_FEX_CPUSTATE_GUEST_STACK_OR_ABI_REJECTED\n",stderr);
            _exit(36);
        }
        if (Count == 1) {
            // Preserve the pinned original ELF guest data identity before
            // asking the shared read-only VM boundary to read its bytes.
            if (frameWitness.decoded.args[0] != STDOUT_FILENO ||
                frameWitness.decoded.args[1] != MessageAddress ||
                frameWitness.decoded.args[2] != MESSAGE_LENGTH) {
                std::fputs("KERNIX_G0_GUEST_WRITE_ARGUMENTS_REJECTED\n",stderr);
                _exit(34);
            }
            const auto out=kernix::g0::DispatchVerifiedGuestTrap(
                frameWitness.decoded,MessageRegion,STDOUT_FILENO);
            if (out.event!=kernix::g0::Event::WroteGuestData ||
                !out.guestBytesValidated || !out.hostWriteCalled ||
                out.guestReturn != static_cast<int64_t>(MESSAGE_LENGTH)) {
                std::fputs("KERNIX_G0_GUEST_WRITE_VM_OR_OUTPUT_REJECTED\n",stderr);
                _exit(35);
            }
            state.gregs[FEXCore::X86State::REG_RAX]=
                static_cast<uint64_t>(out.guestReturn);
            std::fputs("KERNIX_G0_REAL_FEX_ELF64_GUEST_WRITE_VM_BRIDGE_PASS\n",stderr);
        } else {
            const kernix::g2e::c1::GuestVmInterval emptyReadOnlySpan{};
            const auto out=kernix::g0::DispatchVerifiedGuestTrap(
                frameWitness.decoded,emptyReadOnlySpan,-1);
            if (out.event!=kernix::g0::Event::ReturnedRealPid ||
                out.guestReturn!=::getpid() || out.guestReturn<=0 ||
                out.hostWriteCalled || out.guestExitRequested) {
                std::fputs("KERNIX_G0_REAL_FEX_ELF64_GUEST_GETPID_REJECTED\n",stderr);
                _exit(37);
            }
            state.gregs[FEXCore::X86State::REG_RAX]=
                static_cast<uint64_t>(out.guestReturn);
            std::fputs("KERNIX_G0_REAL_FEX_ELF64_GUEST_GETPID_BRIDGE_PASS\n",stderr);
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
    kernix::g2e::c1::X86GuestStackBoundary GuestStack;
    kernix::g2e::c1::GuestVmInterval MessageRegion;
};

int run() {
    std::fprintf(stderr, "KERNIX_ELF64_STAGE=validate_and_map_elf\n");
    kernix::GuestELF guest{};
    const char* reason = nullptr;
    if (!kernix::loadFixedGuestELF(KERNIX_ELF64_BLOB, sizeof(KERNIX_ELF64_BLOB),
                                   guest, reason)) {
        std::fprintf(stderr, "KERNIX_ELF64_LOAD_REJECTED=%s\n", reason);
        return 19;
    }
    if (!guest.containsReadOnlyMessage(guest.message, MESSAGE_LENGTH) ||
        std::memcmp(reinterpret_cast<const void*>(guest.message),
                    MESSAGE, MESSAGE_LENGTH) != 0) {
        std::fprintf(stderr, "KERNIX_ELF64_MESSAGE_MISMATCH\n");
        return 20;
    }
    std::fprintf(stderr, "KERNIX_ELF64_REAL_PT_LOAD_MAPPED_WX_SAFE\n");
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
    // This current FEX session owns these exact VM windows; no arbitrary
    // user-supplied spans or host FDs are admitted into the syscall bridge.
    FixedGuestSyscalls syscalls{guest,
        reinterpret_cast<uintptr_t>(stack),page*2};
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
    std::fprintf(stderr, "KERNIX_ELF64_STAGE=actual_independently_compiled_elf_guest_execution\n");
    ctx->ExecuteThread(thread);
    const uint64_t actual = thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    std::fprintf(stderr, "KERNIX_X86_REGISTER_RAX=%llu\n",
        static_cast<unsigned long long>(actual));
    if (syscalls.Count != 2 || actual != expected) return 18;
    std::fputs("KERNIX_G0_ANDROID_BIONIC_GUEST_ELF_REAL_WRITE_GETPID_BOUNDARY_COMPLETED\n",stderr);
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
