/*
 * KERNIX isolated real x86-64 ELF64 PIE guest mmap/munmap and four syscall execution proof.
 * The guest is a GNU as/ld-built ELF with .text/.rodata/.data PT_LOADs.
 * This is NOT arbitrary external executable loading, glibc or Wine.
 * SPDX-License-Identifier: MIT.
 */
#include "kernix_elf64_loader.h"
#include "kernix_elf64_heap_guest_blob.h"
#include "kernix_guest_memory_syscalls.h"
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
constexpr size_t MESSAGE_LENGTH = 26;
constexpr char MESSAGE[] = "KERNIX_ELF_RW_MEMORY_PASS\n";
static_assert(sizeof(MESSAGE)-1 == MESSAGE_LENGTH);
constexpr char PASS[] = "KERNIX_FEXCORE_ANDROID_ELF64_GUEST_HEAP_FOUR_SYSCALL_PROOF_V1";
class BoundedGuestSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    explicit BoundedGuestSyscalls(const kernix::GuestELF& image)
      : Code(image.entry), Length(image.executableSize), MessageAddress(image.message) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        auto& state = frame->State;
        const std::uint64_t num = state.gregs[FEXCore::X86State::REG_RAX];
        const std::uint64_t rip = state.rip;
        const std::uint64_t next = state.gregs[FEXCore::X86State::REG_RCX];
        if (!kernix::validateTrap(Count,num,Code,rip,next)) {
            std::fprintf(stderr,"KERNIX_HEAP_GUEST_SYSCALL_ORDER_REJECTED number=%llu step=%u\n",
                         (unsigned long long)num, Count);
            _exit(33);
        }
        ++Count;
        if (Count == 1) {
            const auto requestedAddress=state.gregs[FEXCore::X86State::REG_RDI];
            const auto requestedSize=state.gregs[FEXCore::X86State::REG_RSI];
            const auto requestedProt=state.gregs[FEXCore::X86State::REG_RDX];
            const auto requestedFlags=state.gregs[FEXCore::X86State::REG_R10];
            const auto requestedFd=state.gregs[FEXCore::X86State::REG_R8];
            const auto requestedOffset=state.gregs[FEXCore::X86State::REG_R9];
            // The signed guest itself copies x86 R10/R8 into R14/R15 before
            // SYSCALL. Check both sides without inventing syscall arguments.
            const auto shadowFlags=state.gregs[FEXCore::X86State::REG_R14];
            const auto shadowFd=state.gregs[FEXCore::X86State::REG_R15];
            if (shadowFlags != 0x22ULL || shadowFd != UINT64_MAX) {
                std::fprintf(stderr,
                    "KERNIX_MMAP_FAILURE reason=GUEST_SHADOW_WRONG r10=%llu r8=%llu shadow_r14=%llu shadow_r15_low=%llu shadow_r15_high=%llu\n",
                    static_cast<unsigned long long>(requestedFlags),
                    static_cast<unsigned long long>(requestedFd),
                    static_cast<unsigned long long>(shadowFlags),
                    static_cast<unsigned long long>(shadowFd & 0xffffffffULL),
                    static_cast<unsigned long long>(shadowFd >> 32));
                std::fflush(stderr);
                _exit(38);
            }
            if (requestedFlags != shadowFlags || requestedFd != shadowFd) {
                std::fprintf(stderr,
                    "KERNIX_MMAP_FAILURE reason=SYSCALL_REGISTER_MISMATCH r10=%llu r8_low=%llu r8_high=%llu shadow_r14=%llu shadow_r15_low=%llu shadow_r15_high=%llu\n",
                    static_cast<unsigned long long>(requestedFlags),
                    static_cast<unsigned long long>(requestedFd & 0xffffffffULL),
                    static_cast<unsigned long long>(requestedFd >> 32),
                    static_cast<unsigned long long>(shadowFlags),
                    static_cast<unsigned long long>(shadowFd & 0xffffffffULL),
                    static_cast<unsigned long long>(shadowFd >> 32));
                std::fflush(stderr);
                _exit(39);
            }
            int nativeErrno=0;
            const auto result=Heap.allocateChecked(
                requestedAddress,requestedSize,requestedProt,requestedFlags,
                requestedFd,requestedOffset,&nativeErrno);
            if (result != kernix::ManagedGuestHeap::AllocationResult::Success) {
                // Keep precise failure first so Android UI's bounded log does
                // not hide it behind FEXCore initialization stage messages.
                std::fprintf(stderr,
                    "KERNIX_MMAP_FAILURE reason=%u errno=%d addr=%llu len=%llu prot=%llu flags=%llu fd_low=%llu fd_high=%llu off=%llu\n",
                    static_cast<unsigned>(result),nativeErrno,
                    static_cast<unsigned long long>(requestedAddress),
                    static_cast<unsigned long long>(requestedSize),
                    static_cast<unsigned long long>(requestedProt),
                    static_cast<unsigned long long>(requestedFlags),
                    static_cast<unsigned long long>(requestedFd & 0xffffffffULL),
                    static_cast<unsigned long long>(requestedFd >> 32),
                    static_cast<unsigned long long>(requestedOffset));
                std::fflush(stderr);
                _exit(34);
            }
            state.gregs[FEXCore::X86State::REG_RAX] = Heap.address();
            std::fprintf(stderr,"KERNIX_HEAP_MMAP_ALLOCATED_RW_NOT_EXECUTABLE\n");
        } else if (Count == 2) {
            const auto fd=state.gregs[FEXCore::X86State::REG_RDI];
            const auto ptr=state.gregs[FEXCore::X86State::REG_RSI];
            const auto len=state.gregs[FEXCore::X86State::REG_RDX];
            if (fd!=STDOUT_FILENO || !Heap.containsExactMessage(ptr,len) ||
                !Heap.matches(MESSAGE,MESSAGE_LENGTH)) {
                std::fprintf(stderr,"KERNIX_HEAP_GUEST_WRITE_POINTER_OR_MEMORY_REJECTED\n");
                _exit(35);
            }
            const ssize_t written = ::write(STDOUT_FILENO,
                reinterpret_cast<const void*>(ptr), MESSAGE_LENGTH);
            if(written != static_cast<ssize_t>(MESSAGE_LENGTH)) _exit(36);
            state.gregs[FEXCore::X86State::REG_RAX] = written;
            std::fprintf(stderr,"KERNIX_HEAP_GUEST_RW_COPY_AND_WRITE_VERIFIED\n");
        } else if (Count == 3) {
            state.gregs[FEXCore::X86State::REG_RAX] =
                static_cast<std::uint64_t>(getpid());
        } else {
            if (!Heap.freeByGuest(state.gregs[FEXCore::X86State::REG_RDI],
                                 state.gregs[FEXCore::X86State::REG_RSI])) {
                std::fprintf(stderr,"KERNIX_HEAP_GUEST_MUNMAP_ARGUMENTS_REJECTED\n");
                _exit(37);
            }
            state.gregs[FEXCore::X86State::REG_RAX] = 0;
            std::fprintf(stderr,"KERNIX_HEAP_MUNMAP_FREED_PROVEN\n");
        }
        state.rip = next;
    }
    bool completed() const noexcept {
        return Count == kernix::kManagedSyscalls.size() && Heap.isUnmapped();
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
    uintptr_t MessageAddress;
    kernix::ManagedGuestHeap Heap;
    unsigned Count = 0;
};

int run() {
    std::fprintf(stderr, "KERNIX_ELF64_STAGE=validate_and_map_elf\n");
    kernix::GuestELF guest{};
    const char* reason = nullptr;
    if (!kernix::loadFixedGuestELF(KERNIX_ELF64_HEAP_BLOB, sizeof(KERNIX_ELF64_HEAP_BLOB),
                                   guest, reason, kernix::GuestLayout::ManagedHeapSyscalls)) {
        std::fprintf(stderr, "KERNIX_ELF64_LOAD_REJECTED=%s\n", reason);
        return 19;
    }
    if (!guest.message || guest.messageSize != 32 ||
        std::memcmp(reinterpret_cast<const void*>(guest.message),
                    MESSAGE, MESSAGE_LENGTH) != 0) {
        std::fprintf(stderr, "KERNIX_ELF64_MESSAGE_MISMATCH\n");
        return 20;
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
    BoundedGuestSyscalls syscalls{guest};
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
    std::fprintf(stderr, "KERNIX_ELF64_STAGE=actual_guest_mmap_copy_write_getpid_munmap\n");
    ctx->ExecuteThread(thread);
    const uint64_t actual = thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    std::fprintf(stderr, "KERNIX_X86_REGISTER_RAX=%llu\n",
        static_cast<unsigned long long>(actual));
    if (!syscalls.completed() || actual != expected) return 18;
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
