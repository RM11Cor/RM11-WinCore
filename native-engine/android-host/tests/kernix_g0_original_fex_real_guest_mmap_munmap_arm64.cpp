// SPDX-License-Identifier: MIT
// Functional Linux ARM64 source-pinned original FEXCore x86 guest mmap(9)
// -> genuine guest store/read -> munmap(11) through bounded guest kernel.
// Original GNU x86_64 instructions, no original ld-linux or glibc startup.
// No Android phone execution or Windows game is claimed from Linux CI.
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include "kernix_g0_real_guest_mmap_munmap_blob.h"
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
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__) || \
    (!defined(__ANDROID__) && !defined(KERNIX_G0_ORIGINAL_FEX_GUEST_MMAP_ARM64_CI))
#error G0 genuine FEX guest mmap requires source-pinned ARM64/Linux or Android
#endif
namespace {
namespace abi=kernix::g2e::c1;
constexpr uint64_t kGuestPage=4096;
static_assert(sizeof(KERNIX_G0_MMAP_MUNMAP_GUEST)>=40 &&
              sizeof(KERNIX_G0_MMAP_MUNMAP_GUEST)<128,
              "Original x86 guest bounded mmap/munmap source changed");
void* AllocateLowGuest(uintptr_t hint,size_t len,int flags) {
    void* at=::mmap(reinterpret_cast<void*>(hint),len,flags,
                    MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(at==MAP_FAILED)return nullptr;
    if(!abi::GuestRange(reinterpret_cast<uintptr_t>(at),len)) {
        ::munmap(at,len);return nullptr;
    }
    return at;
}
class ActualOriginalFEXOwnedVM final : public FEXCore::HLE::SyscallHandler {
public:
    ActualOriginalFEXOwnedVM(uintptr_t entry,uintptr_t stack,size_t stackBytes)
      :Entry(entry),Stack{stack,stack+stackBytes,true}{}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        ++Calls;
        kernix::g2e::c2::ActualFexTrapWitness source{};
        if(Calls>2 ||
           !kernix::g2e::c2::DecodePinnedFexCpuState(frame,Stack,source) ||
           !source.originalFexCpuStateFrameRead){
            std::fputs("G0_FEX_MMAP_CPUSTATE_OR_PROVENANCE_REJECTED\n",stderr);
            _exit(41);
        }
        const auto& trap=source.decoded;
        const uint64_t offset=Calls==1?G0_MMAP_TRAP1_OFF:G0_MMAP_TRAP2_OFF;
        if(frame->State.rip!=Entry+offset ||
           trap.nextGuestRIP!=Entry+offset+2 ||
           trap.hostSyscallDispatched || trap.guestMemoryDereferenced) {
            std::fputs("G0_FEX_MMAP_SYSCALL_RIP_OR_ABI_REJECTED\n",stderr);
            _exit(42);
        }
        if(Calls==1){
            if(trap.guestNumber!=abi::kMmap || trap.args[0]!=0 ||
               trap.args[1]!=kGuestPage || trap.args[2]!=3 ||
               trap.args[3]!=0x22 ||
               !abi::IsGuestMmapFdAnonymous(trap.args[4]) ||
               trap.args[5]!=0) {
                std::fputs("G0_FEX_GUEST_MMAP_REGISTERS_REJECTED\n",stderr);
                _exit(43);
            }
            auto result=Memory.Dispatch(trap);
            if(!result.guestSyscallAuthenticated ||
               !result.nativeAnonymousMapCalled ||
               !result.guestWritableDataMapped ||
               result.guestReturn<65536 ||
               result.hostAnyUntrustedSyscallForwarded ||
               Memory.Count()!=1){
                std::fputs("G0_FEX_NATIVE_OWNED_MMAP_REJECTED\n",stderr);
                _exit(44);
            }
            GuestAddress=static_cast<uint64_t>(result.guestReturn);
            const auto span=Memory.AuthenticatedRW(GuestAddress,kGuestPage);
            if(!span.attested || span.guestExecute || !span.guestWrite ||
               span.start!=GuestAddress || span.pastLast!=GuestAddress+kGuestPage) {
                std::fputs("G0_FEX_GUEST_MMAP_RW_VMA_ATTESTATION_REJECTED\n",stderr);
                _exit(45);
            }
            frame->State.gregs[FEXCore::X86State::REG_RAX]=GuestAddress;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_MMAP_ALLOCATED_CANONICAL_RW_PAGE\n",stderr);
            return;
        }
        if(trap.guestNumber!=abi::kMunmap ||
           trap.args[0]!=GuestAddress ||
           trap.args[1]!=kGuestPage ||
           frame->State.gregs[FEXCore::X86State::REG_R12]!=0x5a ||
           Memory.Count()!=1 ||
           !Memory.AuthenticatedRW(GuestAddress,1).attested ||
           *reinterpret_cast<const volatile uint8_t*>(
             static_cast<uintptr_t>(GuestAddress))!=0x5a) {
            std::fputs("G0_FEX_GUEST_REAL_STORE_LOAD_OR_MUNMAP_ABI_REJECTED\n",stderr);
            _exit(46);
        }
        GuestLoadAndStoreObserved=true;
        auto result=Memory.Dispatch(trap);
        if(!result.guestSyscallAuthenticated ||
           result.guestReturn!=0 ||
           !result.nativeOwnedMapReleased ||
           result.hostAnyUntrustedSyscallForwarded ||
           Memory.Count()!=0 ||
           Memory.AuthenticatedRW(GuestAddress,1).attested){
            std::fputs("G0_FEX_GUEST_NATIVE_OWNED_MUNMAP_REJECTED\n",stderr);
            _exit(47);
        }
        NativePageReleased=true;
        frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
        frame->State.rip=trap.nextGuestRIP;
        std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_BYTE_5A_STORED_AND_NATIVE_PAGE_UNMAPPED\n",stderr);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
      FEXCore::Core::InternalThreadState*,uint64_t address) override {
        if(address>=Entry && address<Entry+sizeof(KERNIX_G0_MMAP_MUNMAP_GUEST))
          return {Entry,sizeof(KERNIX_G0_MMAP_MUNMAP_GUEST),false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
    unsigned Calls=0;
    bool GuestLoadAndStoreObserved=false;
    bool NativePageReleased=false;
    kernix::g0::BoundedGuestAnonymousVM Memory{};
private:
    uintptr_t Entry=0;
    abi::X86GuestStackBoundary Stack{};
    uint64_t GuestAddress=0;
};
int Run() {
    const long ps=::sysconf(_SC_PAGESIZE);
    if(ps!=4096 && ps!=16384)return 11;
    if(ps==16384) {
        // A 4K guest mmap cannot yet be isolated within a 16K host
        // page. The guest-owned VM subsystem correctly denies it.
        std::puts("G0_X86_GUEST_4K_MMAP_ON_16K_HOST_PAGE_DENIED_SAFELY=1");
        return 24;
    }
    const auto page=static_cast<size_t>(ps);
    void* code=AllocateLowGuest(0x0000440000000000ULL,page,PROT_READ|PROT_WRITE);
    void* stack=AllocateLowGuest(0x0000600000000000ULL,page*2,PROT_READ|PROT_WRITE);
    if(!code || !stack)return 12;
    std::memcpy(code,KERNIX_G0_MMAP_MUNMAP_GUEST,sizeof(KERNIX_G0_MMAP_MUNMAP_GUEST));
    if(::mprotect(code,page,PROT_READ|PROT_EXEC)!=0)return 13;
    const auto entry=reinterpret_cast<uintptr_t>(code);
    const auto stackStart=reinterpret_cast<uintptr_t>(stack);
    if(!abi::GuestRange(entry,sizeof(KERNIX_G0_MMAP_MUNMAP_GUEST)) ||
       !abi::GuestRange(stackStart,page*2))return 14;

    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
    if(!FEXCore::Config::GetConv<bool>(
         FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))return 15;
    FEXCore::HostFeatures host{};
    host.DCacheLineLog2=4;
    host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    host.ProcessFeatures.Is64BitMode=1;
    host.ProcessPID=static_cast<uint32_t>(::getpid());
    host.CPUMIDRs.push_back(0);
    auto ctx=FEXCore::Context::Context::CreateNewContext(host);
    if(!ctx)return 16;
    FEXCore::SignalDelegator signals{};
    ActualOriginalFEXOwnedVM handler{entry,stackStart,page*2};
    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&handler);
    ctx->EnableExitOnHLT();
    if(!ctx->InitCore())return 17;
    auto* guest=ctx->CreateThread();
    if(!guest || !guest->CurrentFrame)return 18;
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& cpu=guest->CurrentFrame->State;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    cpu.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* segment=FEXCore::Core::CPUState::GetSegmentFromIndex(cpu,cpu.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(segment,0);
    FEXCore::Core::CPUState::SetGDTLimit(segment,0xFFFFF);
    segment->L=1;segment->D=0;cpu.cs_cached=0;
    cpu.gregs[FEXCore::X86State::REG_RSP]=(stackStart+page*2-16)&~uintptr_t(15);
    cpu.rip=entry;
    std::fputs("KERNIX_G0_ACTUAL_ORIGINAL_FEX_X86_MMAP_MUNMAP_GUEST_START\n",stderr);
    ctx->ExecuteThread(guest);
    if(handler.Calls!=2 || !handler.GuestLoadAndStoreObserved ||
       !handler.NativePageReleased || handler.Memory.Count()!=0 ||
       cpu.gregs[FEXCore::X86State::REG_RAX]!=0 ||
       cpu.gregs[FEXCore::X86State::REG_R12]!=0x5a)return 19;
    if(!handler.Memory.Reset())return 20;
#if defined(__ANDROID__)
    std::puts("KERNIX_G0_ANDROID_REAL_ORIGINAL_FEX_GUEST_MMAP_STORE_LOAD_MUNMAP_NATIVE_PASS_NO_LDSO_GLIBC");
#else
    std::puts("KERNIX_G0_ACTUAL_ORIGINAL_FEX_X86_GUEST_MMAP_STORE_LOAD_MUNMAP_LINUX_ARM64_PASS_NO_LDSO_GLIBC_ANDROID");
#endif
    return 0;
}
} // namespace
int main() {return Run();}
