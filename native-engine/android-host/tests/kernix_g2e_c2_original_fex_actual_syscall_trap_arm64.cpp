// KERNIX G2-E/C2 real upstream-FEX Linux ARM64 syscall frame proof.
// A precisely fixed, in-memory 41-byte x86 fixture executes ONE SYSCALL.
// We compare the real FEX CpuStateFrame registers against a separate
// attested x86 Linux syscall decoder, return guest -ENOSYS without host
// dispatch, then require the guest to reach HLT with that real RAX result.
// This deliberately does NOT use x86 glibc, ld-linux or arbitrary files.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
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
#include <cassert>

#if !defined(__aarch64__) || !defined(KERNIX_G2EC2_ORIGINAL_FEX_LINUX_ARM64_CI)
#error G2-E/C2 fixture only runs on explicit Linux ARM64 original FEX CI
#endif
namespace {
constexpr uint8_t GUEST[]={
    0xb8,0x27,0x00,0x00,0x00,             // mov eax,39 (Linux x86 getpid)
    0xbf,0x11,0x00,0x00,0x00,             // mov edi,17
    0xbe,0x22,0x00,0x00,0x00,             // mov esi,34
    0xba,0x33,0x00,0x00,0x00,             // mov edx,51
    0x41,0xba,0x44,0x00,0x00,0x00,        // mov r10d,68: ARG FOUR
    0x41,0xb8,0x55,0x00,0x00,0x00,        // mov r8d,85
    0x41,0xb9,0x66,0x00,0x00,0x00,        // mov r9d,102
    0x0f,0x05,                            // SYSCALL at +38, next RIP +40
    0xf4                                  // HLT (bounded guest only)
};
constexpr uintptr_t kTrapOffset=38,kTrapNext=40;
static_assert(sizeof(GUEST)==41 && GUEST[38]==0x0f &&
              GUEST[39]==0x05 && GUEST[40]==0xf4);

class NoDispatchTrap final : public FEXCore::HLE::SyscallHandler {
public:
    NoDispatchTrap(uintptr_t entry,uintptr_t stackStart,uintptr_t stackEnd)
      : Entry(entry),Stack{stackStart,stackEnd,true} {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        ++Calls;
        kernix::g2e::c2::ActualFexTrapWitness witness;
        if(Calls!=1 ||
           !kernix::g2e::c2::DecodePinnedFexCpuState(frame,Stack,witness)) {
            std::fputs("KERNIX_G2EC2_REAL_FEX_TRAP_BOUNDARY_REJECTED\n",stderr);
            _exit(41);
        }
        const auto& dec=witness.decoded;
        if(!witness.originalFexCpuStateFrameRead ||
           dec.guestNumber!=kernix::g2e::c1::kGetpid ||
           dec.category!=kernix::g2e::c1::CallCategory::HostlessIdentity ||
           dec.nextGuestRIP!=Entry+kTrapNext ||
           frame->State.rip!=Entry+kTrapOffset ||
           dec.args[0]!=17 || dec.args[1]!=34 || dec.args[2]!=51 ||
           dec.args[3]!=68 || dec.args[4]!=85 || dec.args[5]!=102 ||
           dec.args[3]==frame->State.gregs[FEXCore::X86State::REG_RCX] ||
           dec.hostSyscallDispatched || dec.guestMemoryDereferenced) {
            std::fputs("KERNIX_G2EC2_REAL_FEX_X86_GPR_MAPPING_REJECTED\n",stderr);
            _exit(42);
        }
        // Actual FEX trap reached. This is NOT a glibc guest loader trap.
        ObservedRealTrap=true;
        frame->State.gregs[FEXCore::X86State::REG_RAX]=
            static_cast<uint64_t>(kernix::g2e::c2::NoHostDispatchLinuxEnosys());
        frame->State.rip=dec.nextGuestRIP;
        std::fputs("KERNIX_G2EC2_REAL_FEX_CPUSTATE_SYSCALL_HANDLED_NO_HOST_FORWARD\n",stderr);
        std::fflush(stderr);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*,uint64_t address) override {
        if(address>=Entry && address<Entry+sizeof(GUEST))
            return {Entry,sizeof(GUEST),false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
    unsigned Calls=0;
    bool ObservedRealTrap=false;
private:
    uintptr_t Entry;
    kernix::g2e::c1::X86GuestStackBoundary Stack;
};

// No MAP_FIXED: low canonical VA is a *hint*, fully checked after mapping.
// On Linux ARM64 this is a bounded source-proven guest fixture, NOT APK/JIT.
void* AllocLowPage(uintptr_t hint,size_t bytes,int prot) {
    void* p=mmap(reinterpret_cast<void*>(hint),bytes,prot,
                 MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED)return nullptr;
    if(!kernix::g2e::c1::GuestRange(
           reinterpret_cast<uintptr_t>(p),bytes)){
        munmap(p,bytes);return nullptr;
    }
    return p;
}
bool SourceLevelFrameNegatives() {
    FEXCore::Core::CpuStateFrame frame{};
    auto& c=frame.State;
    const auto set=[&](FEXCore::Core::CPUState& cpu) {
        cpu.rip=0x0000440000001000ULL;
        cpu.gregs[FEXCore::X86State::REG_RAX]=39;
        cpu.gregs[FEXCore::X86State::REG_RDI]=17;
        cpu.gregs[FEXCore::X86State::REG_RSI]=34;
        cpu.gregs[FEXCore::X86State::REG_RDX]=51;
        cpu.gregs[FEXCore::X86State::REG_R10]=68;
        cpu.gregs[FEXCore::X86State::REG_R8]=85;
        cpu.gregs[FEXCore::X86State::REG_R9]=102;
        cpu.gregs[FEXCore::X86State::REG_RCX]=cpu.rip+2;
        cpu.gregs[FEXCore::X86State::REG_R11]=0x246;
        cpu.gregs[FEXCore::X86State::REG_RSP]=0x0000600000003ff0ULL;
    };
    set(c);
    const kernix::g2e::c1::X86GuestStackBoundary stack{
        0x0000600000000000ULL,0x0000600000004000ULL,true};
    kernix::g2e::c2::ActualFexTrapWitness witness;
    if(!kernix::g2e::c2::DecodePinnedFexCpuState(&frame,stack,witness) ||
       witness.decoded.args[3]!=68 || witness.decoded.args[4]!=85 ||
       witness.decoded.args[5]!=102 ||
       witness.decoded.nextGuestRIP!=c.rip+2)return false;
    // Source-level proof alone MUST NOT be misreported as an executed trap.
    if(witness.guestSyscallExecuted || witness.guestDynamicLinkerEntered ||
       witness.guestKernelDispatched)return false;
    c.gregs[FEXCore::X86State::REG_RCX]=c.rip+3;
    if(kernix::g2e::c2::DecodePinnedFexCpuState(&frame,stack,witness))
        return false;
    set(c);c.gregs[FEXCore::X86State::REG_RSP]=stack.pastLast;
    if(kernix::g2e::c2::DecodePinnedFexCpuState(&frame,stack,witness))
        return false;
    set(c);
    auto untrusted=stack;untrusted.attestedFromPinnedGuest=false;
    return !kernix::g2e::c2::DecodePinnedFexCpuState(
        &frame,untrusted,witness);
}
int run() {
    if(!SourceLevelFrameNegatives())return 20;
    long p=sysconf(_SC_PAGESIZE);
    if(p<4096 || p>65536 || (p&(p-1))!=0)return 21;
    size_t page=static_cast<size_t>(p);
    void* code=AllocLowPage(0x0000480000000000ULL,page,
                            PROT_READ|PROT_WRITE);
    void* stack=AllocLowPage(0x0000600000000000ULL,2*page,
                             PROT_READ|PROT_WRITE);
    if(!code||!stack)return 22;
    const uintptr_t entry=reinterpret_cast<uintptr_t>(code);
    const uintptr_t stackBegin=reinterpret_cast<uintptr_t>(stack);
    const uintptr_t stackEnd=stackBegin+2*page;
    if(stackEnd<=stackBegin ||
       !kernix::g2e::c1::GuestRange(entry,sizeof(GUEST)) ||
       !kernix::g2e::c1::GuestRange(stackBegin,2*page))
        return 23;
    std::memcpy(code,GUEST,sizeof(GUEST));
    if(std::memcmp(code,GUEST,sizeof(GUEST))!=0 ||
       mprotect(code,page,PROT_READ|PROT_EXEC)!=0)return 24;
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    // Real prior G1 finding: set x86-64 mode AFTER meta-layer reload.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
    if(!FEXCore::Config::GetConv<bool>(
          FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))
        return 25;
    FEXCore::HostFeatures host{};
    host.DCacheLineLog2=4;
    host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    host.ProcessFeatures.Is64BitMode=1;
    host.ProcessPID=static_cast<uint32_t>(getpid());
    host.CPUMIDRs.push_back(0);
    auto context=FEXCore::Context::Context::CreateNewContext(host);
    if(!context)return 26;
    FEXCore::SignalDelegator signals{};
    NoDispatchTrap handler{entry,stackBegin,stackEnd};
    context->SetSignalDelegator(&signals);
    context->SetSyscallHandler(&handler);
    context->EnableExitOnHLT();
    if(!context->InitCore())return 27;
    auto* thread=context->CreateThread();
    if(!thread||!thread->CurrentFrame)return 28;
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& state=thread->CurrentFrame->State;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    state.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* segment=FEXCore::Core::CPUState::GetSegmentFromIndex(
        state,state.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(segment,0);
    FEXCore::Core::CPUState::SetGDTLimit(segment,0xFFFFF);
    segment->L=1;segment->D=0;state.cs_cached=0;
    state.gregs[FEXCore::X86State::REG_RSP]=(stackEnd-16)&~uintptr_t(15);
    state.gregs[FEXCore::X86State::REG_RAX]=0;
    state.rip=entry;
    std::fputs("KERNIX_G2EC2_ORIGINAL_FEX_GUEST_FIXTURE_STARTED_NO_GLIBC\n",stderr);
    context->ExecuteThread(thread);
    const auto rax=thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    if(!handler.ObservedRealTrap || handler.Calls!=1 ||
       static_cast<int64_t>(rax)!=-38)
        return 29;
    std::puts("KERNIX_G2EC2_ORIGINAL_FEX_ARM64_REAL_X86_GUEST_SYSCALL_CPUSTATE_R10_R8_R9_TO_ENOSYS_PASS_NO_GLIBC_NO_ANDROID");
    return 0;
}
}
int main(int argc,char**) {
    if(argc!=1)return 2;
    return run();
}
