// SPDX-License-Identifier: MIT
// Functional *single-process* first integration gate: source SHA256-pinned
// original x86 ELF main, ld-linux, libc PT_LOAD and authentic initial AUXV
// stack are owned and W^X protected by the existing C3-D7B/C3-D7G runtime.
// The SAME original upstream FEXCore context executes GNU-as x86 code which
// reads the original main image and initial argc, then makes genuine Linux
// x86 mmap(9) -> guest store/load -> munmap(11) syscalls. This is NOT
// source-original ld-linux instruction execution or full ELF startup.
#include "kernix_g2e_c3d8a_original_loader_handoff_barrier.h"
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include "kernix_g0_original_elf_fex_process_integration_blob.h"
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/fextl/memory.h>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <optional>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__) || \
    (!defined(__ANDROID__) && !defined(KERNIX_G0_ORIGINAL_ELF_INTEGRATED_FEX_ARM64_CI))
#error G0 original pinned ELF + real FEX integration requires ARM64
#endif

namespace {
namespace c1=kernix::g2e::c1;
namespace c2=kernix::g2e::c2;
namespace c7b=kernix::g2e::c3d7b;
namespace c7g=kernix::g2e::c3d7g;
namespace c8a=kernix::g2e::c3d8a;
constexpr uint64_t kGuestAnonBytes=4096;

class OwnedGuestFixtureCode final {
public:
    ~OwnedGuestFixtureCode() {if(address_)::munmap(address_,length_);}
    bool Install() noexcept {
        const long hostPage=::sysconf(_SC_PAGESIZE);
        if(hostPage!=4096)return false; // C3-D7B/C3-D7G are 4K only.
        length_=static_cast<size_t>(hostPage);
        void* p=::mmap(reinterpret_cast<void*>(0x0000440000000000ULL),
            length_,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED)return false;
        address_=p;
        if(!c1::GuestRange(Address(),length_))return false;
        std::memcpy(p,KERNIX_G0_ELF_FEX_INTEGRATION_GUEST,
                    sizeof(KERNIX_G0_ELF_FEX_INTEGRATION_GUEST));
        if(::mprotect(p,length_,PROT_READ|PROT_EXEC)!=0)return false;
        return true;
    }
    uintptr_t Address() const noexcept {
        return reinterpret_cast<uintptr_t>(address_);
    }
private:
    void* address_=nullptr;
    size_t length_=0;
};

class OneProcessOriginalElfSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    OneProcessOriginalElfSyscalls(uint64_t entry,
                                 const kernix::g2b::X86GuestProcessLaunchPlan& plan,
                                 const c7b::ImageMeta& mainImage,
                                 uint64_t mainSourceWord,
                                 const c7b::NativeChosenPIEGuestLayout& owner)
       :Entry(entry),
        Stack{plan.stack.guestBottom,plan.stack.guestTop,true},
        MainStart(mainImage.chosenImageStart),
        InitialRSP(plan.stack.guestRSP),
        MainSourceWord(mainSourceWord),
        OriginalLdsoEntry(plan.guestInterpreterEntry),
        Owner(owner){}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        if(++Calls>2) {
            std::fputs("G0_COMBINED_TOO_MANY_SYSCALLS_REJECTED\n",stderr);
            _exit(51);
        }
        c2::ActualFexTrapWitness verified{};
        if(!c2::DecodePinnedFexCpuState(frame,Stack,verified) ||
           !verified.originalFexCpuStateFrameRead) {
            std::fputs("G0_COMBINED_FEX_CPUSTATE_REJECTED\n",stderr);
            _exit(52);
        }
        const auto& trap=verified.decoded;
        const size_t syscallOffset=Calls==1?
            G0_ELF_INTEGRATION_SYSCALL_MMAP_OFFSET:
            G0_ELF_INTEGRATION_SYSCALL_MUNMAP_OFFSET;
        if(frame->State.rip!=Entry+syscallOffset ||
           trap.nextGuestRIP!=Entry+syscallOffset+2 ||
           Owner.WindowsHeld()!=4 ||
           !Owner.LaunchPlan() ||
           Owner.LaunchPlan()->stack.guestRSP!=InitialRSP ||
           Owner.Module(0)->chosenImageStart!=MainStart ||
           !Owner.GuestReadOnlyBytes(1,OriginalLdsoEntry,8)) {
            std::fputs("G0_COMBINED_ORIGINAL_ENTRY_OR_RIP_REJECTED\n",stderr);
            _exit(53);
        }
        if(Calls==1) {
            if(trap.guestNumber!=c1::kMmap ||
               trap.args[0]!=0 || trap.args[1]!=kGuestAnonBytes ||
               trap.args[2]!=3 || trap.args[3]!=0x22 ||
               !c1::IsGuestMmapFdAnonymous(trap.args[4]) ||
               trap.args[5]!=0 ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1) {
                std::fputs("G0_COMBINED_MAIN_ELF_OR_ARGC_NOT_READ_BY_X86_REJECTED\n",stderr);
                _exit(54);
            }
            const auto result=Heap.Dispatch(trap);
            if(!result.guestSyscallAuthenticated ||
               !result.nativeAnonymousMapCalled ||
               !result.guestWritableDataMapped ||
               result.hostAnyUntrustedSyscallForwarded ||
               result.guestReturn<65536 || Heap.Count()!=1) {
                std::fputs("G0_COMBINED_X86_MMAP_OWNER_REJECTED\n",stderr);
                _exit(55);
            }
            HeapAddress=static_cast<uint64_t>(result.guestReturn);
            const auto span=Heap.AuthenticatedRW(HeapAddress,kGuestAnonBytes);
            if(!span.attested || span.guestExecute ||
               !span.guestRead || !span.guestWrite ||
               span.start!=HeapAddress ||
               span.pastLast!=HeapAddress+kGuestAnonBytes) {
                std::fputs("G0_COMBINED_ANON_PAGE_RIGHTS_REJECTED\n",stderr);
                _exit(56);
            }
            // An authenticated guest must never be able to unmap
            // source-owned main, interpreter, libc or initial stack.
            auto counterfeit=trap;
            counterfeit.guestNumber=c1::kMunmap;
            counterfeit.args={OriginalLdsoEntry,kGuestAnonBytes,0,0,0,0};
            const auto denied=Heap.Dispatch(counterfeit);
            if(denied.guestReturn!=-EINVAL ||
               denied.nativeOwnedMapReleased ||
               Heap.Count()!=1 || Owner.WindowsHeld()!=4) {
                std::fputs("G0_COMBINED_FOREIGN_LDSO_MUNMAP_DENIAL_REJECTED\n",stderr);
                _exit(57);
            }
            DeniedForeignUnmap=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=HeapAddress;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_COMBINED_FEX_ORIGINAL_ELF_AND_STACK_CONSUMED\n",stderr);
            return;
        }
        if(trap.guestNumber!=c1::kMunmap ||
           trap.args[0]!=HeapAddress ||
           trap.args[1]!=kGuestAnonBytes ||
           frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
           frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
           frame->State.gregs[FEXCore::X86State::REG_R15]!=MainSourceWord ||
           Heap.Count()!=1 || !DeniedForeignUnmap ||
           !Heap.AuthenticatedRW(HeapAddress,sizeof(uint64_t)).attested) {
            std::fputs("G0_COMBINED_REAL_X86_HEAP_COPY_OR_MUNMAP_REJECTED\n",stderr);
            _exit(58);
        }
        uint64_t copied=0;
        std::memcpy(&copied,
             reinterpret_cast<const void*>(static_cast<uintptr_t>(HeapAddress)),
             sizeof(copied));
        if(copied!=MainSourceWord ||
           !Owner.GuestReadOnlyBytes(0,MainStart,sizeof(uint64_t))) {
            std::fputs("G0_COMBINED_SOURCE_ELF_GUEST_COPY_REJECTED\n",stderr);
            _exit(59);
        }
        const auto released=Heap.Dispatch(trap);
        if(released.guestReturn!=0 ||
           !released.nativeOwnedMapReleased ||
           released.hostAnyUntrustedSyscallForwarded ||
           Heap.Count()!=0 || Heap.AuthenticatedRW(HeapAddress,1).attested ||
           Owner.WindowsHeld()!=4) {
            std::fputs("G0_COMBINED_HEAP_CLEANUP_REJECTED\n",stderr);
            _exit(60);
        }
        WholeProcessIntegrationCompleted=true;
        frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
        frame->State.rip=trap.nextGuestRIP;
        std::fputs("KERNIX_G0_COMBINED_X86_HEAP_COPY_AND_MUNMAP_WITH_ORIGINAL_PIE_ALIVE\n",stderr);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*,uint64_t address) override {
        if(address>=Entry &&
           address<Entry+sizeof(KERNIX_G0_ELF_FEX_INTEGRATION_GUEST))
            return {Entry,sizeof(KERNIX_G0_ELF_FEX_INTEGRATION_GUEST),false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo>
    LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
    unsigned Calls=0;
    bool DeniedForeignUnmap=false;
    bool WholeProcessIntegrationCompleted=false;
    kernix::g0::BoundedGuestAnonymousVM Heap{};
private:
    uint64_t Entry=0;
    c1::X86GuestStackBoundary Stack{};
    uint64_t MainStart=0,InitialRSP=0,MainSourceWord=0;
    uint64_t OriginalLdsoEntry=0,HeapAddress=0;
    const c7b::NativeChosenPIEGuestLayout& Owner;
};

int Run(int argc,char** argv) {
    if(argc!=2 || !argv[1] || ::sysconf(_SC_PAGESIZE)!=4096)
        return 2;
    const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    kernix::g2e::GuestPreflight original{};
    std::string why{};
    const bool verified=kernix::g2e::Validate(fd,original,why);
    if(!verified || !original.exactSha256Matched ||
       !original.exactInterpreterAndGlibcClosure ||
       !original.readOnlyAnonymousSnapshots) {
        ::close(fd);return 4;
    }
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)entropy[i]=uint8_t(i+1);
    c7b::NativeChosenPIEGuestLayout owned{};
    c7b::Witness source{};
    const bool staged=owned.Stage(fd,entropy,source);
    ::close(fd);
    if(!staged || !source.pinnedOriginalELFSHA256Verified ||
       source.windowsReserved!=4 || owned.WindowsHeld()!=4 ||
       !source.linuxAuxvRebased || !source.originalBytesCopiedReadOnly ||
       source.originalLdsoExecuted || source.originalELFCodeExecuted)
        return 5;
    c7g::ApplyWitness rights{};
    if(!c7g::ApplyOwnedOriginalPTLoadPagePermissions(
        owned,original,rights) ||
       !rights.originalPinnedSourceValidated ||
       !rights.nativeNoWritableExecutablePage ||
       !rights.nativeNonPTLoadHolesDenied ||
       !rights.nativeStackGuardDenied ||
       !rights.nativeLinuxStackWritableNonExecutable ||
       rights.originalModulesProtected!=3 ||
       rights.originalLdsoExecuted || rights.fexEntered)
        return 6;
    const auto* plan=owned.LaunchPlan();
    const auto* main=owned.Module(0);
    const auto* interpreter=owned.Module(1);
    if(!plan || !main || !interpreter ||
       !c1::GuestRange(main->chosenImageStart,8) ||
       !c1::GuestRange(plan->guestInterpreterEntry,8) ||
       plan->guestInterpreterEntry<interpreter->chosenImageStart ||
       !owned.GuestReadOnlyBytes(1,plan->guestInterpreterEntry,8))
        return 7;
    const auto* sourceMain=owned.GuestReadOnlyBytes(
         0,main->chosenImageStart,sizeof(uint64_t));
    if(!sourceMain || sourceMain[0]!=0x7f || sourceMain[1]!='E' ||
       sourceMain[2]!='L' || sourceMain[3]!='F')
        return 8;
    uint64_t first8=0;
    std::memcpy(&first8,sourceMain,sizeof(first8));
    const uint64_t rsp=plan->stack.guestRSP;
    uint64_t argcWord=0;
    std::memcpy(&argcWord,
        reinterpret_cast<const void*>(static_cast<uintptr_t>(rsp)),
        sizeof(argcWord));
    if(argcWord!=1 || (rsp&15)!=0)
        return 9;
    OwnedGuestFixtureCode code;
    if(!code.Install() || !c1::GuestRange(
        code.Address(),sizeof(KERNIX_G0_ELF_FEX_INTEGRATION_GUEST)))
        return 10;

    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
    if(!FEXCore::Config::GetConv<bool>(
         FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))
        return 11;
    FEXCore::HostFeatures host{};
    host.DCacheLineLog2=4;
    host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    host.ProcessFeatures.Is64BitMode=1;
    host.ProcessPID=static_cast<uint32_t>(::getpid());
    host.CPUMIDRs.push_back(0);
    auto ctx=FEXCore::Context::Context::CreateNewContext(host);
    if(!ctx)return 12;
    FEXCore::SignalDelegator signals{};
    OneProcessOriginalElfSyscalls handler{
        code.Address(),*plan,*main,first8,owned};
    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&handler);
    ctx->EnableExitOnHLT();
    if(!ctx->InitCore())return 13;
    auto* thread=ctx->CreateThread();
    if(!thread || !thread->CurrentFrame)return 14;
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& cpu=thread->CurrentFrame->State;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    cpu.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* descriptor=FEXCore::Core::CPUState::GetSegmentFromIndex(cpu,cpu.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(descriptor,0);
    FEXCore::Core::CPUState::SetGDTLimit(descriptor,0xFFFFF);
    descriptor->L=1;descriptor->D=0;cpu.cs_cached=0;
    cpu.rip=code.Address();
    cpu.gregs[FEXCore::X86State::REG_RSP]=rsp;
    cpu.gregs[FEXCore::X86State::REG_R13]=main->chosenImageStart;
    cpu.gregs[FEXCore::X86State::REG_R12]=0;
    cpu.gregs[FEXCore::X86State::REG_R14]=0;
    cpu.gregs[FEXCore::X86State::REG_R15]=0;
    std::fputs("KERNIX_G0_SINGLE_FEX_SOURCE_ORIGINAL_PIE_AUXV_HEAP_START\n",stderr);
    std::fflush(stderr);
    ctx->ExecuteThread(thread);
    if(handler.Calls!=2 ||
       !handler.WholeProcessIntegrationCompleted ||
       !handler.DeniedForeignUnmap ||
       handler.Heap.Count()!=0 ||
       cpu.gregs[FEXCore::X86State::REG_R12]!=first8 ||
       cpu.gregs[FEXCore::X86State::REG_R14]!=1 ||
       cpu.gregs[FEXCore::X86State::REG_R15]!=first8 ||
       cpu.gregs[FEXCore::X86State::REG_RAX]!=0 ||
       cpu.gregs[FEXCore::X86State::REG_RSP]!=rsp ||
       owned.WindowsHeld()!=4)
        return 15;
    uint32_t unchanged=0;
    if(!c8a::FileBackedSegmentsUnchanged(original,owned,unchanged) ||
       unchanged<3)return 16;
    ctx.reset();
    if(!handler.Heap.Reset() ||
       !owned.Release() || owned.WindowsHeld()!=0)return 17;
#if defined(__ANDROID__)
    std::puts("KERNIX_G0_SINGLE_FEX_ORIGINAL_PIE_ELF_AUXV_X86_HEAP_ANDROID_NATIVE_PASS_NO_LDSO");
#else
    std::puts("KERNIX_G0_SINGLE_FEX_ORIGINAL_SHA_PIE_ELF_AUXV_X86_HEAP_LINUX_ARM64_PASS_NO_LDSO_ANDROID");
#endif
    return 0;
}
} // namespace

int main(int argc,char** argv) {return Run(argc,argv);}
