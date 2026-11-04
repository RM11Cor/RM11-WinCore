/*
 * KERNIX G2-D first real x86-64 ELF64 cross-DSO imported-function FEX JIT.
 * Linux ARM64 CI ONLY, no Android distribution or user-triggered APK.
 * One MIT-only SHA-pinned x86 ET_DYN PIE calls a function in a DIFFERENT
 * MIT-only x86 ET_DYN DSO using one real R_X86_64_JUMP_SLOT GOT patch.
 * No glibc, ld-linux startup, TLS, arbitrary dlsym, Wine or games.
 * SPDX-License-Identifier: MIT
 */
#include "kernix_g2d_mit_import_linker.h"
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
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__) || defined(__ANDROID__) || !defined(KERNIX_G2D_NATIVE_ARM64_CI)
#error G2-D real external FEX call is confined to isolated Linux ARM64 CI
#endif
namespace {
class NoSyscalls final : public FEXCore::HLE::SyscallHandler {
public:
    NoSyscalls(uint64_t a,uint64_t as,uint64_t b,uint64_t bs):
        A(a),AS(as),B(b),BS(bs){}
    void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
        std::fputs("KERNIX_G2D_UNEXPECTED_X86_SYSCALL_REJECTED\n",stderr);
        std::fflush(stderr);
        _exit(83);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*,uint64_t where) override {
        if(where>=A && where-A<AS)return {A,AS,false};
        if(where>=B && where-B<BS)return {B,BS,false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo>
    LookupExecutableFileSection(FEXCore::Core::InternalThreadState*,
                                uint64_t) override {
        return std::nullopt;
    }
private:
    uint64_t A=0,AS=0,B=0,BS=0;
};

bool EnableExactlyOneGuestRX(
    const kernix::g2b::GuestReadonlyImage& elf,
    const kernix::g2b::X86HostNoAccessReservation& window,
    uint64_t bias,uint64_t& first,uint64_t& bytes,std::string& why) {
    first=0;bytes=0;unsigned seen=0;
    const long hostPage=sysconf(_SC_PAGESIZE);
    if((hostPage!=4096 && hostPage!=16384) ||
       !elf.hostViewReadOnly || elf.hostViewExecutable ||
       window.guestStart>UINT64_MAX-window.guestBytes ||
       !window.guestStart || !window.guestBytes){
        why="G2D_EXEC_BAD_STAGED_IMAGE_OR_PAGE";return false;
    }
    const uint64_t page=static_cast<uint64_t>(hostPage);
    const uint64_t windowEnd=window.guestStart+window.guestBytes;
    for(const auto& part:elf.segments){
        if(!(part.guestFlags&PF_X))continue;
        if(part.guestFlags&PF_W || !part.memoryBytes || ++seen!=1 ||
           part.guestVaddr>UINT64_MAX-bias) {
            why="G2D_EXEC_AMBIGUOUS_OR_RWX_TEXT";return false;
        }
        const uint64_t text=bias+part.guestVaddr;
        if(part.memoryBytes>UINT64_MAX-text || text<window.guestStart ||
           text+part.memoryBytes>windowEnd){
            why="G2D_EXEC_TEXT_OUTSIDE_PROTECTED_WINDOW";return false;
        }
        const uint64_t start=text & ~(page-1);
        if(text+part.memoryBytes>UINT64_MAX-(page-1)) {
            why="G2D_EXEC_HOST_PAGE_OVERFLOW";return false;
        }
        const uint64_t end=(text+part.memoryBytes+page-1)&~(page-1);
        if(start<window.guestStart || end>windowEnd || end<=start){
            why="G2D_EXEC_HOST_RX_PAGE_OUTSIDE_RESERVATION";return false;
        }
        for(const auto& other:elf.segments){
            if(&other==&part || !other.memoryBytes)continue;
            if(other.guestVaddr>UINT64_MAX-bias ||
               other.memoryBytes>UINT64_MAX-(bias+other.guestVaddr)) {
                why="G2D_EXEC_OTHER_PTLOAD_ADDRESS_OVERFLOW";return false;
            }
            const uint64_t firstOther=bias+other.guestVaddr;
            if(firstOther<end && firstOther+other.memoryBytes>start) {
                why="G2D_EXEC_HOST_PAGE_RX_COLLIDES_WITH_OTHER_PTLOAD";return false;
            }
        }
        if(mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(start)),
                   static_cast<size_t>(end-start),PROT_READ|PROT_EXEC)!=0) {
            why="G2D_EXEC_MPROTECT_RX_FAILED";return false;
        }
        first=text;bytes=part.memoryBytes;
    }
    if(seen!=1){why="G2D_EXEC_EXACTLY_ONE_TEXT_REQUIRED";return false;}
    why="none";return true;
}

int Execute(const char* appDir) {
    if(!appDir || appDir[0]!='/')return 2;
    kernix::g2d::PinnedImportELFs src;
    std::string why;
    if(!kernix::g2d::PinFixedImportELFs(appDir,src,why)) {
        std::fprintf(stderr,"KERNIX_G2D_MIT_SHA_PIN_REJECTED:%s\n",why.c_str());
        return 10;
    }
    kernix::g2d::FixedImportPlan reloc{};
    if(!kernix::g2d::AuditFixedImport(src,reloc,why)) {
        std::fprintf(stderr,"KERNIX_G2D_GUEST_RELA_IMPORT_REJECTED:%s\n",why.c_str());
        return 11;
    }
    auto resolver=kernix::g2d::Resolver(src);
    kernix::g2b::GuestDependencyClosure closure;
    if(!kernix::g2b::AuditGuestELFDependencyClosureFromResolver(
           resolver,kernix::g2d::kMain,closure,why) ||
       closure.guestInterpreter!=kernix::g2d::kInterp ||
       closure.nodes.size()!=3 || closure.resolvedEdges!=1 ||
       !closure.allDirectAndTransitiveFilesPresent) {
        std::fprintf(stderr,"KERNIX_G2D_GUEST_DEPENDENCY_CLOSURE_REJECTED:%s\n",why.c_str());
        return 12;
    }
    std::array<uint8_t,16> random{};
    for(unsigned i=0;i<16;i++)random[i]=static_cast<uint8_t>(i+1);
    kernix::g2b::X86HostReservedGuestLaunch host;
    if(!kernix::g2b::ReserveAndValidateX86HostGuestWindowsFromResolver(
           resolver,kernix::g2d::kMain,4096,65536,random,
           {kernix::g2d::kMain},{"LANG=C"},host,why)) {
        std::fprintf(stderr,"KERNIX_G2D_GUEST_LAUNCH_PLAN_REJECTED:%s\n",why.c_str());
        return 13;
    }
    kernix::g2b::GuestReadonlyImage main,interp,provider;
    if(!kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
           std::span<const unsigned char>(src.files[0].bytes(),src.files[0].size()),
           main,why,true) ||
       !kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
           std::span<const unsigned char>(src.files[2].bytes(),src.files[2].size()),
           interp,why,false) ||
       !kernix::g2b::StageReadOnlyGuestELFImageFromBytes(
           std::span<const unsigned char>(src.files[1].bytes(),src.files[1].size()),
           provider,why,false) ||
       !kernix::g2b::StageX86ReadonlyHostBytesFromImages(host,main,interp,why)){
        std::fprintf(stderr,"KERNIX_G2D_PTLOAD_SNAPSHOT_STAGE_REJECTED:%s\n",why.c_str());
        return 14;
    }
    kernix::g2b::X86HostNoAccessReservation libWindow;
    if(!kernix::g2b::ReserveX86NoAccessHostWindow(
           provider.hostViewBytes,4096,libWindow,why)) {
        std::fprintf(stderr,"KERNIX_G2D_PROVIDER_VA_REJECTED:%s\n",why.c_str());
        return 15;
    }
    void* dest=reinterpret_cast<void*>(static_cast<uintptr_t>(libWindow.guestStart));
    if(!provider.hostViewReadOnly || provider.hostViewExecutable ||
       provider.hostViewBytes!=libWindow.guestBytes ||
       mprotect(dest,provider.hostViewBytes,PROT_READ|PROT_WRITE)!=0)
        return 16;
    std::memcpy(dest,provider.hostView,provider.hostViewBytes);
    if(mprotect(dest,provider.hostViewBytes,PROT_READ)!=0 ||
       std::memcmp(dest,provider.hostView,provider.hostViewBytes)!=0)
        return 17;
    if(libWindow.guestStart<provider.guestPageAlignedBase)return 18;
    const uint64_t providerBias=libWindow.guestStart-provider.guestPageAlignedBase;
    if(!kernix::g2d::WriteOneVerifiedGuestJumpSlot(
           reloc,host.plan.mainLoadBias,providerBias,host.main,libWindow,why)){
        std::fprintf(stderr,"KERNIX_G2D_JUMP_SLOT_GOT_REJECTED:%s\n",why.c_str());
        return 19;
    }
    uint64_t mainText=0,mainSize=0,libText=0,libSize=0;
    if(!EnableExactlyOneGuestRX(main,host.main,host.plan.mainLoadBias,
                                mainText,mainSize,why) ||
       !EnableExactlyOneGuestRX(provider,libWindow,providerBias,
                                libText,libSize,why)){
        std::fprintf(stderr,"KERNIX_G2D_PROVIDER_RX_REJECTED:%s\n",why.c_str());
        return 20;
    }
    // An actual x86 CALL/RET requires a writable (never executable) stack.
    // The previous G2-C fixed MOV/HLT witness needed only a readonly stack.
    if(!host.plan.stackAndAuxvConsistent ||
       !host.hostStackBytesStagedReadonly ||
       mprotect(reinterpret_cast<void*>(static_cast<uintptr_t>(
           host.stack.guestStart)),host.stack.guestBytes,
           PROT_READ|PROT_WRITE)!=0) return 21;
    if(host.plan.guestMainEntry<mainText ||
       host.plan.guestMainEntry-mainText>=mainSize ||
       host.plan.stack.guestRSP<host.stack.guestStart ||
       host.plan.stack.guestRSP>=host.stack.guestStart+host.stack.guestBytes)
        return 22;

    std::fputs("KERNIX_G2D_STAGE=MIT_THREE_GUEST_ELFS_SHA256_PINNED_ANONYMOUS_SNAPSHOTS\n",stderr);
    std::fputs("KERNIX_G2D_STAGE=REAL_GNU_LD_JUMP_SLOT_GOT_BOUND_TO_EXTERNAL_X86_PROVIDER_AND_REPROTECTED_READONLY\n",stderr);
    std::fputs("KERNIX_G2D_STAGE=MAIN_AND_PROVIDER_TEXT_RX_STACK_RW_GUARDS_NONE_NO_GLIBC\n",stderr);
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    if(!FEXCore::Config::GetConv<bool>(
         FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))return 23;
    FEXCore::HostFeatures features{};
    features.DCacheLineLog2=4;
    features.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    features.ProcessFeatures.Is64BitMode=1;
    features.ProcessPID=static_cast<uint32_t>(getpid());
    features.CPUMIDRs.push_back(0);
    auto context=FEXCore::Context::Context::CreateNewContext(features);
    if(!context)return 24;
    FEXCore::SignalDelegator signals{};
    NoSyscalls noSyscalls{mainText,mainSize,libText,libSize};
    context->SetSignalDelegator(&signals);
    context->SetSyscallHandler(&noSyscalls);
    context->EnableExitOnHLT();
    if(!context->InitCore())return 25;
    auto* thread=context->CreateThread();
    if(!thread || !thread->CurrentFrame)return 26;
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& state=thread->CurrentFrame->State;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    state.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    state.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* seg=FEXCore::Core::CPUState::GetSegmentFromIndex(state,state.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(seg,0);
    FEXCore::Core::CPUState::SetGDTLimit(seg,0xFFFFF);
    seg->L=1;
    seg->D=0;
    state.cs_cached=0;
    state.gregs[FEXCore::X86State::REG_RSP]=host.plan.stack.guestRSP;
    state.gregs[FEXCore::X86State::REG_RAX]=0;
    state.rip=host.plan.guestMainEntry;
    context->ExecuteThread(thread);
    const uint64_t got=thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    std::fprintf(stderr,"KERNIX_G2D_FEX_REAL_EXTERNAL_X86_FUNCTION_RAX=0x%016llx\n",
                 static_cast<unsigned long long>(got));
    if(got!=kernix::g2d::kRax)return 27;
    std::puts("KERNIX_G2D_ORIGINAL_FEX_X86_64_REAL_PLT_JUMP_SLOT_CROSS_DSO_CALL_RETURN_PASS_NO_GLIBC");
    std::fflush(stdout);return 0;
}
} // namespace

int main(int argc,char** argv) {
    if(argc!=3 || !argv[1] || argv[1][0]!='/' || !argv[2] ||
       std::strcmp(argv[2],"--g2d-fixed-mit-x86-import-only")!=0) {
        std::fputs("KERNIX_G2D_FIXED_ORIGINAL_IMPORT_CLI_REJECTED\n",stderr);
        return 126;
    }
    return Execute(argv[1]);
}
