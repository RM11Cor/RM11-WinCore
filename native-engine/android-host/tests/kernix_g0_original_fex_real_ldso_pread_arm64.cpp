// SPDX-License-Identifier: MIT
// KERNIX G0: genuine upstream FEX x86 pread64(17) into owned guest RW memory
// backed by exact, SHA256-pinned original Linux ld-linux-x86-64.so.2 bytes.
// Linux ARM64 reference only. NO guest PT_INTERP, glibc execution or Android
// device execution is claimed by this runner.
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
#include "kernix_g0_original_guest_snapshot_table.h"
#include "kernix_g0_original_pread_guest_blob.h"
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
#include <fcntl.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>

#if !defined(__aarch64__) || \
    (!defined(__ANDROID__) && !defined(KERNIX_G0_ORIGINAL_LDSO_PREAD_ARM64_CI))
#error KERNIX G0 source-pinned ldso FEX pread requires Linux ARM64 CI or Android ARM64
#endif
namespace {
namespace abi=kernix::g2e::c1;
constexpr uintptr_t kTrapOffset=18, kNextOffset=20;
constexpr size_t kRequested=64;
static_assert(sizeof(KERNIX_G0_PREAD_GUEST)==24 &&
              KERNIX_G0_PREAD_GUEST[18]==0x0f &&
              KERNIX_G0_PREAD_GUEST[19]==0x05 &&
              KERNIX_G0_PREAD_GUEST[20]==0x0f &&
              KERNIX_G0_PREAD_GUEST[21]==0xb6 &&
              KERNIX_G0_PREAD_GUEST[22]==0x06 &&
              KERNIX_G0_PREAD_GUEST[23]==0xf4,
              "Source-generated authentic GNU-as x86 fixture changed");
void* AllocateLowOwned(uintptr_t hint,size_t len,int flags) {
    void* p=::mmap(reinterpret_cast<void*>(hint),len,flags,
                   MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED)return nullptr;
    if(!abi::GuestRange(reinterpret_cast<uintptr_t>(p),len)) {
        ::munmap(p,len);return nullptr;
    }
    return p;
}
class ActualFexOriginalGuestPread final : public FEXCore::HLE::SyscallHandler {
public:
    ActualFexOriginalGuestPread(uintptr_t entry, uintptr_t stack, size_t stackBytes,
                              uintptr_t output, size_t outputBytes,
                              kernix::g0::OriginalGuestSnapshotTable& table)
     : Entry(entry),Stack{stack,stack+stackBytes,true},
       Buffer{output,output+outputBytes,true,true,false,true},
       Destination(output),Sources(table) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        ++Calls;
        kernix::g2e::c2::ActualFexTrapWitness witness{};
        if(Calls!=1 ||
           !kernix::g2e::c2::DecodePinnedFexCpuState(frame,Stack,witness) ||
           !witness.originalFexCpuStateFrameRead) {
            std::fputs("G0_ACTUAL_FEX_PREAD_ORIGINAL_FRAME_REJECTED\n",stderr);
            _exit(41);
        }
        const auto& guest=witness.decoded;
        if(frame->State.rip!=Entry+kTrapOffset ||
           guest.nextGuestRIP!=Entry+kNextOffset ||
           guest.guestNumber!=abi::kPread64 ||
           guest.args[0]!=4 || // original ld-linux guest virtual fd
           guest.args[1]!=Destination ||
           guest.args[2]!=kRequested ||
           guest.args[3]!=0 || // original x86 R10 (offset), not RCX
           guest.args[3]==frame->State.gregs[FEXCore::X86State::REG_RCX] ||
           guest.hostSyscallDispatched ||
           guest.guestMemoryDereferenced) {
            std::fputs("G0_ACTUAL_FEX_PREAD_GUEST_X86_REGISTER_ABI_REJECTED\n",stderr);
            _exit(42);
        }
        const auto read=Sources.Dispatch(guest,Buffer);
        if(!read.authenticated || !read.guestWritableSpanValidated ||
           !read.readFromImmutableSnapshot ||
           read.anyHostSyscallForwarded ||
           read.linuxReturn!=static_cast<int64_t>(kRequested)) {
            std::fputs("G0_ACTUAL_FEX_ORIGINAL_LDSO_GUEST_PREAD_MEMORY_REJECTED\n",stderr);
            _exit(43);
        }
        // Actual upstream FEX CpuStateFrame callback, not synthetic register data.
        Observed=true;
        frame->State.gregs[FEXCore::X86State::REG_RAX]=
            static_cast<uint64_t>(read.linuxReturn);
        frame->State.rip=guest.nextGuestRIP;
        std::fputs("KERNIX_G0_ORIGINAL_FEX_GUEST_PREAD64_LDSO_SNAPSHOT_TO_GUEST_RW_PASS\n",stderr);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*,uint64_t address) override {
        if(address>=Entry && address<Entry+sizeof(KERNIX_G0_PREAD_GUEST))
           return {Entry,sizeof(KERNIX_G0_PREAD_GUEST),false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
    unsigned Calls=0;
    bool Observed=false;
private:
    uintptr_t Entry;
    abi::X86GuestStackBoundary Stack;
    abi::GuestVmInterval Buffer;
    uintptr_t Destination;
    kernix::g0::OriginalGuestSnapshotTable& Sources;
};
int run(const char* privateRoot) {
    int fd=::open(privateRoot,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return 11;
    kernix::g0::OriginalGuestSnapshotTable originals;
    std::string reason;
    const bool good=originals.MountVerifiedAppPrivateOriginalRoot(fd,reason);
    ::close(fd);
    if(!good || !originals.Mounted()) {
        std::fprintf(stderr,"G0_ORIGINAL_GUEST_TRIAD_REJECTED=%s\n",reason.c_str());
        return 12;
    }
    const long ps=::sysconf(_SC_PAGESIZE);
    if(ps!=4096 && ps!=16384)return 13;
    const auto page=static_cast<size_t>(ps);
    void* code=AllocateLowOwned(0x0000440000000000ULL,page,PROT_READ|PROT_WRITE);
    void* stack=AllocateLowOwned(0x0000600000000000ULL,page*2,PROT_READ|PROT_WRITE);
    void* data=AllocateLowOwned(0x0000500000000000ULL,page,PROT_READ|PROT_WRITE);
    if(!code || !stack || !data)return 14;
    std::memset(data,0,page);
    std::memcpy(code,KERNIX_G0_PREAD_GUEST,sizeof(KERNIX_G0_PREAD_GUEST));
    if(::mprotect(code,page,PROT_READ|PROT_EXEC)!=0)return 15;
    const auto entry=reinterpret_cast<uintptr_t>(code);
    const auto stackStart=reinterpret_cast<uintptr_t>(stack);
    const auto dest=reinterpret_cast<uintptr_t>(data);
    if(!abi::GuestRange(entry,sizeof(KERNIX_G0_PREAD_GUEST)) ||
       !abi::GuestRange(stackStart,page*2) ||
       !abi::GuestRange(dest,page))return 16;

    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
    if(!FEXCore::Config::GetConv<bool>(
       FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))return 17;
    FEXCore::HostFeatures host{};
    host.DCacheLineLog2=4;
    host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    host.ProcessFeatures.Is64BitMode=1;
    host.ProcessPID=static_cast<uint32_t>(::getpid());
    host.CPUMIDRs.push_back(0);
    auto ctx=FEXCore::Context::Context::CreateNewContext(host);
    if(!ctx)return 18;
    FEXCore::SignalDelegator signals{};
    ActualFexOriginalGuestPread handler{entry,stackStart,page*2,dest,page,originals};
    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&handler);
    ctx->EnableExitOnHLT();
    if(!ctx->InitCore())return 19;
    auto* guest=ctx->CreateThread();
    if(!guest || !guest->CurrentFrame)return 20;
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& cpu=guest->CurrentFrame->State;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    cpu.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* seg=FEXCore::Core::CPUState::GetSegmentFromIndex(cpu,cpu.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(seg,0);
    FEXCore::Core::CPUState::SetGDTLimit(seg,0xFFFFF);
    seg->L=1;seg->D=0;cpu.cs_cached=0;
    cpu.gregs[FEXCore::X86State::REG_RSP]=(stackStart+page*2-16)&~uintptr_t(15);
    cpu.gregs[FEXCore::X86State::REG_RSI]=dest; // guest ABI destination
    cpu.gregs[FEXCore::X86State::REG_RAX]=0;
    cpu.rip=entry;
    std::fputs("KERNIX_G0_REAL_FEX_GUEST_PREAD_ORIGINAL_LDSO_START\n",stderr);
    ctx->ExecuteThread(guest);
    const auto rax=guest->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    const auto* bytes=static_cast<const uint8_t*>(data);
    if(!handler.Observed || handler.Calls!=1 ||
       rax!=0x7f || // actual x86 MOVZBL (%RSI),%EAX after return from SYSCALL
       bytes[0]!=0x7f || bytes[1]!='E' || bytes[2]!='L' || bytes[3]!='F' ||
       bytes[4]!=2 || bytes[5]!=1 ||
       bytes[18]!=62 || bytes[19]!=0)
       return 21;
    std::puts("KERNIX_G0_REAL_ORIGINAL_FEX_X86_PREAD_LDSO_GUEST_CONSUMED_ELF_MAGIC_AND_RAX_7F_PASS_NO_GLIBC_NO_ANDROID");
    return 0;
}
} // namespace
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    return run(argv[1]);
}
