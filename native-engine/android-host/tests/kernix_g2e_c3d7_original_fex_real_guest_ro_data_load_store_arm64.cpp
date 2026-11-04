// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D7: Linux AArch64 source-pinned ORIGINAL FEXCore executes
// real bounded x86-64 LOAD from authentic pinned original Linux ELF bytes
// staged in a kernel-chosen read-only native 4K page, then x86 STORE into an
// independently allocated 4K result page. Actual FEX CpuStateFrame proves
// guest RAX + host-visible data. This uses NATIVE (identity) pointer values
// in guest RBX/RCX, NOT original high x86 ELF guest logical addresses.
// NO original guest ELF RIP, ld-linux, glibc, Android FEX or Wine proof.
#define main kernix_g2ec2_fixture_reference_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main

#include "kernix_g2e_c3d6r2_kernel_chosen_guest_window.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__) || !defined(KERNIX_G2EC2_ORIGINAL_FEX_LINUX_ARM64_CI)
#error C3-D7 requires pinned original FEXCore on genuine Linux ARM64
#endif

namespace c3d7 {
// mov rax,[rbx]; add rax,7; mov [rcx],rax; hlt.
// Source bytes are never modified. Two real guest memory instructions must
// touch mapped host pages, NOT print a synthetic PASS marker.
constexpr uint8_t kGuest[]={
    0x48,0x8b,0x03,             // mov rax, qword ptr [rbx]
    0x48,0x83,0xc0,0x07,        // add rax, 7
    0x48,0x89,0x01,             // mov qword ptr [rcx], rax
    0xf4                       // hlt (original FEX ExitOnHLT)
};
static_assert(sizeof(kGuest)==11);

class RejectEveryGuestSyscall final : public FEXCore::HLE::SyscallHandler {
public:
    explicit RejectEveryGuestSyscall(uintptr_t entry) : Entry(entry) {}
    void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {
        std::fputs("KERNIX_C3D7_UNEXPECTED_GUEST_SYSCALL_REJECTED\n",stderr);
        _exit(83);
    }
    FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(
        FEXCore::Core::InternalThreadState*,uint64_t address) override {
        if(address>=Entry && address<Entry+sizeof(kGuest))
            return {Entry,sizeof(kGuest),false};
        return {0,0,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo>
    LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
private:
    uintptr_t Entry;
};

bool VerifyAll609OriginalReadOnlyBytes(
    const kernix::g2e::c3d6r2::KernelChosenReadOnlyGuestWindow& lease,
    const kernix::g2e::c3d::UnifiedGuestShadow& source) {
    size_t checked=0;
    for(const auto& [base,backing]:source.host16K) {
        for(size_t sub=0;sub<4;++sub) {
            if(!backing.subpages[sub].present)continue;
            const uint64_t guestVA=base+sub*4096;
            auto* page=lease.ReadOnlyNativePageForGuestVA(guestVA,4096);
            if(!page || std::memcmp(page,backing.bytes.data()+sub*4096,4096)!=0)
                return false;
            ++checked;
        }
    }
    return checked==609 && lease.PagesHeld()==609;
}

class NativePage final {
    void* ptr_=MAP_FAILED;
    size_t size_=0;
public:
    NativePage()=default;
    NativePage(const NativePage&)=delete;
    NativePage& operator=(const NativePage&)=delete;
    ~NativePage(){if(ptr_!=MAP_FAILED)::munmap(ptr_,size_);}
    bool Create(uintptr_t lowHint,size_t bytes,int protection) noexcept {
        if(ptr_!=MAP_FAILED)return false;
        void* p=::mmap(reinterpret_cast<void*>(lowHint),bytes,protection,
                       MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED)return false;
        if(!kernix::g2e::c1::GuestRange(
               reinterpret_cast<uintptr_t>(p),bytes)) {
            ::munmap(p,bytes);
            return false;
        }
        ptr_=p;size_=bytes;
        return true;
    }
    void* get() const noexcept {
        return ptr_==MAP_FAILED?nullptr:ptr_;
    }
    uintptr_t base() const noexcept {
        return reinterpret_cast<uintptr_t>(get());
    }
};
} // namespace c3d7

int main(int argc,char** argv) {
    if(argc!=2 || !argv[1])return 2;
    if(sysconf(_SC_PAGESIZE)!=4096)return 3;
    const int fd=::open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 4;
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    kernix::g2e::GuestPreflight pinned;
    std::string why;
    if(!kernix::g2e::Validate(fd,pinned,why)) {
        ::close(fd);return 5;
    }
    kernix::g2e::c3d::UnifiedGuestShadow original;
    if(!kernix::g2e::c3d::BuildUnifiedHost16KShadowFromPinnedOriginals(
        pinned,entropy,original,why)) {
        ::close(fd);return 6;
    }
    kernix::g2e::c3d6r2::KernelChosenReadOnlyGuestWindow lease;
    kernix::g2e::c3d6r2::Witness memory;
    if(!lease.StageOriginals(fd,entropy,memory) ||
       memory.phase!=kernix::g2e::c3d6r2::Phase::Complete ||
       !memory.originalSourceSha256Verified ||
       memory.originalGuestPages!=609 ||
       memory.pagesCopiedAndCompared!=609 ||
       !memory.kernelChoseHostVA ||
       !memory.allPagesFinallyReadOnly ||
       memory.fexOriginalGuestMemoryAttached ||
       memory.originalLdsoEntered ||
       !c3d7::VerifyAll609OriginalReadOnlyBytes(lease,original)) {
        ::close(fd);return 7;
    }
    ::close(fd);
    const uint8_t* mainBytes=lease.ReadOnlyNativePageForGuestVA(
        kernix::g2e::kC0MainTestVA,8);
    if(!mainBytes)return 8;
    uint64_t expectedBefore=0;
    std::memcpy(&expectedBefore,mainBytes,sizeof(expectedBefore));
    if(expectedBefore>std::numeric_limits<uint64_t>::max()-7)return 9;
    const uint64_t expectedAfter=expectedBefore+7;

    c3d7::NativePage code,result,stack;
    if(!code.Create(0x0000480000000000ULL,4096,
                    PROT_READ|PROT_WRITE) ||
       !result.Create(0x0000500000000000ULL,4096,
                      PROT_READ|PROT_WRITE) ||
       !stack.Create(0x0000600000000000ULL,8192,
                     PROT_READ|PROT_WRITE))return 10;
    std::memcpy(code.get(),c3d7::kGuest,sizeof(c3d7::kGuest));
    if(std::memcmp(code.get(),c3d7::kGuest,sizeof(c3d7::kGuest))!=0 ||
       ::mprotect(code.get(),4096,PROT_READ|PROT_EXEC)!=0)
        return 11;
    const uint64_t sentinel=0x4b45524e49585a31ULL;
    std::memcpy(result.get(),&sentinel,sizeof(sentinel));
    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();
    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE,"1");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST,"1");
    if(!FEXCore::Config::GetConv<bool>(
          FEXCore::Config::CONFIG_IS64BIT_MODE).value_or(false))
        return 12;
    FEXCore::HostFeatures host{};
    host.DCacheLineLog2=4;
    host.ProcessFeatures.HostType=FEXCore::HostFeatures::HostTypeEnum::Linux;
    host.ProcessFeatures.Is64BitMode=1;
    host.ProcessPID=static_cast<uint32_t>(getpid());
    host.CPUMIDRs.push_back(0);
    auto ctx=FEXCore::Context::Context::CreateNewContext(host);
    if(!ctx)return 13;
    FEXCore::SignalDelegator signals{};
    c3d7::RejectEveryGuestSyscall noSyscalls{code.base()};
    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&noSyscalls);
    ctx->EnableExitOnHLT();
    if(!ctx->InitCore())return 14;
    auto* thread=ctx->CreateThread();
    if(!thread||!thread->CurrentFrame)return 15;
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& state=thread->CurrentFrame->State;
    state.segment_arrays[
      FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    state.segment_arrays[
      FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    state.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* segment=FEXCore::Core::CPUState::GetSegmentFromIndex(
        state,state.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(segment,0);
    FEXCore::Core::CPUState::SetGDTLimit(segment,0xFFFFF);
    segment->L=1;segment->D=0;state.cs_cached=0;
    state.rip=code.base();
    state.gregs[FEXCore::X86State::REG_RSP]=
        (stack.base()+8192-16)&~uintptr_t(15);
    state.gregs[FEXCore::X86State::REG_RBX]=
        reinterpret_cast<uintptr_t>(mainBytes);
    state.gregs[FEXCore::X86State::REG_RCX]=result.base();
    state.gregs[FEXCore::X86State::REG_RAX]=0;
    std::fputs(
        "KERNIX_C3D7_PINNED_FEX_REAL_GUEST_MEMORY_LOAD_STORE_START\n",
        stderr);
    std::fflush(stderr);
    ctx->ExecuteThread(thread);
    uint64_t hostResult=0;
    std::memcpy(&hostResult,result.get(),sizeof(hostResult));
    const uint64_t guestRAX=
        thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
    if(hostResult==sentinel ||
       hostResult!=expectedAfter ||
       guestRAX!=expectedAfter)return 16;
    if(!c3d7::VerifyAll609OriginalReadOnlyBytes(lease,original))
        return 17;
    if(!lease.Release() || lease.PagesHeld()!=0)return 18;
    std::puts(
      "KERNIX_G2EC3D7_PINNED_FEX_REAL_X86_LOAD_AUTHENTIC_RO_ELF_AND_STORE_HOST_RESULT_LINUX_ARM64_PASS pages=609 source_sha_verified=1 x86_load_executed=1 x86_store_executed=1 x86_rax_compared=1 native_pointer_identity_only=1 original_guest_logical_va_used_as_x86_pointer=0 original_guest_elf_rip=0 original_ldso_executed=0 android_tested=0 wine=0");
    return 0;
}
