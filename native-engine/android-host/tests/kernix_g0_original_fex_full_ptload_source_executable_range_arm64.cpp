// SPDX-License-Identifier: MIT
// Functional *same FEX session* original PT_INTERP callee RW-state integration after live guest syscalls: source SHA256-pinned
// original x86 ELF main, ld-linux, libc PT_LOAD and authentic initial AUXV
// stack are owned and W^X protected by the existing C3-D7B/C3-D7G runtime.
// The SAME original upstream FEXCore context executes GNU-as x86 code which
// reads the original main image and initial argc, then makes genuine Linux
// x86 mmap(9) -> guest store/load -> munmap(11), and branches DIRECTLY to
// original PT_INTERP RIP to execute BOTH 48 89 e7 = MOV RSP,RDI and
// the authentic source-backed rel32 CALL. Only the CALL destination's
// 79th offset byte is temporarily HLT in owned guest shadow; source callee first 79 bytes run.
// This remains an instrumented bounded transition, NOT full glibc/Wine startup.
#include "kernix_g2e_c3d8a_original_loader_handoff_barrier.h"
#include "kernix_g0_guest_owned_anonymous_vm_kernel.h"
#include "kernix_g0_source_verified_guest_elf_fd_kernel.h"
#include "kernix_g0_original_elf_ldso_handoff_blob.h"
#include "kernix_g2e_c2_original_fex_cpu_state_adapter.h"
#include "kernix_g2e_c3d7n_original_ldso_call_source_target_gate.h"
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
#include "kernix_g2e_c3d7j_original_x86_static_tls_variant2_order_gate.h"
#include "kernix_g0_source_relative_rela_guest_writer_gate.h"
#include "kernix_g0_original_source_relr_target_witness.h"
#include "kernix_g0_original_source_ptload_fex_executable_range.h"
#include "kernix_g0_original_source_guest_program_break_owner.h"
#include "kernix_g0_original_source_guest_loader_access.h"
#include "kernix_g0_source_owned_guest_fs_tls_runtime.h"
#include <fcntl.h>
#include <fstream>
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
namespace h=kernix::g2e::c3d7h;
namespace d=kernix::g2e::c3d7i;
namespace tls=kernix::g2e::c3d7j;
namespace rela=kernix::g0::relawriter;
namespace relr=kernix::g0::relr;
namespace rx=kernix::g0::source_exec;
namespace gbrk=kernix::g0::guestbrk;
namespace gaccess=kernix::g0::access21;
namespace fs=kernix::g0::fsruntime;
constexpr uint64_t kGuestAnonBytes=4096;
// The byte stream is additionally pinned by the original triad SHA256 check.
constexpr size_t kStop=79;
constexpr size_t kFrame=192;
constexpr std::array<uint8_t,80> kCallee{{
0xf3,0x0f,0x1e,0xfa,0x55,
0x48,0x8d,0x0d,0x14,0xfe,0xfd,0xff,
0x48,0x8d,0x05,0xe5,0x90,0x01,0x00,
0x66,0x48,0x0f,0x6e,0xc9,0x66,0x48,0x0f,0x6e,0xd0,
0x66,0x0f,0x6c,0xca,0x48,0x89,0xe5,
0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,
0x48,0x81,0xec,0x88,0x00,0x00,0x00,
0x48,0x89,0xbd,0x78,0xff,0xff,0xff,
0x0f,0x29,0x4d,0x80,0x0f,0x31,
0x80,0x25,0xde,0x8b,0x01,0x00,0xdf,
0x48,0x8d,0x35,0xc1,0x88,0x01,0x00,0x41
}};
static_assert(kCallee.size()==kStop+1);
std::string RightsAt(uint64_t address) {
 std::ifstream maps("/proc/self/maps");
 std::string line;
 while(std::getline(maps,line)){
  unsigned long long lo=0,hi=0; char rights[5]{};
  if(std::sscanf(line.c_str(),"%llx-%llx %4s",&lo,&hi,rights)!=3)continue;
  if(address>=lo && address<hi)return rights;
 }
 return "unmapped";
}

class SingleFEXOriginalCallRetGuard final {
  void* ptr_=MAP_FAILED;
  size_t total_=0;
public:
  SingleFEXOriginalCallRetGuard()=default;
  SingleFEXOriginalCallRetGuard(
      const SingleFEXOriginalCallRetGuard&)=delete;
  SingleFEXOriginalCallRetGuard& operator=(
      const SingleFEXOriginalCallRetGuard&)=delete;
  ~SingleFEXOriginalCallRetGuard(){(void)Release();}
  static constexpr size_t kGuard=4096;
  static constexpr size_t kCallRetBytes=
    FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
  bool Reserve() noexcept {
    if(ptr_!=MAP_FAILED || kCallRetBytes<32768 ||
       (kCallRetBytes%4096)!=0 ||
       kCallRetBytes>SIZE_MAX-2*kGuard)return false;
    total_=kCallRetBytes+2*kGuard;
    void* raw=::mmap(nullptr,total_,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(raw==MAP_FAILED) {total_=0;return false;}
    ptr_=raw;
    if(::mprotect(Base(),kCallRetBytes,
                  PROT_READ|PROT_WRITE)!=0) {
      (void)Release();return false;
    }
    return InitialSP()!=0 && Contains(InitialSP()-16,16);
  }
  void* Base() const noexcept {
    return ptr_==MAP_FAILED?nullptr:
       static_cast<void*>(static_cast<uint8_t*>(ptr_)+kGuard);
  }
  uint64_t InitialSP() const noexcept {
    return Base()?reinterpret_cast<uintptr_t>(Base())+
                    kCallRetBytes/4:0;
  }
  bool Contains(uint64_t at,size_t n) const noexcept {
    if(!Base() || at<reinterpret_cast<uintptr_t>(Base()))
      return false;
    const auto offset=at-reinterpret_cast<uintptr_t>(Base());
    return n<=kCallRetBytes &&
           offset<=kCallRetBytes-n;
  }
  bool Release() noexcept {
    if(ptr_==MAP_FAILED)return true;
    if(::munmap(ptr_,total_)!=0)return false;
    ptr_=MAP_FAILED;
    total_=0;
    return true;
  }
};

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
        std::memcpy(p,KERNIX_G0_ELF_LDSO_HANDOFF_GUEST,
                    sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST));
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
    OneProcessOriginalElfSyscalls(uint64_t entry,uint64_t originalLdsoTarget,
                                 const kernix::g2b::X86GuestProcessLaunchPlan& plan,
                                 const c7b::ImageMeta& mainImage,
                                 uint64_t mainSourceWord,
                                 const c7b::NativeChosenPIEGuestLayout& owner,
                                 const fs::OwnedGuestFS& guestFS,
                                 uint64_t sourceMainRelroPage,
                                 kernix::g0::SourceVerifiedGuestElfFDKernel& sourceFileKernel,
                                 const relr::Witness& originalRELR,
                                 const c7g::PermissionPlan& sourceExecPolicy,
                                 const c7g::ApplyWitness& nativeWXApplied,
                                 gbrk::OriginalGuestMainProgramBreak* guestProgramBreak=nullptr)
       :Entry(entry),
        Stack{plan.stack.guestBottom,plan.stack.guestTop,true},
        MainStart(mainImage.chosenImageStart),
        InitialRSP(plan.stack.guestRSP),
        MainSourceWord(mainSourceWord),
        OriginalLdsoEntry(plan.guestInterpreterEntry),
        OriginalLdsoTarget(originalLdsoTarget),
        Owner(owner),
        GuestFS(guestFS),
        SourceMainRelroPage(sourceMainRelroPage),
        SourceFileKernel(sourceFileKernel),
        OriginalSourceRELR(originalRELR),
        SourceExecPolicy(sourceExecPolicy),
        NativeWXApplied(nativeWXApplied),
        GuestProgramBreak(guestProgramBreak){}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        if(++Calls>15) {
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION)
            // This is not a fixture syscall. The unmodified original
            // GNU ld-linux requested another genuine x86 Linux kernel
            // service. Safely handle source main-ELF-owned brk(12)
            // through native W^X guest pages ONLY when the separate
            // trusted original source/owner and x86 trap gates pass.
#if defined(KERNIX_G0_ENABLE_GUEST_BRK12)
            c2::ActualFexTrapWitness next{};
            if(!c2::DecodePinnedFexCpuState(frame,Stack,next) ||
               !next.originalFexCpuStateFrameRead){
               std::fputs("KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_BRK12_X86_CPUSTATE_REJECT\n",stderr);
               _exit(121);
            }
            if(next.decoded.guestNumber==c1::kBrk && GuestProgramBreak){
              if(RealOriginalLdsoBrkCalls>=16){
                 std::fputs("KERNIX_G0_GUEST_BRK12_REPEATED_UNBOUNDED_REJECT\n",stderr);
                 _exit(122);
              }
              const auto response=GuestProgramBreak->Dispatch(next.decoded);
              if(!response.authenticatedGuestBrk ||
                 !response.originalMainOwnerRangeUsed ||
                 response.nativeHostBrkOrSbrkCalled ||
                 response.originalPTLoadRightsModified ||
                 response.guestReturn<GuestProgramBreak->Minimum() ||
                 response.guestReturn>GuestProgramBreak->Limit()){
                 std::fputs("KERNIX_G0_GUEST_BRK12_ORIGINAL_MAIN_OWNER_DISPATCH_REJECT\n",stderr);
                 _exit(123);
              }
              ++RealOriginalLdsoBrkCalls;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=
                   response.guestReturn;
              frame->State.rip=next.decoded.nextGuestRIP;
              std::fprintf(stderr,
                "KERNIX_G0_REAL_UNPATCHED_ORIGINAL_GNU_LDSO_GUEST_BRK12_SAFE_MAIN_PTLOAD_OWNER_RESPONSE call=%zu requested=%llx returned=%llx changed=%d\n",
                RealOriginalLdsoBrkCalls,
                static_cast<unsigned long long>(next.decoded.args[0]),
                static_cast<unsigned long long>(response.guestReturn),
                int(response.nativeGuestHeapPermissionsChanged));
              std::fflush(stderr);
              return;
            }
#endif
#if defined(KERNIX_G0_ENABLE_GUEST_ACCESS21)
            if(next.decoded.guestNumber==c1::kAccess){
              if(RealOriginalLdsoAccessCalls>=4){
                std::fputs("KERNIX_G0_GUEST_ACCESS21_REPEATED_UNBOUNDED_REJECT\n",stderr);
                _exit(126);
              }
              const auto answer=gaccess::DispatchOriginalLoaderOptionalAccess(
                   next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
              if(!answer.trustedGuestAccess ||
                 !answer.guestSourceLdlinuxPTLoadLiteralRead ||
                 !answer.optionalVirtualPreloadAbsent ||
                 answer.guestReturn!=-ENOENT ||
                 answer.nativeHostFileAccessCalled ||
                 answer.guestPointerPassedToNativeHost ||
                 answer.requestDenied){
                std::fprintf(stderr,
                  "KERNIX_G0_UNPATCHED_ORIGINAL_GNU_LDSO_ACCESS21_SOURCE_PATH_NOT_ALLOWLISTED ptr=%llx mode=%llu\n",
                  static_cast<unsigned long long>(next.decoded.args[0]),
                  static_cast<unsigned long long>(next.decoded.args[1]));
                _exit(127);
              }
              ++RealOriginalLdsoAccessCalls;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=
                static_cast<uint64_t>(answer.guestReturn);
              frame->State.rip=next.decoded.nextGuestRIP;
              std::fputs("KERNIX_G0_REAL_UNPATCHED_ORIGINAL_GNU_LDSO_ACCESS21_OPTIONAL_PRELOAD_R_OK_VIRTUAL_ENOENT_NO_HOST_FS\n",stderr);
              std::fflush(stderr);
              return;
            }
#endif
            // First remaining unsupported x86 syscall: precise source
            // RIP and number, never forwarded to host Linux/Android.
            std::fprintf(stderr,
              "KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL num=%llu rip=%llx rdi=%llx rsi=%llx rdx=%llx\n",
              static_cast<unsigned long long>(
                  frame->State.gregs[FEXCore::X86State::REG_RAX]),
              static_cast<unsigned long long>(frame->State.rip),
              static_cast<unsigned long long>(
                  frame->State.gregs[FEXCore::X86State::REG_RDI]),
              static_cast<unsigned long long>(
                  frame->State.gregs[FEXCore::X86State::REG_RSI]),
              static_cast<unsigned long long>(
                  frame->State.gregs[FEXCore::X86State::REG_RDX]));
            std::fflush(stderr);
            _exit(117);
#else
            std::fputs("G0_COMBINED_TOO_MANY_SYSCALLS_REJECTED\n",stderr);
            _exit(51);
#endif
        }
        c2::ActualFexTrapWitness verified{};
        if(!c2::DecodePinnedFexCpuState(frame,Stack,verified) ||
           !verified.originalFexCpuStateFrameRead) {
            std::fputs("G0_COMBINED_FEX_CPUSTATE_REJECTED\n",stderr);
            _exit(52);
        }
        const auto& trap=verified.decoded;
        const size_t syscallOffset=Calls==1?
            G0_ELF_LDSO_HANDOFF_ARCH_SET_FS_OFFSET:Calls==2?
            G0_ELF_LDSO_HANDOFF_MMAP_OFFSET:Calls==3?
            G0_ELF_LDSO_HANDOFF_GETRANDOM_1_OFFSET:Calls==4?
            G0_ELF_LDSO_HANDOFF_GETRANDOM_2_OFFSET:Calls==5?
            G0_ELF_LDSO_HANDOFF_OPENAT_OFFSET:Calls==6?
            G0_ELF_LDSO_HANDOFF_PREAD64_OFFSET:Calls==7?
            G0_ELF_LDSO_HANDOFF_READ_OFFSET:Calls==8?
            G0_ELF_LDSO_HANDOFF_FILE_MMAP_OFFSET:Calls==9?
            G0_ELF_LDSO_HANDOFF_FILE_MUNMAP_OFFSET:Calls==10?
            G0_ELF_LDSO_HANDOFF_RX_MMAP_OFFSET:Calls==11?
            G0_ELF_LDSO_HANDOFF_RX_MUNMAP_OFFSET:Calls==12?
            G0_ELF_LDSO_HANDOFF_CLOSE_OFFSET:Calls==13?
            G0_ELF_LDSO_HANDOFF_FOREIGN_RELRO_MPROTECT_OFFSET:Calls==14?
            G0_ELF_LDSO_HANDOFF_MPROTECT_OFFSET:
            G0_ELF_LDSO_HANDOFF_MUNMAP_OFFSET;
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
            // ARCH_SET_FS guest-only FEX CPUState update; never host TLS.
            if(trap.guestNumber!=158 ||
               trap.args[0]!=0x1002 ||
               trap.args[1]!=GuestFS.FSBase() ||
               GuestFS.FSBase()<65536 ||
               frame->State.fs_cached!=0 ||
               frame->State.gs_cached!=0 ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
               RightsAt(GuestFS.FSBase())!="rw-p") {
                std::fputs("KERNIX_G0_ARCH_SET_FS_GUEST_ONLY_AUTH_REJECT\n",stderr);
                _exit(61);
            }
            frame->State.fs_cached=GuestFS.FSBase();
            frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
            frame->State.rip=trap.nextGuestRIP;
            GuestArchSetFSObserved=true;
            std::fputs("KERNIX_G0_SOURCE_AUTHENTICATED_X86_ARCH_SET_FS_CPUSTATE_APPLIED_NOT_HOST_TLS\n",stderr);
            return;
        }
        if(Calls==2) {
            if(!GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch()) {
                std::fputs("KERNIX_G0_X86_FS_TCB_DTV_SOURCE_LIBC_TLS_READBACK_REJECT\n",stderr);
                _exit(62);
            }
            std::fputs("KERNIX_G0_REAL_FEX_X86_FS_TCB_DTV_ORIGINAL_LIBC_TLS_READS_BEFORE_MMAP_PASS\n",stderr);
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
            // Exact source SHA256-locked original GNU ELF64 DT_RELR
            // target values enter ONLY the guest-owned RW page after
            // a genuine translated x86 mmap(9) guest syscall.
            if(!OriginalSourceRELR.authenticSourceELF64DynamicRELR ||
               !OriginalSourceRELR.verifiedGuestRWTargetNotExecutable ||
               !OriginalSourceRELR.sourceDescriptorDecoded ||
               OriginalSourceRELR.guestRelocationActuallyExecuted ||
               OriginalSourceRELR.originalLdsoRelocationActuallyExecuted ||
               !c1::GuestRange(OriginalSourceRELR.guestTarget,8) ||
               !Heap.AuthenticatedRW(HeapAddress+640,24).guestWrite){
                std::fputs("KERNIX_G0_ORIGINAL_RELR_SOURCE_HEAP_STAGE_REJECT\n",stderr);
                _exit(98);
            }
            const std::array<uint64_t,3> stagedSourceRELR{{
               OriginalSourceRELR.guestTarget,
               OriginalSourceRELR.sourceInitialAddend,
               OriginalSourceRELR.guestLoadBias}};
            std::memcpy(reinterpret_cast<void*>(
                 static_cast<uintptr_t>(HeapAddress+640)),
                 stagedSourceRELR.data(),sizeof(stagedSourceRELR));
            frame->State.gregs[FEXCore::X86State::REG_RAX]=HeapAddress;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_COMBINED_FEX_ORIGINAL_ELF_AND_STACK_CONSUMED\n",stderr);
            return;
        }
        if(Calls==3 || Calls==4) {
            // Both are actual translated x86 Linux getrandom(318) from
            // the genuine FEX CPU frame, not a host-only test call.
            // All guest buffers must be in the SAME native owner-held
            // heap VMA; the original source ELF/TLS/JIT is forbidden.
            const bool first=(Calls==3);
            const uint64_t guestAt=HeapAddress+(first?64:96);
            if(!GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               (first?FirstEntropyWritten:!FirstEntropyWritten) ||
               trap.guestNumber!=c1::kGetrandom ||
               trap.args[0]!=guestAt ||
               trap.args[1]!=32 || trap.args[2]!=0 ||
               Heap.Count()!=1 || RightsAt(HeapAddress)!="rw-p" ||
               !Heap.AuthenticatedRW(guestAt,32).guestWrite ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1){
                 std::fputs("KERNIX_G0_X86_REAL_GUEST_GETRANDOM_SOURCE_OR_OWNER_REJECT\n",stderr);
                 _exit(71);
            }
            const std::array<unsigned char,32> zeros{};
            std::array<unsigned char,32> before{};
            std::memcpy(before.data(),
                reinterpret_cast<const void*>(static_cast<uintptr_t>(guestAt)),32);
            if(before!=zeros) {
                std::fputs("KERNIX_G0_X86_GUEST_ENTROPY_STAGING_NOT_ZERO_REJECT\n",stderr);
                _exit(72);
            }
            const auto result=Heap.Dispatch(trap);
            if(result.guestReturn!=32 ||
               !result.guestSyscallAuthenticated ||
               !result.nativeTrustedEntropySourceRead ||
               !result.guestOwnedWritableEntropyFilled ||
               result.hostAnyUntrustedSyscallForwarded){
                std::fputs("KERNIX_G0_X86_REAL_GUEST_KERNEL_ENTROPY_BRIDGE_REJECT\n",stderr);
                _exit(73);
            }
            std::array<unsigned char,32> after{};
            std::memcpy(after.data(),
                reinterpret_cast<const void*>(static_cast<uintptr_t>(guestAt)),32);
            if(after==zeros || (!first && after==FirstEntropyBytes)){
                std::fputs("KERNIX_G0_X86_GUEST_RANDOM_OUTPUT_NOT_INDEPENDENT_REJECT\n",stderr);
                _exit(74);
            }
            if(first){
                FirstEntropyBytes=after;FirstEntropyWritten=true;
                std::fputs("KERNIX_G0_ACTUAL_FEX_X86_GETRANDOM_318_FIRST_AUTHENTIC_OWNED_RW_BUFFER_KERNEL_ENTROPY_FILLED\n",stderr);
            }else{
                SecondEntropyWritten=true;
                std::fputs("KERNIX_G0_ACTUAL_FEX_X86_GETRANDOM_318_SECOND_INDEPENDENT_OWNED_RW_BUFFER_KERNEL_ENTROPY_FILLED\n",stderr);
            }
            frame->State.gregs[FEXCore::X86State::REG_RAX]=32;
            frame->State.rip=trap.nextGuestRIP;
            return;
        }
        if(Calls==8) {
            // Real x86 guest file mmap: guest R8=virtual fd 100 and
            // R9=0 original ELF offset; immutable source bytes are
            // copied to a guest-owned native anonymous page then RO.
            const uint64_t virtualFD=static_cast<uint64_t>(
                 kernix::g0::SourceVerifiedGuestElfFDKernel::kGuestBaseFD);
            if(!GuestArchSetFSObserved ||
               !FirstEntropyWritten || !SecondEntropyWritten ||
               trap.guestNumber!=c1::kMmap ||
               trap.args[0]!=0 || trap.args[1]!=4096 ||
               trap.args[2]!=PROT_READ || trap.args[3]!=MAP_PRIVATE ||
               trap.args[4]!=virtualFD || trap.args[5]!=0 ||
               Heap.Count()!=1 || SourceFileKernel.OpenCount()!=1 ||
               RightsAt(HeapAddress)!="rw-p" || Owner.WindowsHeld()!=4){
                std::fputs("KERNIX_G0_X86_ELF_SNAPSHOT_MMAP_ABI_REJECT\n",stderr);
                _exit(84);
            }
            const auto mapped=SourceFileKernel.Dispatch(trap,Heap);
            if(mapped.guestReturn<65536 ||
               !mapped.guestSyscallAuthenticated ||
               !mapped.readonlySourceELFSnapshotMapped ||
               !mapped.guestReadonlySourceELFNativeProtectionApplied ||
               mapped.hostPathOpened || mapped.hostGuestFdForwarded ||
               mapped.hostAnyUntrustedSyscallForwarded ||
               Heap.Count()!=2 || SourceFileKernel.OpenCount()!=1){
                std::fputs("KERNIX_G0_X86_ELF_SNAPSHOT_MMAP_KERNEL_REJECT\n",stderr);
                _exit(85);
            }
            FileSourceMapAddress=static_cast<uint64_t>(mapped.guestReturn);
            const auto span=Heap.AuthenticatedRW(FileSourceMapAddress,4096);
            const auto* bytes=reinterpret_cast<const uint8_t*>(
                    static_cast<uintptr_t>(FileSourceMapAddress));
            if(!span.attested || !span.guestRead ||
               span.guestWrite || span.guestExecute ||
               RightsAt(FileSourceMapAddress)!="r--p" ||
               bytes[0]!=0x7f || bytes[1]!='E' ||
               bytes[2]!='L' || bytes[3]!='F' ||
               std::memcmp(bytes,reinterpret_cast<const void*>(
                   static_cast<uintptr_t>(HeapAddress+512)),32)!=0){
                std::fputs("KERNIX_G0_X86_ELF_SNAPSHOT_RO_BYTES_REJECT\n",stderr);
                _exit(86);
            }
            auto attack=trap;
            attack.guestNumber=c1::kMprotect;
            attack.args={FileSourceMapAddress,4096,PROT_READ|PROT_WRITE,0,0,0};
            const auto denied=Heap.Dispatch(attack);
            if(denied.guestReturn!=-EINVAL ||
               denied.nativeOwnedMapProtectionChanged ||
               RightsAt(FileSourceMapAddress)!="r--p"){
                std::fputs("KERNIX_G0_X86_ELF_SNAPSHOT_RO_UPGRADE_REJECT\n",stderr);
                _exit(87);
            }
            GuestSourceFileMmapReadonly=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=FileSourceMapAddress;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_REAL_FEX_GUEST_X86_ELF_SHA_SNAPSHOT_MMAP_9_PRIVATE_NATIVE_RO_NO_RX\n",stderr);
            return;
        }
        if(Calls==9) {
            // The immediately preceding guest x86 instruction sequence
            // actually read r--p ELF bytes before syscall munmap(11).
            if(!GuestSourceFileMmapReadonly ||
               trap.guestNumber!=c1::kMunmap ||
               trap.args[0]!=FileSourceMapAddress ||
               trap.args[1]!=4096 || Heap.Count()!=2 ||
               SourceFileKernel.OpenCount()!=1 ||
               RightsAt(FileSourceMapAddress)!="r--p" ||
               !Heap.AuthenticatedRW(FileSourceMapAddress,32).guestRead ||
               Heap.AuthenticatedRW(FileSourceMapAddress,32).guestWrite){
                std::fputs("KERNIX_G0_REAL_FEX_X86_SOURCE_ELF_FILE_UNMAP_ARGS_REJECT\n",stderr);
                _exit(88);
            }
            const auto result=Heap.Dispatch(trap);
            if(result.guestReturn!=0 || !result.nativeOwnedMapReleased ||
               result.hostAnyUntrustedSyscallForwarded ||
               Heap.Count()!=1 ||
               Heap.AuthenticatedRW(FileSourceMapAddress,1).attested){
                std::fputs("KERNIX_G0_REAL_FEX_X86_SOURCE_ELF_FILE_UNMAP_REJECT\n",stderr);
                _exit(89);
            }
            GuestSourceFileMmapUnmapped=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_REAL_FEX_GUEST_X86_ELF_SHA_SNAPSHOT_NATIVE_RO_LOAD_AND_MUNMAP_11_PASS\n",stderr);
            return;
        }
        if(Calls==10) {
            const uint64_t fd=static_cast<uint64_t>(
                kernix::g0::SourceVerifiedGuestElfFDKernel::kGuestBaseFD);
            if(!GuestSourceFileMmapUnmapped || !GuestArchSetFSObserved ||
               !FirstEntropyWritten || !SecondEntropyWritten ||
               trap.guestNumber!=c1::kMmap ||
               trap.args[0]!=0 || trap.args[1]!=4096 ||
               trap.args[2]!=(PROT_READ|PROT_EXEC) ||
               trap.args[3]!=MAP_PRIVATE || trap.args[4]!=fd ||
               trap.args[5]!=G0_ELF_LDSO_SOURCE_RX_OFFSET ||
               Heap.Count()!=1 || SourceFileKernel.OpenCount()!=1 ||
               RightsAt(HeapAddress)!="rw-p" || Owner.WindowsHeld()!=4){
                std::fputs("KERNIX_G0_SOURCE_ELF_RX_GUEST_MMAP_ARGS_REJECT\n",stderr);
                _exit(90);
            }
            const auto mapped=SourceFileKernel.Dispatch(trap,Heap);
            if(mapped.guestReturn<65536 ||
               !mapped.guestSyscallAuthenticated ||
               !mapped.executableSourceELFSnapshotMapped ||
               !mapped.guestExecutableSourceELFNativeProtectionApplied ||
               mapped.readonlySourceELFSnapshotMapped ||
               mapped.guestReadonlySourceELFNativeProtectionApplied ||
               mapped.hostPathOpened || mapped.hostGuestFdForwarded ||
               mapped.hostAnyUntrustedSyscallForwarded ||
               Heap.Count()!=2 || SourceFileKernel.OpenCount()!=1){
                std::fputs("KERNIX_G0_SOURCE_ELF_RX_NATIVE_MMAP_SEAL_REJECT\n",stderr);
                _exit(91);
            }
            FileSourceRXAddress=static_cast<uint64_t>(mapped.guestReturn);
            const auto span=Heap.AuthenticatedRW(FileSourceRXAddress,4096);
            if(!span.attested || !span.guestRead || span.guestWrite ||
               !span.guestExecute || RightsAt(FileSourceRXAddress)!="r-xp"){
                std::fputs("KERNIX_G0_SOURCE_ELF_RX_RIGHTS_REJECT\n",stderr);
                _exit(92);
            }
            std::memcpy(&FileSourceRXOriginalQword,
                        reinterpret_cast<const void*>(
                          static_cast<uintptr_t>(FileSourceRXAddress)),
                        sizeof(FileSourceRXOriginalQword));
            auto forged=trap;
            forged.guestNumber=c1::kMprotect;
            forged.args={FileSourceRXAddress,4096,
                         PROT_READ|PROT_WRITE,0,0,0};
            const auto denial=Heap.Dispatch(forged);
            if(denial.guestReturn!=-EINVAL ||
               denial.nativeOwnedMapProtectionChanged ||
               RightsAt(FileSourceRXAddress)!="r-xp"){
                std::fputs("KERNIX_G0_SOURCE_ELF_RX_WX_UPGRADE_REJECT\n",stderr);
                _exit(93);
            }
            GuestSourceRXMapped=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=FileSourceRXAddress;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_REAL_FEX_X86_ELF64_SOURCE_PT_LOAD_PF_RX_NATIVE_WX_MMAP9_PASS\n",stderr);
            return;
        }
        if(Calls==11) {
            // Guest x86 loaded genuine original ld-linux RX code bytes
            // from the native r-xp page and stored one qword on guest
            // owner-held RW heap. This is DATA READ, not execution
            // of full original GNU dynamic linker.
            const uint64_t guestLoaded=HeapAddress+592;
            uint64_t observed=0;
            if(!GuestSourceRXMapped ||
               trap.guestNumber!=c1::kMunmap ||
               trap.args[0]!=FileSourceRXAddress ||
               trap.args[1]!=4096 || Heap.Count()!=2 ||
               SourceFileKernel.OpenCount()!=1 ||
               RightsAt(FileSourceRXAddress)!="r-xp" ||
               !Heap.AuthenticatedRW(guestLoaded,8).guestWrite ||
               !Heap.AuthenticatedRW(FileSourceRXAddress,8).guestExecute){
                std::fputs("KERNIX_G0_GUEST_RX_SOURCE_LOAD_ABI_REJECT\n",stderr);
                _exit(94);
            }
            std::memcpy(&observed,reinterpret_cast<const void*>(
                           static_cast<uintptr_t>(guestLoaded)),8);
            if(observed!=FileSourceRXOriginalQword){
                std::fputs("KERNIX_G0_GUEST_RX_SOURCE_QWORD_MISMATCH_REJECT\n",stderr);
                _exit(95);
            }
            const auto unmapped=Heap.Dispatch(trap);
            if(unmapped.guestReturn!=0 || !unmapped.nativeOwnedMapReleased ||
               unmapped.hostAnyUntrustedSyscallForwarded ||
               Heap.Count()!=1 ||
               Heap.AuthenticatedRW(FileSourceRXAddress,1).attested){
                std::fputs("KERNIX_G0_GUEST_RX_SOURCE_UNMAP_REJECT\n",stderr);
                _exit(96);
            }
            GuestSourceRXUnmappedAfterRead=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_REAL_FEX_X86_ORIGINAL_ELF64_RX_NATIVE_PAGE_GUEST_CODE_QWORD_READ_AND_MUNMAP11_PASS\n",stderr);
            return;
        }
        if((Calls>=5 && Calls<=7) || Calls==12){
            const uint64_t guestFD=static_cast<uint64_t>(
                kernix::g0::SourceVerifiedGuestElfFDKernel::kGuestBaseFD);
            if(!FirstEntropyWritten || !SecondEntropyWritten ||
               !GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               Heap.Count()!=1 || RightsAt(HeapAddress)!="rw-p" ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
               Owner.WindowsHeld()!=4 || !SourceFileKernel.Bound()){
                std::fputs("KERNIX_G0_X86_SOURCE_LDSO_GUEST_FILE_SERVICE_AUTH_REJECT\n",stderr);
                _exit(75);
            }
            if(Calls==5 &&
               (trap.guestNumber!=c1::kOpenat ||
                trap.args[0]!=static_cast<uint64_t>(int64_t(-100)) ||
                trap.args[1]!=HeapAddress+160 ||
                trap.args[2]!=0x80000 || trap.args[3]!=0 ||
                SourceFileKernel.OpenCount()!=0)){
                std::fputs("KERNIX_G0_X86_SOURCE_LDSO_OPENAT_ARGS_REJECT\n",stderr);
                _exit(76);
            }
            if((Calls==6 || Calls==7) &&
               (trap.guestNumber!=(Calls==6?c1::kPread64:c1::kRead) ||
                trap.args[0]!=guestFD ||
                trap.args[1]!=HeapAddress+(Calls==6?512:544) ||
                trap.args[2]!=32 ||
                (Calls==6 && trap.args[3]!=0) ||
                SourceFileKernel.OpenCount()!=1)){
                std::fputs("KERNIX_G0_X86_SOURCE_LDSO_PREAD_READ_ARGS_REJECT\n",stderr);
                _exit(77);
            }
            if(Calls==12 &&
               (!GuestSourceFileMmapUnmapped ||
                trap.guestNumber!=c1::kClose || trap.args[0]!=guestFD ||
                SourceFileKernel.OpenCount()!=1)){
                std::fputs("KERNIX_G0_X86_SOURCE_LDSO_CLOSE_ARGS_REJECT\n",stderr);
                _exit(78);
            }
            const auto result=SourceFileKernel.Dispatch(trap,Heap);
            const int64_t expected=Calls==5?100:Calls==12?0:32;
            if(result.guestReturn!=expected ||
               !result.guestSyscallAuthenticated ||
               result.hostPathOpened || result.hostGuestFdForwarded ||
               result.hostAnyUntrustedSyscallForwarded ||
               (Calls==5 && !result.openedPinnedReadonlySnapshot) ||
               ((Calls==6 || Calls==7) &&
                !result.copiedSnapshotToAuthenticatedGuestWritable) ||
               (Calls==12 && (!result.guestFdClosed ||
                              SourceFileKernel.OpenCount()!=0))){
                std::fputs("KERNIX_G0_X86_SOURCE_LDSO_FD_SERVICE_REJECT\n",stderr);
                _exit(79);
            }
            if(Calls==6 || Calls==7){
                const uint64_t at=HeapAddress+(Calls==6?512:544);
                const auto* bytes=reinterpret_cast<const uint8_t*>(
                                      static_cast<uintptr_t>(at));
                if(bytes[0]!=0x7f || bytes[1]!='E' ||
                   bytes[2]!='L' || bytes[3]!='F'){
                    std::fputs("KERNIX_G0_X86_SOURCE_LDSO_ELF_HEADER_REJECT\n",stderr);
                    _exit(80);
                }
                if(Calls==7 && std::memcmp(
                    reinterpret_cast<const void*>(
                      static_cast<uintptr_t>(HeapAddress+512)),bytes,32)!=0){
                    std::fputs("KERNIX_G0_X86_SOURCE_LDSO_PREAD_READ_MISMATCH\n",stderr);
                    _exit(81);
                }
            }
            if(Calls==5)
                std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_OPENAT_257_SHA256_LDSO_SYNTHETIC_FD_NO_NATIVE_PATH\n",stderr);
            if(Calls==6)
                std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_PREAD64_17_ORIGINAL_LDSO_IMMUTABLE_SNAPSHOT_HEADER\n",stderr);
            if(Calls==7)
                std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_READ_0_ORIGINAL_LDSO_HEADER_AFTER_POSITIONAL_PREAD\n",stderr);
            if(Calls==12){
                GuestSourceELFFdClosed=true;
                std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_CLOSE_3_SYNTHETIC_FD_NO_HOST_CLOSE\n",stderr);
            }
            frame->State.gregs[FEXCore::X86State::REG_RAX]=
                static_cast<uint64_t>(result.guestReturn);
            frame->State.rip=trap.nextGuestRIP;
            return;
        }
        if(Calls==13) {
            if(!GuestSourceRXUnmappedAfterRead || !GuestSourceFileMmapUnmapped || !GuestSourceELFFdClosed || SourceFileKernel.OpenCount()!=0){
                std::fputs("KERNIX_G0_GUEST_ELF_FD_OPEN_AFTER_CLOSE_REJECT\n",stderr);
                _exit(82);
            }
            // Actual x86 guest syscall 10 targeting the AUTHENTIC,
            // SOURCE-PINNED main ELF PT_GNU_RELRO full writable page.
            // No original dynamic-linker relocation closure witness;
            // deny without modifying the guest source mapping.
            if(!GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               trap.guestNumber!=c1::kMprotect ||
               trap.args[0]!=SourceMainRelroPage ||
               trap.args[1]!=4096 ||
               trap.args[2]!=PROT_READ ||
               SourceMainRelroPage<MainStart ||
               !Owner.GuestReadOnlyBytes(0,SourceMainRelroPage,8) ||
               RightsAt(SourceMainRelroPage)!="rw-p" ||
               Heap.Count()!=1 ||
               RightsAt(HeapAddress)!="rw-p" ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1) {
               std::fputs("KERNIX_G0_GUEST_SOURCE_MAIN_RELRO_MPROTECT_TRAP_REJECT\n",stderr);
               _exit(66);
            }
            const auto beforeOriginal=RightsAt(SourceMainRelroPage);
            const auto denial=Heap.Dispatch(trap);
            if(denial.guestReturn!=-EINVAL ||
               denial.nativeOwnedMapProtectionChanged ||
               denial.hostAnyUntrustedSyscallForwarded ||
               RightsAt(SourceMainRelroPage)!=beforeOriginal ||
               Heap.Count()!=1 || Owner.WindowsHeld()!=4){
               std::fputs("KERNIX_G0_SOURCE_ELF_RELRO_PREMATURE_SEAL_DENIAL_REJECT\n",stderr);
               _exit(67);
            }
            GuestSourceRelroSealDenied=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=
                static_cast<uint64_t>(static_cast<int64_t>(-EINVAL));
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_ACTUAL_FEX_GUEST_X86_ORIGINAL_MAIN_GNU_RELRO_MPROTECT_PREMATURE_DENIED_SOURCE_PAGE_UNCHANGED\n",stderr);
            return;
        }
        if(Calls==14) {
            if(!GuestSourceRXUnmappedAfterRead || !GuestSourceFileMmapUnmapped || !GuestSourceELFFdClosed || SourceFileKernel.OpenCount()!=0 ||
               !FirstEntropyWritten || !SecondEntropyWritten ||
               !GuestSourceRelroSealDenied ||
               RightsAt(SourceMainRelroPage)!="rw-p" ||
               !GuestArchSetFSObserved ||
               frame->State.fs_cached!=GuestFS.FSBase() ||
               !GuestFS.GuestReadbacksMatch() ||
               trap.guestNumber!=c1::kMprotect ||
               trap.args[0]!=HeapAddress ||
               trap.args[1]!=kGuestAnonBytes ||
               trap.args[2]!=PROT_READ ||
               Heap.Count()!=1 ||
               !DeniedForeignUnmap ||
               frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
               frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
               RightsAt(HeapAddress)!="rw-p") {
                std::fputs("KERNIX_G0_ORIGINAL_FEX_REAL_X86_MPROTECT_TRAP_REJECT\n",stderr);
                _exit(63);
            }
            const auto beforeLD=RightsAt(OriginalLdsoEntry);
            auto counterfeit=trap;
            counterfeit.args={OriginalLdsoEntry,kGuestAnonBytes,PROT_READ,0,0,0};
            const auto denied=Heap.Dispatch(counterfeit);
            if(denied.guestReturn!=-EINVAL ||
               denied.nativeOwnedMapProtectionChanged ||
               RightsAt(OriginalLdsoEntry)!=beforeLD ||
               Heap.Count()!=1) {
                std::fputs("KERNIX_G0_ORIGINAL_ELF_MPROTECT_OWNER_DENIAL_REJECT\n",stderr);
                _exit(64);
            }
            const auto protect=Heap.Dispatch(trap);
            const auto span=Heap.AuthenticatedRW(HeapAddress,kGuestAnonBytes);
            if(protect.guestReturn!=0 ||
               !protect.guestSyscallAuthenticated ||
               !protect.nativeOwnedMapProtectionChanged ||
               protect.guestWritableDataMapped ||
               protect.hostAnyUntrustedSyscallForwarded ||
               !span.attested || !span.guestRead ||
               span.guestWrite || span.guestExecute ||
               RightsAt(HeapAddress)!="r--p") {
                std::fputs("KERNIX_G0_NATIVE_ONLY_OWNED_X86_MPROTECT_RO_REJECT\n",stderr);
                _exit(65);
            }
            ProtectedGuestAnonRO=true;
            frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
            frame->State.rip=trap.nextGuestRIP;
            std::fputs("KERNIX_G0_REAL_FEX_X86_GUEST_MPROTECT_OWNED_HEAP_RW_TO_RO_NATIVE_PROTECTED_BEFORE_X86_READ\n",stderr);
            return;
        }
        if(!GuestSourceELFFdClosed || SourceFileKernel.OpenCount()!=0 ||
           !FirstEntropyWritten || !SecondEntropyWritten ||
           !GuestSourceRelroSealDenied ||
           RightsAt(SourceMainRelroPage)!="rw-p" ||
           !ProtectedGuestAnonRO ||
           !GuestArchSetFSObserved ||
           frame->State.fs_cached!=GuestFS.FSBase() ||
           !GuestFS.GuestReadbacksMatch() ||
           trap.guestNumber!=c1::kMunmap ||
           trap.args[0]!=HeapAddress ||
           trap.args[1]!=kGuestAnonBytes ||
           frame->State.gregs[FEXCore::X86State::REG_R12]!=MainSourceWord ||
           frame->State.gregs[FEXCore::X86State::REG_R14]!=1 ||
           frame->State.gregs[FEXCore::X86State::REG_R15]!=MainSourceWord ||
           Heap.Count()!=1 || !DeniedForeignUnmap ||
           !Heap.AuthenticatedRW(HeapAddress,sizeof(uint64_t)).attested ||
           Heap.AuthenticatedRW(HeapAddress,sizeof(uint64_t)).guestWrite ||
           !Heap.AuthenticatedRW(HeapAddress,sizeof(uint64_t)).guestRead ||
           RightsAt(HeapAddress)!="r--p") {
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
           address<Entry+sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST))
            return {Entry,sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST),false};
        // Fundamental old-engine limitation: previously exposed only
        // 16 entry + 128 target bytes of original GNU ld-linux.
        // Resolve every authenticated 4K RX PT_LOAD page in all three
        // source x86 ELF images instead, with genuine native r-xp
        // kernel rights. NEVER expose RW data, PROT_NONE holes, stack,
        // host FEX JIT or any unauthenticated guest image.
        rx::Range verified{};
        if(!rx::ResolveOriginalSourceExecutableRange(
             Owner,SourceExecPolicy,NativeWXApplied,address,verified))
            return {0,0,false};
        if(!verified.sourceVerifiedOriginalPTLoadRX ||
           !verified.nativeGuestAddressIsOwned ||
           verified.originalGNUInterpreterStartupCompleted ||
           verified.originalRelocationsExecuted ||
           verified.pageBytes!=4096 ||
           RightsAt(verified.pageStart)!="r-xp")
            return {0,0,false};
        ++SourceRXQueries;
        if(verified.moduleIndex==0)++SourceMainRXQueries;
        if(verified.moduleIndex==1){
            ++SourceInterpreterRXQueries;
            if(address>=OriginalLdsoTarget &&
               address-OriginalLdsoTarget<128)
               ++SourceOriginalCalleeRXQueries;
        }
        if(verified.moduleIndex==2)++SourceLibcRXQueries;
        return {verified.pageStart,verified.pageBytes,false};
    }
    std::optional<FEXCore::ExecutableFileSectionInfo>
    LookupExecutableFileSection(
        FEXCore::Core::InternalThreadState*,uint64_t) override {
        return std::nullopt;
    }
    unsigned Calls=0;
    size_t SourceRXQueries=0;
    size_t SourceMainRXQueries=0;
    size_t SourceInterpreterRXQueries=0;
    size_t SourceOriginalCalleeRXQueries=0;
    size_t SourceLibcRXQueries=0;
    bool DeniedForeignUnmap=false;
    bool WholeProcessIntegrationCompleted=false;
    bool GuestArchSetFSObserved=false;
    bool ProtectedGuestAnonRO=false;
    bool GuestSourceRelroSealDenied=false;
    bool FirstEntropyWritten=false;
    bool SecondEntropyWritten=false;
    bool GuestSourceELFFdClosed=false;
    bool GuestSourceFileMmapReadonly=false;
    bool GuestSourceFileMmapUnmapped=false;
    uint64_t FileSourceRXAddress=0;
    uint64_t FileSourceRXOriginalQword=0;
    bool GuestSourceRXMapped=false;
    bool GuestSourceRXUnmappedAfterRead=false;
    uint64_t FileSourceMapAddress=0;
    std::array<unsigned char,32> FirstEntropyBytes{};
    kernix::g0::BoundedGuestAnonymousVM Heap{};
    // The original x86 fixture preserves its mmap result in guest RBX
    // through the real munmap; that historic pointer is a register
    // witness only. It must never be dereferenced after unmapping.
    uint64_t HistoricalMmapAddress() const noexcept {return HeapAddress;}
private:
    uint64_t Entry=0;
    c1::X86GuestStackBoundary Stack{};
    uint64_t MainStart=0,InitialRSP=0,MainSourceWord=0;
    uint64_t OriginalLdsoEntry=0,OriginalLdsoTarget=0,HeapAddress=0;
    const c7b::NativeChosenPIEGuestLayout& Owner;
    const fs::OwnedGuestFS& GuestFS;
    uint64_t SourceMainRelroPage=0;
    kernix::g0::SourceVerifiedGuestElfFDKernel& SourceFileKernel;
    const relr::Witness& OriginalSourceRELR;
    const c7g::PermissionPlan& SourceExecPolicy;
    const c7g::ApplyWitness& NativeWXApplied;
    gbrk::OriginalGuestMainProgramBreak* GuestProgramBreak=nullptr;
    size_t RealOriginalLdsoBrkCalls=0;
    size_t RealOriginalLdsoAccessCalls=0;
};

int Run(int argc,char** argv) {
    // New test proves a real guest-x86 fixture RELA write from an
    // authentic original source record. Genuine ld-linux dynamic
    // relocation and TLS/FS remain unexecuted.
    // Preflight extends device-accepted G0 without executing a genuine
    // relocation writer / guest FS/GS or full dynamic linker.
    // Deterministic stage markers are stderr-only, bounded and do not
    // modify the guest or host address-space permissions. Detect
    // pre-ExecuteThread SIGSEGV separately from original FEX JIT.
    const auto stage=[](const char* name) noexcept {
        std::fprintf(stderr,"KERNIX_G0_MOV_CALL_DIAGNOSTIC_STAGE=%s\n",name);
        std::fflush(stderr);
    };
    stage("entered");
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
    stage("source_sha256_verified");
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)entropy[i]=uint8_t(i+1);
    c7b::NativeChosenPIEGuestLayout owned{};
    c7b::Witness source{};
    const bool staged=owned.Stage(fd,entropy,source);
    // Trusted host-only bootstrap, fixed literal relative descriptor
    // names, O_NOFOLLOW, no guest filename ever forwarded to host.
    kernix::g0::SourceVerifiedGuestElfFDKernel sourceFileKernel{};
    const int binFD=::openat(fd,"bin",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    const int libFD=::openat(fd,"lib",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    const int lib64FD=::openat(fd,"lib64",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    const int libcDirFD=libFD<0?-1: ::openat(
        libFD,"x86_64-linux-gnu",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    const std::array<int,3> sourceFDs{{
      binFD<0 ? -1 : ::openat(binFD,"kernix-g2e-dynamic-guest",O_RDONLY|O_NOFOLLOW|O_CLOEXEC),
      lib64FD<0 ? -1 : ::openat(lib64FD,"ld-linux-x86-64.so.2",O_RDONLY|O_NOFOLLOW|O_CLOEXEC),
      libcDirFD<0 ? -1 : ::openat(libcDirFD,"libc.so.6",O_RDONLY|O_NOFOLLOW|O_CLOEXEC)
    }};
    const bool sourceFileSnapshotsOK=sourceFileKernel.BindSourceOriginalTriad(sourceFDs);
    for(const int f:sourceFDs)if(f>=0)::close(f);
    for(const int f:{binFD,libFD,lib64FD,libcDirFD})if(f>=0)::close(f);
    ::close(fd);
    if(!sourceFileSnapshotsOK || !sourceFileKernel.Bound() ||
       sourceFileKernel.OpenCount()!=0)return 83;
    stage("verified_exact_three_original_guest_ELF_immutable_snapshot_fd_kernel_bound");
    if(!staged || !source.pinnedOriginalELFSHA256Verified ||
       source.windowsReserved!=4 || owned.WindowsHeld()!=4 ||
       !source.linuxAuxvRebased || !source.originalBytesCopiedReadOnly ||
       source.originalLdsoExecuted || source.originalELFCodeExecuted)
        return 5;
    stage("original_source_ptload_staged");
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
    // Link to the original source-verified PT_INTERP entry within the
    // SAME exact original PT_LOAD/guest AUXV VMAs, not a synthetic
    // separately allocated copy or a second FEX process.
    const uint64_t originalLdsoRIP=plan->guestInterpreterEntry;
    if((originalLdsoRIP&4095)>4096-16 ||
       originalLdsoRIP<interpreter->chosenImageStart ||
       !c1::GuestRange(originalLdsoRIP,16))return 20;
    stage("original_elf_and_auxv_stack_read_verified");
    // Reuse the existing source-only C3-D7N exact original ELF
    // entry CALL rel32 target contract (NO second competing loader).
    c7g::PermissionPlan planRights{};
    c7g::Reject rightsReject{};
    if(!c7g::BuildVerifiedOriginalPermissionPlan(
          original,owned,planRights,rightsReject))return 22;
    stage("original_permission_plan_verified");
    // This is NOT a relocated loader or TLS runtime: reuse independent
    // source-authenticated C3-D7H/I/J metadata and TLS-model contracts
    // before PT_LOAD W^X hardening. No guest relocations/FS/GS writes.
    h::Plan relro{};
    h::Reject relroReject{};
    if(!h::BuildVerifiedOriginalThreeELFRelroPlan(
         original,owned,planRights,relro,relroReject)){
      std::fprintf(stderr,"KERNIX_G0_ELF_RELRO_PREFLIGHT_REJECT reason=%u\n",
                   unsigned(relroReject));return 42;
    }
    d::Plan dynamic{};
    d::Reject dynamicReject{};
    if(!d::InspectOriginalThreeModules(
         original,owned,planRights,relro,dynamic,dynamicReject)){
      std::fprintf(stderr,"KERNIX_G0_ELF_DYNAMIC_PREFLIGHT_REJECT reason=%u\n",
                   unsigned(dynamicReject));return 43;
    }
    tls::TLSModel tlsModel{};
    tls::DependencyGate dependencies{};
    tls::Reject tlsReject{};
    if(!tls::BuildOriginalStaticTLSModel(
        original,owned,dynamic,relro,tlsModel,dependencies,tlsReject)){
      std::fprintf(stderr,"KERNIX_G0_ORIGINAL_TLS_MODEL_REJECT reason=%u\n",
                   unsigned(tlsReject));return 44;
    }
    const auto& libcDyn=dynamic.modules[2];
    if(!dynamic.originalThreeSHA256SourcesVerified ||
       !dynamic.allOriginalDynamicTablesBounded ||
       !dynamic.allOriginalTLSRangesBounded ||
       dynamic.originalELFRelocationsApplied ||
       dynamic.x86GuestFSGSInitialized ||
       !dependencies.authenticateThreeOriginalELFs ||
       !dependencies.requiresActualRelocationWrites ||
       !dependencies.requiresRealGuestTCBAndDTV ||
       !dependencies.requiresActualGuestFSBase ||
       !dependencies.requiresRealIFUNCResolverGuestExecution ||
       !dependencies.requiresPostRelocationRELRO ||
       dependencies.realRelocationWritePerformed ||
       dependencies.guestFSBaseAssigned ||
       dependencies.guestRelroApplied ||
       !tlsModel.sourceInitializerMatchesOriginalELF ||
       !tlsModel.zeroFillMatchesOriginalPTTLSMemsz ||
       tlsModel.realGuestFSBaseAssigned ||
       tlsModel.originalLdsoExecuted ||
       dependencies.sourceOriginalTLSModules!=1 ||
       !tlsModel.originalInitializerBytes ||
       !libcDyn.tlsTotalMemorySize ||
       dependencies.sourceOriginalRelrTargets==0 ||
       dependencies.sourceOriginalIRelativeResolvers==0 ||
       dynamic.relocationTargetsOutsideInitialRW!=0)return 45;
    // The initial source-verified TLS data is still byte-identical to
    // its original guest memory and remains a HOST-ONLY model.
    const auto* tlsBytes=owned.GuestReadOnlyBytes(
        2,libcDyn.tlsOriginalGuestVA,tlsModel.originalInitializerBytes);
    if(!tlsBytes ||
       std::memcmp(tlsBytes,
          tlsModel.bytes.data()+tlsModel.negativeTLSBlockStart,
          tlsModel.originalInitializerBytes)!=0)return 46;
    stage("original_three_elf_dynamic_relr_rela_and_libc_tls_source_preflight_only");
    fs::OwnedGuestFS guestFS{};
    const bool tlsOwnerInstalled=guestFS.Install(tlsModel);
    if(!tlsOwnerInstalled ||
       !guestFS.FSBase() ||
       RightsAt(guestFS.FSBase())!="rw-p") {
      std::fprintf(stderr,
       "KERNIX_G0_GUEST_FS_OWNER_INSTALL_REJECT installed=%d fs=%llx rights=%s source_init=%zu source_aligned=%zu source_negative_start=%zu native_errno=%d\n",
       int(tlsOwnerInstalled),
       static_cast<unsigned long long>(guestFS.FSBase()),
       RightsAt(guestFS.FSBase()).c_str(),
       tlsModel.originalInitializerBytes,
       tlsModel.alignedStaticBlockBytes,
       tlsModel.negativeTLSBlockStart,errno);
      return 63;
    }
    stage("source_original_libc_PT_TLS_installed_into_bounded_guest_TCB_DTV_not_full_glibc");
    // One exact main ELF R_X86_64_RELATIVE is authorized by SHA-pinned
    // DT_RELA + ELF PT_LOAD permission plan, before native W^X hardening.
    // The guest FIXTURE, not the original ld-linux, later performs it
    // between real x86 mmap and munmap. We intentionally do NOT claim
    // the real dynamic linker handled relocations.
    rela::Witness relative{};
    rela::Reject relativeReject{};
    if(!rela::FindSourceMainRelativeRela(
         original,owned,planRights,dynamic,relative,relativeReject) ||
       !relative.authenticatedOriginalRela ||
       !relative.independentGuestPTLoadWritePermitted ||
       relative.actuallyExecutedByOriginalLdso ||
       relative.sourceRelocationInfo!=uint64_t(R_X86_64_RELATIVE) ||
       relative.guestMainLoadBias!=main->chosenImageStart ||
       relative.previousValue==relative.expectedSourceValue){
      std::fprintf(stderr,"KERNIX_G0_REAL_X86_RELATIVE_SOURCE_SELECT_REJECT reason=%u\n",
                   unsigned(relativeReject));return 48;
    }
    stage("original_sha256_main_elf_relative_rela_source_and_rw_target_authorized");
    // Decode an authentic source GNU x86 ELF DT_RELR even descriptor
    // or odd compact bitmap. Prefer libc source; the RW guest target
    // must be in its exact allocated PT_LOAD, and MUST differ from
    // the already selected original main R_X86_64_RELATIVE target.
    // The later translated x86 writer is a KERNIX fixture, NOT GNU
    // ld-linux's actual dynamic relocation loop.
    relr::Witness sourceRelr{};
    size_t relrModuleIndex=3;
    for(const size_t moduleIndex:{size_t(2),size_t(0),size_t(1)}){
      const auto* image=owned.Module(moduleIndex);
      const auto& src=original.snapshots[moduleIndex];
      if(!image || !src.readOnlySnapshot() || !src.bytes())continue;
      relr::Witness candidate{};
      relr::Reject why{};
      if(!relr::SourceOriginalRELRWitness(
           src.bytes(),src.size(),original.exactSha256Matched,
           image->loadBias,candidate,why))continue;
      if(candidate.guestTarget==relative.guestTarget ||
         candidate.guestTarget<image->chosenImageStart ||
         candidate.guestTarget-image->chosenImageStart>
           c7b::kImageCapacity-8)continue;
      const size_t pg=static_cast<size_t>(
        (candidate.guestTarget-image->chosenImageStart)/4096);
      const auto rights=planRights.modules[moduleIndex].rights[pg];
      if((rights&(c7g::kRead|c7g::kWrite))!=
            (c7g::kRead|c7g::kWrite) ||
         (rights&c7g::kExecute)!=0)continue;
      const auto* word=owned.GuestReadOnlyBytes(
          moduleIndex,candidate.guestTarget,8);
      uint64_t sourceInitial=0;
      if(!word)continue;
      std::memcpy(&sourceInitial,word,8);
      if(sourceInitial!=candidate.sourceInitialAddend ||
         candidate.expectedRelocatedPointer==sourceInitial)continue;
      sourceRelr=candidate;relrModuleIndex=moduleIndex;break;
    }
    if(relrModuleIndex>=3 ||
       !sourceRelr.authenticSourceELF64DynamicRELR ||
       sourceRelr.originalLdsoRelocationActuallyExecuted ||
       sourceRelr.guestRelocationActuallyExecuted ||
       sourceRelr.sourceTargetVA==0)return 97;
    stage("original_SHA256_GNU_ELF_DT_RELR_source_bitmap_and_nonexec_guest_RW_target_pinned_not_executed_yet");
    kernix::g2e::c3d7n::CallProof call{};
    kernix::g2e::c3d7n::Reject callReject{};
    if(!kernix::g2e::c3d7n::VerifyAuthenticLdsoSecondCallTarget(
          original,owned,planRights,call,callReject) ||
       call.originalEntry!=originalLdsoRIP ||
       call.originalReturnRIP!=originalLdsoRIP+8 ||
       call.originalGuestStartupRSP!=rsp ||
       call.originalTarget==originalLdsoRIP ||
       (call.originalTarget&4095)>4096-80 ||
       !c1::GuestRange(call.originalTarget,16))
        return 23;
    stage("original_source_call_target_verified");
    // Source and ELF permission policy MUST be fully verified before
    // C3-D7G mprotect(PROT_NONE) hides genuine non-PT_LOAD holes.
    // BuildVerifiedOriginalPermissionPlan reads source/guest metadata;
    // rebuilding the plan after hardening previously SIGSEGV'd.
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
    stage("ptload_native_wx_permissions_applied");
    // The pending original PT_GNU_RELRO must stay RW until the REAL
    // GNU dynamic linker has completed all relocations. A single
    // KERNIX-owned RELATIVE fixture store is NOT that completion.
    uint64_t authenticMainRelroRWPage=0;
    for(size_t pg=0;pg<c7g::kModulePages;++pg) {
        if(!relro.modules[0].sealedAfterRealRelocation[pg] ||
           (planRights.modules[0].rights[pg]&(c7g::kRead|c7g::kWrite))!=
            (c7g::kRead|c7g::kWrite))continue;
        const uint64_t addr=main->chosenImageStart+uint64_t(pg)*4096;
        if(RightsAt(addr)!="rw-p" ||
           !owned.GuestReadOnlyBytes(0,addr,8))continue;
        authenticMainRelroRWPage=addr;
        break;
    }
    h::Reject earlySealReject{};
    if(!authenticMainRelroRWPage ||
       h::SealOriginalRelroBeforeVerifiedRealRelocations(
          relro,earlySealReject) ||
       earlySealReject!=h::Reject::NoRelocationProof ||
       (authenticMainRelroRWPage&4095)!=0 ||
       !c1::GuestRange(authenticMainRelroRWPage,4096))
       return 70;
    stage("source_main_GNU_RELRO_original_RW_fullpage_selected_but_no_real_ldso_relocation_completion_witness");
    if(RightsAt(relative.guestTarget)!="rw-p" ||
       RightsAt(sourceRelr.guestTarget)!="rw-p" ||
       !owned.GuestReadOnlyBytes(0,relative.sourceGuestRela,sizeof(Elf64_Rela)))
       return 49;
    uint64_t beforeSourceRelaInfo=0;
    std::memcpy(&beforeSourceRelaInfo,
      reinterpret_cast<const void*>(
        static_cast<uintptr_t>(relative.sourceGuestRela+8)),8);
    if(beforeSourceRelaInfo!=uint64_t(R_X86_64_RELATIVE))return 50;
    const uint64_t originalTarget=call.originalTarget;
    auto* originalEntry=owned.GuestReadOnlyBytes(1,originalLdsoRIP,16);
    auto* originalTargetBytes=owned.GuestReadOnlyBytes(1,originalTarget,16);
    if(!originalEntry || !originalTargetBytes ||
       std::memcmp(originalEntry,call.originalEntryBytes.data(),16)!=0 ||
       std::memcmp(originalTargetBytes,call.originalTargetBytes.data(),16)!=0 ||
       call.originalTargetBytes[0]==0xf4)return 24;
    stage("original_entry_target_rx_source_bytes_verified");
    // Execute authentic source-backed callee after real guest mmap/munmap:
    // prove the original loader updates its own RW data and stack state.
    // Only the *next* opcode is replaced by HLT in owned guest staging.
    const auto* actual80=owned.GuestReadOnlyBytes(1,originalTarget,kCallee.size());
    if(!actual80 || std::memcmp(actual80,kCallee.data(),kCallee.size())!=0)
      return 36;
    const uint64_t base=interpreter->loadBias;
    int32_t dispAND=0,dispRSI=0;
    std::memcpy(&dispAND,kCallee.data()+67,4);
    std::memcpy(&dispRSI,kCallee.data()+75,4);
    const uint64_t dataAt=originalTarget+72+
        static_cast<uint64_t>(static_cast<int64_t>(dispAND));
    const uint64_t pointerRSI=originalTarget+79+
        static_cast<uint64_t>(static_cast<int64_t>(dispRSI));
    if(dataAt!=base+0x38e06 || pointerRSI!=base+0x38af0 ||
       RightsAt(dataAt)!="rw-p" || RightsAt(rsp-kFrame)!="rw-p" ||
       (rsp&15)!=0)return 37;
    auto* dataByte=reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(dataAt));
    const uint8_t originalData=*dataByte;
    const uint8_t seededData=static_cast<uint8_t>(originalData|0x20u);
    const uint8_t expectedData=static_cast<uint8_t>(seededData&0xdfu);
    if(expectedData==seededData)return 38;
    std::array<uint8_t,kFrame> originalStack{};
    std::memcpy(originalStack.data(),reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-kFrame)),originalStack.size());
    *dataByte=seededData;
    stage("source_original_callee_writable_data_and_guest_stack_verified");
    const auto targetPage=originalTarget&~uint64_t(4095);
    auto* targetByte=reinterpret_cast<uint8_t*>(
        static_cast<uintptr_t>(originalTarget));
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION)
    // A REAL GNU loader continuation probe. Do not patch the original
    // source 80th byte with HLT; the source code stays exactly intact.
    // Never call this an actual full GNU relocation test: the next
    // unsupported syscall, x86 trap or bounded execution timeout
    // will be recorded independently in the isolated Linux CI runner.
    if(targetByte[kStop]!=kCallee[kStop] ||
       std::memcmp(targetByte,kCallee.data(),kCallee.size())!=0 ||
       std::memcmp(originalEntry,call.originalEntryBytes.data(),8)!=0 ||
       RightsAt(targetPage)!="r-xp")return 118;
    stage("original_GNU_ldso_source_callee_entire_original_unpatched_RX_code_preserved");
#else
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
        return 25;
    targetByte[kStop]=0xf4;
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
        return 26;
    if(targetByte[kStop]!=0xf4 ||
       std::memcmp(targetByte,kCallee.data(),kStop)!=0 ||
       std::memcmp(originalEntry,call.originalEntryBytes.data(),8)!=0)
        return 27;
    stage("original_callee_next_source_opcode_bounded_hlt_rx_installed");
#endif
    OwnedGuestFixtureCode code;
    if(!code.Install() || !c1::GuestRange(
        code.Address(),sizeof(KERNIX_G0_ELF_LDSO_HANDOFF_GUEST)))
        return 10;

    stage("integration_guest_fixture_rx_installed");
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
    stage("original_fex_host_features_initialized");
    SingleFEXOriginalCallRetGuard callret{};
    if(!callret.Reserve())return 29;
    stage("fex_callret_host_guard_initialized");
    auto ctx=FEXCore::Context::Context::CreateNewContext(host);
    if(!ctx)return 12;
    FEXCore::SignalDelegator signals{};
    gbrk::OriginalGuestMainProgramBreak guestBreak{};
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION) && defined(KERNIX_G0_ENABLE_GUEST_BRK12)
    if(!guestBreak.Install(owned,planRights,rights) ||
       !guestBreak.Ready() ||
       guestBreak.Minimum()==0 ||
       RightsAt(guestBreak.Minimum())!="---p")
        return 124; // no native ::brk and no guest source WX changes
#endif
    OneProcessOriginalElfSyscalls handler{
        code.Address(),originalTarget,*plan,*main,first8,
        owned,guestFS,authenticMainRelroRWPage,sourceFileKernel,
        sourceRelr,planRights,rights
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION) && defined(KERNIX_G0_ENABLE_GUEST_BRK12)
        ,&guestBreak
#endif
    };
    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&handler);
    ctx->EnableExitOnHLT();
    stage("original_fex_context_configured");
    if(!ctx->InitCore())return 13;
    stage("original_fex_core_initialized");
    auto* thread=ctx->CreateThread();
    if(!thread || !thread->CurrentFrame)return 14;
    stage("original_fex_thread_created");
    FEXCore::Core::CPUState::gdt_segment gdt[32]{};
    auto& cpu=thread->CurrentFrame->State;
    thread->CallRetStackBase=callret.Base();
    cpu.callret_sp=callret.InitialSP();
    if(!thread->CallRetStackBase ||
       !callret.Contains(cpu.callret_sp-16,16))return 30;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT]=gdt;
    cpu.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT]=gdt;
    cpu.cs_idx=FEXCore::Core::CPUState::DEFAULT_USER_CS<<3;
    auto* descriptor=FEXCore::Core::CPUState::GetSegmentFromIndex(cpu,cpu.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(descriptor,0);
    FEXCore::Core::CPUState::SetGDTLimit(descriptor,0xFFFFF);
    descriptor->L=1;descriptor->D=0;cpu.cs_cached=0;
    cpu.rip=code.Address();
    cpu.gregs[FEXCore::X86State::REG_RSP]=rsp;
    cpu.gregs[FEXCore::X86State::REG_RAX]=authenticMainRelroRWPage;
    cpu.gregs[FEXCore::X86State::REG_R13]=main->chosenImageStart;
    cpu.gregs[FEXCore::X86State::REG_R8]=guestFS.FSBase();
    cpu.gregs[FEXCore::X86State::REG_R9]=relative.sourceGuestRela;
    cpu.fs_cached=0;
    cpu.gs_cached=0;
    cpu.gregs[FEXCore::X86State::REG_RBP]=originalLdsoRIP;
    cpu.gregs[FEXCore::X86State::REG_RDI]=0x4b45524e49585431ULL;
    cpu.gregs[FEXCore::X86State::REG_R12]=0;
    cpu.gregs[FEXCore::X86State::REG_R14]=0;
    cpu.gregs[FEXCore::X86State::REG_R15]=0;
    stage("original_x86_guest_cpu_state_ready_before_execute");
    std::fputs("KERNIX_G0_ORIGINAL_LDSO_MOV_CALL_AFTER_FEX_HEAP_START\n",stderr);
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION)
    std::fputs("KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_UNPATCHED_CONTINUATION_BEFORE_FEX_EXECUTE_NOT_RUNTIME_SUCCESS\n",stderr);
#endif
    std::fflush(stderr);
    ctx->ExecuteThread(thread);
    stage("original_fex_execute_thread_returned");
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION)
    std::fprintf(stderr,
       "KERNIX_G0_ORIGINAL_GNU_LDSO_UNPATCHED_EXECUTION_RETURNED_NO_RELOCATION_PROOF guest_rip=%llx real_guest_syscall_traps=%u original_rx_queries=%zu\n",
       static_cast<unsigned long long>(cpu.rip),
       handler.Calls,handler.SourceInterpreterRXQueries);
    return 119; // this experimental invocation is NOT a loader PASS
#endif
    if(handler.Calls!=15 || !handler.GuestArchSetFSObserved ||
       !handler.GuestSourceRXMapped ||
       !handler.GuestSourceRXUnmappedAfterRead ||
       !handler.GuestSourceFileMmapReadonly ||
       !handler.GuestSourceFileMmapUnmapped ||
       !handler.GuestSourceELFFdClosed || sourceFileKernel.OpenCount()!=0 ||
       !handler.FirstEntropyWritten || !handler.SecondEntropyWritten ||
       !handler.GuestSourceRelroSealDenied ||
       RightsAt(authenticMainRelroRWPage)!="rw-p" ||
       !handler.ProtectedGuestAnonRO ||
       cpu.fs_cached!=guestFS.FSBase() ||
       cpu.gs_cached!=0 ||
       !guestFS.GuestReadbacksMatch() ||
       !handler.WholeProcessIntegrationCompleted ||
       !handler.DeniedForeignUnmap || handler.Heap.Count()!=0 ||
       cpu.gregs[FEXCore::X86State::REG_R12]!=first8 ||
       cpu.gregs[FEXCore::X86State::REG_R14]!=1 ||
       cpu.gregs[FEXCore::X86State::REG_R15]!=first8 ||
       cpu.gregs[FEXCore::X86State::REG_RSP]!=rsp-kFrame ||
       cpu.gregs[FEXCore::X86State::REG_RDI]!=rsp ||
       cpu.gregs[FEXCore::X86State::REG_RBP]!=rsp-16 ||
       cpu.gregs[FEXCore::X86State::REG_RSI]!=pointerRSI ||
       cpu.gregs[FEXCore::X86State::REG_RCX]!=base ||
       cpu.xmm.sse.data[1][0]!=base ||
       cpu.xmm.sse.data[1][1]!=base+0x392d8 ||
       *dataByte!=expectedData ||
       (cpu.rip!=originalTarget+kStop &&
        cpu.rip!=originalTarget+kStop+1) ||
       owned.WindowsHeld()!=4){
      std::fprintf(stderr,
       "KERNIX_G0_FUNCTIONAL_LOADER_RW_REJECT stage=post_fex rip=%llx rsp=%llx rsi=%llx expected_rsi=%llx byte=%02x expected_byte=%02x\n",
       static_cast<unsigned long long>(cpu.rip),
       static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSP]),
       static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSI]),
       static_cast<unsigned long long>(pointerRSI),unsigned(*dataByte),unsigned(expectedData));
      return 15;
    }
    std::array<uint64_t,7> stackSlots{};
    for(size_t i=0;i<stackSlots.size();++i)
      std::memcpy(&stackSlots[i],reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-8*(i+1))),sizeof(uint64_t));
    const uint64_t historicalHeap=handler.HistoricalMmapAddress();
    if(historicalHeap<65536 ||
       (historicalHeap&uint64_t{4095})!=0 ||
       handler.Heap.Count()!=0)return 30;
    // The seventh saved slot is authentic RBX: it holds the unmapped
    // guest heap's previous address, not zero.
    const std::array<uint64_t,7> wantedSlots{
      call.originalReturnRIP,originalLdsoRIP,first8,1,
      main->chosenImageStart,first8,historicalHeap};
    if(stackSlots!=wantedSlots){
      for(size_t i=0;i<stackSlots.size();++i)
        std::fprintf(stderr,
          "KERNIX_G0_STACK_STATE_MISMATCH slot=%zu actual=%llx expected=%llx\n",
          i,static_cast<unsigned long long>(stackSlots[i]),
          static_cast<unsigned long long>(wantedSlots[i]));
      return 31;
    }
    uint64_t localRDI=0;
    std::array<uint64_t,2> localXMM{};
    std::memcpy(&localRDI,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-16-0x88)),8);
    std::memcpy(localXMM.data(),reinterpret_cast<const void*>(
        static_cast<uintptr_t>(rsp-16-0x80)),16);
    if(localRDI!=rsp || localXMM[0]!=base ||
       localXMM[1]!=base+0x392d8){
      std::fprintf(stderr,
         "KERNIX_G0_LOCAL_STATE_MISMATCH rdi=%llx expected_rdi=%llx xmm1lo=%llx expected_lo=%llx xmm1hi=%llx expected_hi=%llx\n",
         static_cast<unsigned long long>(localRDI),
         static_cast<unsigned long long>(rsp),
         static_cast<unsigned long long>(localXMM[0]),
         static_cast<unsigned long long>(base),
         static_cast<unsigned long long>(localXMM[1]),
         static_cast<unsigned long long>(base+0x392d8));
      return 39;
    }
    // This witness is a genuine original-source-derived guest x86
    // store, not a fabricated host-side relocation success marker.
    uint64_t actualGuestRelative=0;
    std::memcpy(&actualGuestRelative,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(relative.guestTarget)),8);
    uint64_t afterSourceRelaInfo=0;
    std::memcpy(&afterSourceRelaInfo,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(relative.sourceGuestRela+8)),8);
    if(actualGuestRelative!=relative.expectedSourceValue ||
       actualGuestRelative==relative.previousValue ||
       afterSourceRelaInfo!=beforeSourceRelaInfo ||
       RightsAt(relative.guestTarget)!="rw-p"){
      std::fprintf(stderr,
       "KERNIX_G0_SOURCE_RELATIVE_GUEST_WRITE_REJECT target=%llx actual=%llx expected=%llx previous=%llx info=%llx\n",
       static_cast<unsigned long long>(relative.guestTarget),
       static_cast<unsigned long long>(actualGuestRelative),
       static_cast<unsigned long long>(relative.expectedSourceValue),
       static_cast<unsigned long long>(relative.previousValue),
       static_cast<unsigned long long>(afterSourceRelaInfo));
      return 51;
    }
    // After real source guest x86 DT_RELR fixture translated store:
    // validate the exact original SHA-locked source PT_LOAD RW qword.
    uint64_t afterGuestRELR=0;
    std::memcpy(&afterGuestRELR,reinterpret_cast<const void*>(
         static_cast<uintptr_t>(sourceRelr.guestTarget)),8);
    if(afterGuestRELR!=sourceRelr.expectedRelocatedPointer ||
       afterGuestRELR==sourceRelr.sourceInitialAddend ||
       RightsAt(sourceRelr.guestTarget)!="rw-p") {
      std::fprintf(stderr,
        "KERNIX_G0_ACTUAL_GUEST_RELR_SOURCE_WRITE_REJECT mod=%zu target=%llx actual=%llx expected=%llx source=%llx\n",
        relrModuleIndex,
        static_cast<unsigned long long>(sourceRelr.guestTarget),
        static_cast<unsigned long long>(afterGuestRELR),
        static_cast<unsigned long long>(sourceRelr.expectedRelocatedPointer),
        static_cast<unsigned long long>(sourceRelr.sourceInitialAddend));
      return 99;
    }
    if(handler.SourceRXQueries==0 ||
       handler.SourceInterpreterRXQueries==0 ||
       handler.SourceOriginalCalleeRXQueries==0){
       std::fprintf(stderr,
          "KERNIX_G0_REAL_FEX_ORIGINAL_SOURCE_PTLOAD_EXEC_RANGE_JIT_QUERIES_REJECT all=%zu ldso=%zu\n",
          handler.SourceRXQueries,handler.SourceInterpreterRXQueries);
       return 101;
    }
    std::fputs("KERNIX_G0_REAL_FEX_ORIGINAL_MAIN_LDSO_LIBC_FULL_PTLOAD_RX_SOURCE_JIT_RANGE_PROVIDER_USED_NOT_FULL_LDSO\n",stderr);
    std::fputs("KERNIX_G0_REAL_FEX_X86_AUTHENTIC_ORIGINAL_GNU_DT_RELR_COMPACT_SOURCE_GUEST_RW_STORE_VERIFIED_NOT_LDSO_RELOCATOR\n",stderr);
    std::fputs("KERNIX_G0_REAL_FEX_X86_ARCH_PRCTL_SET_FS_GUEST_TCB_DTV_LIBC_TLS_READ_PASS_SAME_HEAP_LDSO_PROCESS\n",stderr);
    std::fputs("KERNIX_G0_REAL_GUEST_SOURCE_RELA_FS_MMAP_MPROTECT_RO_MUNMAP_EARLY_ORIGINAL_LDSO_COMPOSED_NOT_FULL_GLIBC_RELRO\n",stderr);
    std::fputs("KERNIX_G0_SOURCE_ORIGINAL_MAIN_GNU_RELRO_NATIVE_MPROTECT_FROM_X86_DENIED_PENDING_REAL_LDSO_RELOCATION\n",stderr);
    std::fputs("KERNIX_G0_SAME_ORIGINAL_FEX_X86_GUEST_GETRANDOM_318_TWICE_FS_RELA_GNURELRO_DENY_ANON_RO_EARLY_LDSO_PASS_NOT_FULL_GLIBC\n",stderr);
    std::fputs("KERNIX_G0_SAME_FEX_GUEST_OPENAT_PREAD_READ_CLOSE_SHA256_VERIFIED_SOURCE_LDSO_BEFORE_GNU_RELRO_DENIAL\n",stderr);
    std::fputs("KERNIX_G0_SAME_FEX_X86_ELF_SNAPSHOT_MMAP_PRIVATE_RO_NATIVE_GUEST_LOAD_UNMAP_AND_EARLY_LDSO_NOT_FULL_GLIBC\n",stderr);
    std::fputs("KERNIX_G0_SAME_FEX_SOURCE_SHA256_ELF64_PT_LOAD_RX_WX_NATIVE_GUEST_SOURCE_BYTE_READ_BEFORE_LDSO_NOT_FULL_DYNAMIC_LOADER\n",stderr);
    std::fputs("KERNIX_G0_REAL_FEX_GUEST_X86_SOURCE_RELATIVE_RELA_STORE_AFTER_MMAP_VERIFIED_NOT_ORIGINAL_LDSO_RELOCATION\n",stderr);
    if(!dependencies.requiresActualRelocationWrites ||
       !dependencies.requiresRealGuestTCBAndDTV ||
       !dependencies.requiresRealIFUNCResolverGuestExecution ||
       dependencies.realRelocationWritePerformed ||
       dependencies.guestFSBaseAssigned || dependencies.guestRelroApplied ||
       !dynamic.originalThreeSHA256SourcesVerified ||
       !tlsModel.sourceInitializerMatchesOriginalELF)
      return 47;
    std::fputs("KERNIX_G0_REAL_FEX_HEAP_LDSO_RW_AND_SOURCE_DYNAMIC_TLS_PREFLIGHT_COEXIST\n",stderr);
    std::fputs("KERNIX_G0_SAME_FEX_ORIGINAL_LDSO_CALLEE_GUEST_RW_AND_STACK_STATE_VERIFIED\n",stderr);
    // Destroy native JIT context before modifying source-owned RX
    // guest PT_LOAD and before releasing the host-only callret stack.
    ctx.reset();
    if(!callret.Release())return 32;
    if(!guestFS.Release())return 64;
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_WRITE)!=0)
      return 33;
    targetByte[kStop]=kCallee[kStop];
    if(::mprotect(reinterpret_cast<void*>(
          static_cast<uintptr_t>(targetPage)),4096,PROT_READ|PROT_EXEC)!=0)
      return 34;
    if(std::memcmp(kCallee.data(),targetByte,kCallee.size())!=0 ||
       std::memcmp(call.originalEntryBytes.data(),originalEntry,16)!=0)
      return 35;
    *dataByte=originalData;
    if(*dataByte!=originalData)return 40;
    // A guest x86 reloc fixture modified original main ELF's staged
    // PT_LOAD RW word; restore this exact source prior to file-backed
    // unchanged/release gates. Never mutate on-disk ELF or user games.
    // Restore the exact source ELF RELR bytes independently of
    // main RELA. Neither original ELF on disk nor user game data
    // are ever modified by this guest relocation test.
    std::memcpy(reinterpret_cast<void*>(
        static_cast<uintptr_t>(sourceRelr.guestTarget)),
        &sourceRelr.sourceInitialAddend,sizeof(sourceRelr.sourceInitialAddend));
    uint64_t sourceRelrRestored=0;
    std::memcpy(&sourceRelrRestored,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(sourceRelr.guestTarget)),8);
    if(sourceRelrRestored!=sourceRelr.sourceInitialAddend)return 100;
    std::fputs("KERNIX_G0_SOURCE_GNU_ELF_DT_RELR_GUEST_RW_QWORD_RESTORED_NOT_FULL_LDSO\n",stderr);
    std::memcpy(reinterpret_cast<void*>(
       static_cast<uintptr_t>(relative.guestTarget)),
       &relative.previousValue,sizeof(relative.previousValue));
    uint64_t restoredRelative=0;
    std::memcpy(&restoredRelative,reinterpret_cast<const void*>(
       static_cast<uintptr_t>(relative.guestTarget)),8);
    if(restoredRelative!=relative.previousValue)return 52;
    std::fputs("KERNIX_G0_GUEST_SOURCE_RELA_RELATIVE_RW_QWORD_RESTORED_NO_LDSO_RELOCATION_CLAIM\n",stderr);
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(rsp-kFrame)),
                originalStack.data(),originalStack.size());
    if(std::memcmp(reinterpret_cast<const void*>(static_cast<uintptr_t>(rsp-kFrame)),
                   originalStack.data(),originalStack.size())!=0)return 41;
    std::fputs("KERNIX_G0_SOURCE_CALLEE_GUEST_RW_STACK_AND_EXECUTABLE_RESTORED_WX_SAFE\n",stderr);
    std::fputs("KERNIX_G0_ORIGINAL_LDSO_DYNAMIC_GLIBC_TLS_FULL_RUNTIME_NOT_EXECUTED\n",stderr);
    uint32_t unchanged=0;
    if(!c8a::FileBackedSegmentsUnchanged(original,owned,unchanged) ||
       unchanged<3)return 16;
    if(!handler.Heap.Reset() ||
       !owned.Release() || owned.WindowsHeld()!=0)return 17;
#if defined(__ANDROID__)
    std::puts("KERNIX_G0_X86_SOURCE_FULL_PTLOAD_FEX_RANGE_ANDROID_CANDIDATE_NOT_FULL_GLIBC");
#else
    std::puts("KERNIX_G0_X86_SOURCE_FULL_PTLOAD_FEX_RANGE_LINUX_PASS_NOT_FULL_GLIBC");
#endif
    return 0;
}
} // namespace

int main(int argc,char** argv) {return Run(argc,argv);}
