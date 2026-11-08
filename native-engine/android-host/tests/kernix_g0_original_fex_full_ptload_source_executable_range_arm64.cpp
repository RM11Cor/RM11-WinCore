// SPDX-License-Identifier: MIT
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_ORIGINAL_LIBC_PRLIMIT64_GETSTACK)
#define KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_LDSO_SELF_RELRO_8K 1
#endif
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_LDSO_SELF_RELRO_8K)
#define KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_MAIN_RELRO_GUEST_MPROTECT10 1
#endif
// The next gate is a SEPARATELY COMPILED Linux ARM64 source-pinned
// FEX experiment. Do not change default KERNIX/Android/game execution.
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_MAIN_RELRO_GUEST_MPROTECT10)
#define KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY 1
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
// Original GNU next guest syscall after libc RELRO stays observation only:
// source main RELRO cannot be sealed without verified full relocations.
#define KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_RSEQ_RELRO_MPROTECT_ONLY 1
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_RSEQ_RELRO_MPROTECT_ONLY)
// The isolated next-step test retains every preceding real FEX source gate.
#define KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY 1
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
// Reuse the exact preceding original GNU loader/syscall source proof,
// adding ONE independently original-ELF-authorized GLOB_DAT diagnostic.
#define KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY 1
#endif
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
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_RSEQ_RELRO_MPROTECT_ONLY)
#include "kernix_g0_original_libc_source_relro_mprotect_gate.h"
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
#include "kernix_g0_original_main_relro_post_libc_source_audit.h"
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_MAIN_RELRO_GUEST_MPROTECT10)
#include "kernix_g0_original_main_relro_real_fex_guest_mprotect_seal.h"
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_LDSO_SELF_RELRO_8K)
#include "kernix_g0_original_ldso_self_relro_real_fex_guest_mprotect_8k.h"
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_ORIGINAL_LIBC_PRLIMIT64_GETSTACK)
#include "kernix_g0_original_source_libc_prlimit64_rlimit_stack_guest_vma.h"
#endif
#endif
#endif
#include "kernix_g0_original_main_relro_source_relocation_target_audit.h"
#include "kernix_g0_original_main_relro_libc_source_export_witness.h"
#include "kernix_g0_original_main_relro_source_version_requirement_witness.h"
#include "kernix_g0_original_main_relro_libc_source_version_definition_witness.h"
#include "kernix_g0_original_main_plt_jump_slot_source_witness.h"
#include "kernix_g0_original_main_plt_versioned_source_witness.h"
#include "kernix_g0_original_ldso_x86_mprotect_syscall_source_witness.h"
#include "kernix_g0_original_main_relro_spoof_negative_controls.h"
#include "kernix_g0_original_triad_source_relocation_inventory.h"
#include "kernix_g0_original_ldso_relr_dual_phase_readonly.h"
#include "kernix_g0_original_ldso_rela_three_phase_readonly.h"
#include "kernix_g0_original_ldso_rela_source_symbols_irelative_resolver.h"
#include "kernix_g0_original_libc_1067_relr_boundary_readonly.h"
#include "kernix_g0_original_libc_147_rela_jmprel_two_boundary_readonly.h"
#include "kernix_g0_original_libc_single_zero_irelative_source_resolver.h"
#include "kernix_g0_original_libc_46_irelative_resolver_source_inventory.h"
#include "kernix_g0_original_libc_45_ifunc_return_rx_source_bytes_readonly.h"
#endif
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
#if defined(KERNIX_G0_PROBE_UPSTREAM_SIGBUS_BACKPATCH_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_OPEN_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_READ_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
#if defined(__ANDROID__)
#include "kernix_g0_original_fex_sigbus_backpatch_android_bionic_diagnostic.h"
#else
#include "kernix_g0_original_fex_sigbus_backpatch_linux_arm64_diagnostic.h"
#endif
#endif
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/fextl/memory.h>
#include <algorithm>
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
#include "kernix_g0_original_source_guest_loader_cache_openat.h"
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
namespace gcache=kernix::g0::cacheopen;
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
                                 const d::Plan& originalDynamicSource,
                                 const kernix::g2e::GuestPreflight& originalVerifiedSource,
                                 const c7g::PermissionPlan& sourceExecPolicy,
                                 const c7g::ApplyWitness& nativeWXApplied,
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
                                 const kernix::g0::mainpltsource::Witness& mainPLTBeforeFex,
                                 const kernix::g0::mainrelrotargets::ThreeRelativeSnapshot& threeRelativeBeforeFex,
                                 uint64_t originalFixtureRelativeTarget,
                                 const kernix::g0::ldsorelr::Witness& ldsoRelrBeforeFex,
                                 const kernix::g0::ldsorela::Witness& ldsoRelaBeforeFex,
#endif
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
        OriginalDynamicSource(originalDynamicSource),
        OriginalVerifiedSource(originalVerifiedSource),
        SourceExecPolicy(sourceExecPolicy),
        NativeWXApplied(nativeWXApplied),
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
        MainPLTBeforeFex(mainPLTBeforeFex),
        ThreeRelativeBeforeFex(threeRelativeBeforeFex),
        OriginalFixtureRelativeTarget(originalFixtureRelativeTarget),
        LdsoRelrBeforeFex(ldsoRelrBeforeFex),
        LdsoRelaBeforeFex(ldsoRelaBeforeFex),
#endif
        GuestProgramBreak(guestProgramBreak){}
    void HandleSyscall(FEXCore::Core::CpuStateFrame* frame) override {
        if(++Calls>15) {
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION)
            // This is not a fixture syscall. The unmodified original
            // GNU ld-linux requested another genuine x86 Linux kernel
            // service. Safely handle source main-ELF-owned brk(12)
            // through native W^X guest pages ONLY when the separate
            // trusted original source/owner and x86 trap gates pass.
// Decode the authentic original x86 syscall trap in EVERY
            // continuation build, independent of optional brk dispatch.
            // Previously, `next` only existed behind the brk feature
            // guard and broke builds which disable brk support.
            c2::ActualFexTrapWitness next{};
            if(!c2::DecodePinnedFexCpuState(frame,Stack,next) ||
               !next.originalFexCpuStateFrameRead){
               std::fputs("KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_X86_CPUSTATE_REJECT\n",stderr);
               _exit(121);
            }
#if defined(KERNIX_G0_ENABLE_GUEST_BRK12)
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
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
            // Original guest close(3) fd=100 after exact BSS. No native
            // file descriptor, path, mapping, source ELF snapshot is
            // forwarded/released by this x86 guest service.
            if(RealOriginalLdsoLibcCloses==1) {
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoPostCloseAnonMaps==0 &&
                 next.decoded.guestNumber==c1::kMmap) {
                const auto answer=
                  SourceFileKernel.DispatchOriginalLdsoPostLibcCloseAnonymous8K(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                const auto at=static_cast<uint64_t>(answer.guestReturn);
                const auto& guestVM=
                  SourceFileKernel.OriginalLdsoPostCloseAnonymousVM();
                if(!answer.guestSyscallAuthenticated ||
                   !answer.guestOriginalLdsoPostCloseAnonymous8KMapped ||
                   answer.hostPathOpened || answer.hostGuestFdForwarded ||
                   answer.hostAnyUntrustedSyscallForwarded ||
                   answer.guestReturn<65536 ||
                   !c1::GuestRange(at,8192) ||
                   guestVM.Count()!=1 ||
                   guestVM.AllocatedRequestedBytes()!=8192 ||
                   RightsAt(at)!="rw-p" ||
                   RightsAt(at+4096)!="rw-p" ||
                   SourceFileKernel.OpenCount()!=0 ||
                   !SourceFileKernel.OriginalLibcClosedAfterBSS()) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_POST_LIBC_CLOSE_ANON8K_GUEST_VMA_REJECT code=%lld request=%llx flags=%llx fd=%llx\n",
                    static_cast<long long>(answer.guestReturn),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(next.decoded.args[3]),
                    static_cast<unsigned long long>(next.decoded.args[4]));
                  _exit(156);
                }
                // Anonymous mappings MUST be zero filled; read live
                // actual x86 guest native owner VMA, not fixture bytes.
                const auto* p=reinterpret_cast<const uint8_t*>(
                  static_cast<uintptr_t>(at));
                for(size_t k=0;k<8192;++k) {
                  if(p[k]!=0) {
                    std::fputs("KERNIX_G0_ORIGINAL_LDSO_POST_LIBC_CLOSE_ANON8K_ZERO_REJECT\n",stderr);
                    _exit(157);
                  }
                }
                const auto oldLibc=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap().Address();
                if(!oldLibc || RightsAt(oldLibc)!="r--p" ||
                   RightsAt(oldLibc+0x28000ULL)!="r-xp" ||
                   RightsAt(oldLibc+0x1b0000ULL)!="r--p" ||
                   RightsAt(oldLibc+0x1ff000ULL)!="rw-p" ||
                   RightsAt(oldLibc+0x205000ULL)!="rw-p" ||
                   !SourceFileKernel.OriginalLibcLargeReadonlyMap().OriginalOwnedBSSZeroed()) {
                  std::fputs("KERNIX_G0_ORIGINAL_LDSO_POST_LIBC_CLOSE_ANON8K_PRIOR_MAPPINGS_REJECT\n",stderr);
                  _exit(158);
                }
                ++RealOriginalLdsoPostCloseAnonMaps;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=
                    static_cast<uint64_t>(answer.guestReturn);
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_POST_LIBC_CLOSE_ANONYMOUS_RW_8K_OWNED_ZERO_SOURCE_VM_PASS base=%llx NO_HOST_GUEST_FD_NO_WX\n",
                  static_cast<unsigned long long>(at));
                std::fflush(stderr);
                return;
              }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoPostCloseAnonMaps==1 &&
                 RealOriginalLdsoPostCloseSetFSCalls==0 &&
                 next.decoded.guestNumber==c1::kArchPrctl) {
                const auto verified=
                  SourceFileKernel.AuthenticateOriginalLdsoPostCloseArchSetFS(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                if(!verified.originalGuestArchPrctlSetFSAuthenticated ||
                   !verified.ownedAnonymousGuestTLSWindowValidated ||
                   !verified.noNativeHostTLSMutation ||
                   !verified.noWExecutableGuestPagesGranted ||
                   verified.guestReturn!=0 ||
                   verified.authenticatedGuestFSBase<65536 ||
                   // The real loader resumes AFTER the initial source-
                   // authenticated handoff arch_prctl. Its previous
                   // guest FS is the existing pinned original source
                   // FS/TLS TCB, not zero. Require precise provenance
                   // and intact original guest FS readbacks before
                   // allowing the genuine loader to rebase FS to the
                   // fresh source-owned 8KiB anonymous thread block.
                   frame->State.fs_cached!=GuestFS.FSBase() ||
                   !GuestFS.GuestReadbacksMatch() ||
                   frame->State.gs_cached!=0 ||
                   !SourceFileKernel.OriginalLdsoPostCloseFSBaseVerified() ||
                   SourceFileKernel.OriginalLdsoPostCloseFSBase()!=
                     verified.authenticatedGuestFSBase ||
                   RightsAt(verified.authenticatedGuestFSBase)!="rw-p" ||
                   SourceFileKernel.OpenCount()!=0 ||
                   !SourceFileKernel.OriginalLibcClosedAfterBSS()) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_POST_CLOSE_ARCH_SET_FS_GUEST_TLS_AUTH_OR_FEX_STATE_REJECT code=%lld requested_base=%llx current_fs=%llx\n",
                    static_cast<long long>(verified.guestReturn),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(frame->State.fs_cached));
                  _exit(159);
                }
                // This is original guest CPU FS base: never call host
                // arch_prctl(), set_tls, or alter Android/Bionic thread
                // TLS. Upstream FEX owns x86 segment translation.
                frame->State.fs_cached=verified.authenticatedGuestFSBase;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
                frame->State.rip=next.decoded.nextGuestRIP;
                ++RealOriginalLdsoPostCloseSetFSCalls;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_POST_CLOSE_ARCH_PRCTL158_ARCH_SET_FS1002_OWNED_8K_TCB_PLUS_0x10c0_FEX_FS_CACHED_GUEST_ONLY_PASS fs=%llx NO_HOST_TLS\n",
                  static_cast<unsigned long long>(frame->State.fs_cached));
                std::fflush(stderr);
                return;
              }
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoPostCloseSetFSCalls==1 &&
                 RealOriginalLdsoPostCloseSetTidAddressCalls==0 &&
                 next.decoded.guestNumber==c1::kSetTidAddress) {
                const uint64_t originalFSBase=
                  SourceFileKernel.OriginalLdsoPostCloseFSBase();
                const uint64_t requested=next.decoded.args[0];
                if(!originalFSBase || !c1::GuestRange(requested,4) ||
                   frame->State.fs_cached!=originalFSBase ||
                   frame->State.gs_cached!=0 ||
                   RightsAt(requested)!="rw-p" ||
                   SourceFileKernel.OpenCount()!=0 ||
                   !SourceFileKernel.OriginalLibcClosedAfterBSS()) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_AFTER_FS_SET_TID_ADDRESS_PRECONDITION_REJECT\n",stderr);
                  _exit(161);
                }
                uint32_t originalTidSlot=0;
                std::memcpy(&originalTidSlot,
                  reinterpret_cast<const void*>(
                    static_cast<uintptr_t>(requested)),sizeof(originalTidSlot));
                const auto tid=
                  SourceFileKernel.RegisterOriginalLdsoGuestClearChildTid(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                uint32_t tidSlotAfter=0;
                std::memcpy(&tidSlotAfter,
                  reinterpret_cast<const void*>(
                    static_cast<uintptr_t>(requested)),sizeof(tidSlotAfter));
                if(!tid.originalGuestSetTidAddressAuthenticated ||
                   !tid.ownedThreadClearChildTidPointerVerified ||
                   !tid.noGuestMemoryWrittenAtRegistration ||
                   !tid.noHostSetTidAddressOrTLSMutation ||
                   !tid.diagnosticMainThreadIdentityOnly ||
                   tid.guestReturn!=1 ||
                   tid.authenticatedGuestClearChildTID!=requested ||
                   !SourceFileKernel.OriginalLdsoClearChildTIDVerified() ||
                   SourceFileKernel.OriginalLdsoClearChildTID()!=requested ||
                   originalTidSlot!=tidSlotAfter ||
                   frame->State.fs_cached!=originalFSBase ||
                   RightsAt(requested)!="rw-p") {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_AFTER_FS_SET_TID_ADDRESS_OWNER_OR_TID_REJECT code=%lld req=%llx tls=%llx old_word=%x new_word=%x\n",
                    static_cast<long long>(tid.guestReturn),
                    static_cast<unsigned long long>(requested),
                    static_cast<unsigned long long>(originalFSBase),
                    static_cast<unsigned>(originalTidSlot),
                    static_cast<unsigned>(tidSlotAfter));
                  _exit(162);
                }
                frame->State.gregs[FEXCore::X86State::REG_RAX]=
                   static_cast<uint64_t>(tid.guestReturn);
                frame->State.rip=next.decoded.nextGuestRIP;
                ++RealOriginalLdsoPostCloseSetTidAddressCalls;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_SET_TID_ADDRESS218_AFTER_ARCH_SET_FS_CLEAR_CHILD_TID_POINTER_IN_OWNED_GUEST_8K_TLS_NO_HOST_TID_SYSCALL_PASS ptr=%llx tid=%lld\n",
                  static_cast<unsigned long long>(requested),
                  static_cast<long long>(tid.guestReturn));
                std::fflush(stderr);
                return;
              }
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoPostCloseSetFSCalls==1 &&
                 RealOriginalLdsoPostCloseSetTidAddressCalls==1 &&
                 RealOriginalLdsoPostCloseRobustListCalls==0 &&
                 next.decoded.guestNumber==c1::kSetRobustList) {
                const uint64_t oldFSBase=
                  SourceFileKernel.OriginalLdsoPostCloseFSBase();
                const uint64_t head=next.decoded.args[0];
                if(frame->State.fs_cached!=oldFSBase ||
                   frame->State.gs_cached!=0 ||
                   !c1::GuestRange(head,24) ||
                   RightsAt(head)!="rw-p" ||
                   SourceFileKernel.OpenCount()!=0 ||
                   !SourceFileKernel.OriginalLibcClosedAfterBSS() ||
                   !SourceFileKernel.OriginalLdsoClearChildTIDVerified()) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_SET_ROBUST_LIST_PRIOR_GUEST_TID_FS_OWNER_REJECT\n",stderr);
                  _exit(164);
                }
                std::array<uint8_t,24> originalHead{};
                std::memcpy(originalHead.data(),
                  reinterpret_cast<const void*>(static_cast<uintptr_t>(head)),
                  originalHead.size());
                const auto robust=
                  SourceFileKernel.RegisterOriginalLdsoGuestRobustList(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                std::array<uint8_t,24> afterHead{};
                std::memcpy(afterHead.data(),
                  reinterpret_cast<const void*>(static_cast<uintptr_t>(head)),
                  afterHead.size());
                if(!robust.originalGuestSetRobustListAuthenticated ||
                   !robust.ownedGuestTLSRobustListHeadVerified ||
                   !robust.noGuestRobustListMemoryWrittenOnRegistration ||
                   !robust.noHostRobustListSyscallOrFutexWake ||
                   !robust.noGuestThreadExitSideEffects ||
                   robust.guestReturn!=0 ||
                   robust.authenticatedGuestRobustListHead!=head ||
                   !SourceFileKernel.OriginalLdsoRobustListVerified() ||
                   SourceFileKernel.OriginalLdsoRobustListHead()!=head ||
                   head!=oldFSBase+0x2e0ULL ||
                   SourceFileKernel.OriginalLdsoClearChildTID()!=oldFSBase+0x2d0ULL ||
                   originalHead!=afterHead ||
                   frame->State.fs_cached!=oldFSBase ||
                   RightsAt(head)!="rw-p") {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_SET_ROBUST_LIST_TLS_OWNER_OR_GUEST_BYTES_REJECT code=%lld requested_head=%llx len=%llx fs=%llx\n",
                    static_cast<long long>(robust.guestReturn),
                    static_cast<unsigned long long>(head),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(frame->State.fs_cached));
                  _exit(165);
                }
                frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
                frame->State.rip=next.decoded.nextGuestRIP;
                ++RealOriginalLdsoPostCloseRobustListCalls;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_SET_ROBUST_LIST273_AFTER_TID218_GUEST_FS_PLUS_0x2e0_LEN24_SOURCE_OWNED_NO_NATIVE_FUTEX_PASS head=%llx\n",
                  static_cast<unsigned long long>(head));
                std::fflush(stderr);
                return;
              }
              if(RealOriginalLdsoPostCloseRobustListCalls==1 &&
                 (!SourceFileKernel.OriginalLdsoRobustListVerified() ||
                  SourceFileKernel.OriginalLdsoRobustListHead()!=
                    SourceFileKernel.OriginalLdsoPostCloseFSBase()+0x2e0ULL ||
                  frame->State.fs_cached!=SourceFileKernel.OriginalLdsoPostCloseFSBase())) {
                std::fputs(
                  "KERNIX_G0_ORIGINAL_LDSO_SET_ROBUST_LIST_NEXT_SYSCALL_THREAD_OWNER_LOST_REJECT\n",stderr);
                _exit(166);
              }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoPostCloseSetFSCalls==1 &&
                 RealOriginalLdsoPostCloseSetTidAddressCalls==1 &&
                 RealOriginalLdsoPostCloseRobustListCalls==1 &&
                 RealOriginalLdsoPostCloseRseqENOSYSCalls==0 &&
                 next.decoded.guestNumber==c1::kRseq) {
                const uint64_t fsBase=
                  SourceFileKernel.OriginalLdsoPostCloseFSBase();
                const uint64_t request=next.decoded.args[0];
                if(!fsBase || !c1::GuestRange(request,32) ||
                   frame->State.fs_cached!=fsBase ||
                   frame->State.gs_cached!=0 ||
                   RightsAt(request)!="rw-p" ||
                   SourceFileKernel.OpenCount()!=0 ||
                   !SourceFileKernel.OriginalLdsoRobustListVerified()) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_RSEQ334_BEFORE_GUEST_FALLBACK_PRECONDITION_REJECT\n",stderr);
                  _exit(167);
                }
                std::array<uint8_t,32> beforeRseq{};
                std::memcpy(beforeRseq.data(),
                  reinterpret_cast<const void*>(static_cast<uintptr_t>(request)),
                  beforeRseq.size());
                const auto rsp=
                  SourceFileKernel.DispatchOriginalLdsoRseqENOSYSFallback(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                std::array<uint8_t,32> afterRseq{};
                std::memcpy(afterRseq.data(),
                  reinterpret_cast<const void*>(static_cast<uintptr_t>(request)),
                  afterRseq.size());
                if(!rsp.exactOriginalGuestRseqRequestAuthenticated ||
                   !rsp.guestRWOwnedTLSRseqAreaVerified ||
                   !rsp.genuineRseqUnsupportedFallbackENOSYS ||
                   !rsp.nativeHostRseqNeverRegistered ||
                   !rsp.noGuestRseqCpuStateFabricated ||
                   !rsp.noGuestTLSBytesWritten ||
                   rsp.guestReturn!=-ENOSYS ||
                   rsp.authenticatedOriginalGuestRseqPointer!=request ||
                   !SourceFileKernel.OriginalLdsoRseqENOSYSVerified() ||
                   SourceFileKernel.OriginalLdsoRseqAddress()!=request ||
                   beforeRseq!=afterRseq ||
                   frame->State.fs_cached!=fsBase ||
                   SourceFileKernel.OpenCount()!=0) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_RSEQ334_GUEST_TLS_ENOSYS_FALLBACK_OR_MEMORY_REJECT code=%lld addr=%llx len=%llx flags=%llx sig=%llx\n",
                    static_cast<long long>(rsp.guestReturn),
                    static_cast<unsigned long long>(request),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(next.decoded.args[2]),
                    static_cast<unsigned long long>(next.decoded.args[3]));
                  _exit(168);
                }
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
                // The first libc instruction after rseq ENOSYS needs
                // libc GOT[0x202eb0] -> original ld-linux
                // _rtld_global_ro@GLIBC_PRIVATE (source symbol 0x37aa0).
                // This is NOT a guessed runtime address and MUST NOT
                // bypass SHA-locked dynsym/R_X86_64_GLOB_DAT source proof.
                const auto* originalLdso=Owner.Module(1);
                const uint64_t originalLibcBase=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap().Address();
                const uint64_t got=originalLibcBase+
                  kernix::g0::originalglobdat::kLibcGOTVaddr;
                const uint64_t sourceLdsoTarget=originalLdso?
                  originalLdso->loadBias+
                    kernix::g0::originalglobdat::kLdsoSymbolVaddr:0;
                if(!originalLdso || !originalLdso->loadBias ||
                   !originalLibcBase ||
                   RightsAt(got)!="rw-p" ||
                   RightsAt(sourceLdsoTarget)!="rw-p" ||
                   !Owner.GuestReadOnlyBytes(1,sourceLdsoTarget,8) ||
                   !c1::GuestRange(got-8,24) ||
                   frame->State.fs_cached!=fsBase ||
                   SourceFileKernel.OpenCount()!=0) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_ONE_GLOB_DAT_GOT_OR_LDSO_OWNER_REJECT got=%llx sym=%llx libcRights=%s ldsoRights=%s\n",
                    static_cast<unsigned long long>(got),
                    static_cast<unsigned long long>(sourceLdsoTarget),
                    RightsAt(got).c_str(),
                    RightsAt(sourceLdsoTarget).c_str());
                  _exit(171);
                }
                std::array<uint8_t,24> beforeGOT{};
                std::memcpy(beforeGOT.data(),
                  reinterpret_cast<const void*>(
                    static_cast<uintptr_t>(got-8)),beforeGOT.size());
                const auto relocated=
                  SourceFileKernel.ApplyOriginalLdsoSourceVerifiedLibcOneGLOB_DAT(
                    Owner,SourceExecPolicy,NativeWXApplied,
                    RightsAt(got)=="rw-p",
                    RightsAt(sourceLdsoTarget)=="rw-p");
                std::array<uint8_t,24> afterGOT{};
                std::memcpy(afterGOT.data(),
                  reinterpret_cast<const void*>(
                    static_cast<uintptr_t>(got-8)),afterGOT.size());
                uint64_t actualGOT=0;
                std::memcpy(&actualGOT,
                  reinterpret_cast<const void*>(static_cast<uintptr_t>(got)),8);
                if(!relocated.exactSourceELF64GLOB_DATEntryVerified ||
                   !relocated.libcUndefinedGLIBC_PRIVATENameVerified ||
                   !relocated.ldsoSourceGlobalRoDefinedInsideRWPTLoad ||
                   !relocated.guestGOTOwnedRWAndInitiallyZero ||
                   !relocated.targetOriginalGuestLdsoOwnerChecked ||
                   !relocated.onlyExactEightGuestWritableBytesChanged ||
                   !relocated.noHostSyscallNorNativeMapFixed ||
                   relocated.completeOriginalDynamicRelocations ||
                   !SourceFileKernel.OriginalPinnedLibcGlobalRoOneRelocationApplied() ||
                   relocated.guestGOT!=got ||
                   relocated.originalGOTValue!=0 ||
                   relocated.updatedGOTValue!=sourceLdsoTarget ||
                   actualGOT!=sourceLdsoTarget ||
                   std::memcmp(beforeGOT.data(),afterGOT.data(),8)!=0 ||
                   std::memcmp(beforeGOT.data()+16,afterGOT.data()+16,8)!=0 ||
                   RightsAt(got)!="rw-p" ||
                   RightsAt(originalLibcBase+0x28000ULL)!="r-xp" ||
                   RightsAt(sourceLdsoTarget)!="rw-p" ||
                   frame->State.fs_cached!=fsBase) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_ONE_SOURCE_GLOB_DAT_GOT_SYMBOL_OR_GUEST_WX_REJECT got=%llx expected=%llx actual=%llx witness=%d%d%d%d%d\n",
                    static_cast<unsigned long long>(got),
                    static_cast<unsigned long long>(sourceLdsoTarget),
                    static_cast<unsigned long long>(actualGOT),
                    int(relocated.exactSourceELF64GLOB_DATEntryVerified),
                    int(relocated.libcUndefinedGLIBC_PRIVATENameVerified),
                    int(relocated.ldsoSourceGlobalRoDefinedInsideRWPTLoad),
                    int(relocated.guestGOTOwnedRWAndInitiallyZero),
                    int(relocated.onlyExactEightGuestWritableBytesChanged));
                  _exit(172);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_LIBC_GLOB_DAT_RTLD_GLOBAL_RO_ONE_AUTHENTIC_SOURCE_ELF_GUEST_RW_GOT8_RELOCATED_TO_SOURCE_LDSO_GLOBAL_RO_PASS got=%llx symbol=%llx NOT_FULL_LDSO_RELOCATIONS\n",
                  static_cast<unsigned long long>(got),
                  static_cast<unsigned long long>(actualGOT));
                std::fflush(stderr);
#endif
                frame->State.gregs[FEXCore::X86State::REG_RAX]=
                   static_cast<uint64_t>(rsp.guestReturn);
                frame->State.rip=next.decoded.nextGuestRIP;
                ++RealOriginalLdsoPostCloseRseqENOSYSCalls;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_RSEQ334_AFTER_ROBUST273_GUEST_FS_PLUS_0x920_LEN32_SIG_53053053_NATIVE_UNSUPPORTED_ENOSYS_NO_FAKE_CPU_TLS_PASS ptr=%llx\n",
                  static_cast<unsigned long long>(request));
                std::fflush(stderr);
                return;
              }
              if(RealOriginalLdsoPostCloseRseqENOSYSCalls==1) {
                const uint64_t fsBase=
                  SourceFileKernel.OriginalLdsoPostCloseFSBase();
                const uint64_t rseqPointer=
                  SourceFileKernel.OriginalLdsoRseqAddress();
                // On original GNU libc's kernel-rseq-unsupported path,
                // glibc sets x86 struct rseq.cpu_id to registration
                // failed (-2), NOT a fabricated host CPU number.
                uint32_t cpuId=0;
                if(rseqPointer!=fsBase+0x920ULL ||
                   frame->State.fs_cached!=fsBase ||
                   RightsAt(rseqPointer)!="rw-p") {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_RSEQ334_NEXT_GUEST_FS_OWNER_LOST_REJECT\n",stderr);
                  _exit(169);
                }
                std::memcpy(&cpuId,
                  reinterpret_cast<const void*>(
                    static_cast<uintptr_t>(rseqPointer+4)),sizeof(cpuId));
                if(cpuId!=UINT32_MAX-1U) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_RSEQ334_GLIBC_FALLBACK_CPU_ID_NOT_FAILED_REJECT observed=%x expected=fffffffe\n",
                    static_cast<unsigned>(cpuId));
                  _exit(170);
                }
                std::fputs(
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_RSEQ334_ENOSYS_GLIBC_TLS_CPU_ID_REGISTRATION_FAILED_NEG2_OBSERVED_PASS\n",
                  stderr);
                std::fflush(stderr);
              }
#endif
              if(RealOriginalLdsoPostCloseSetTidAddressCalls==1 &&
                 (!SourceFileKernel.OriginalLdsoClearChildTIDVerified() ||
                  SourceFileKernel.OriginalLdsoClearChildTID()!=
                    SourceFileKernel.OriginalLdsoPostCloseFSBase()+0x2d0ULL)) {
                std::fputs(
                  "KERNIX_G0_ORIGINAL_LDSO_SET_TID_ADDRESS_NEXT_SYSCALL_OWNER_LOST_REJECT\n",stderr);
                _exit(163);
              }
#endif
              if(RealOriginalLdsoPostCloseSetFSCalls==1 &&
                 (frame->State.fs_cached!=SourceFileKernel.OriginalLdsoPostCloseFSBase() ||
                  RightsAt(frame->State.fs_cached)!="rw-p" ||
                  SourceFileKernel.OpenCount()!=0)) {
                std::fputs(
                  "KERNIX_G0_ORIGINAL_LDSO_POST_CLOSE_FEX_GUEST_FS_STATE_SURVIVAL_REJECT\n",
                  stderr);
                _exit(160);
              }
#endif
  #if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_RSEQ_RELRO_MPROTECT_ONLY)
              // Exact next genuine x86 syscall after the one source GLOB_DAT
              // and glibc's real rseq ENOSYS fallback. Never forward guest
              // mprotect to host for a user-selected address.
              if(next.decoded.guestNumber==c1::kMprotect &&
                 RealOriginalLdsoPostCloseRseqENOSYSCalls==1 &&
                 OriginalLibcRELROMprotectCalls==0) {
                const auto& libc=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap();
                const auto* ldso=Owner.Module(1);
                const uint64_t base=libc.Address();
                const uint64_t sourceSymbol=ldso?ldso->loadBias+
                  kernix::g0::originalglobdat::kLdsoSymbolVaddr:0;
                const uint64_t got=base+
                  kernix::g0::originalglobdat::kLibcGOTVaddr;
                uint64_t before=0;
                if(!base || !sourceSymbol ||
                   !SourceFileKernel.OriginalPinnedLibcGlobalRoOneRelocationApplied() ||
                   !SourceFileKernel.OriginalLibcClosedAfterBSS() ||
                   !SourceFileKernel.OriginalLdsoRseqENOSYSVerified() ||
                   SourceFileKernel.OpenCount()!=0 ||
                   RightsAt(base)!="r--p" ||
                   RightsAt(base+0x28000ULL)!="r-xp" ||
                   RightsAt(base+0x1ff000ULL)!="rw-p" ||
                   RightsAt(base+0x200000ULL)!="rw-p" ||
                   RightsAt(base+0x201000ULL)!="rw-p" ||
                   RightsAt(base+0x202000ULL)!="rw-p" ||
                   RightsAt(base+0x203000ULL)!="rw-p" ||
                   !c1::GuestRange(got,8) ||
                   frame->State.fs_cached!=
                     SourceFileKernel.OriginalLdsoPostCloseFSBase()) {
                   std::fputs("KERNIX_G0_ORIGINAL_LIBC_RELRO10_PRECONDITION_REJECT\n",stderr);
                   _exit(174);
                }
                std::memcpy(&before,
                  reinterpret_cast<const void*>(static_cast<uintptr_t>(got)),8);
                if(before!=sourceSymbol) {
                   std::fputs("KERNIX_G0_ORIGINAL_LIBC_RELRO10_GOT_SOURCE_REJECT\n",stderr);
                   _exit(175);
                }
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
                // Genuine original GNU x86 mprotect(10) for LIBC is the
                // intermediate point: all earlier FEX-translated guest
                // instructions have run, but main RELRO isn't sealed.
                // Compare a single SHA-source-attested main GOT slot.
                if(MainPLTAtLibcRELROCaptured ||
                   !MainPLTBeforeFex.authenticatedSourceJumpSlot ||
                   !MainPLTBeforeFex.targetInMainRELRO ||
                   MainPLTBeforeFex.symbolIndex!=3 ||
                   std::strcmp(MainPLTBeforeFex.symbolName,"puts")!=0 ||
                   RightsAt(SourceMainRelroPage)!="rw-p") {
                  std::fputs(
                    "KERNIX_G0_MAIN_PLT_LIBC_RELRO_BOUNDARY_REJECT\n",stderr);
                  _exit(188);
                }
                const auto& pinnedLdsoSource=
                     OriginalVerifiedSource.snapshots[1];
                if(LibcMprotectOpcodeAuthenticated ||
                   !pinnedLdsoSource.readOnlySnapshot() ||
                   !pinnedLdsoSource.bytes() ||
                   !kernix::g0::ldsosyscallorigin::
                     AuthenticateOriginalLdsoSyscallInstruction(
                       pinnedLdsoSource.bytes(),pinnedLdsoSource.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       Owner,SourceExecPolicy,frame->State.rip,
                       next.decoded.nextGuestRIP,LibcMprotectOpcode) ||
                   !LibcMprotectOpcode.originalGNUInterpreterPinnedSource ||
                   !LibcMprotectOpcode.sourceAndGuestOpcodeIdentical ||
                   !LibcMprotectOpcode.guestPageOwnedOriginalRX ||
                   LibcMprotectOpcode.originalDynamicRelocationClosureProven ||
                   RightsAt(frame->State.rip)!="r-xp") {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_LIBC_MPROTECT_SOURCE_OPCODE_REJECT\n",
                    stderr);
                  _exit(216);
                }
                LibcMprotectOpcodeAuthenticated=true;
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_LIBC_MPROTECT_SYSCALL_OPCODE_READONLY"
                  " guest_rip=%llx source_va=%llx file_offset=%zx"
                  " opcode=0f05 source_equal_live=1 original_ldso_rx=1"
                  " no_dynamic_relocation_closure=1 no_guest_write=1\n",
                  static_cast<unsigned long long>(
                      LibcMprotectOpcode.guestRIP),
                  static_cast<unsigned long long>(
                      LibcMprotectOpcode.sourceVA),
                  LibcMprotectOpcode.sourceFileOffset);
                const auto* originalMainSlotAtLibc=
                   Owner.GuestReadOnlyBytes(
                     0,MainPLTBeforeFex.guestTarget,8);
                if(!originalMainSlotAtLibc) {
                  std::fputs(
                    "KERNIX_G0_MAIN_PLT_LIBC_RELRO_GUEST_OWNER_REJECT\n",stderr);
                  _exit(189);
                }
                std::memcpy(&MainPLTAtLibcRELROValue,
                            originalMainSlotAtLibc,8);
                MainPLTAtLibcRELROCaptured=true;
                // Snapshot the five authenticated original main-ELF
                // .rela.dyn GLOB_DAT slots at the REAL original libc
                // mprotect boundary, before original main's mprotect.
                // Preserve exact guest values and source symbol identity.
                const auto& origMainSnapshot=
                    OriginalVerifiedSource.snapshots[0];
                if(MainSymbolicAtLibcRELROCaptured ||
                   !origMainSnapshot.readOnlySnapshot() ||
                   !origMainSnapshot.bytes() ||
                   !kernix::g0::mainrelrotargets::
                     AuditOriginalMainRELROTargets(
                       origMainSnapshot.bytes(),origMainSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,Owner,
                       SourceExecPolicy,SourceMainRelroPage,
                       RightsAt(SourceMainRelroPage)=="rw-p",
                       MainSymbolicAtLibcRELRO) ||
                   MainSymbolicAtLibcRELRO.verifiedSymbolicNameCount!=5 ||
                   MainSymbolicAtLibcRELRO.symbolicTargetsGlobDat!=5 ||
                   // Source-pinned main dynsym has one GLOBAL and four
                   // WEAK GLOB_DAT imports. __cxa_finalize is WEAK
                   // even though its live GOT value is resolved.
                   MainSymbolicAtLibcRELRO.strongSymbolCount!=1 ||
                   MainSymbolicAtLibcRELRO.weakSymbolCount!=4 ||
                   MainSymbolicAtLibcRELRO.strongSymbolCount+
                     MainSymbolicAtLibcRELRO.weakSymbolCount!=5 ||
                   MainSymbolicAtLibcRELRO.originalGNUDynamicRelocationClosureProven) {
                  std::fputs(
                    "KERNIX_G0_MAIN_GLOB_DAT_AT_LIBC_RELRO_SNAPSHOT_REJECT\n",
                    stderr);
                  _exit(191);
                }
                MainSymbolicAtLibcRELROCaptured=true;
                if(ThreeRelativeAtLibcRELROCaptured ||
                   !kernix::g0::mainrelrotargets::
                     ReadOnlyOriginalMainThreeRelative(
                       origMainSnapshot.bytes(),origMainSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,Owner,
                       SourceExecPolicy,SourceMainRelroPage,
                       ThreeRelativeAtLibcRELRO) ||
                   !ThreeRelativeAtLibcRELRO.sourceAuthenticated ||
                   ThreeRelativeAtLibcRELRO.originalLdsoStoreRIPProven ||
                   RightsAt(SourceMainRelroPage)!="rw-p") {
                  std::fputs(
                    "KERNIX_G0_MAIN_RELATIVE_TRIPLE_AT_LIBC_REJECT\n",stderr);
                  _exit(195);
                }
                ThreeRelativeAtLibcRELROCaptured=true;
                // The only first-interval changed RELATIVE must
                // be precisely the authored fixture target. Both other
                // original source RELATIVE targets must still be source
                // initial bytes. This does not trace the guest write RIP.
                size_t authoredFixtureEarly=0,otherUnchanged=0;
                for(size_t k=0;k<ThreeRelativeAtLibcRELRO.total;++k){
                  const auto& a=ThreeRelativeBeforeFex.slots[k];
                  const auto& b=ThreeRelativeAtLibcRELRO.slots[k];
                  if(a.guestTarget!=b.guestTarget ||
                     a.expectedValue!=b.expectedValue ||
                     a.targetInRELRO!=b.targetInRELRO) {
                    std::fputs(
                      "KERNIX_G0_MAIN_RELATIVE_FIXTURE_LIBC_IDENTITY_REJECT\n",
                      stderr);
                    _exit(200);
                  }
                  if(a.guestTarget==OriginalFixtureRelativeTarget) {
                    if(a.guestValue==a.expectedValue ||
                       b.guestValue!=b.expectedValue ||
                       a.guestValue==b.guestValue){
                      std::fputs(
                        "KERNIX_G0_MAIN_RELATIVE_FIXTURE_LIBC_VALUE_REJECT\n",
                        stderr);
                      _exit(201);
                    }
                    ++authoredFixtureEarly;
                  }else{
                    if(a.guestValue==a.expectedValue ||
                       b.guestValue!=a.guestValue) {
                      std::fputs(
                        "KERNIX_G0_MAIN_RELATIVE_NONFIXTURE_LIBC_VALUE_REJECT\n",
                        stderr);
                      _exit(202);
                    }
                    ++otherUnchanged;
                  }
                }
                if(authoredFixtureEarly!=1 || otherUnchanged!=2 ||
                   ThreeRelativeAtLibcRELRO.exactExpected!=1 ||
                   ThreeRelativeAtLibcRELRO.notExpected!=2){
                  std::fputs(
                    "KERNIX_G0_MAIN_RELATIVE_FIXTURE_LIBC_COUNTS_REJECT\n",
                    stderr);
                  _exit(203);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_RELATIVE_FIXTURE_AT_LIBC_BOUNDARY_READONLY"
                  " fixture_target=%llx fixture_changed=1"
                  " other_source_relatives_unchanged=2"
                  " no_guest_write_instruction_trace=1 no_guest_write=1\n",
                  static_cast<unsigned long long>(
                    OriginalFixtureRelativeTarget));
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_RELATIVE_TRIPLE_AT_LIBC_READONLY"
                  " count=%zu matched=%zu not_matched=%zu"
                  " source_owned=1 no_guest_write=1\n",
                  ThreeRelativeAtLibcRELRO.total,
                  ThreeRelativeAtLibcRELRO.exactExpected,
                  ThreeRelativeAtLibcRELRO.notExpected);
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_GLOB_DAT_AT_LIBC_RELRO_SOURCE_READONLY"
                  " symbolic=%zu strong=%zu weak=%zu"
                  " nonzero=%zu zero=%zu"
                  " main_relro_still_rw=1 original_loader_store_untraced=1"
                  " no_guest_write=1\n",
                  MainSymbolicAtLibcRELRO.verifiedSymbolicNameCount,
                  MainSymbolicAtLibcRELRO.strongSymbolCount,
                  MainSymbolicAtLibcRELRO.weakSymbolCount,
                  MainSymbolicAtLibcRELRO.symbolicTargetsLiveNonzero,
                  MainSymbolicAtLibcRELRO.symbolicTargetsLiveZero);
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_PLT_AT_LIBC_RELRO_BOUNDARY_READONLY"
                  " symbol=%s target=%llx pre_fex=%llx"
                  " at_libc_relro=%llx pre_to_libc_changed=%u"
                  " original_guest_syscall_mprotect10=1"
                  " main_relro_still_rw=1 no_guest_write=1\n",
                  MainPLTBeforeFex.symbolName,
                  static_cast<unsigned long long>(
                    MainPLTBeforeFex.guestTarget),
                  static_cast<unsigned long long>(
                    MainPLTBeforeFex.guestValue),
                  static_cast<unsigned long long>(
                    MainPLTAtLibcRELROValue),
                  unsigned(MainPLTBeforeFex.guestValue!=
                           MainPLTAtLibcRELROValue));
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
                // Read ORIGINAL libc RELR from its exact source snapshot
                // and from guest VMA *before* authentic libc seal.
                // This is a read-only observer, not guest relocation.
                const auto& libcSnapshotAtBoundary=
                     OriginalVerifiedSource.snapshots[2];
                const auto& originalLibcMap=
                     SourceFileKernel.OriginalLibcLargeReadonlyMap();
                const auto libcReadable=[&](uint64_t addr) noexcept{
                  const std::string right=RightsAt(addr);
                  return c1::GuestRange(addr,8) &&
                      (right=="rw-p" || right=="r--p") &&
                      addr>=originalLibcMap.Address() &&
                      addr-originalLibcMap.Address()<=
                        originalLibcMap.BytesHeld()-8;
                };
                if(LibcRELRAtLibcBoundaryCaptured ||
                   !libcSnapshotAtBoundary.readOnlySnapshot() ||
                   !libcSnapshotAtBoundary.bytes() ||
                   !kernix::g0::libcrelr::
                      SampleOriginalLibc1067RELRReadOnly(
                        libcSnapshotAtBoundary.bytes(),
                        libcSnapshotAtBoundary.size(),
                        OriginalVerifiedSource.exactSha256Matched,
                        originalLibcMap,libcReadable,
                        LibcRELRAtLibcBoundary) ||
                   !LibcRELRAtLibcBoundary.originalLibcSHAProven ||
                   LibcRELRAtLibcBoundary.count!=1067 ||
                   LibcRELRAtLibcBoundary.actualGuestStoreRIPsTraced ||
                   LibcRELRAtLibcBoundary.fullOriginalRelocationClosureProven ||
                   RightsAt(SourceMainRelroPage)!="rw-p") {
                  std::fputs(
                    "KERNIX_G0_LIBC_1067_RELR_LIBC_BOUNDARY_REJECT\n",
                    stderr);
                  _exit(229);
                }
                // Original libc DT_RELA=86 and DT_JMPREL=61.
                // Capture all 147 source-backed relocation TARGETS
                // before genuine libc seal, with no symbol lookup
                // or IFUNC result assertion and NO writes to guest.
                if(LibcRelaAtLibcBoundaryCaptured ||
                   !kernix::g0::libcrela::
                      SampleOriginalLibc147RelaJmprelReadonly(
                        libcSnapshotAtBoundary.bytes(),
                        libcSnapshotAtBoundary.size(),
                        OriginalVerifiedSource.exactSha256Matched,
                        originalLibcMap,libcReadable,
                        LibcRelaAtLibcBoundary) ||
                   !LibcRelaAtLibcBoundary.originalSourceShaPinned ||
                   LibcRelaAtLibcBoundary.count!=147 ||
                   LibcRelaAtLibcBoundary.irelative!=46 ||
                   LibcRelaAtLibcBoundary.symbolic!=101 ||
                   LibcRelaAtLibcBoundary.guestStoreInstructionsTraced ||
                   LibcRelaAtLibcBoundary.symbolOrIfuncResolutionsProven ||
                   LibcRelaAtLibcBoundary.wholeLibcRelocationClosureProven ||
                   RightsAt(SourceMainRelroPage)!="rw-p"){
                  std::fprintf(stderr,
                    "KERNIX_G0_LIBC_147_RELA_JMPREL_FAILURE_DETAIL"
                    " reason=%s index=%zu va=%llx"
                    " type=%u symbol=%u counted=%zu rela=%zu jmprel=%zu"
                    " irelative=%zu symbolic=%zu backed=%zu bss=%zu\n",
                    LibcRelaAtLibcBoundary.rejectReason,
                    LibcRelaAtLibcBoundary.rejectIndex,
                    static_cast<unsigned long long>(
                       LibcRelaAtLibcBoundary.rejectVA),
                    LibcRelaAtLibcBoundary.rejectType,
                    LibcRelaAtLibcBoundary.rejectSymbol,
                    LibcRelaAtLibcBoundary.count,
                    LibcRelaAtLibcBoundary.rela,
                    LibcRelaAtLibcBoundary.jmprel,
                    LibcRelaAtLibcBoundary.irelative,
                    LibcRelaAtLibcBoundary.symbolic,
                    LibcRelaAtLibcBoundary.sourceBacked,
                    LibcRelaAtLibcBoundary.sourceBSS);
                  std::fputs(
                    "KERNIX_G0_LIBC_147_RELA_JMPREL_PRE_SEAL_REJECT\n",
                    stderr);
                  _exit(233);
                }
                LibcRelaAtLibcBoundaryCaptured=true;
                // Compare the exact original 1214 libc relocation
                // targets between authentic close(3) and libc
                // mprotect(10). This captures *actual* FEX-run temporal
                // changes, unlike a one-boundary source-only snapshot.
                // It does NOT identify the x86 store RIP or prove the
                // IFUNC/symbol resolver semantics.
                if(!LibcRELRAtSourceCloseCaptured ||
                   !LibcRelaAtSourceCloseCaptured ||
                   LibcRELRAtLibcBoundary.liveEqualExpected!=1067 ||
                   LibcRELRAtLibcBoundary.liveEqualSource!=0 ||
                   LibcRelaAtLibcBoundary.liveMatchesSource!=1 ||
                   LibcRelaAtLibcBoundary.liveNonzero!=146){
                  std::fputs(
                    "KERNIX_G0_LIBC_CLOSE_TO_RELRO_EXPECTED_VALUE_REJECT\n",
                    stderr);
                  _exit(249);
                }
                size_t closeToRelrChanged=0,closeToRelaChanged=0;
                size_t closeToIfuncChanged=0,closeToIfuncUnchanged=0;
                size_t closeToSymbolChanged=0,closeToSymbolUnchanged=0;
                size_t unchangedIfuncIndex=0;
                uint64_t unchangedIfuncTarget=0,unchangedIfuncValue=0;
                for(size_t k=0;k<1067;++k){
                  const auto& a=LibcRELRAtSourceClose.entries[k];
                  const auto& d=LibcRELRAtLibcBoundary.entries[k];
                  if(!a.guest || a.guest!=d.guest ||
                     a.sourceAddend!=d.sourceAddend ||
                     a.expected!=d.expected ||
                     a.fileBacked!=d.fileBacked){
                    std::fputs(
                      "KERNIX_G0_LIBC_CLOSE_TO_RELRO_RELR_IDENTITY_REJECT\n",
                      stderr);
                    _exit(250);
                  }
                  closeToRelrChanged+=size_t(a.live!=d.live);
                }
                for(size_t k=0;k<147;++k){
                  const auto& a=LibcRelaAtSourceClose.slots[k];
                  const auto& d=LibcRelaAtLibcBoundary.slots[k];
                  if(!a.target || a.target!=d.target ||
                     a.source!=d.source || a.addend!=d.addend ||
                     a.type!=d.type || a.symbol!=d.symbol ||
                     a.sourceBacked!=d.sourceBacked || a.plt!=d.plt){
                    std::fputs(
                      "KERNIX_G0_LIBC_CLOSE_TO_RELRO_RELA_IDENTITY_REJECT\n",
                      stderr);
                    _exit(251);
                  }
                  const bool changed=a.live!=d.live;
                  closeToRelaChanged+=size_t(changed);
                  if(d.type==R_X86_64_IRELATIVE){
                    closeToIfuncChanged+=size_t(changed);
                    closeToIfuncUnchanged+=size_t(!changed);
                    if(!changed){
                      unchangedIfuncIndex=k;
                      unchangedIfuncTarget=d.target;
                      unchangedIfuncValue=d.live;
                    }
                  }else{
                    closeToSymbolChanged+=size_t(changed);
                    closeToSymbolUnchanged+=size_t(!changed);
                  }
                }
                if(closeToRelrChanged!=1067 || closeToRelaChanged!=146 ||
                   closeToIfuncChanged!=45 || closeToIfuncUnchanged!=1 ||
                   closeToSymbolChanged!=101 || closeToSymbolUnchanged!=0 ||
                   unchangedIfuncIndex!=85 ||
                   unchangedIfuncValue!=0 || unchangedIfuncTarget==0 ||
                   LibcRelaAtSourceClose.slots[unchangedIfuncIndex].source!=0 ||
                   LibcRelaAtSourceClose.slots[unchangedIfuncIndex].live!=0 ||
                   RightsAt(SourceMainRelroPage)!="rw-p"){
                  std::fprintf(stderr,
                    "KERNIX_G0_LIBC_CLOSE_TO_RELRO_CHANGED_COUNT_REJECT"
                    " relr=%zu rela_jmprel=%zu\n",
                    closeToRelrChanged,closeToRelaChanged);
                  _exit(252);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_1214_RELOCATION_TARGETS_REAL_FEX_CLOSE3_TO_MPROTECT10"
                  " relr_changed=%zu rela_jmprel_changed=%zu"
                  " rela_jmprel_still_source=%zu"
                  " original_sha_locked=1 source_targets_unchanged_identity=1"
                  " guest_store_rips_not_traced=1"
                  " symbol_lookup_ifunc_not_proven=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  closeToRelrChanged,closeToRelaChanged,
                  LibcRelaAtLibcBoundary.liveMatchesSource);
                std::fflush(stderr);
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_RELOCATION_CLASSIFIED_CLOSE3_TO_LIBC_MPROTECT10"
                  " original_libc_rela_jmprel=147"
                  " irelative_changed=%zu irelative_unchanged=%zu"
                  " symbolic_changed=%zu symbolic_unchanged=%zu"
                  " one_unchanged_irelative_index=%zu"
                  " one_unchanged_irelative_target=%llx"
                  " one_unchanged_irelative_value=%llx"
                  " unchanged_irelative_result_unproven=1"
                  " original_guest_store_rips_untraced=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  closeToIfuncChanged,closeToIfuncUnchanged,
                  closeToSymbolChanged,closeToSymbolUnchanged,
                  unchangedIfuncIndex,
                  static_cast<unsigned long long>(unchangedIfuncTarget),
                  static_cast<unsigned long long>(unchangedIfuncValue));
                std::fflush(stderr);
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_147_RELA_JMPREL_PRE_SEAL_READONLY"
                  " total=147 rela=%zu jmprel=%zu"
                  " irelative=%zu symbolic=%zu"
                  " backed=%zu bss=%zu"
                  " source_equal=%zu live_nonzero=%zu"
                  " ifunc_nonzero=%zu symbolic_nonzero=%zu"
                  " original_libc_sha=1 libc_relro_unsealed=1"
                  " source_guest_observation_only=1"
                  " ifunc_and_symbol_resolution_unproven=1"
                  " no_guest_write=1\n",
                  LibcRelaAtLibcBoundary.rela,
                  LibcRelaAtLibcBoundary.jmprel,
                  LibcRelaAtLibcBoundary.irelative,
                  LibcRelaAtLibcBoundary.symbolic,
                  LibcRelaAtLibcBoundary.sourceBacked,
                  LibcRelaAtLibcBoundary.sourceBSS,
                  LibcRelaAtLibcBoundary.liveMatchesSource,
                  LibcRelaAtLibcBoundary.liveNonzero,
                  LibcRelaAtLibcBoundary.ifuncNonzero,
                  LibcRelaAtLibcBoundary.symbolicNonzero);
                LibcRELRAtLibcBoundaryCaptured=true;
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_1067_RELR_PRE_SEAL_READONLY"
                  " targets=%zu backed=%zu bss=%zu"
                  " source_equal=%zu relocated_expected=%zu"
                  " original_libc_source_sha=1 before_libc_seal=1"
                  " original_store_rips_not_traced=1"
                  " no_guest_write=1\n",
                  LibcRELRAtLibcBoundary.count,
                  LibcRELRAtLibcBoundary.sourceBacked,
                  LibcRELRAtLibcBoundary.sourceBSS,
                  LibcRELRAtLibcBoundary.liveEqualSource,
                  LibcRELRAtLibcBoundary.liveEqualExpected);
#endif
                const auto sealed=
                  kernix::g0::originalrelro::SealOriginalLibcSourceRELRO(
                    next.decoded,libc,true,true,true,true);
                uint64_t after=0;
                if(sealed.nativeGuestRELROPageRangeChangedToReadOnly)
                  std::memcpy(&after,
                    reinterpret_cast<const void*>(static_cast<uintptr_t>(got)),8);
                if(sealed.guestReturn!=0 ||
                   !sealed.genuineGuestMprotect10Authenticated ||
                   !sealed.originalELF64GNURELROPageSpanMatched ||
                   !sealed.sourceOriginalLibcRWPTLoadMatched ||
                   !sealed.nativeGuestRELROPageRangeChangedToReadOnly ||
                   sealed.completeDynamicRelocations || after!=before ||
                   RightsAt(base+0x1ff000ULL)!="r--p" ||
                   RightsAt(base+0x200000ULL)!="r--p" ||
                   RightsAt(base+0x201000ULL)!="r--p" ||
                   RightsAt(base+0x202000ULL)!="r--p" ||
                   RightsAt(base+0x203000ULL)!="rw-p" ||
                   RightsAt(base+0x28000ULL)!="r-xp") {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_RELRO10_SOURCE_PROOF_REJECT"
                    " code=%lld source_begin=%llx source_end=%llx"
                    " exact_source=%d rw_ptload=%d mapped=%d\n",
                    static_cast<long long>(sealed.guestReturn),
                    static_cast<unsigned long long>(sealed.sourceRelroBegin),
                    static_cast<unsigned long long>(sealed.sourceRelroEnd),
                    int(sealed.originalELF64GNURELROPageSpanMatched),
                    int(sealed.sourceOriginalLibcRWPTLoadMatched),
                    int(sealed.nativeGuestRELROPageRangeChangedToReadOnly));
                  _exit(176);
                }
                ++OriginalLibcRELROMprotectCalls;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_LIBC_SOURCE_GNU_RELRO"
                  "_MPROTECT10_RW_TO_RO_FOUR_4K_PAGES_PASS"
                  " base=%llx len=4000 prot=1 GOT=%llx"
                  " NO_FULL_DYNAMIC_RELOCATION_PROOF\n",
                  static_cast<unsigned long long>(base+0x1ff000ULL),
                  static_cast<unsigned long long>(after));
                std::fflush(stderr);
                return;
              }
  #endif
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_LDSO_SELF_RELRO_8K)
              // This is the SECOND authentic GNU ld-linux source guest
              // mprotect(10) after the already sealed original libc+main
              // pages. Never route a general guest page through this gate.
              // Only the 8KiB original ld-linux PT_GNU_RELRO, source-locked
              // original x86 syscall opcode, and exact owner VMA are legal.
              if(next.decoded.guestNumber==c1::kMprotect &&
                 OriginalLibcRELROMprotectCalls==1 &&
                 OriginalMainGuestRELRORealSealed) {
                const auto& ldsoSnapshot=OriginalVerifiedSource.snapshots[1];
                kernix::g0::ldsosyscallorigin::Witness selfOpcode{};
                const bool authenticOpcode=
                  ldsoSnapshot.readOnlySnapshot() &&
                  ldsoSnapshot.bytes() &&
                  kernix::g0::ldsosyscallorigin::
                    AuthenticateOriginalLdsoSyscallInstruction(
                      ldsoSnapshot.bytes(),ldsoSnapshot.size(),
                      OriginalVerifiedSource.exactSha256Matched,
                      Owner,SourceExecPolicy,frame->State.rip,
                      next.decoded.nextGuestRIP,selfOpcode) &&
                  selfOpcode.originalGNUInterpreterPinnedSource &&
                  selfOpcode.sourceAndGuestOpcodeIdentical &&
                  selfOpcode.guestPageOwnedOriginalRX &&
                  selfOpcode.guestRIP==0x801025db9ULL &&
                  next.decoded.nextGuestRIP==frame->State.rip+2 &&
                  !selfOpcode.originalDynamicRelocationClosureProven &&
                  RightsAt(frame->State.rip)=="r-xp";
                const auto result=
                  kernix::g0::originalldsoself::
                    SealOriginalGNUInterpreterTwo4KPages(
                      next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                      ldsoSnapshot.bytes(),ldsoSnapshot.size(),
                      OriginalVerifiedSource.exactSha256Matched &&
                        OriginalLibcRELROMprotectCalls==1 &&
                        OriginalMainGuestRELRORealSealed &&
                        RightsAt(SourceMainRelroPage)=="r--p",
                      authenticOpcode,
                      OriginalMainGuestRELRORealSealed,
                      true, // source-original writer proven in separate
                            // authentic native FEX hardware run #42519037018;
                            // not a same-process hardware execution claim
                      RightsAt);
                if(result.guestReturn!=0 ||
                   !result.originalLdsoSourceELF64PTGNURELROExactlyTwoPages ||
                   !result.genuineGuestSourceSyscall10StageAuthenticated ||
                   !result.sourceOwnedTwoNativePages ||
                   !result.sameValueZeroSlotBeforeAndAfter ||
                   !result.realNativeMprotectTwoPagesSucceeded ||
                   !result.bothOriginalLdsoPagesReadOnly ||
                   !result.precedingAndFollowingOutsidePagesUnchanged ||
                   !result.twoRealChildWriteDenialsSIGSEGV ||
                   result.originalSourceResolverEntryReturnProven ||
                   result.originalMainAndOtherELFCompleteRelocationClosureProven ||
                   result.androidBionicWineProtonGamesProven ||
                   RightsAt(0x801036000ULL)!="r--p" ||
                   RightsAt(0x801037000ULL)!="r--p") {
                  std::fprintf(stderr,
                    "KERNIX_G0_REAL_FEX_ORIGINAL_GNU_LDSO_SELF_RELRO_8K_KERNEL_DENIED"
                    " result=%lld genuine=%u source_pht=%u owner=%u"
                    " self_slot_zero=%u kernel=%u two_ro=%u outside_safe=%u"
                    " two_sigsegv=%u req=%llx len=%llx prot=%llx rip=%llx"
                    " first_rights=%s second_rights=%s\n",
                    static_cast<long long>(result.guestReturn),
                    unsigned(result.genuineGuestSourceSyscall10StageAuthenticated),
                    unsigned(result.originalLdsoSourceELF64PTGNURELROExactlyTwoPages),
                    unsigned(result.sourceOwnedTwoNativePages),
                    unsigned(result.sameValueZeroSlotBeforeAndAfter),
                    unsigned(result.realNativeMprotectTwoPagesSucceeded),
                    unsigned(result.bothOriginalLdsoPagesReadOnly),
                    unsigned(result.precedingAndFollowingOutsidePagesUnchanged),
                    unsigned(result.twoRealChildWriteDenialsSIGSEGV),
                    static_cast<unsigned long long>(next.decoded.args[0]),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(next.decoded.args[2]),
                    static_cast<unsigned long long>(frame->State.rip),
                    RightsAt(0x801036000ULL).c_str(),
                    RightsAt(0x801037000ULL).c_str());
                  std::fflush(stderr);
                  _exit(247);
                }
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_ORIGINAL_LIBC_PRLIMIT64_GETSTACK)
                OriginalLdsoSelfRELRORealSealed=true;
#endif
                frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fputs(
                  "KERNIX_G0_ORIGINAL_FEX_GNU_LDSO_SELF_PT_GNU_RELRO"
                  "_TWO_4K_NATIVE_KERNEL_RO_CHILD_SIGSEGV_BOTH_GUEST_RAX_SUCCESS"
                  " addr=801036000 len=2000 prot=1"
                  " both_rights=r--p outside_pages_unchanged=1"
                  " original_irelative_slot_zero=1"
                  " two_real_child_sigsegv=1 guest_rax_zero_after_kernel=1"
                  " original_self_resolver_entry_return_not_directly_traced=1"
                  " linux_original_main_exit_zero_not_yet_proven=1"
                  " android_games_not_tested=1\n",stderr);
                std::fflush(stderr);
                return;
              }
#endif
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_ORIGINAL_LIBC_PRLIMIT64_GETSTACK)
              // First NEXT genuine x86 Linux syscall after source GNU
              // libc/main/ldso RELRO pages all actually protected.
              // Limited to the exact original libc source prlimit64(302)
              // *GET* pid=0/RLIMIT_STACK=3/null-new/owned-stack-old only.
              // No generic host forwarding, no foreign guest pointer.
              if(next.decoded.guestNumber==302) {
                const auto& libcSource=OriginalVerifiedSource.snapshots[2];
                const auto base=SourceFileKernel.
                  OriginalLibcLargeReadonlyMap().Address();
                if(!OriginalLdsoSelfRELRORealSealed ||
                   !OriginalMainGuestRELRORealSealed ||
                   OriginalLibcRELROMprotectCalls!=1 ||
                   OriginalLibcPrlimit64Calls!=0 ||
                   !OriginalVerifiedSource.exactSha256Matched ||
                   base!=0x8041ff000ULL ||
                   frame->State.rip!=0x80411d082ULL ||
                   !libcSource.readOnlySnapshot() ||
                   !libcSource.bytes() ||
                   !next.decoded.trapBoundaryAuthenticated ||
                   !next.decoded.sourceRegisterMappingChecked ||
                   next.decoded.nextGuestRIP!=frame->State.rip+2 ||
                   RightsAt(frame->State.rip)!="r-xp") {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LIBC_PRLIMIT64_SOURCE_TRAP_PRECONDITION_REJECT\n",
                    stderr);
                  _exit(252);
                }
                const auto witness=
                  kernix::g0::originalprlimit::
                    HandleOneOriginalLibcPrlimit64GetStack(
                      next.decoded.guestNumber,frame->State.rip,
                      next.decoded.nextGuestRIP,
                      next.decoded.args[0],next.decoded.args[1],
                      next.decoded.args[2],next.decoded.args[3],
                      Owner,libcSource.bytes(),libcSource.size(),
                      OriginalVerifiedSource.exactSha256Matched,
                      OriginalLdsoSelfRELRORealSealed &&
                        OriginalMainGuestRELRORealSealed &&
                        OriginalLibcRELROMprotectCalls==1,
                      RightsAt(frame->State.rip)=="r-xp" &&
                        SourceExecPolicy.sourceShaVerified &&
                        NativeWXApplied.originalPinnedSourceValidated,
                      RightsAt);
                if(witness.guestReturn!=0 ||
                   !witness.exactOriginalLibcSourceRXSyscallByteAndGuestOpcode ||
                   !witness.exactOriginalGuestPID0RLIMIT_STACKGetOnly ||
                   !witness.outputOriginalOwnerStack16BytesWritable ||
                   !witness.realNativeKernelGetrlimitSucceeded ||
                   !witness.nativeLinuxRLIMITStackCopiedIntoOriginalGuestBuffer ||
                   !witness.originalLdsoSelfRelroNative8KAlreadySealed ||
                   witness.androidBionicWineProtonGamesProven ||
                   witness.originalGuestOutput!=next.decoded.args[3]) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_PRLIMIT64_SOURCE_AND_STACK_VMA_REJECT"
                    " return=%lld source=%u args=%u stack_owned=%u"
                    " kernel=%u write=%u guest_old=%llx"
                    " request=%llx soft=%llx hard=%llx\n",
                    static_cast<long long>(witness.guestReturn),
                    unsigned(witness.exactOriginalLibcSourceRXSyscallByteAndGuestOpcode),
                    unsigned(witness.exactOriginalGuestPID0RLIMIT_STACKGetOnly),
                    unsigned(witness.outputOriginalOwnerStack16BytesWritable),
                    unsigned(witness.realNativeKernelGetrlimitSucceeded),
                    unsigned(witness.nativeLinuxRLIMITStackCopiedIntoOriginalGuestBuffer),
                    static_cast<unsigned long long>(witness.originalGuestOutput),
                    static_cast<unsigned long long>(next.decoded.args[3]),
                    static_cast<unsigned long long>(witness.nativeSoftLimit),
                    static_cast<unsigned long long>(witness.nativeHardLimit));
                  std::fflush(stderr);
                  _exit(253);
                }
                ++OriginalLibcPrlimit64Calls;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_LIBC_PRLIMIT64_RLIMIT_STACK_NATIVE_KERNEL_GET"
                  "_SOURCE_GUEST_LIBC_RX_SYSCALL_AND_OWNED_STACK_16BYTE_RESULT_PASS"
                  " rip=%llx pid=0 resource=3 new=0"
                  " old=%llx original_owned_stack=1"
                  " real_kernel_getrlimit=1 guest_rax_zero_after_write=1"
                  " soft=%llx hard=%llx"
                  " libc_main_ldso_relro_kernel_protected=1"
                  " source_original_guest_program_exit_zero_not_proven=1"
                  " android_wine_games_not_tested=1\n",
                  static_cast<unsigned long long>(0x80411d082ULL),
                  static_cast<unsigned long long>(witness.originalGuestOutput),
                  static_cast<unsigned long long>(witness.nativeSoftLimit),
                  static_cast<unsigned long long>(witness.nativeHardLimit));
                std::fflush(stderr);
                return;
              }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
              // The original GNU loader has just sealed source libc RELRO;
              // its next x86 syscall targets the ORIGINAL MAIN module's
              // exact PT_GNU_RELRO page. Observe source and real guest
              // args WITHOUT claiming relocations completed or sealing.
              if(next.decoded.guestNumber==c1::kMprotect &&
                 OriginalLibcRELROMprotectCalls==1 &&
                 RealOriginalLdsoPostCloseRseqENOSYSCalls==1) {
                const auto beforeRights=RightsAt(SourceMainRelroPage);
                const auto attested=
                  kernix::g0::mainrelroaudit::ObserveNextOriginalMainRELRO(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                    SourceMainRelroPage,beforeRights=="rw-p");
                if(!attested.authenticatedGuestMprotect10 ||
                   !attested.sourceOwnedOriginalMainRWPage ||
                   !attested.originalSourceELF64PTGNURelroFullPage ||
                   attested.realDynamicRelocationClosureAttested ||
                   !attested.noGuestVMRightsModified ||
                   attested.start!=SourceMainRelroPage ||
                   attested.end!=SourceMainRelroPage+4096 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights ||
                   SourceFileKernel.OpenCount()!=0 ||
                   !SourceFileKernel.OriginalLibcClosedAfterBSS() ||
                   !SourceFileKernel.OriginalLdsoRseqENOSYSVerified() ||
                   !SourceFileKernel.OriginalPinnedLibcGlobalRoOneRelocationApplied()) {
                  std::fprintf(stderr,
                    "KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT"
                    " request=%llx expected=%llx relro_first=%llx"
                    " relro_end=%llx source=%d owner=%d live=%s\n",
                    static_cast<unsigned long long>(next.decoded.args[0]),
                    static_cast<unsigned long long>(SourceMainRelroPage),
                    static_cast<unsigned long long>(attested.start),
                    static_cast<unsigned long long>(attested.end),
                    int(attested.originalSourceELF64PTGNURelroFullPage),
                    int(attested.sourceOwnedOriginalMainRWPage),
                    RightsAt(SourceMainRelroPage).c_str());
                  _exit(177);
                }
                kernix::g0::ldsosyscallorigin::Witness
                  mainMprotectOpcode{};
                const auto& interpreterSnapshot=
                  OriginalVerifiedSource.snapshots[1];
                if(!LibcMprotectOpcodeAuthenticated ||
                   !interpreterSnapshot.readOnlySnapshot() ||
                   !interpreterSnapshot.bytes() ||
                   !kernix::g0::ldsosyscallorigin::
                     AuthenticateOriginalLdsoSyscallInstruction(
                       interpreterSnapshot.bytes(),
                       interpreterSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       Owner,SourceExecPolicy,frame->State.rip,
                       next.decoded.nextGuestRIP,mainMprotectOpcode) ||
                   !mainMprotectOpcode.originalGNUInterpreterPinnedSource ||
                   !mainMprotectOpcode.sourceAndGuestOpcodeIdentical ||
                   !mainMprotectOpcode.guestPageOwnedOriginalRX ||
                   mainMprotectOpcode.originalDynamicRelocationClosureProven ||
                   mainMprotectOpcode.guestRIP!=LibcMprotectOpcode.guestRIP ||
                   mainMprotectOpcode.sourceVA!=LibcMprotectOpcode.sourceVA ||
                   mainMprotectOpcode.sourceFileOffset!=
                     LibcMprotectOpcode.sourceFileOffset ||
                   RightsAt(frame->State.rip)!="r-xp" ||
                   RightsAt(SourceMainRelroPage)!="rw-p") {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_MAIN_MPROTECT_SOURCE_OPCODE_REJECT\n",
                    stderr);
                  _exit(217);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_MAIN_MPROTECT_SYSCALL_OPCODE_READONLY"
                  " guest_rip=%llx source_va=%llx file_offset=%zx"
                  " opcode=0f05 source_equal_live=1 original_ldso_rx=1"
                  " same_original_ldso_syscall_site_as_libc=1"
                  " original_ldso_symbol_store_rips_not_traced=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  static_cast<unsigned long long>(
                      mainMprotectOpcode.guestRIP),
                  static_cast<unsigned long long>(
                      mainMprotectOpcode.sourceVA),
                  mainMprotectOpcode.sourceFileOffset);
                // Authored x86 RELATIVE-RELA and one source DT_RELR
                // guest fixture store ran BEFORE original GNU ld-linux.
                // Source relocation totals are only preflight metadata;
                // no source main dynamic relocation closure is proven.
                const auto& mainDyn=OriginalDynamicSource.modules[0];
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_SOURCE_RELOCATION_COVERAGE_READONLY"
                  " main_rela=%zu main_relative_rela=%zu"
                  " main_irelative_rela=%zu main_symbolic_rela=%zu"
                  " main_plt_rela=%zu main_relr_words=%zu"
                  " main_relr_targets=%zu authored_fixture_relative_rela=1"
                  " authored_fixture_relr=1 original_ldso_relocation_closure=0"
                  " source_relr_module_is_not_necessarily_main=1"
                  " NOT_FULL_DYNAMIC_LINKING\n",
                  mainDyn.relaEntries,mainDyn.relativeRelaEntries,
                  mainDyn.irelativeRelaEntries,mainDyn.symbolicRelaEntries,
                  mainDyn.pltRelaEntries,mainDyn.relrWords,
                  mainDyn.relrTargets);
                const auto& mainSnapshot=OriginalVerifiedSource.snapshots[0];
                kernix::g0::mainrelrotargets::Witness targets{};
                if(!mainSnapshot.readOnlySnapshot() || !mainSnapshot.bytes() ||
                   !kernix::g0::mainrelrotargets::AuditOriginalMainRELROTargets(
                     mainSnapshot.bytes(),mainSnapshot.size(),
                     OriginalVerifiedSource.exactSha256Matched,Owner,
                     SourceExecPolicy,SourceMainRelroPage,
                     RightsAt(SourceMainRelroPage)=="rw-p",targets) ||
                   !targets.sourceMainELF64DynamicVerified ||
                   !targets.originalMainOwnedGuestRWPageVerified ||
                   !targets.readOnlyTargetInspection ||
                   targets.originalGNUDynamicRelocationClosureProven ||
                   targets.sourceMainRelaEntries!=mainDyn.relaEntries ||
                   targets.sourceMainPLTRelaEntries!=mainDyn.pltRelaEntries ||
                   targets.sourceRelaTargetsInThisRELROPage>
                     targets.sourceMainRelaEntries ||
                   targets.relativeTargetsInRELRO+
                     targets.irelativeTargetsInRELRO+
                     targets.symbolicTargetsInRELRO!=
                     targets.sourceRelaTargetsInThisRELROPage ||
                   targets.relativeTargetsMatchingLoadBiasAddend+
                     targets.relativeTargetsNotMatchingExpected!=
                     targets.relativeTargetsInRELRO ||
                   targets.symbolicTargetsGlobDat+
                     targets.symbolicTargetsOther!=
                     targets.symbolicTargetsInRELRO ||
                   targets.symbolicTargetsLiveZero+
                     targets.symbolicTargetsLiveNonzero!=
                     targets.symbolicTargetsInRELRO ||
                   targets.symbolicTargetsSourceFileBacked+
                     targets.symbolicTargetsSourceNotFileBacked!=
                     targets.symbolicTargetsInRELRO ||
                   targets.symbolicTargetsUnchangedFromOriginalFile+
                     targets.symbolicTargetsDifferentFromOriginalFile!=
                     targets.symbolicTargetsSourceFileBacked ||
                   targets.symbolicTargetsLiveOwnedOriginalELF+
                     targets.symbolicTargetsLiveNotInOriginalOwnedELF!=
                     targets.symbolicTargetsLiveNonzero ||
                   targets.verifiedSymbolicNameCount!=
                     targets.symbolicTargetsInRELRO ||
                   targets.weakSymbolCount+targets.strongSymbolCount!=
                     targets.verifiedSymbolicNameCount ||
                   targets.weakSymbolLiveZeroCount+
                     targets.strongSymbolLiveZeroCount!=
                     targets.symbolicTargetsLiveZero ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_REAL_ORIGINAL_MAIN_RELRO_DYNAMIC_TARGETS_READONLY_REJECT\n",
                    stderr);
                  _exit(178);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_RELRO_DYNAMIC_TARGETS_READONLY_AUDIT"
                  " source_main_rela=%zu source_main_plt_rela=%zu"
                  " rela_targets_in_main_relro=%zu"
                  " relative_targets=%zu relative_expected_matches=%zu"
                  " relative_expected_mismatches=%zu"
                  " symbolic_targets=%zu irelative_targets=%zu"
                  " only_source_or_live_values_no_original_ldso_completion=1"
                  " relro_page_still_rw=1 NOT_GLIBC_RELOCATIONS_PASS\n",
                  targets.sourceMainRelaEntries,
                  targets.sourceMainPLTRelaEntries,
                  targets.sourceRelaTargetsInThisRELROPage,
                  targets.relativeTargetsInRELRO,
                  targets.relativeTargetsMatchingLoadBiasAddend,
                  targets.relativeTargetsNotMatchingExpected,
                  targets.symbolicTargetsInRELRO,
                  targets.irelativeTargetsInRELRO);
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_RELRO_SYMBOLIC_SOURCE_AND_LIVE_READONLY"
                  " symbolic=%zu glob_dat=%zu other=%zu"
                  " live_zero=%zu live_nonzero=%zu"
                  " file_backed=%zu non_file_backed=%zu"
                  " source_equal=%zu source_different=%zu"
                  " live_original_owned=%zu live_other_or_unknown=%zu"
                  " no_symbol_resolution_completion_proof=1"
                  " no_native_guest_memory_write_or_relro_seal=1\n",
                  targets.symbolicTargetsInRELRO,
                  targets.symbolicTargetsGlobDat,
                  targets.symbolicTargetsOther,
                  targets.symbolicTargetsLiveZero,
                  targets.symbolicTargetsLiveNonzero,
                  targets.symbolicTargetsSourceFileBacked,
                  targets.symbolicTargetsSourceNotFileBacked,
                  targets.symbolicTargetsUnchangedFromOriginalFile,
                  targets.symbolicTargetsDifferentFromOriginalFile,
                  targets.symbolicTargetsLiveOwnedOriginalELF,
                  targets.symbolicTargetsLiveNotInOriginalOwnedELF);
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_RELRO_SOURCE_DYNSYM_NAME_SUMMARY"
                  " symbols=%zu weak=%zu weak_zero=%zu"
                  " strong_or_other=%zu strong_or_other_zero=%zu"
                  " symbol_names_immutable_elf_only=1"
                  " resolved_symbol_versions_not_proven=1\n",
                  targets.verifiedSymbolicNameCount,
                  targets.weakSymbolCount,
                  targets.weakSymbolLiveZeroCount,
                  targets.strongSymbolCount,
                  targets.strongSymbolLiveZeroCount);
                for(size_t n=0;n<targets.verifiedSymbolicNameCount;++n) {
                  const auto& symbol=targets.symbolicSourceNames[n];
                  std::fprintf(stderr,
                    "KERNIX_G0_MAIN_RELRO_SOURCE_DYNSYM_SYMBOL"
                    " index=%zu elf_sym=%u binding=%u type=%u"
                    " defined=%u target=%llx live=%llx name=%s"
                    " not_original_gnu_symbol_resolution_proof=1\n",
                    n,static_cast<unsigned>(symbol.symbolIndex),
                    static_cast<unsigned>(symbol.binding),
                    static_cast<unsigned>(symbol.type),
                    static_cast<unsigned>(symbol.sourceDefinition),
                    static_cast<unsigned long long>(symbol.guestTarget),
                    static_cast<unsigned long long>(symbol.guestValue),
                    symbol.name);
                }
                // Read only the SHA-pinned ORIGINAL libc ELF file. The
                // libc base comes from the native guest VMA authenticated
                // by the preceding genuine GNU loader mmap tests.
                const auto& libcSnapshot=OriginalVerifiedSource.snapshots[2];
                const uint64_t libcBase=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap().Address();
                kernix::g0::libcsourceexports::Witness libcExports{};
                if(!libcSnapshot.readOnlySnapshot() ||
                   !libcSnapshot.bytes() || !libcBase ||
                   !kernix::g0::libcsourceexports::AuditOriginalLibcExports(
                     libcSnapshot.bytes(),libcSnapshot.size(),
                     OriginalVerifiedSource.exactSha256Matched,
                     libcBase,targets,libcExports) ||
                   !libcExports.sourceLibcElf64DynsymVerified ||
                   !libcExports.comparedOnlyOriginalOwnedLibcMap ||
                   libcExports.originalLdsoSymbolVersioningVerified ||
                   libcExports.originalLdsoAllRelocationsFinished ||
                   libcExports.mainNonzeroSymbolTargets!=2 ||
                   libcExports.weakUndefinedMainZeroSlots!=3 ||
                   RightsAt(libcBase)!="r--p" ||
                   RightsAt(libcBase+0x28000ULL)!="r-xp" ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_SOURCE_LIBC_EXPORTED_MAIN_GLOB_DAT_READONLY_REJECT\n",
                    stderr);
                  _exit(179);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_TWO_GLOB_DAT_LIBC_SOURCE_DYNSYM_READONLY"
                  " nonzero_main=%zu weak_zero=%zu"
                  " source_libc_names=%zu source_libc_exact_addresses=%zu"
                  " original_libc_base=%llx"
                  " symbol_versions_not_proven=1"
                  " not_all_dynamic_relocations=1"
                  " no_native_or_guest_write_or_relro_seal=1\n",
                  libcExports.mainNonzeroSymbolTargets,
                  libcExports.weakUndefinedMainZeroSlots,
                  libcExports.sourceLibcDefinedSymbolNamesFound,
                  libcExports.sourceLibcExactGuestAddressMatches,
                  static_cast<unsigned long long>(libcBase));
                kernix::g0::mainversions::Witness verneed{};
                if(!kernix::g0::mainversions::
                     CheckSourceMainGNUVersionRequirements(
                       mainSnapshot.bytes(),mainSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       targets,verneed) ||
                   !verneed.originalImmutableSourceGnuVersymVerneedVerified ||
                   verneed.originalLibcVersionDefinitionMatched ||
                   verneed.originalGNUVersionedRelocationCompletion ||
                   verneed.mainNonzeroGLOB_DAT!=2 ||
                   verneed.mainVersionRequirementsFound!=2 ||
                   verneed.absentWeakZeroSlots!=3 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_MAIN_SOURCE_GNU_VERNEED_READONLY_REJECT\n",
                    stderr);
                  _exit(180);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_MAIN_SOURCE_GNU_VERNEED_READONLY"
                  " nonzero=2 required_versions=%zu weak_zero=%zu"
                  " source_versym_verneed_only=1"
                  " libc_version_definition_match_not_proven=1"
                  " original_linker_versioned_relocations_not_proven=1"
                  " no_guest_write_or_mprotect=1\n",
                  verneed.mainVersionRequirementsFound,
                  verneed.absentWeakZeroSlots);
                for(size_t n=0;n<verneed.mainVersionRequirementsFound;++n) {
                  const auto& version=verneed.sourceRequired[n];
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_MAIN_SOURCE_VERNEED_ENTRY"
                    " index=%zu symbol_index=%u version_index=%u"
                    " symbol=%s provider=%s required=%s"
                    " source_requirements_only=1\n",
                    n,version.originalSymbolIndex,
                    unsigned(version.originalVersymIndex),
                    version.symbolName,version.providerName,
                    version.requiredVersionName);
                }
                kernix::g0::libcversions::Witness verifiedVersions{};
                if(!kernix::g0::libcversions::
                     AuditDefinedLibcSymbolVersions(
                       libcSnapshot.bytes(),libcSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       libcBase,verneed,targets,libcExports,
                       verifiedVersions) ||
                   !verifiedVersions.originalSourceLibcVersymAndVerdefVerified ||
                   verifiedVersions.originalGNUVersionedLookupExecuted ||
                   verifiedVersions.allOriginalLoaderRelocationsVerified ||
                   verifiedVersions.libcSymbolVersionExactMatches!=2 ||
                   verifiedVersions.originalMainWeakZeroSlots!=3 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LIBC_GNU_VERDEF_EXACT_MATCH_REJECT\n",
                    stderr);
                  _exit(181);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_SOURCE_LIBC_GNU_VERDEF_EXACT_MATCH_READONLY"
                  " symbol_name_address_and_version=2"
                  " source_weak_zero=3"
                  " libc_export_verdef_readonly=1"
                  " original_ldso_symbol_resolution_not_proven=1"
                  " not_full_dynamic_relocations=1"
                  " main_relro_still_rw=1\n");
                for(size_t n=0;n<verifiedVersions.libcSymbolVersionExactMatches;++n) {
                  const auto& matched=verifiedVersions.checked[n];
                  std::fprintf(stderr,
                    "KERNIX_G0_SOURCE_LIBC_GNU_VERDEF_SYMBOL"
                    " index=%zu original_main_sym=%u"
                    " source_libc_ver_index=%u"
                    " source_libc_sym_va=%llx"
                    " symbol=%s version=%s"
                    " source_definition_only=1\n",
                    n,matched.mainSymbolIndex,
                    unsigned(matched.sourceLibcVersionIndex),
                    static_cast<unsigned long long>(
                      matched.sourceLibcSymbolVA),
                    matched.symbol,matched.version);
                }
                kernix::g0::mainpltsource::Witness mainPLT{};
                if(mainDyn.pltRelaEntries!=1 ||
                   !kernix::g0::mainpltsource::ReadOnlyOriginalMainJumpSlot(
                     mainSnapshot.bytes(),mainSnapshot.size(),
                     OriginalVerifiedSource.exactSha256Matched,Owner,
                     SourceExecPolicy,SourceMainRelroPage,mainPLT) ||
                   !mainPLT.authenticatedSourceJumpSlot ||
                   !mainPLT.originalWritablePageVerified ||
                   mainPLT.originalGNUJmpSlotResolutionProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_PLT_JUMP_SLOT_READONLY_REJECT\n",stderr);
                  _exit(182);
                }
                // Distinguish pre-existing source/fixture slot content
                // from a live guest slot change during actual FEX
                // translated execution of the original GNU ld-linux.
                // No write tracing yet, so do not attribute a particular
                // store instruction or claim full relocation closure.
                if(!MainPLTBeforeFex.authenticatedSourceJumpSlot ||
                   MainPLTBeforeFex.guestTarget!=mainPLT.guestTarget ||
                   MainPLTBeforeFex.symbolIndex!=mainPLT.symbolIndex ||
                   std::strcmp(MainPLTBeforeFex.symbolName,
                               mainPLT.symbolName)!=0 ||
                   MainPLTBeforeFex.originalGNUJmpSlotResolutionProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_PLT_PRE_POST_GUEST_EXEC_COMPARE_REJECT\n",
                    stderr);
                  _exit(187);
                }
                if(!MainPLTAtLibcRELROCaptured ||
                   !MainPLTBeforeFex.authenticatedSourceJumpSlot ||
                   MainPLTBeforeFex.guestTarget!=mainPLT.guestTarget ||
                   MainPLTBeforeFex.symbolIndex!=mainPLT.symbolIndex ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_PLT_THREE_PHASE_GUEST_COMPARE_REJECT\n",
                    stderr);
                  _exit(190);
                }
                // Same source-authenticated original five GLOB_DAT
                // slots at the next authentic MAIN PT_GNU_RELRO request.
                // Separate values changed between the two real x86
                // syscall boundaries; do not infer a specific guest RIP.
                if(!MainSymbolicAtLibcRELROCaptured ||
                   !MainSymbolicAtLibcRELRO.sourceMainELF64DynamicVerified ||
                   MainSymbolicAtLibcRELRO.verifiedSymbolicNameCount!=5 ||
                   targets.verifiedSymbolicNameCount!=5 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_GLOB_DAT_PHASE_COMPARISON_REJECT\n",
                    stderr);
                  _exit(192);
                }
                size_t symbolicChanged=0,strongChanged=0,weakChanged=0;
                for(size_t k=0;k<targets.verifiedSymbolicNameCount;++k){
                  const auto& early=
                      MainSymbolicAtLibcRELRO.symbolicSourceNames[k];
                  const auto& late=targets.symbolicSourceNames[k];
                  if(early.symbolIndex!=late.symbolIndex ||
                     early.guestTarget!=late.guestTarget ||
                     early.binding!=late.binding ||
                     early.type!=late.type ||
                     early.sourceDefinition!=late.sourceDefinition ||
                     late.type!=R_X86_64_GLOB_DAT ||
                     std::strcmp(early.name,late.name)!=0) {
                    std::fputs(
                      "KERNIX_G0_MAIN_GLOB_DAT_SYMBOL_IDENTITY_REJECT\n",
                      stderr);
                    _exit(193);
                  }
                  const bool changed=early.guestValue!=late.guestValue;
                  symbolicChanged+=size_t(changed);
                  if(changed){
                    if(late.binding==STB_WEAK)++weakChanged;
                    else ++strongChanged;
                  }
                  std::fprintf(stderr,
                    "KERNIX_G0_MAIN_GLOB_DAT_TWO_BOUNDARY_ENTRY"
                    " index=%zu symbol=%s target=%llx"
                    " at_libc_relro=%llx at_main_relro=%llx"
                    " changed=%u weak=%u guest_write_untraced=1\n",
                    k,late.name,
                    static_cast<unsigned long long>(late.guestTarget),
                    static_cast<unsigned long long>(early.guestValue),
                    static_cast<unsigned long long>(late.guestValue),
                    unsigned(changed),unsigned(late.binding==STB_WEAK));
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_GLOB_DAT_TWO_BOUNDARY_SUMMARY_READONLY"
                  " symbolic=5 strong=1 weak=4"
                  " changed=%zu strong_changed=%zu weak_changed=%zu"
                  " original_ldso_specific_store_untraced=1"
                  " full_relocation_closure_unproven=1"
                  " no_guest_write=1\n",
                  symbolicChanged,strongChanged,weakChanged);
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_PLT_THREE_PHASE_GUEST_EXEC_READONLY"
                  " symbol=%s target=%llx"
                  " before_fex=%llx at_libc_relro=%llx at_main_relro=%llx"
                  " pre_to_libc_changed=%u libc_to_main_changed=%u"
                  " source_guest_owned=1 main_relro_still_rw=1"
                  " original_ldso_write_rip_not_traced=1"
                  " original_relocation_closure_unproven=1"
                  " no_guest_write=1\n",
                  mainPLT.symbolName,
                  static_cast<unsigned long long>(mainPLT.guestTarget),
                  static_cast<unsigned long long>(
                    MainPLTBeforeFex.guestValue),
                  static_cast<unsigned long long>(
                    MainPLTAtLibcRELROValue),
                  static_cast<unsigned long long>(
                    mainPLT.guestValue),
                  unsigned(MainPLTBeforeFex.guestValue!=
                           MainPLTAtLibcRELROValue),
                  unsigned(MainPLTAtLibcRELROValue!=mainPLT.guestValue));
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_PLT_PRE_POST_GUEST_EXEC_READONLY"
                  " symbol=%s target=%llx"
                  " before=%llx after=%llx changed=%u"
                  " fixture_targets_excluded=1"
                  " ldso_specific_write_not_traced=1"
                  " full_linker_closure_unproven=1 no_guest_write=1\n",
                  mainPLT.symbolName,
                  static_cast<unsigned long long>(mainPLT.guestTarget),
                  static_cast<unsigned long long>(
                     MainPLTBeforeFex.guestValue),
                  static_cast<unsigned long long>(mainPLT.guestValue),
                  unsigned(MainPLTBeforeFex.guestValue!=mainPLT.guestValue));
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_PLT_JUMP_SLOT_SOURCE_LIVE_READONLY"
                  " source_entries=1 owned_rw=1"
                  " target=%llx live=%llx elf_sym=%u"
                  " symbol=%s binding=%u in_relro=%u"
                  " file_backed=%u source_equal=%u"
                  " source_only=1 no_guest_write=1"
                  " original_ldso_binding_unproven=1\n",
                  static_cast<unsigned long long>(mainPLT.guestTarget),
                  static_cast<unsigned long long>(mainPLT.guestValue),
                  mainPLT.symbolIndex,mainPLT.symbolName,mainPLT.binding,
                  unsigned(mainPLT.targetInMainRELRO),
                  unsigned(mainPLT.sourceFileBackedTarget),
                  unsigned(mainPLT.sourceValueMatchesLive));
                kernix::g0::mainpltsource::LibcExportWitness pltLibc{};
                if(!kernix::g0::mainpltsource::
                     ReadOnlyOriginalLibcJumpSlotExport(
                       libcSnapshot.bytes(),libcSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       libcBase,mainPLT,pltLibc) ||
                   !pltLibc.boundedOriginalLibcDynsym ||
                   !pltLibc.sourceValueWithinReadablePTLoad ||
                   pltLibc.exactDefinedExportMatches!=1 ||
                   pltLibc.originalGNUResolverAlgorithmProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_PLT_LIBC_EXPORT_READONLY_REJECT\n",stderr);
                  _exit(183);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_PLT_LIBC_EXPORT_SOURCE_ADDRESS_READONLY"
                  " symbol=%s name_candidates=%zu exact_address=%zu"
                  " source_libc_va=%llx libc_guest_base=%llx"
                  " source_elf_sha_verified=1 no_guest_write=1"
                  " versions_not_verified=1 ldso_lookup_not_proven=1\n",
                  mainPLT.symbolName,
                  pltLibc.sourceNameCandidates,
                  pltLibc.exactDefinedExportMatches,
                  static_cast<unsigned long long>(pltLibc.sourceSymbolVA),
                  static_cast<unsigned long long>(pltLibc.originalLibcBase));
                kernix::g0::pltversions::Witness pltVersion{};
                if(!kernix::g0::pltversions::AuditOriginalMainPLTLibcSymbolVersion(
                     mainSnapshot.bytes(),mainSnapshot.size(),
                     OriginalVerifiedSource.exactSha256Matched,
                     libcSnapshot.bytes(),libcSnapshot.size(),
                     OriginalVerifiedSource.exactSha256Matched,
                     mainPLT,pltLibc,pltVersion) ||
                   !pltVersion.mainSourceVerneedVerified ||
                   !pltVersion.libcSourceVersymVerdefVerified ||
                   !pltVersion.exactVersionAndAddressMatched ||
                   pltVersion.originalGNUVersionedLookupExecuted ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs("KERNIX_G0_MAIN_PLT_GNU_VERSION_SOURCE_REJECT\n",stderr);
                  _exit(184);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_PLT_GNU_VERSION_SOURCE_EXACT_READONLY"
                  " symbol=%s main_version=%s libc_version=%s"
                  " main_index=%u libc_index=%u"
                  " same_export_address=1 source_sha_verified=1"
                  " original_lookup_not_proven=1 no_guest_write=1\n",
                  mainPLT.symbolName,pltVersion.requiredVersion,
                  pltVersion.definedVersion,
                  unsigned(pltVersion.mainVersionIndex),
                  unsigned(pltVersion.libcVersionIndex));
                kernix::g0::mainrelrotargets::OutsideRELRORelativeWitness
                    outsideRelative{};
                if(!kernix::g0::mainrelrotargets::
                     AuditOriginalMainRelativeOutsideRELRO(
                       mainSnapshot.bytes(),mainSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       Owner,SourceExecPolicy,SourceMainRelroPage,
                       outsideRelative) ||
                   outsideRelative.mainRelaEntries!=mainDyn.relaEntries ||
                   outsideRelative.relativeEntries!=mainDyn.relativeRelaEntries ||
                   outsideRelative.relativeEntries!=3 ||
                   outsideRelative.insideRELROEntries!=
                       targets.relativeTargetsInRELRO ||
                   outsideRelative.insideRELROEntries!=2 ||
                   outsideRelative.outsideRELROEntries!=1 ||
                   !outsideRelative.outsideSourceOriginalRWPTLoad ||
                   !outsideRelative.outsideGuestOwnedNativeRWPage ||
                   outsideRelative.originalLdsoRelocationClosureProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_MAIN_OUTSIDE_RELRO_RELATIVE_AUDIT_REJECT\n",
                    stderr);
                  _exit(185);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_MAIN_OUTSIDE_RELRO_RELATIVE_READONLY"
                  " main_rela=%zu relative_total=%zu relro_relative=%zu"
                  " outside_relative=%zu matched=%zu different=%zu"
                  " target=%llx expected=%llx live=%llx"
                  " original_source_rw=1 owned_guest_rw=1"
                  " main_relocation_closure_not_proven=1"
                  " no_guest_write=1\n",
                  outsideRelative.mainRelaEntries,
                  outsideRelative.relativeEntries,
                  outsideRelative.insideRELROEntries,
                  outsideRelative.outsideRELROEntries,
                  outsideRelative.outsideValueMatches,
                  outsideRelative.outsideValueDiffers,
                  static_cast<unsigned long long>(
                    outsideRelative.outsideTarget),
                  static_cast<unsigned long long>(
                    outsideRelative.outsideExpected),
                  static_cast<unsigned long long>(
                    outsideRelative.outsideLive));
                kernix::g0::mainrelrotargets::ThreeRelativeSnapshot tripleAtMain{};
                if(!ThreeRelativeAtLibcRELROCaptured ||
                   !ThreeRelativeBeforeFex.sourceAuthenticated ||
                   !ThreeRelativeAtLibcRELRO.sourceAuthenticated ||
                   !kernix::g0::mainrelrotargets::
                     ReadOnlyOriginalMainThreeRelative(
                       mainSnapshot.bytes(),mainSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,Owner,
                       SourceExecPolicy,SourceMainRelroPage,tripleAtMain) ||
                   !tripleAtMain.sourceAuthenticated ||
                   tripleAtMain.exactExpected!=3 ||
                   tripleAtMain.notExpected!=0 ||
                   tripleAtMain.originalLdsoStoreRIPProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_RELATIVE_TRIPLE_MAIN_BOUNDARY_REJECT\n",
                    stderr);
                  _exit(196);
                }
                size_t preToLibcChanged=0,libcToMainChanged=0;
                size_t fixtureUnchangedAfterLibc=0,nonfixtureCompletedAfterLibc=0;
                for(size_t k=0;k<tripleAtMain.total;++k) {
                  const auto& a=ThreeRelativeBeforeFex.slots[k];
                  const auto& b=ThreeRelativeAtLibcRELRO.slots[k];
                  const auto& d=tripleAtMain.slots[k];
                  if(a.guestTarget!=b.guestTarget ||
                     a.guestTarget!=d.guestTarget ||
                     a.expectedValue!=b.expectedValue ||
                     a.expectedValue!=d.expectedValue ||
                     a.targetInRELRO!=b.targetInRELRO ||
                     a.targetInRELRO!=d.targetInRELRO) {
                    std::fputs(
                      "KERNIX_G0_MAIN_RELATIVE_TRIPLE_IDENTITY_REJECT\n",
                      stderr);
                    _exit(197);
                  }
                  preToLibcChanged+=size_t(a.guestValue!=b.guestValue);
                  libcToMainChanged+=size_t(b.guestValue!=d.guestValue);
                  if(a.guestTarget==OriginalFixtureRelativeTarget){
                    if(b.guestValue!=d.guestValue ||
                       d.guestValue!=d.expectedValue ||
                       a.guestValue==b.guestValue){
                      std::fputs(
                        "KERNIX_G0_MAIN_RELATIVE_FIXTURE_MAIN_IDENTITY_REJECT\n",
                        stderr);
                      _exit(204);
                    }
                    ++fixtureUnchangedAfterLibc;
                  }else{
                    if(a.guestValue!=b.guestValue ||
                       b.guestValue==b.expectedValue ||
                       d.guestValue!=d.expectedValue ||
                       b.guestValue==d.guestValue){
                      std::fputs(
                        "KERNIX_G0_MAIN_RELATIVE_NONFIXTURE_MAIN_BOUNDARY_REJECT\n",
                        stderr);
                      _exit(205);
                    }
                    ++nonfixtureCompletedAfterLibc;
                  }

                  std::fprintf(stderr,
                    "KERNIX_G0_MAIN_RELATIVE_TRIPLE_THREE_PHASE_ENTRY"
                    " index=%zu target=%llx expected=%llx"
                    " before_fex=%llx at_libc_relro=%llx"
                    " at_main_relro=%llx in_relro=%u"
                    " fixture_vs_loader_write_not_proven=1\n",
                    k,
                    static_cast<unsigned long long>(a.guestTarget),
                    static_cast<unsigned long long>(a.expectedValue),
                    static_cast<unsigned long long>(a.guestValue),
                    static_cast<unsigned long long>(b.guestValue),
                    static_cast<unsigned long long>(d.guestValue),
                    unsigned(a.targetInRELRO));
                }
                if(fixtureUnchangedAfterLibc!=1 ||
                   nonfixtureCompletedAfterLibc!=2 ||
                   preToLibcChanged!=1 || libcToMainChanged!=2 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_RELATIVE_FIXTURE_TWO_BOUNDARY_COUNTS_REJECT\n",
                    stderr);
                  _exit(206);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_RELATIVE_FIXTURE_VS_NONFIXTURE_SOURCE_READONLY"
                  " fixture_target=%llx authored_fixture_early=1"
                  " other_original_source_relative_later=2"
                  " first_changed_guest_slot_matches_authored_fixture=1"
                  " separate_specific_guest_write_rips_not_traced=1"
                  " original_ldso_full_relocation_closure_unproven=1"
                  " no_guest_write=1\n",
                  static_cast<unsigned long long>(
                    OriginalFixtureRelativeTarget));
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_RELATIVE_TRIPLE_THREE_PHASE_SUMMARY"
                  " total=3 relro=2 outside=1"
                  " final_matches=3 pre_to_libc_changed=%zu"
                  " libc_to_main_changed=%zu"
                  " main_relro_unsealed=1"
                  " guest_write_instruction_not_traced=1"
                  " full_dynamic_relocations_unproven=1 no_guest_write=1\n",
                  preToLibcChanged,libcToMainChanged);

                // Read-only nine-entry SOURCE-MAIN relocation ledger.
                // Original DT_RELA holds 3 RELATIVE + 5 GLOB_DAT; the
                // one DT_JMPREL JUMP_SLOT is separate. The source-plan
                // symbolic counter (6) includes BOTH tables, hence it
                // must never be mistaken for six GLOB_DAT in DT_RELA.
                // These are boundary-value checks, NOT execution of
                // ldso lookup algorithm, TLS/IFUNC nor seal authority.
                if(mainDyn.relaEntries!=8 ||
                   mainDyn.relativeRelaEntries!=3 ||
                   mainDyn.irelativeRelaEntries!=0 ||
                   mainDyn.symbolicRelaEntries!=6 ||
                   mainDyn.pltRelaEntries!=1 ||
                   mainDyn.relrWords!=0 || mainDyn.relrTargets!=0 ||
                   mainDyn.relaEntries+mainDyn.pltRelaEntries!=9 ||
                   mainDyn.symbolicRelaEntries!=
                        targets.symbolicTargetsGlobDat+
                        mainDyn.pltRelaEntries ||
                   targets.sourceMainRelaEntries!=8 ||
                   targets.sourceMainPLTRelaEntries!=1 ||
                   targets.sourceRelaTargetsInThisRELROPage!=7 ||
                   targets.relativeTargetsInRELRO!=2 ||
                   targets.symbolicTargetsGlobDat!=5 ||
                   targets.symbolicTargetsOther!=0 ||
                   targets.irelativeTargetsInRELRO!=0 ||
                   !tripleAtMain.sourceAuthenticated ||
                   tripleAtMain.total!=3 ||
                   !pltVersion.exactVersionAndAddressMatched ||
                   verifiedVersions.libcSymbolVersionExactMatches!=2 ||
                   verifiedVersions.originalGNUVersionedLookupExecuted ||
                   libcExports.sourceLibcExactGuestAddressMatches!=2 ||
                   libcExports.weakUndefinedMainZeroSlots!=3 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_HEADER_REJECT\n",
                    stderr);
                  _exit(207);
                }
                std::array<uint64_t,9> ledgerTargets{};
                size_t ledgerIndex=0,ledgerRELATIVE=0,ledgerGLOB=0,
                       ledgerPLT=0,ledgerWeakZero=0,ledgerLibc=0;
                for(const auto& slot:tripleAtMain.slots) {
                  if(!slot.guestTarget ||
                     slot.guestValue!=slot.expectedValue) {
                    std::fputs(
                      "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_RELATIVE_REJECT\n",
                      stderr);
                    _exit(208);
                  }
                  ledgerTargets[ledgerIndex]=slot.guestTarget;
                  std::fprintf(stderr,
                    "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_ENTRY"
                    " index=%zu type=RELATIVE symbol=none"
                    " target=%llx live=%llx expected=%llx"
                    " source_attested=1 no_guest_write=1\n",
                    ledgerIndex,
                    static_cast<unsigned long long>(slot.guestTarget),
                    static_cast<unsigned long long>(slot.guestValue),
                    static_cast<unsigned long long>(slot.expectedValue));
                  ++ledgerIndex;++ledgerRELATIVE;
                }
                for(size_t k=0;k<targets.verifiedSymbolicNameCount;++k) {
                  const auto& symbol=targets.symbolicSourceNames[k];
                  if(symbol.type!=R_X86_64_GLOB_DAT ||
                     symbol.sourceDefinition ||
                     !symbol.guestTarget) {
                    std::fputs(
                      "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_GLOB_TYPE_REJECT\n",
                      stderr);
                    _exit(209);
                  }
                  uint64_t expected=0;
                  if(symbol.guestValue==0) {
                    if(symbol.binding!=STB_WEAK) {
                      std::fputs(
                        "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_WEAK_REJECT\n",
                        stderr);
                      _exit(210);
                    }
                    ++ledgerWeakZero;
                  }else{
                    size_t versionCount=0;
                    for(size_t n=0;n<verifiedVersions.libcSymbolVersionExactMatches;++n) {
                      const auto& v=verifiedVersions.checked[n];
                      if(v.mainSymbolIndex!=symbol.symbolIndex ||
                         std::strcmp(v.symbol,symbol.name)!=0)continue;
                      if(libcBase>UINT64_MAX-v.sourceLibcSymbolVA)continue;
                      expected=libcBase+v.sourceLibcSymbolVA;
                      ++versionCount;
                    }
                    if(versionCount!=1 || expected!=symbol.guestValue) {
                      std::fputs(
                        "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_LIBC_VERSION_REJECT\n",
                        stderr);
                      _exit(211);
                    }
                    ++ledgerLibc;
                  }
                  ledgerTargets[ledgerIndex]=symbol.guestTarget;
                  std::fprintf(stderr,
                    "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_ENTRY"
                    " index=%zu type=GLOB_DAT symbol=%s"
                    " target=%llx live=%llx expected=%llx"
                    " source_attested=1 no_guest_write=1\n",
                    ledgerIndex,symbol.name,
                    static_cast<unsigned long long>(symbol.guestTarget),
                    static_cast<unsigned long long>(symbol.guestValue),
                    static_cast<unsigned long long>(expected));
                  ++ledgerIndex;++ledgerGLOB;
                }
                if(!mainPLT.authenticatedSourceJumpSlot ||
                   mainPLT.originalGNUJmpSlotResolutionProven ||
                   std::strcmp(mainPLT.symbolName,"puts")!=0 ||
                   pltLibc.originalLibcBase!=libcBase ||
                   pltLibc.sourceSymbolVA>UINT64_MAX-libcBase ||
                   mainPLT.guestValue!=libcBase+pltLibc.sourceSymbolVA) {
                  std::fputs(
                    "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_PLT_REJECT\n",
                    stderr);
                  _exit(212);
                }
                ledgerTargets[ledgerIndex]=mainPLT.guestTarget;
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_ENTRY"
                  " index=%zu type=JUMP_SLOT symbol=%s"
                  " target=%llx live=%llx expected=%llx"
                  " source_attested=1 no_guest_write=1\n",
                  ledgerIndex,mainPLT.symbolName,
                  static_cast<unsigned long long>(mainPLT.guestTarget),
                  static_cast<unsigned long long>(mainPLT.guestValue),
                  static_cast<unsigned long long>(
                    libcBase+pltLibc.sourceSymbolVA));
                ++ledgerIndex;++ledgerPLT;
                if(ledgerIndex!=9 || ledgerRELATIVE!=3 ||
                   ledgerGLOB!=5 || ledgerPLT!=1 ||
                   ledgerWeakZero!=3 || ledgerLibc!=2) {
                  std::fputs(
                    "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_TOTAL_REJECT\n",
                    stderr);
                  _exit(213);
                }
                for(size_t k=0;k<ledgerIndex;++k) {
                  if(!ledgerTargets[k] ||
                     !Owner.GuestReadOnlyBytes(0,ledgerTargets[k],8)) {
                    std::fputs(
                      "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_OWNER_REJECT\n",
                      stderr);
                    _exit(214);
                  }
                  for(size_t prev=0;prev<k;++prev)
                    if(ledgerTargets[prev]==ledgerTargets[k]) {
                      std::fputs(
                        "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_DUPLICATE_REJECT\n",
                        stderr);
                      _exit(215);
                    }
                }
                std::fprintf(stderr,
                  "KERNIX_G0_MAIN_SOURCE_RELOCATION_LEDGER_READONLY_PASS"
                  " original_main_rela=8 original_main_jmprel=1"
                  " total_unique=9 relative=3 glob_dat=5 jump_slot=1"
                  " glob_weak_zero=3 glob_libc_versioned=2"
                  " plt_libc_versioned=1"
                  " source_plan_symbolic_counts_both_tables=6"
                  " original_ldso_lookup_algorithm_not_traced=1"
                  " entire_process_relocation_closure_unproven=1"
                  " main_relro_not_sealed=1 no_guest_write=1\n");
                // Independent pinned ORIGINAL-ELF source inventory
                // for main, ld-linux and libc. The nine main records
                // are a narrow verified read-only ledger; the other
                // two ELF modules still need genuine relocation-closure
                // evidence, NOT a guess based on source metadata.
                kernix::g0::triadsourceinventory::Witness triad{};
                if(!kernix::g0::triadsourceinventory::
                       OriginalThreeELFSourceRelocationInventory(
                           OriginalDynamicSource,OriginalVerifiedSource,
                           Owner,triad) ||
                   !triad.originalThreeSHA256SourcesVerified ||
                   triad.originalModules!=3 ||
                   triad.guestRelocationClosureProven ||
                   triad.AndroidDeviceTested ||
                   triad.modules[0].rela!=mainDyn.relaEntries ||
                   triad.modules[0].plt!=mainDyn.pltRelaEntries ||
                   triad.modules[0].sourceRelocationTargets!=9 ||
                   triad.modules[0].relative!=3 ||
                   triad.modules[0].symbolic!=6 ||
                   triad.modules[0].relrTargets!=0 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_TRIAD_SOURCE_RELOCATION_INVENTORY_REJECT\n",
                    stderr);
                  _exit(219);
                }
                for(size_t module=0;module<triad.originalModules;++module) {
                  const auto& row=triad.modules[module];
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_TRIAD_SOURCE_RELOCATION_MODULE"
                    " module=%zu rela=%zu jmprel=%zu relr_words=%zu"
                    " relr_targets=%zu relative=%zu irelative=%zu"
                    " symbolic=%zu total_targets=%zu needed=%zu"
                    " outside_initial_rw=%zu"
                    " original_sha_source_attested=1"
                    " guest_relocation_execution_unproven=1\n",
                    module,row.rela,row.plt,row.relrWords,
                    row.relrTargets,row.relative,row.irelative,
                    row.symbolic,row.sourceRelocationTargets,row.needed,
                    row.relocationTargetsOutsideRW);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_TRIAD_SOURCE_RELOCATION_INVENTORY_READONLY"
                  " modules=%zu rela=%zu jmprel=%zu relr_words=%zu"
                  " relr_targets=%zu relative=%zu irelative=%zu"
                  " symbolic=%zu total_targets=%zu needed=%zu"
                  " outside_initial_rw=%zu"
                  " original_three_elf_sha_verified=1"
                  " full_guest_relocation_closure_unproven=1"
                  " original_main_relro_unsealed=1"
                  " android_not_tested=1 no_guest_write=1\n",
                  triad.originalModules,triad.totalRela,triad.totalPLT,
                  triad.totalRELRWords,triad.totalRELRTgt,
                  triad.totalRelative,triad.totalIRelative,
                  triad.totalSymbolic,triad.totalSourceTargets,
                  triad.totalNeeded,triad.totalOutsideInitialRW);
                // The exact 11 original ld-linux RELR source
                // descriptors: compare their owned guest qwords before
                // any FEX guest instructions with the real original
                // main RELRO syscall boundary, WITHOUT claiming the
                // original loader's write RIP or RELRO seal completion.
                kernix::g0::ldsorelr::Witness ldsoRelrAtMain{};
                if(!LdsoRelrBeforeFex.attestedOriginalSource ||
                   LdsoRelrBeforeFex.count!=11 ||
                   !interpreterSnapshot.readOnlySnapshot() ||
                   !kernix::g0::ldsorelr::SampleOriginalLdsoRelrReadOnly(
                       interpreterSnapshot.bytes(),
                       interpreterSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       Owner,SourceExecPolicy,ldsoRelrAtMain) ||
                   !ldsoRelrAtMain.attestedOriginalSource ||
                   ldsoRelrAtMain.count!=11 ||
                   ldsoRelrAtMain.expectedKnown!=11 ||
                   ldsoRelrAtMain.guestLdsoWriteRIPTraced ||
                   ldsoRelrAtMain.originalRelocationClosureProven ||
                   triad.modules[1].relrTargets!=11 ||
                   triad.modules[1].relrWords!=3 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights){
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_11_RELR_TWO_PHASE_REJECT\n",
                    stderr);
                  _exit(221);
                }
                size_t ldsoRelrChanged=0;
                size_t ldsoRelrBeforeSource=0,ldsoRelrAfterExpected=0;
                for(size_t k=0;k<ldsoRelrAtMain.count;++k){
                  const auto& before=LdsoRelrBeforeFex.entries[k];
                  const auto& after=ldsoRelrAtMain.entries[k];
                  if(!before.target || before.target!=after.target ||
                     before.sourceAddend!=after.sourceAddend ||
                     before.expected!=after.expected ||
                     before.fileBacked!=after.fileBacked){
                    std::fputs(
                      "KERNIX_G0_ORIGINAL_LDSO_11_RELR_TARGET_IDENTITY_REJECT\n",
                      stderr);
                    _exit(222);
                  }
                  ldsoRelrChanged+=size_t(before.live!=after.live);
                  ldsoRelrBeforeSource+=
                     size_t(before.live==before.sourceAddend);
                  ldsoRelrAfterExpected+=
                     size_t(after.live==after.expected);
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_11_RELR_TWO_PHASE_ENTRY"
                    " index=%zu target=%llx source_addend=%llx"
                    " expected=%llx before_fex=%llx at_main=%llx"
                    " backed=%u changed=%u"
                    " original_guest_write_rip_untraced=1\n",
                    k,static_cast<unsigned long long>(before.target),
                    static_cast<unsigned long long>(before.sourceAddend),
                    static_cast<unsigned long long>(before.expected),
                    static_cast<unsigned long long>(before.live),
                    static_cast<unsigned long long>(after.live),
                    unsigned(after.fileBacked),
                    unsigned(before.live!=after.live));
                }
                if(ldsoRelrBeforeSource!=
                     LdsoRelrBeforeFex.sourceMatching ||
                   ldsoRelrAfterExpected!=
                     ldsoRelrAtMain.expectedMatching ||
                   ldsoRelrChanged>11){
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_11_RELR_COUNTS_REJECT\n",
                    stderr);
                  _exit(223);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_11_RELR_TWO_PHASE_SUMMARY"
                  " total=11 changed=%zu before_source_equal=%zu"
                  " at_main_expected_equal=%zu"
                  " before_expected_equal=%zu"
                  " source_attested=1 guest_owned=1"
                  " original_ldso_write_rip_untraced=1"
                  " full_original_ldso_relocation_closure_unproven=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  ldsoRelrChanged,ldsoRelrBeforeSource,
                  ldsoRelrAfterExpected,
                  LdsoRelrBeforeFex.expectedMatching);
                // The other three authentic source ld-linux .rela.dyn
                // entries are two symbolic imports and one IRELATIVE.
                // No source-only address arithmetic can certify the
                // GNU symbol lookup or IFUNC resolver result. Read and
                // compare their real guest qwords without touching them.
                kernix::g0::ldsorela::Witness ldsoRelaAtMain{};
                if(!LdsoRelaBeforeFex.authenticatedSource ||
                   !kernix::g0::ldsorela::SampleOriginalLdsoThreeRelaReadOnly(
                       interpreterSnapshot.bytes(),
                       interpreterSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       Owner,SourceExecPolicy,ldsoRelaAtMain) ||
                   !ldsoRelaAtMain.authenticatedSource ||
                   ldsoRelaAtMain.count!=3 ||
                   ldsoRelaAtMain.irelative!=1 ||
                   ldsoRelaAtMain.symbolic!=2 ||
                   triad.modules[1].rela!=3 ||
                   triad.modules[1].plt!=0 ||
                   ldsoRelaAtMain.originalLdsoStoreRIPTraced ||
                   ldsoRelaAtMain.fullRelocationClosureProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_3_RELA_TWO_PHASE_REJECT\n",
                    stderr);
                  _exit(225);
                }
                size_t ldsoRelaChanged=0;
                for(size_t k=0;k<3;++k){
                  const auto& before=LdsoRelaBeforeFex.entries[k];
                  const auto& after=ldsoRelaAtMain.entries[k];
                  if(before.target!=after.target ||
                     before.type!=after.type ||
                     before.symbol!=after.symbol ||
                     before.addend!=after.addend ||
                     before.sourceInitial!=after.sourceInitial ||
                     before.backed!=after.backed ||
                     !before.target) {
                    std::fputs(
                      "KERNIX_G0_ORIGINAL_LDSO_3_RELA_IDENTITY_REJECT\n",
                      stderr);
                    _exit(226);
                  }
                  const unsigned changed=unsigned(before.live!=after.live);
                  ldsoRelaChanged+=changed;
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LDSO_3_RELA_TWO_PHASE_ENTRY"
                    " index=%zu type=%u symbol=%u target=%llx"
                    " source=%llx addend=%llx"
                    " before_fex=%llx at_main=%llx"
                    " backed=%u changed=%u"
                    " original_symbol_resolution_not_traced=1\n",
                    k,unsigned(after.type),unsigned(after.symbol),
                    static_cast<unsigned long long>(after.target),
                    static_cast<unsigned long long>(after.sourceInitial),
                    static_cast<unsigned long long>(
                        static_cast<uint64_t>(after.addend)),
                    static_cast<unsigned long long>(before.live),
                    static_cast<unsigned long long>(after.live),
                    unsigned(after.backed),changed);
                }
                if(ldsoRelaChanged>3 ||
                   LdsoRelaBeforeFex.sourceEqual+
                     LdsoRelaBeforeFex.sourceDifferent!=3 ||
                   ldsoRelaAtMain.sourceEqual+
                     ldsoRelaAtMain.sourceDifferent!=3 ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LDSO_3_RELA_SUMMARY_REJECT\n",
                    stderr);
                  _exit(227);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_3_RELA_TWO_PHASE_SUMMARY"
                  " total=3 irelative=1 symbolic=2"
                  " changed=%zu before_source_equal=%zu"
                  " at_main_source_equal=%zu"
                  " original_ldso_rela_source_attested=1"
                  " no_ifunc_or_symbol_resolution_proof=1"
                  " loader_store_rips_not_traced=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  ldsoRelaChanged,LdsoRelaBeforeFex.sourceEqual,
                  ldsoRelaAtMain.sourceEqual);
                // The two changed ldso GLOB_DAT values are
                // classified against original ldso DYNSYM/STRTAB
                // names and (if defined here) source definitions.
                // The third IRELATIVE remains a deferred unknown:
                // authenticate executable resolver bytes, NEVER call
                // it, and do not call the resolver result successful.
                kernix::g0::ldsorelasource::Witness provenance{};
                if(!kernix::g0::ldsorelasource::
                     ReadOriginalLdsoThreeRelaSymbolAndResolverSource(
                       interpreterSnapshot.bytes(),
                       interpreterSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       Owner,SourceExecPolicy,ldsoRelaAtMain,
                       provenance) ||
                   provenance.symbolicNames!=2 ||
                   !provenance.resolverSourceCodeVerified ||
                   !provenance.resolverGuestBytesIdenticalToSource ||
                   provenance.ifuncExecutedOrResultValidated ||
                   provenance.fullDynamicRelocationClosureProven ||
                   provenance.resolverSourceVA!=
                      static_cast<uint64_t>(ldsoRelaAtMain.entries[2].addend) ||
                   provenance.ifuncSlotTarget!=ldsoRelaAtMain.entries[2].target ||
                   provenance.ifuncSlotLive!=ldsoRelaAtMain.entries[2].live ||
                   RightsAt(SourceMainRelroPage)!=beforeRights){
                  std::fputs(
                    "KERNIX_G0_LDSO_RELA_SOURCE_SYMBOL_IFUNC_REJECT\n",
                    stderr);
                  _exit(228);
                }
                for(size_t i=0;i<provenance.symbolicNames;++i){
                  const auto& sym=provenance.symbolic[i];
                  std::fprintf(stderr,
                    "KERNIX_G0_LDSO_GLOB_DAT_SOURCE_SYM_ENTRY"
                    " index=%zu elf_index=%u name=%s binding=%u type=%u"
                    " target=%llx live=%llx source_definition=%u"
                    " source_defined_guest=%llx exact_self_def=%u"
                    " source_only=1 no_guest_write=1\n",
                    i,sym.symbolIndex,sym.name,
                    unsigned(sym.binding),unsigned(sym.type),
                    static_cast<unsigned long long>(sym.target),
                    static_cast<unsigned long long>(sym.live),
                    unsigned(sym.sourceDefined),
                    static_cast<unsigned long long>(sym.definitionGuest),
                    unsigned(sym.exactSelfDefinition));
                }
                std::fprintf(stderr,
                  "KERNIX_G0_LDSO_IRELATIVE_RESOLVER_SOURCE_READONLY"
                  " source_va=%llx guest_va=%llx target=%llx live=%llx"
                  " source_rx=1 guest_rx=1 source_live_code_match=1"
                  " ifunc_result_not_verified=1"
                  " resolver_not_executed_by_probe=1 no_guest_write=1\n",
                  static_cast<unsigned long long>(
                    provenance.resolverSourceVA),
                  static_cast<unsigned long long>(
                    provenance.resolverGuestVA),
                  static_cast<unsigned long long>(
                    provenance.ifuncSlotTarget),
                  static_cast<unsigned long long>(
                    provenance.ifuncSlotLive));
                std::fprintf(stderr,
                  "KERNIX_G0_LDSO_RELA_SOURCE_SYM_IFUNC_SUMMARY_READONLY"
                  " symbolic_names=%zu defined_in_ldso=%zu"
                  " self_definition_matches=%zu"
                  " ifunc_resolver_executable_verified=1"
                  " ifunc_not_invoked=1 full_loader_closure_unproven=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  provenance.symbolicNames,provenance.definedInLdso,
                  provenance.matchedOwnDefinitions);
                // Audit all 1067 original libc RELR targets again AFTER
                // the authentic libc 4-page RELRO seal, at the original
                // main RELRO syscall. Stable identity is required; live
                // values are observed, not modified or attributed to an
                // untraced x86 writer.
                kernix::g0::libcrelr::Witness libcRELRAtMain{};
                const auto& actualLibcMap=
                     SourceFileKernel.OriginalLibcLargeReadonlyMap();
                const auto& immutableLibc=
                     OriginalVerifiedSource.snapshots[2];
                const auto readLibc=[&](uint64_t addr) noexcept {
                  const std::string rights=RightsAt(addr);
                  return c1::GuestRange(addr,8) &&
                      (rights=="r--p" || rights=="rw-p") &&
                      addr>=actualLibcMap.Address() &&
                      addr-actualLibcMap.Address()<=
                        actualLibcMap.BytesHeld()-8;
                };
                if(!LibcRELRAtLibcBoundaryCaptured ||
                   !immutableLibc.readOnlySnapshot() ||
                   !immutableLibc.bytes() ||
                   !kernix::g0::libcrelr::
                     SampleOriginalLibc1067RELRReadOnly(
                       immutableLibc.bytes(),immutableLibc.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       actualLibcMap,readLibc,libcRELRAtMain) ||
                   !libcRELRAtMain.originalLibcSHAProven ||
                   libcRELRAtMain.count!=1067 ||
                   triad.modules[2].relrTargets!=1067 ||
                   triad.modules[2].relrWords!=32 ||
                   !LibcRELRAtLibcBoundary.originalLibcSHAProven ||
                   libcRELRAtMain.actualGuestStoreRIPsTraced ||
                   libcRELRAtMain.fullOriginalRelocationClosureProven ||
                   RightsAt(actualLibcMap.Address()+0x1ff000ULL)!="r--p" ||
                   RightsAt(actualLibcMap.Address()+0x200000ULL)!="r--p" ||
                   RightsAt(actualLibcMap.Address()+0x201000ULL)!="r--p" ||
                   RightsAt(actualLibcMap.Address()+0x202000ULL)!="r--p" ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_LIBC_1067_RELR_MAIN_BOUNDARY_REJECT\n",
                    stderr);
                  _exit(230);
                }
                size_t libcRELRChanged=0;
                for(size_t k=0;k<1067;++k){
                  const auto& before=LibcRELRAtLibcBoundary.entries[k];
                  const auto& after=libcRELRAtMain.entries[k];
                  if(!before.guest || before.guest!=after.guest ||
                     before.sourceAddend!=after.sourceAddend ||
                     before.expected!=after.expected ||
                     before.fileBacked!=after.fileBacked) {
                    std::fputs(
                      "KERNIX_G0_LIBC_1067_RELR_IDENTITY_REJECT\n",
                      stderr);
                    _exit(231);
                  }
                  libcRELRChanged+=size_t(before.live!=after.live);
                }
                if(libcRELRChanged>1067 ||
                   libcRELRAtMain.sourceBacked!=
                       LibcRELRAtLibcBoundary.sourceBacked ||
                   libcRELRAtMain.sourceBSS!=
                       LibcRELRAtLibcBoundary.sourceBSS ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_LIBC_1067_RELR_SUMMARY_REJECT\n",
                    stderr);
                  _exit(232);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_1067_RELR_TWO_BOUNDARY_SUMMARY"
                  " targets=1067 changed=%zu"
                  " at_libc_source_equal=%zu"
                  " at_libc_expected_equal=%zu"
                  " at_main_source_equal=%zu"
                  " at_main_expected_equal=%zu"
                  " backed=%zu bss=%zu"
                  " source_elf_sha=1 real_libc_relro_sealed=1"
                  " original_guest_relocation_write_rips_untraced=1"
                  " no_full_dynamic_relocation_closure_proof=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  libcRELRChanged,
                  LibcRELRAtLibcBoundary.liveEqualSource,
                  LibcRELRAtLibcBoundary.liveEqualExpected,
                  libcRELRAtMain.liveEqualSource,
                  libcRELRAtMain.liveEqualExpected,
                  libcRELRAtMain.sourceBacked,
                  libcRELRAtMain.sourceBSS);
                // Cross-audit the SAME 147 original libc RELA/JMPREL
                // qwords at the subsequent authentic original main
                // mprotect boundary, after libc GNU_RELRO has been
                // sealed. Changed values are measurements only.
                kernix::g0::libcrela::Witness libcRelaAtMain{};
                if(!LibcRelaAtLibcBoundaryCaptured ||
                   !LibcRelaAtLibcBoundary.originalSourceShaPinned ||
                   !kernix::g0::libcrela::
                     SampleOriginalLibc147RelaJmprelReadonly(
                       immutableLibc.bytes(),immutableLibc.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       actualLibcMap,readLibc,libcRelaAtMain) ||
                   !libcRelaAtMain.originalSourceShaPinned ||
                   libcRelaAtMain.count!=147 ||
                   libcRelaAtMain.rela!=86 ||
                   libcRelaAtMain.jmprel!=61 ||
                   libcRelaAtMain.irelative!=46 ||
                   libcRelaAtMain.symbolic!=101 ||
                   triad.modules[2].rela!=86 ||
                   triad.modules[2].plt!=61 ||
                   triad.modules[2].irelative!=46 ||
                   triad.modules[2].symbolic!=101 ||
                   libcRelaAtMain.guestStoreInstructionsTraced ||
                   libcRelaAtMain.symbolOrIfuncResolutionsProven ||
                   libcRelaAtMain.wholeLibcRelocationClosureProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights){
                  std::fputs(
                    "KERNIX_G0_LIBC_147_RELA_JMPREL_MAIN_BOUNDARY_REJECT\n",
                    stderr);
                  _exit(234);
                }
                size_t libcRelaChanged=0,changedIFUNC=0;
                for(size_t k=0;k<147;++k) {
                  const auto& before=LibcRelaAtLibcBoundary.slots[k];
                  const auto& after=libcRelaAtMain.slots[k];
                  if(!before.target || before.target!=after.target ||
                     before.source!=after.source ||
                     before.type!=after.type ||
                     before.symbol!=after.symbol ||
                     before.addend!=after.addend ||
                     before.plt!=after.plt ||
                     before.sourceBacked!=after.sourceBacked) {
                    std::fputs(
                      "KERNIX_G0_LIBC_147_RELA_JMPREL_IDENTITY_REJECT\n",
                      stderr);
                    _exit(235);
                  }
                  if(before.live!=after.live){
                    ++libcRelaChanged;
                    if(after.type==R_X86_64_IRELATIVE)
                       ++changedIFUNC;
                  }
                }
                if(libcRelaChanged>147 || changedIFUNC>46 ||
                   libcRelaAtMain.sourceBacked!=
                     LibcRelaAtLibcBoundary.sourceBacked ||
                   libcRelaAtMain.sourceBSS!=
                     LibcRelaAtLibcBoundary.sourceBSS ||
                   RightsAt(actualLibcMap.Address()+0x1ff000ULL)!="r--p" ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_LIBC_147_RELA_JMPREL_SUMMARY_REJECT\n",
                    stderr);
                  _exit(236);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_147_RELA_JMPREL_TWO_BOUNDARY_SUMMARY"
                  " total=147 rela=%zu jmprel=%zu"
                  " irelative=%zu symbolic=%zu"
                  " changed=%zu changed_ifunc=%zu"
                  " pre_source_equal=%zu main_source_equal=%zu"
                  " pre_nonzero=%zu main_nonzero=%zu"
                  " pre_ifunc_nonzero=%zu main_ifunc_nonzero=%zu"
                  " pre_symbolic_nonzero=%zu main_symbolic_nonzero=%zu"
                  " backed=%zu bss=%zu"
                  " source_libc_sha=1 real_libc_relro_sealed=1"
                  " original_guest_write_rips_untraced=1"
                  " ifunc_and_symbol_resolution_unproven=1"
                  " full_dynamic_relocation_closure_unproven=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  libcRelaAtMain.rela,libcRelaAtMain.jmprel,
                  libcRelaAtMain.irelative,libcRelaAtMain.symbolic,
                  libcRelaChanged,changedIFUNC,
                  LibcRelaAtLibcBoundary.liveMatchesSource,
                  libcRelaAtMain.liveMatchesSource,
                  LibcRelaAtLibcBoundary.liveNonzero,
                  libcRelaAtMain.liveNonzero,
                  LibcRelaAtLibcBoundary.ifuncNonzero,
                  libcRelaAtMain.ifuncNonzero,
                  LibcRelaAtLibcBoundary.symbolicNonzero,
                  libcRelaAtMain.symbolicNonzero,
                  libcRelaAtMain.sourceBacked,
                  libcRelaAtMain.sourceBSS);
                // Exactly one original-libc IRELATIVE target remains
                // zero at both AUTHENTIC guest syscall boundaries.
                // Prove ONLY that the pinned source resolver points to
                // unchanged owned guest RX code. Do NOT execute it or
                // assert that zero means a failed/successful resolver.
                kernix::g0::libcifunczero::Witness ifuncZero{};
                const auto sourceRX=[&](uint64_t address) noexcept {
                  return c1::GuestRange(address,8) &&
                      RightsAt(address)=="r-xp";
                };
                if(!kernix::g0::libcifunczero::
                     AuditSingleZeroOriginalLibcIRELATIVEResolverReadOnly(
                       immutableLibc.bytes(),immutableLibc.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       actualLibcMap,LibcRelaAtLibcBoundary,
                       libcRelaAtMain,sourceRX,ifuncZero) ||
                   !ifuncZero.sourceSHA256Authenticated ||
                   ifuncZero.totalIRELATIVE!=46 ||
                   ifuncZero.nonzeroBeforeLibcSeal!=45 ||
                   ifuncZero.nonzeroAtMainBoundary!=45 ||
                   ifuncZero.zeroAtBothBoundaries!=1 ||
                   !ifuncZero.zeroResolverInsidePinnedSourceRX ||
                   !ifuncZero.exactOriginalResolverBytesPresentInGuestRX ||
                   ifuncZero.originalIFUNCInvocationProven ||
                   ifuncZero.zeroIsAValidResolutionProven ||
                   ifuncZero.allLoaderRelocationsProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_LIBC_SINGLE_ZERO_IRELATIVE_SOURCE_REJECT\n",
                    stderr);
                  _exit(237);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_SINGLE_ZERO_IRELATIVE_SOURCE_READONLY"
                  " total_ifunc=%zu nonzero_libc=%zu nonzero_main=%zu"
                  " zero_both=%zu index=%zu target=%llx"
                  " resolver_va=%llx resolver_guest=%llx"
                  " before=0 at_main=0"
                  " original_sha=1 resolver_source_rx=1"
                  " resolver_guest_rx_exact_source_bytes=1"
                  " original_resolver_execution_not_traced=1"
                  " zero_result_validity_unproven=1"
                  " original_process_relocation_closure_unproven=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  ifuncZero.totalIRELATIVE,
                  ifuncZero.nonzeroBeforeLibcSeal,
                  ifuncZero.nonzeroAtMainBoundary,
                  ifuncZero.zeroAtBothBoundaries,ifuncZero.zeroIndex,
                  static_cast<unsigned long long>(ifuncZero.target),
                  static_cast<unsigned long long>(
                    ifuncZero.resolverSourceVA),
                  static_cast<unsigned long long>(
                    ifuncZero.resolverGuestVA));
                // Inventory all forty-six *original* glibc
                // R_X86_64_IRELATIVE resolver source code addresses;
                // source-backed executable 8 bytes MUST match the
                // real guest RX map after FEX. This observer NEVER
                // invokes them or attributes nonzero GOT values to
                // a proven original GNU ldso store instruction.
                kernix::g0::libcifuncinventory::Witness allResolvers{};
                if(!kernix::g0::libcifuncinventory::
                     AuditAllOriginalLibc46IRELATIVEResolverSourcesReadonly(
                       immutableLibc.bytes(),immutableLibc.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       actualLibcMap,LibcRelaAtLibcBoundary,
                       libcRelaAtMain,sourceRX,allResolvers) ||
                   !allResolvers.originalSourceSHA256Verified ||
                   allResolvers.total!=46 ||
                   allResolvers.sourceRX!=46 ||
                   allResolvers.guestRXEqual!=46 ||
                   allResolvers.unchanged!=46 ||
                   allResolvers.nonzeroAtLibc!=45 ||
                   allResolvers.nonzeroAtMain!=45 ||
                   allResolvers.zeroBoth!=1 ||
                   allResolvers.originalResolversExecutedByThisAudit ||
                   allResolvers.originalLoaderStoreRIPsTraced ||
                   allResolvers.originalIFUNCResultsCorrectlyBoundProven ||
                   allResolvers.originalDynamicRelocationClosureProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_LIBC_ALL_46_IRELATIVE_RESOLVERS_REJECT\n",
                    stderr);
                  _exit(238);
                }
                size_t zeroMatched=0;
                for(const auto& entry:allResolvers.entries){
                  if(entry.sourceRelaIndex==ifuncZero.zeroIndex){
                    if(entry.target!=ifuncZero.target ||
                       entry.guestResolver!=ifuncZero.resolverGuestVA ||
                       entry.sourceResolverVA!=ifuncZero.resolverSourceVA ||
                       entry.valueAtLibc!=0 || entry.valueAtMain!=0) {
                      std::fputs(
                        "KERNIX_G0_LIBC_ALL_46_IRELATIVE_ZERO_IDENTITY_REJECT\n",
                        stderr);
                      _exit(239);
                    }
                    ++zeroMatched;
                  }
                }
                if(zeroMatched!=1){
                  std::fputs(
                    "KERNIX_G0_LIBC_ALL_46_IRELATIVE_ZERO_DUPLICATE_REJECT\n",
                    stderr);
                  _exit(240);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_ALL_46_IRELATIVE_RESOLVER_SOURCES_READONLY"
                  " count=%zu source_rx=%zu guest_rx_source_equal=%zu"
                  " snapshots_unchanged=%zu"
                  " nonzero_libc=%zu nonzero_main=%zu zero_both=%zu"
                  " nonzero_in_original_libc_rx=%zu"
                  " nonzero_outside_original_libc_rx=%zu"
                  " zero_index=%zu zero_guest_resolver=%llx"
                  " pinned_source_sha256=1"
                  " original_ifunc_execution_not_traced=1"
                  " actual_ldso_stores_not_traced=1"
                  " return_values_not_validated=1"
                  " original_process_relocation_closure_unproven=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  allResolvers.total,allResolvers.sourceRX,
                  allResolvers.guestRXEqual,allResolvers.unchanged,
                  allResolvers.nonzeroAtLibc,allResolvers.nonzeroAtMain,
                  allResolvers.zeroBoth,
                  allResolvers.nonzeroResultInsideLibcRX,
                  allResolvers.nonzeroResultOutsideLibcRX,
                  ifuncZero.zeroIndex,
                  static_cast<unsigned long long>(
                    ifuncZero.resolverGuestVA));
                // Authentic original-libc IFUNC relocation targets
                // provide forty-five nonzero guest code pointers.
                // Check EVERY returned pointer against original
                // source executable bytes and native-protected RX
                // mapping. Source==guest does NOT establish that
                // the resolver itself executed or semantically
                // selected the correct implementation.
                kernix::g0::libcifuncresult::Witness returnCodes{};
                if(!kernix::g0::libcifuncresult::
                    Audit45OriginalLibcIFUNCReturnCodePointersReadOnly(
                      immutableLibc.bytes(),immutableLibc.size(),
                      OriginalVerifiedSource.exactSha256Matched,
                      actualLibcMap,allResolvers,sourceRX,returnCodes) ||
                   !returnCodes.originalSHA256Pinned ||
                   returnCodes.checkedNonzero!=45 ||
                   returnCodes.sourceRX!=45 ||
                   returnCodes.guestRX!=45 ||
                   returnCodes.firstEightSourceGuestEqual!=45 ||
                   returnCodes.distinctResultCodeAddresses+
                      returnCodes.duplicatedResultCodeAddresses!=45 ||
                   returnCodes.guestRelocationStoreRIPsTraced ||
                   returnCodes.originalIFUNCResolverInvocationsProven ||
                   returnCodes.storedResultsSemanticallyCorrectProven ||
                   returnCodes.originalLoaderRelocationClosureProven ||
                   RightsAt(SourceMainRelroPage)!=beforeRights){
                  std::fputs(
                    "KERNIX_G0_LIBC_45_IFUNC_RETURN_CODE_SOURCE_REJECT\n",
                    stderr);
                  _exit(241);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_LIBC_45_IFUNC_RETURN_CODE_SOURCE_GUEST_READONLY"
                  " nonzero=45 source_rx=%zu guest_rx=%zu"
                  " source_guest_first8_equal=%zu"
                  " unique_return_addresses=%zu aliased_return_addresses=%zu"
                  " original_libc_sha=1 native_guest_rx=1"
                  " no_ifunc_invocation_proof=1"
                  " stored_result_semantics_unproven=1"
                  " no_loader_store_rips_proven=1"
                  " original_ldso_relocation_closure_unproven=1"
                  " main_relro_unsealed=1 no_guest_write=1\n",
                  returnCodes.sourceRX,returnCodes.guestRX,
                  returnCodes.firstEightSourceGuestEqual,
                  returnCodes.distinctResultCodeAddresses,
                  returnCodes.duplicatedResultCodeAddresses);
                // Main RELRO stays writable. Validate eleven forged
                // mprotect classifications and five source-opcode spoof
                // cases using only local trap copies/read-only source.
                kernix::g0::relrospoof::Witness spoofDenied{};
                if(!kernix::g0::relrospoof::
                     RejectSixteenSpoofedOriginalMainRELRORequests(
                       interpreterSnapshot.bytes(),
                       interpreterSnapshot.size(),
                       OriginalVerifiedSource.exactSha256Matched,
                       Owner,SourceExecPolicy,NativeWXApplied,
                       next.decoded,frame->State.rip,
                       next.decoded.nextGuestRIP,SourceMainRelroPage,
                       beforeRights=="rw-p",spoofDenied) ||
                   spoofDenied.invalidMainMprotectDenied!=11 ||
                   spoofDenied.invalidSourceOpcodeDenied!=5 ||
                   !spoofDenied.originalMainPageStillRW ||
                   spoofDenied.originalLoaderSealOrFullRelocationClaim ||
                   spoofDenied.testedOnAndroid ||
                   RightsAt(SourceMainRelroPage)!=beforeRights) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_MAIN_RELRO_SPOOF_NEGATIVE_CONTROLS_REJECT\n",
                    stderr);
                  _exit(218);
                }
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_MAIN_RELRO_SPOOF_NEGATIVE_CONTROLS_PASS"
                  " forged_mprotect_denied=%u forged_opcode_denied=%u"
                  " original_main_relro_rw_unchanged=1"
                  " no_guest_or_host_write=1"
                  " no_original_ldso_full_relocation_proof=1"
                  " android_device_not_tested=1\n",
                  spoofDenied.invalidMainMprotectDenied,
                  spoofDenied.invalidSourceOpcodeDenied);
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_MAIN_PT_GNU_RELRO"
                  "_AFTER_LIBC_RELRO_NEXT_MPROTECT10_SOURCE_ONLY_PASS"
                  " addr=%llx len=1000 prot=1 rights=rw-p"
                  " NOT_SEALED_NO_FULL_RELOCATION_PROOF\n",
                  static_cast<unsigned long long>(SourceMainRelroPage));
                std::fflush(stderr);
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_MAIN_RELRO_GUEST_MPROTECT10)
                // REAL original guest x86 trap, not the authored fixture
                // syscall. The underlying source-pinned FEX CPUState
                // + original ld-linux RX opcode + exact owned PT_GNU_RELRO
                // have been authenticated above in this SAME process.
                // Read-only value verification is NOT falsely labeled
                // source GNU store-RIP coverage; that exists as a separate
                // same-source real FEX hardware run and 8/8 replay.
                if(!OriginalVerifiedSource.exactSha256Matched ||
                   !MainSymbolicAtLibcRELROCaptured ||
                   !ThreeRelativeAtLibcRELROCaptured ||
                   !LibcMprotectOpcodeAuthenticated ||
                   SourceMainRelroPage!=0x800003000ULL ||
                   frame->State.rip!=0x801025db9ULL ||
                   mainMprotectOpcode.guestRIP!=frame->State.rip ||
                   !targets.sourceMainELF64DynamicVerified ||
                   targets.relativeTargetsMatchingLoadBiasAddend!=2 ||
                   targets.relativeTargetsNotMatchingExpected!=0 ||
                   targets.relativeTargetsInRELRO!=2 ||
                   targets.symbolicTargetsGlobDat!=5 ||
                   targets.symbolicTargetsLiveZero!=3 ||
                   targets.symbolicTargetsLiveNonzero!=2 ||
                   !MainPLTAtLibcRELROCaptured ||
                   RightsAt(SourceMainRelroPage+4096)!="rw-p") {
                  std::fputs("KERNIX_G0_FEX_ORIGINAL_MAIN_NATIVE_RELRO_STAGE_EIGHT_SOURCE_VALUES_PRECONDITION_REJECT\n",stderr);
                  _exit(238);
                }
                const auto sealed=
                  kernix::g0::originalmainnative::SealExactlyOneOwnedOriginalMainPage(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                    OriginalVerifiedSource.exactSha256Matched,
                    mainMprotectOpcode.originalGNUInterpreterPinnedSource &&
                      mainMprotectOpcode.sourceAndGuestOpcodeIdentical &&
                      mainMprotectOpcode.guestPageOwnedOriginalRX &&
                      mainMprotectOpcode.guestRIP==frame->State.rip &&
                      next.decoded.nextGuestRIP==frame->State.rip+2,
                    OriginalLibcRELROMprotectCalls==1 &&
                      RightsAt(SourceFileKernel.OriginalLibcLargeReadonlyMap().Address()+0x1ff000ULL)=="r--p",
                    targets.sourceRelaTargetsInThisRELROPage==7 &&
                      targets.sourceMainPLTRelaEntries==1,
                    RightsAt);
                if(sealed.guestReturn!=0 ||
                   !sealed.authenticOriginalGNUTrapAndSourcePage ||
                   !sealed.eightSourceMainRelocationQwordsExactNow ||
                   !sealed.actualHostKernelMprotectSucceeded ||
                   !sealed.nativeOwnedOriginalMainPageReadOnly ||
                   !sealed.adjacentOriginalMainDataPageStillWritable ||
                   !sealed.realChildAttemptedWriteWasDeniedBySIGSEGV ||
                   sealed.originalLdsoSelfIRELATIVEExecuted ||
                   sealed.AndroidBionicOrWineGameProven ||
                   RightsAt(SourceMainRelroPage)!="r--p" ||
                   RightsAt(SourceMainRelroPage+4096)!="rw-p") {
                  std::fprintf(stderr,
                    "KERNIX_G0_REAL_FEX_GNU_MAIN_RELRO_NATIVE_MPROTECT_FAIL_CLOSED"
                    " return=%lld authentic=%u eight_values=%u"
                    " kernel=%u ro=%u next_rw=%u child_denied=%u\n",
                    static_cast<long long>(sealed.guestReturn),
                    unsigned(sealed.authenticOriginalGNUTrapAndSourcePage),
                    unsigned(sealed.eightSourceMainRelocationQwordsExactNow),
                    unsigned(sealed.actualHostKernelMprotectSucceeded),
                    unsigned(sealed.nativeOwnedOriginalMainPageReadOnly),
                    unsigned(sealed.adjacentOriginalMainDataPageStillWritable),
                    unsigned(sealed.realChildAttemptedWriteWasDeniedBySIGSEGV));
                  _exit(239);
                }
                // ONLY after the real kernel RO + child SIGSEGV proof
                // may original guest x86 see Linux syscall10 RAX=0.
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_LDSO_SELF_RELRO_8K)
                OriginalMainGuestRELRORealSealed=true;
#endif
                frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED"
                  " guest_rip=801025db9 target=800003000 len=1000 prot=1"
                  " native_rights=r--p next_guest_page=rw-p"
                  " eight_original_main_values_verified=1"
                  " actual_host_mprotect_succeeded=1 guest_rax_zero_after_kernel=1"
                  " ldso_self_IFUNC_not_yet_proven=1 android_games_not_tested=1\n");
                std::fflush(stderr);
                return;
#else
                // Original baseline remains diagnostic-only. No host
                // mprotect and no invented original guest return value.
#endif
              }
#endif
              std::fprintf(stderr,
                "KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL num=%llu rip=%llx rdi=%llx rsi=%llx rdx=%llx r10=%llx r8=%llx r9=%llx\n",
                static_cast<unsigned long long>(next.decoded.guestNumber),
                static_cast<unsigned long long>(frame->State.rip),
                static_cast<unsigned long long>(next.decoded.args[0]),
                static_cast<unsigned long long>(next.decoded.args[1]),
                static_cast<unsigned long long>(next.decoded.args[2]),
                static_cast<unsigned long long>(next.decoded.args[3]),
                static_cast<unsigned long long>(next.decoded.args[4]),
                static_cast<unsigned long long>(next.decoded.args[5]));
              std::fflush(stderr);
              _exit(117);
            }
            if(next.decoded.guestNumber==c1::kClose) {
              if(RealOriginalLdsoLibcOpens!=1 ||
                 RealOriginalLdsoLibcReads!=1 ||
                 RealOriginalLdsoLibcPreads<2 ||
                 RealOriginalLdsoLibcFstats!=1 ||
                 RealOriginalLdsoLibcMmaps!=5 ||
                 RealOriginalLdsoLibcCloses!=0 ||
                 SourceFileKernel.OpenCount()!=1) {
                std::fputs(
                  "KERNIX_G0_ORIGINAL_LIBC_CLOSE3_AFTER_BSS_PRECONDITION_REJECT\n",stderr);
                _exit(154);
              }
              const auto originalBase=
                SourceFileKernel.OriginalLibcLargeReadonlyMap().Address();
              const auto response=
                SourceFileKernel.DispatchOriginalLdsoPinnedLibcCloseAfterBSS(
                  next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
              if(!response.guestSyscallAuthenticated ||
                 !response.guestFdClosed ||
                 response.guestReturn!=0 ||
                 response.hostPathOpened || response.hostGuestFdForwarded ||
                 response.hostAnyUntrustedSyscallForwarded ||
                 SourceFileKernel.OpenCount()!=0 ||
                 !SourceFileKernel.OriginalLibcClosedAfterBSS() ||
                 SourceFileKernel.OriginalLibcLargeReadonlyMap().Address()!=originalBase ||
                 SourceFileKernel.OriginalLibcLargeReadonlyMap().BytesHeld()!=0x212000ULL ||
                 RightsAt(originalBase)!="r--p" ||
                 RightsAt(originalBase+0x28000ULL)!="r-xp" ||
                 RightsAt(originalBase+0x1b0000ULL)!="r--p" ||
                 RightsAt(originalBase+0x1ff000ULL)!="rw-p" ||
                 RightsAt(originalBase+0x205000ULL)!="rw-p") {
                std::fputs(
                  "KERNIX_G0_ORIGINAL_LIBC_CLOSE3_FD_OR_MAPPED_PTLOAD_REJECT\n",stderr);
                _exit(155);
              }
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
              // The authentic loader has just mapped all libc PT_LOAD
              // pages and completed close(3), but no simulated linker
              // writes are performed by this observer. Record the
              // pristine original 1067 RELR and 147 RELA/JMPREL targets
              // before original ld-linux returns to relocation work.
              const auto& beforeLibcSource=OriginalVerifiedSource.snapshots[2];
              const auto& beforeLibcMap=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap();
              const auto sourceLibcReadable=[&](uint64_t address) noexcept {
                const auto permissions=RightsAt(address);
                return c1::GuestRange(address,8) &&
                    (permissions=="r--p" || permissions=="rw-p") &&
                    address>=beforeLibcMap.Address() &&
                    address-beforeLibcMap.Address()<=
                        beforeLibcMap.BytesHeld()-8;
              };
              if(LibcRELRAtSourceCloseCaptured ||
                 LibcRelaAtSourceCloseCaptured ||
                 !beforeLibcSource.readOnlySnapshot() ||
                 !beforeLibcSource.bytes() ||
                 !kernix::g0::libcrelr::
                   SampleOriginalLibc1067RELRReadOnly(
                     beforeLibcSource.bytes(),beforeLibcSource.size(),
                     OriginalVerifiedSource.exactSha256Matched,
                     beforeLibcMap,sourceLibcReadable,
                     LibcRELRAtSourceClose) ||
                 !kernix::g0::libcrela::
                   SampleOriginalLibc147RelaJmprelReadonly(
                     beforeLibcSource.bytes(),beforeLibcSource.size(),
                     OriginalVerifiedSource.exactSha256Matched,
                     beforeLibcMap,sourceLibcReadable,
                     LibcRelaAtSourceClose) ||
                 !LibcRELRAtSourceClose.originalLibcSHAProven ||
                 !LibcRelaAtSourceClose.originalSourceShaPinned ||
                 LibcRELRAtSourceClose.count!=1067 ||
                 LibcRELRAtSourceClose.liveEqualSource!=1067 ||
                 LibcRELRAtSourceClose.liveEqualExpected!=0 ||
                 LibcRelaAtSourceClose.count!=147 ||
                 LibcRelaAtSourceClose.liveMatchesSource!=147 ||
                 LibcRELRAtSourceClose.actualGuestStoreRIPsTraced ||
                 LibcRelaAtSourceClose.guestStoreInstructionsTraced ||
                 RightsAt(originalBase+0x1ff000ULL)!="rw-p"){
                std::fputs(
                  "KERNIX_G0_LIBC_PRISTINE_RELOCATIONS_CLOSE3_REJECT\n",
                  stderr);
                _exit(248);
              }
              LibcRELRAtSourceCloseCaptured=true;
              LibcRelaAtSourceCloseCaptured=true;
              std::fprintf(stderr,
                "KERNIX_G0_LIBC_1214_ORIGINAL_RELOCATION_TARGETS_PRISTINE_AFTER_CLOSE3"
                " relr=1067 rela_jmprel=147 relr_source_equal=%zu"
                " rela_source_equal=%zu relr_expected_before=%zu"
                " exact_libc_sha=1 before_original_libc_relocation=1"
                " original_guest_store_rips_untraced=1"
                " original_ifunc_execution_unproven=1"
                " original_main_relro_unsealed=1 no_guest_write=1\n",
                LibcRELRAtSourceClose.liveEqualSource,
                LibcRelaAtSourceClose.liveMatchesSource,
                LibcRELRAtSourceClose.liveEqualExpected);
              std::fflush(stderr);
#endif
              ++RealOriginalLdsoLibcCloses;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
              frame->State.rip=next.decoded.nextGuestRIP;
              std::fprintf(stderr,
                "KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_CLOSE3_AFTER_FIFTH_BSS_SYNTHETIC_FD100_ONLY_MAPPED_RO_RX_RW_PTLOADS_REMAIN_PASS base=%llx NO_HOST_CLOSE\n",
                static_cast<unsigned long long>(originalBase));
              std::fflush(stderr);
              return;
            }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_READ_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
            if(next.decoded.guestNumber==c1::kRead){
              if(RealOriginalLdsoLibcOpens!=1 ||
                 RealOriginalLdsoLibcReads!=0 ||
                 SourceFileKernel.OpenCount()!=1 ||
                 next.decoded.args[2]!=832){
                std::fputs("KERNIX_G0_ORIGINAL_LDSO_LIBC_READ_DUPLICATE_OR_SIZE_REJECT\n",stderr);
                _exit(134);
              }
              const auto got=
                SourceFileKernel.DispatchOriginalLdsoPinnedLibcReadToStack(
                  next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                  RightsAt(next.decoded.args[1])=="rw-p");
              if(!got.guestSyscallAuthenticated ||
                 !got.copiedSnapshotToAuthenticatedGuestWritable ||
                 got.hostPathOpened || got.hostGuestFdForwarded ||
                 got.hostAnyUntrustedSyscallForwarded ||
                 got.guestReturn!=832){
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_LIBC_READ_GUEST_STACK_REJECT code=%lld\n",
                  static_cast<long long>(got.guestReturn));
                _exit(135);
              }
              // Independent original libc ELF64 header witness from the
              // authenticated guest destination of the genuine x86 read.
              constexpr unsigned char kElf64Magic[]{0x7f,'E','L','F',2,1,1};
              const auto* actual=reinterpret_cast<const unsigned char*>(
                  static_cast<uintptr_t>(next.decoded.args[1]));
              if(std::memcmp(actual,kElf64Magic,sizeof(kElf64Magic))!=0)
                _exit(136);
              ++RealOriginalLdsoLibcReads;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(got.guestReturn);
              frame->State.rip=next.decoded.nextGuestRIP;
              std::fputs(
                "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_SYNTHETIC_FD_READ_832_SOURCE_ELF64_TO_OWNED_GUEST_STACK_PASS_NO_HOST_READ\n",
                stderr);
              std::fflush(stderr);
              return;
            }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
            if(next.decoded.guestNumber==c1::kPread64) {
              const uint64_t requested=next.decoded.args[2];
              const uint64_t offset=next.decoded.args[3]; // true x86 R10
              const bool first=(RealOriginalLdsoLibcPreads==0);
              const bool firstBound=first &&
                  RealOriginalLdsoLibcFstats==0 && requested==784;
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              // After real fstat, the authentic GNU loader issues
              // another pread64 on the SAME synthetic original libc FD.
              // No guesses about source offsets or exact request counts.
              // Bound repeats to eight requests per diagnostic process,
              // each with independently verified owned stack and 4K cap.
              const bool followup=!first &&
                  RealOriginalLdsoLibcFstats==1 &&
                  RealOriginalLdsoLibcPreads<8 &&
                  requested>0 && requested<=4096;
#else
              const bool followup=false; // old pread-only gate unchanged
#endif
              if(RealOriginalLdsoLibcOpens!=1 ||
                 RealOriginalLdsoLibcReads!=1 ||
                 SourceFileKernel.OpenCount()!=1 ||
                 (!firstBound && !followup)) {
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_LIBC_PREAD64_AUTH_OR_BOUND_REJECT call=%zu fs=%zu bytes=%llu offset=%llx\n",
                  RealOriginalLdsoLibcPreads+1,RealOriginalLdsoLibcFstats,
                  static_cast<unsigned long long>(requested),
                  static_cast<unsigned long long>(offset));
                _exit(137);
              }
              const auto got=
                SourceFileKernel.DispatchOriginalLdsoPinnedLibcPreadToStack(
                  next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                  RightsAt(next.decoded.args[1])=="rw-p");
              if(!got.guestSyscallAuthenticated ||
                 !got.copiedSnapshotToAuthenticatedGuestWritable ||
                 got.hostPathOpened || got.hostGuestFdForwarded ||
                 got.hostAnyUntrustedSyscallForwarded ||
                 got.guestReturn!=static_cast<int64_t>(requested)) {
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_LIBC_PREAD64_GUEST_STACK_REJECT call=%zu code=%lld bytes=%llu offset=%llx\n",
                  RealOriginalLdsoLibcPreads+1,
                  static_cast<long long>(got.guestReturn),
                  static_cast<unsigned long long>(requested),
                  static_cast<unsigned long long>(offset));
                _exit(138);
              }
              ++RealOriginalLdsoLibcPreads;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(got.guestReturn);
              frame->State.rip=next.decoded.nextGuestRIP;
              if(first) {
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_SYNTHETIC_FD_PREAD64_784_SOURCE_OFFSET_%llx_OWNED_GUEST_STACK_PASS_NO_HOST_PREAD\n",
                  static_cast<unsigned long long>(offset));
              } else {
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_POST_FSTAT_FOLLOWUP_PREAD64_SOURCE_OFFSET_%llx_COUNT_%llu_CALL_%zu_OWNED_GUEST_STACK_PASS_NO_HOST_PREAD\n",
                  static_cast<unsigned long long>(offset),
                  static_cast<unsigned long long>(requested),
                  RealOriginalLdsoLibcPreads);
              }
              std::fflush(stderr);
              return;
            }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
            if(next.decoded.guestNumber==c1::kFstat) {
              if(RealOriginalLdsoLibcOpens!=1 ||
                 RealOriginalLdsoLibcReads!=1 ||
                 RealOriginalLdsoLibcPreads!=1 ||
                 RealOriginalLdsoLibcFstats!=0 ||
                 SourceFileKernel.OpenCount()!=1) {
                std::fputs("KERNIX_G0_ORIGINAL_LDSO_LIBC_FSTAT5_REPEATED_OR_UNBOUND_REJECT\n",stderr);
                _exit(139);
              }
              const auto got=
                SourceFileKernel.DispatchOriginalLdsoPinnedLibcFstatToStack(
                  next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                  RightsAt(next.decoded.args[1])=="rw-p");
              if(!got.guestSyscallAuthenticated || !got.guestVirtualStatWritten ||
                 got.hostPathOpened || got.hostGuestFdForwarded ||
                 got.hostAnyUntrustedSyscallForwarded || got.guestReturn!=0) {
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_LIBC_FSTAT5_GUEST_STACK_REJECT rc=%lld\n",
                  static_cast<long long>(got.guestReturn));
                _exit(140);
              }
              kernix::g0::statabi::LinuxX86_64Stat sourceStat{};
              std::memcpy(&sourceStat,
                reinterpret_cast<const void*>(
                  static_cast<uintptr_t>(next.decoded.args[1])),
                sizeof(sourceStat));
              if(sourceStat.size!=2118168 ||
                 sourceStat.mode!=0100444U ||
                 sourceStat.blockSize!=4096 ||
                 sourceStat.hardLinks!=1 ||
                 sourceStat.allocated512Blocks!=(2118168+511)/512 ||
                 sourceStat.inode!=0x7e262ac92a454f36ULL ||
                 sourceStat.reserved[0]!=0 ||
                 sourceStat.reserved[1]!=0 ||
                 sourceStat.reserved[2]!=0) {
                std::fputs("KERNIX_G0_ORIGINAL_LDSO_LIBC_X86_STAT144_ABI_FIELDS_REJECT\n",stderr);
                _exit(141);
              }
              ++RealOriginalLdsoLibcFstats;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=0;
              frame->State.rip=next.decoded.nextGuestRIP;
              std::fprintf(stderr,
                "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_FSTAT5_VIRTUAL_X86_64_STAT144_SOURCE_SIZE_%lld_OWNED_GUEST_STACK_PASS_NO_HOST_FSTAT\n",
                static_cast<long long>(sourceStat.size));
              std::fflush(stderr);
              return;
            }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
            if(next.decoded.guestNumber==c1::kMmap) {
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoLibcMmaps==4) {
                if(RealOriginalLdsoLibcOpens!=1 ||
                   RealOriginalLdsoLibcReads!=1 ||
                   RealOriginalLdsoLibcPreads<2 ||
                   RealOriginalLdsoLibcFstats!=1 ||
                   SourceFileKernel.OpenCount()!=1) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LIBC_FIFTH_ANON_BSS_INCOMPLETE_SOURCE_ORDER_REJECT\n",stderr);
                  _exit(151);
                }
                const auto bss=
                  SourceFileKernel.DispatchOriginalLdsoPinnedLibcOwnedAnonymousBSS(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                const auto& original=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap();
                const uint64_t bssStart=original.Address()+0x205000ULL;
                const uint64_t rxStart=original.Address()+0x28000ULL;
                const uint64_t roStart=original.Address()+0x1b0000ULL;
                const uint64_t dataStart=original.Address()+0x1ff000ULL;
                const uint64_t bssEndPage=original.Address()+0x211000ULL;
                if(!bss.sourceOriginalRWPTLoadMemExtentVerified ||
                   !bss.originalOwnedAnonymousZeroMapped ||
                   !bss.alreadyOwnedPagesNowOnlyReadWrite ||
                   !bss.noNativeMAPFIXEDOrHostFdForwarding ||
                   bss.writableExecutableEverGranted ||
                   !original.OriginalSourceWritablePTLoadConfirmed() ||
                   !original.OriginalOwnedBSSZeroed() ||
                   bss.guestReturn!=static_cast<int64_t>(bssStart) ||
                   RightsAt(original.Address())!="r--p" ||
                   RightsAt(rxStart)!="r-xp" ||
                   RightsAt(roStart)!="r--p" ||
                   RightsAt(dataStart)!="rw-p" ||
                   RightsAt(bssStart)!="rw-p" ||
                   RightsAt(bssEndPage)!="rw-p" ||
                   original.BytesHeld()!=0x212000ULL) {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_FIFTH_BSS_ZERO_OR_WX_RIGHTS_REJECT code=%lld addr=%llx len=%llx prot=%llx flags=%llx fd=%llx offset=%llx\n",
                    static_cast<long long>(bss.guestReturn),
                    static_cast<unsigned long long>(next.decoded.args[0]),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(next.decoded.args[2]),
                    static_cast<unsigned long long>(next.decoded.args[3]),
                    static_cast<unsigned long long>(next.decoded.args[4]),
                    static_cast<unsigned long long>(next.decoded.args[5]));
                  _exit(152);
                }
                const auto* sample=reinterpret_cast<const uint8_t*>(
                  static_cast<uintptr_t>(bssStart));
                if(sample[0]!=0 || sample[0x1000]!=0 ||
                   sample[0xc000]!=0 || sample[0xcfff]!=0) {
                  std::fputs("KERNIX_G0_ORIGINAL_LIBC_FIFTH_BSS_REAL_GUEST_ZERO_SAMPLE_REJECT\n",stderr);
                  _exit(153);
                }
                ++RealOriginalLdsoLibcMmaps;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(bss.guestReturn);
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_FIFTH_ANONYMOUS_BSS_MMAP_ORIGINAL_RW_PTLOAD_SOURCE_MEM_END_0x211d90_ZERO_0xcd90_OWNED_NO_NATIVE_FIXED_NO_WX_PASS base=%llx\n",
                  static_cast<unsigned long long>(bssStart));
                std::fflush(stderr);
                return;
              }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoLibcMmaps==3) {
                if(RealOriginalLdsoLibcOpens!=1 ||
                   RealOriginalLdsoLibcReads!=1 ||
                   RealOriginalLdsoLibcPreads<2 ||
                   RealOriginalLdsoLibcFstats!=1 ||
                   SourceFileKernel.OpenCount()!=1) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LIBC_FOURTH_RW_MMAP_INCOMPLETE_SOURCE_ORDER_REJECT\n",stderr);
                  _exit(149);
                }
                const auto rw=
                  SourceFileKernel.DispatchOriginalLdsoPinnedLibcOwnedWritablePTLoad(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                const auto& original=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap();
                const uint64_t rwStart=original.Address()+0x1ff000ULL;
                const uint64_t originalRX=original.Address()+0x28000ULL;
                const uint64_t originalRO=original.Address()+0x1b0000ULL;
                const uint64_t beyondEOF=original.Address()+
                  kernix::g0::PinnedLibcLargeReadonlyGuestMap::RoundUp(
                    kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize);
                if(!rw.originalRWPTLoadVaddrOffsetVerified ||
                   !rw.fileSourceSubrangeVerified ||
                   !rw.nativeOwnedReadWriteApplied ||
                   !rw.noHostFixedMappingOrGuestFileFDForwarding ||
                   rw.writableExecutableEverGranted ||
                   !original.OriginalSourceTextRXSealed() ||
                   !original.OriginalSourceReadOnlyPTLoadConfirmed() ||
                   !original.OriginalSourceWritablePTLoadConfirmed() ||
                   rw.guestReturn!=static_cast<int64_t>(rwStart) ||
                   RightsAt(original.Address())!="r--p" ||
                   RightsAt(originalRX)!="r-xp" ||
                   RightsAt(originalRO)!="r--p" ||
                   RightsAt(rwStart)!="rw-p" ||
                   RightsAt(beyondEOF)!="---p") {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_FOURTH_RW_MMAP_SOURCE_PTLOAD_SHIFT_OR_RIGHTS_REJECT code=%lld addr=%llx len=%llx prot=%llx flags=%llx fd=%llx offset=%llx\n",
                    static_cast<long long>(rw.guestReturn),
                    static_cast<unsigned long long>(next.decoded.args[0]),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(next.decoded.args[2]),
                    static_cast<unsigned long long>(next.decoded.args[3]),
                    static_cast<unsigned long long>(next.decoded.args[4]),
                    static_cast<unsigned long long>(next.decoded.args[5]));
                  _exit(150);
                }
                ++RealOriginalLdsoLibcMmaps;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(rw.guestReturn);
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_FOURTH_FIXED_RW_MMAP_PTLOAD_OFFSET_SHIFT_SOURCE_0x1fe000_TO_VADDR_0x1ff000_LENGTH_0x6000_NO_NATIVE_FIXED_NO_WX_PASS base=%llx\n",
                  static_cast<unsigned long long>(rwStart));
                std::fflush(stderr);
                return;
              }
              [[maybe_unused]] constexpr size_t kStopAfterVerifiedMaps=
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
                5;
#else
                4;
#endif
#if !defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) && \
    !defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) && \
    !defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) && \
    !defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) && \
    !defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) && \
    !defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoLibcMmaps>=kStopAfterVerifiedMaps) {
                std::fprintf(stderr,
                  "KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL num=%llu rip=%llx rdi=%llx rsi=%llx rdx=%llx r10=%llx r8=%llx r9=%llx\n",
                  static_cast<unsigned long long>(next.decoded.guestNumber),
                  static_cast<unsigned long long>(frame->State.rip),
                  static_cast<unsigned long long>(next.decoded.args[0]),
                  static_cast<unsigned long long>(next.decoded.args[1]),
                  static_cast<unsigned long long>(next.decoded.args[2]),
                  static_cast<unsigned long long>(next.decoded.args[3]),
                  static_cast<unsigned long long>(next.decoded.args[4]),
                  static_cast<unsigned long long>(next.decoded.args[5]));
                std::fflush(stderr);
                _exit(117);
              }
#endif // close-after-BSS probe skips previous stop
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoLibcMmaps==2) {
                if(RealOriginalLdsoLibcOpens!=1 ||
                   RealOriginalLdsoLibcReads!=1 ||
                   RealOriginalLdsoLibcPreads<2 ||
                   RealOriginalLdsoLibcFstats!=1 ||
                   SourceFileKernel.OpenCount()!=1) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LIBC_THIRD_RO_MMAP_INCOMPLETE_SOURCE_ORDER_REJECT\n",stderr);
                  _exit(147);
                }
                const auto ro=
                  SourceFileKernel.DispatchOriginalLdsoPinnedLibcOwnedReadOnlyPTLoad(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                const auto& original=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap();
                const uint64_t roStart=original.Address()+0x1b0000ULL;
                const uint64_t textStart=original.Address()+0x28000ULL;
                const uint64_t eofGuard=original.Address()+
                  kernix::g0::PinnedLibcLargeReadonlyGuestMap::RoundUp(
                    kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize);
                if(!ro.originalReadOnlyPTLoadSourceVerified ||
                   !ro.originalSourceContentsUnchanged ||
                   !ro.nativeOwnedExistingReadOnlyPagesPreserved ||
                   !ro.noNativeMAPFIXEDOrUntrustedHostFD ||
                   ro.guestWritableExecutableEverGranted ||
                   !original.OriginalSourceTextRXSealed() ||
                   !original.OriginalSourceReadOnlyPTLoadConfirmed() ||
                   ro.guestReturn!=static_cast<int64_t>(roStart) ||
                   RightsAt(original.Address())!="r--p" ||
                   RightsAt(textStart)!="r-xp" ||
                   RightsAt(roStart)!="r--p" ||
                   RightsAt(eofGuard)!="---p") {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_THIRD_RO_MMAP_SOURCE_PTLOAD_OR_NATIVE_RIGHTS_REJECT code=%lld addr=%llx len=%llx prot=%llx flags=%llx fd=%llx offset=%llx\n",
                    static_cast<long long>(ro.guestReturn),
                    static_cast<unsigned long long>(next.decoded.args[0]),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(next.decoded.args[2]),
                    static_cast<unsigned long long>(next.decoded.args[3]),
                    static_cast<unsigned long long>(next.decoded.args[4]),
                    static_cast<unsigned long long>(next.decoded.args[5]));
                  _exit(148);
                }
                ++RealOriginalLdsoLibcMmaps;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(ro.guestReturn);
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_THIRD_FIXED_RO_MMAP_PTLOAD_VERIFIED_SOURCE_NO_NATIVE_FIXED_NO_WX_PASS base=%llx length=0x4f000 offset=0x1b0000\n",
                  static_cast<unsigned long long>(roStart));
                std::fflush(stderr);
                return;
              }
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
              if(RealOriginalLdsoLibcMmaps==1) {
                if(RealOriginalLdsoLibcOpens!=1 ||
                   RealOriginalLdsoLibcReads!=1 ||
                   RealOriginalLdsoLibcPreads<2 ||
                   RealOriginalLdsoLibcFstats!=1 ||
                   SourceFileKernel.OpenCount()!=1) {
                  std::fputs(
                    "KERNIX_G0_ORIGINAL_LIBC_SECOND_RX_MMAP_INCOMPLETE_SOURCE_ORDER_REJECT\n",
                    stderr);
                  _exit(145);
                }
                const auto rx=
                  SourceFileKernel.DispatchOriginalLdsoPinnedLibcOwnedTextRX(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
                const auto& original=
                  SourceFileKernel.OriginalLibcLargeReadonlyMap();
                const uint64_t textStart=original.Address()+0x28000ULL;
                const uint64_t sourceEOF=original.Address()+
                  kernix::g0::PinnedLibcLargeReadonlyGuestMap::RoundUp(
                    kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize);
                if(!rx.originalSourceRXPTLoadValidated ||
                   !rx.originalBytesUnchangedAfterMapping ||
                   !rx.nativeOwnedReadExecuteApplied ||
                   !rx.noNativeMAPFIXEDOrGuestFDForwarding ||
                   rx.guestWritableExecutableEverGranted ||
                   !original.OriginalSourceTextRXSealed() ||
                   rx.guestReturn!=static_cast<int64_t>(textStart) ||
                   RightsAt(original.Address())!="r--p" ||
                   RightsAt(textStart)!="r-xp" ||
                   RightsAt(sourceEOF)!="---p") {
                  std::fprintf(stderr,
                    "KERNIX_G0_ORIGINAL_LIBC_SECOND_RX_MMAP_PTLOAD_OR_RIGHTS_REJECT code=%lld addr=%llx len=%llx prot=%llx flags=%llx fd=%llx offset=%llx\n",
                    static_cast<long long>(rx.guestReturn),
                    static_cast<unsigned long long>(next.decoded.args[0]),
                    static_cast<unsigned long long>(next.decoded.args[1]),
                    static_cast<unsigned long long>(next.decoded.args[2]),
                    static_cast<unsigned long long>(next.decoded.args[3]),
                    static_cast<unsigned long long>(next.decoded.args[4]),
                    static_cast<unsigned long long>(next.decoded.args[5]));
                  _exit(146);
                }
                ++RealOriginalLdsoLibcMmaps;
                frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(rx.guestReturn);
                frame->State.rip=next.decoded.nextGuestRIP;
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LIBC_SECOND_FIXED_TEXT_MMAP_PTLOAD_VERIFIED_RX_NO_NATIVE_FIXED_NO_WX_PASS base=%llx length=0x188000 offset=0x28000\n",
                  static_cast<unsigned long long>(textStart));
                std::fflush(stderr);
                return;
              }
#endif
              if(RealOriginalLdsoLibcOpens!=1 ||
                 RealOriginalLdsoLibcReads!=1 ||
                 RealOriginalLdsoLibcPreads<2 ||
                 RealOriginalLdsoLibcFstats!=1 ||
                 RealOriginalLdsoLibcMmaps!=0 ||
                 SourceFileKernel.OpenCount()!=1) {
                // The next original glibc mmap may be a distinct segment
                // permission transition (e.g. MAP_FIXED). NEVER infer that:
                // capture authentic FEX x86 registers, then deny without
                // overwriting the already-owned read-only source mapping.
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_PRECONDITION_REJECT after_first=%zu addr=%llx len=%llx prot=%llx flags=%llx fd=%llx offset=%llx\n",
                  RealOriginalLdsoLibcMmaps,
                  static_cast<unsigned long long>(next.decoded.args[0]),
                  static_cast<unsigned long long>(next.decoded.args[1]),
                  static_cast<unsigned long long>(next.decoded.args[2]),
                  static_cast<unsigned long long>(next.decoded.args[3]),
                  static_cast<unsigned long long>(next.decoded.args[4]),
                  static_cast<unsigned long long>(next.decoded.args[5]));
                std::fflush(stderr);
                _exit(142);
              }
              const auto mapped=
                SourceFileKernel.DispatchOriginalLdsoPinnedLibcLargeReadonlyMmap(
                  next.decoded,Owner,SourceExecPolicy,NativeWXApplied);
              const auto& large=SourceFileKernel.OriginalLibcLargeReadonlyMap();
              if(!mapped.guestSyscallAuthenticated ||
                 !mapped.guestOriginalLibcLargeReadonlyMapped ||
                 !mapped.guestOriginalLibcBeyondEOFInaccessible ||
                 mapped.hostPathOpened || mapped.hostGuestFdForwarded ||
                 mapped.hostAnyUntrustedSyscallForwarded ||
                 mapped.guestReturn<65536 ||
                 large.Address()!=static_cast<uint64_t>(mapped.guestReturn) ||
                 large.BytesHeld()!=
                   kernix::g0::PinnedLibcLargeReadonlyGuestMap::RoundUp(
                     kernix::g0::PinnedLibcLargeReadonlyGuestMap::kExpectedGuestLength) ||
                 !c1::GuestRange(large.Address(),large.BytesHeld())) {
                std::fprintf(stderr,
                  "KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_GUEST_OWNER_REJECT code=%lld flags=%llx fd=%llx off=%llx\n",
                  static_cast<long long>(mapped.guestReturn),
                  static_cast<unsigned long long>(next.decoded.args[3]),
                  static_cast<unsigned long long>(next.decoded.args[4]),
                  static_cast<unsigned long long>(next.decoded.args[5]));
                _exit(143);
              }
              constexpr unsigned char kElf64Magic[]{0x7f,'E','L','F',2,1,1};
              const auto* source=large.AuthenticatedReadonlyBytes(
                large.Address(),sizeof(kElf64Magic));
              const uint64_t firstBeyondFilePage=large.Address()+
                kernix::g0::PinnedLibcLargeReadonlyGuestMap::RoundUp(
                  kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize);
              if(!source ||
                 std::memcmp(source,kElf64Magic,sizeof(kElf64Magic))!=0 ||
                 RightsAt(large.Address())!="r--p" ||
                 RightsAt(firstBeyondFilePage)!="---p") {
                std::fputs("KERNIX_G0_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_WX_EOF_RIGHTS_REJECT\n",stderr);
                _exit(144);
              }
              ++RealOriginalLdsoLibcMmaps;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(mapped.guestReturn);
              frame->State.rip=next.decoded.nextGuestRIP;
              std::fprintf(stderr,
                "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_MMAP9_LARGE_PRIVATE_RO_SOURCE_2118168_REQUEST_0x211d90_FD100_OFFSET0_WX_SAFE_EOF_GUARD_PASS guest_base=%llx\n",
                static_cast<unsigned long long>(large.Address()));
              std::fflush(stderr);
              return;
            }
#endif
#if defined(KERNIX_G0_ENABLE_GUEST_OPENAT257_CACHE) && defined(KERNIX_G0_ENABLE_GUEST_BRK12)
            if(next.decoded.guestNumber==c1::kOpenat){
              if(RealOriginalLdsoCacheOpenCalls>=4){
                 std::fputs("KERNIX_G0_SOURCE_LDSO_CACHE_OPENAT257_REPEATED_UNBOUNDED_REJECT\n",stderr);
                 _exit(129);
              }
              const auto answer=
                gcache::DispatchOriginalLoaderOptionalCacheOpenat(
                  next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                  SourceFileKernel.Bound());
              if(!answer.authenticGuestOpenat ||
                 !answer.originalLdsoSourcePTLoadLiteralValidated ||
                 !answer.optionalVirtualCacheAbsent ||
                 !answer.originalTriadSourceClosureAttested ||
                 answer.guestReturn!=-ENOENT ||
                 answer.nativeHostOpenatCalled ||
                 answer.guestPointerOrPathForwardedToHost ||
                 answer.unsupportedRequestRejected){
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_OPEN_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_READ_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
                // Source-pinned libc only: the genuine GNU loader built
                // its requested file path on an owned RW x86 guest stack.
                // No host openat and no raw path forwarding.
                if(RealOriginalLdsoLibcOpens!=0 ||
                   SourceFileKernel.OpenCount()!=0) {
                  std::fputs("KERNIX_G0_ORIGINAL_LDSO_LIBC_SYNTHETIC_FD_REPEAT_OR_LEAK_REJECT\n",stderr);
                  _exit(132);
                }
                const auto libc=
                  SourceFileKernel.DispatchOriginalLdsoPinnedLibcStackOpenat(
                    next.decoded,Owner,SourceExecPolicy,NativeWXApplied,
                    RightsAt(next.decoded.args[1])=="rw-p");
                if(libc.guestSyscallAuthenticated &&
                   libc.openedPinnedReadonlySnapshot &&
                   !libc.hostPathOpened && !libc.hostGuestFdForwarded &&
                   !libc.hostAnyUntrustedSyscallForwarded &&
                   libc.guestReturn==
                       SourceFileKernel.kGuestBaseFD &&
                   SourceFileKernel.OpenCount()==1) {
                  ++RealOriginalLdsoLibcOpens;
                  frame->State.gregs[FEXCore::X86State::REG_RAX]=
                    static_cast<uint64_t>(libc.guestReturn);
                  frame->State.rip=next.decoded.nextGuestRIP;
                  std::fprintf(stderr,
                    "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_STACK_OPENAT257_SHA_PINNED_SYNTHETIC_FD_PASS fd=%lld NO_HOST_OPEN\n",
                    static_cast<long long>(libc.guestReturn));
                  std::fflush(stderr);
                  return;
                }
                std::fprintf(stderr,
                  "KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_LIBC_STACK_OPENAT257_REJECT guest_error=%lld no_host_open=1\n",
                  static_cast<long long>(libc.guestReturn));
#endif
#if defined(KERNIX_G0_PROBE_UPSTREAM_SIGBUS_BACKPATCH_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_OPEN_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_READ_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
                // Next original GNU ld-linux pathname witness after the
                // TSO-enabled upstream FEX SIGBUS backpatch. Diagnostic ONLY.
                // Copy bounded readable source-owned guest bytes; never trust
                // a raw guest pointer, open its path on the host, or broaden
                // guest filesystem policy based on a merely printed string.
                bool provenSourcePath=false;
                for(size_t module=0;module<3 && !provenSourcePath;++module) {
                  const auto* image=Owner.Module(module);
                  const uint64_t ptr=next.decoded.args[1];
                  if(!image || ptr<image->chosenImageStart ||
                     ptr-image->chosenImageStart>=c7b::kImageCapacity)
                    continue;
                  const uint64_t offset=ptr-image->chosenImageStart;
                  const size_t page=static_cast<size_t>(offset/4096);
                  if(page>=c7g::kModulePages ||
                     (SourceExecPolicy.modules[module].rights[page]&c7g::kRead)==0)
                    continue;
                  constexpr size_t kMaxBytes=96;
                  const size_t pageRemain=4096-static_cast<size_t>(ptr&4095);
                  const size_t count=pageRemain<kMaxBytes?pageRemain:kMaxBytes;
                  const auto* bytes=Owner.GuestReadOnlyBytes(module,ptr,count);
                  if(!bytes)continue;
                  char printable[kMaxBytes+1]{};
                  size_t used=0;
                  for(;used<count && bytes[used]!=0;++used) {
                    const unsigned char v=bytes[used];
                    printable[used]=(v>=32 && v<=126)?static_cast<char>(v):'?';
                  }
                  std::fprintf(stderr,
                    "KERNIX_G0_POST_SIGBUS_OPENAT_SOURCE_PATH_DIAGNOSTIC_ONLY module=%zu source_offset=%llx read_rights=%u bytes=%zu nul_terminated=%d preview=%s\\n",
                    module,static_cast<unsigned long long>(offset),
                    unsigned(SourceExecPolicy.modules[module].rights[page]),
                    used,int(used<count),printable);
                  provenSourcePath=true;
                }
                if(!provenSourcePath){
                  // A genuine dynamic linker may assemble its next search
                  // pathname on its already-owned guest initial stack, not
                  // in the original read-only PT_LOAD. Read *only* the first
                  // mapped owned guest stack page, strictly bounded, with no
                  // guest filename/path forwarded to the native host.
                  bool provenStackPath=false;
                  const auto* launch=Owner.LaunchPlan();
                  const uint64_t guestPtr=next.decoded.args[1];
                  if(launch && guestPtr>=launch->stack.guestBottom &&
                     guestPtr<launch->stack.guestTop &&
                     c1::GuestRange(guestPtr,1) &&
                     RightsAt(guestPtr)=="rw-p"){
                    constexpr size_t kMaxStackPreview=96;
                    const size_t pageRemain=4096-static_cast<size_t>(guestPtr&4095);
                    const uint64_t stackRemain=launch->stack.guestTop-guestPtr;
                    const size_t maxCopy=static_cast<size_t>(
                      std::min<uint64_t>(
                        std::min<uint64_t>(stackRemain,pageRemain),
                        kMaxStackPreview));
                    if(maxCopy!=0 && c1::GuestRange(guestPtr,maxCopy)){
                      std::array<char,kMaxStackPreview+1> printed{};
                      const auto* bytes=reinterpret_cast<const unsigned char*>(
                        static_cast<uintptr_t>(guestPtr));
                      size_t used=0;
                      for(;used<maxCopy && bytes[used]!=0;++used){
                        const unsigned char v=bytes[used];
                        printed[used]=(v>=32 && v<=126)?
                          static_cast<char>(v):'?';
                      }
                      provenStackPath=true;
                      std::fprintf(stderr,
                        "KERNIX_G0_POST_SIGBUS_OPENAT_OWNED_GUEST_STACK_PATH_DIAGNOSTIC_ONLY stack_offset=%llx copied=%zu nul_terminated=%d preview=%s NO_HOST_OPEN\\n",
                        static_cast<unsigned long long>(
                          guestPtr-launch->stack.guestBottom),
                        used,int(used<maxCopy),printed.data());
                    }
                  }
                  if(!provenStackPath)
                    std::fputs(
                      "KERNIX_G0_POST_SIGBUS_OPENAT_PATH_NOT_IN_AUTHENTICATED_SOURCE_OR_STACK_NO_DEREFERENCE\\n",
                      stderr);
                }
#endif
                std::fprintf(stderr,
                  "KERNIX_G0_UNPATCHED_ORIGINAL_GNU_LDSO_OPENAT257_SOURCE_CACHE_PATH_NOT_ALLOWLISTED dirfd=%llx path_ptr=%llx flags=%llx\n",
                  static_cast<unsigned long long>(next.decoded.args[0]),
                  static_cast<unsigned long long>(next.decoded.args[1]),
                  static_cast<unsigned long long>(next.decoded.args[2]));
                _exit(130);
              }
              ++RealOriginalLdsoCacheOpenCalls;
              frame->State.gregs[FEXCore::X86State::REG_RAX]=
                  static_cast<uint64_t>(answer.guestReturn);
              frame->State.rip=next.decoded.nextGuestRIP;
              std::fputs("KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_X86_OPENAT257_OPTIONAL_LD_SO_CACHE_VIRTUAL_ENOENT_SOURCE_PTLOAD_NO_HOST_FS\n",stderr);
              std::fflush(stderr);
              return;
            }
#endif
            // First remaining unsupported x86 syscall: precise source
            // RIP and number, never forwarded to host Linux/Android.
            std::fprintf(stderr,
              "KERNIX_G0_UNPATCHED_REAL_GNU_LDSO_NEXT_UNSUPPORTED_X86_SYSCALL num=%llu rip=%llx rdi=%llx rsi=%llx rdx=%llx r10=%llx r8=%llx r9=%llx\n",
              static_cast<unsigned long long>(next.decoded.guestNumber),
              static_cast<unsigned long long>(frame->State.rip),
              static_cast<unsigned long long>(next.decoded.args[0]),
              static_cast<unsigned long long>(next.decoded.args[1]),
              static_cast<unsigned long long>(next.decoded.args[2]),
              static_cast<unsigned long long>(next.decoded.args[3]),
              static_cast<unsigned long long>(next.decoded.args[4]),
              static_cast<unsigned long long>(next.decoded.args[5]));
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
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
        // Source-verified x86 libc 4KiB entry page only. Read-only query audit.
        const uint64_t libcBase=
          SourceFileKernel.OriginalLibcLargeReadonlyMap().Address();
        const bool libcStopPage=libcBase &&
          address>=libcBase+0xc8000ULL &&
          address<libcBase+0xc9000ULL;
#endif
        // The original ld-linux maps libc a SECOND time using its own
        // authenticated synthetic FD100 mmap(NULL) result. That live
        // source-backed guest VA is distinct from the initial preflight
        // NativeChosenPIEGuestLayout::Module(2) reservation. The normal
        // 3-module resolver must keep rejecting unrelated addresses;
        // permit only the real, source-verified PF_R|PF_X PT_LOAD of
        // the separately owned loader mapping, AFTER the original ELF
        // mapper has sealed RX, all later PT_LOAD/BSS gates passed,
        // and synthetic FD100 was authentically closed. No mprotect,
        // mmap, ELF byte patch, or generic guest address allowlist.
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
        const auto& genuineLibc=
          SourceFileKernel.OriginalLibcLargeReadonlyMap();
        const uint64_t mappedLibcBase=genuineLibc.Address();
        if(mappedLibcBase && address>=mappedLibcBase &&
           address-mappedLibcBase>=0x28000ULL &&
           address-mappedLibcBase<0x1b0000ULL) {
            const uint64_t pageStart=address&~uint64_t(4095);
            const bool sourceOwnedRX=
              ::sysconf(_SC_PAGESIZE)==4096 &&
              SourceFileKernel.OriginalLibcClosedAfterBSS() &&
              SourceFileKernel.OpenCount()==0 &&
              genuineLibc.OriginalSourceTextRXSealed() &&
              genuineLibc.OriginalSourceReadOnlyPTLoadConfirmed() &&
              genuineLibc.OriginalSourceWritablePTLoadConfirmed() &&
              genuineLibc.OriginalOwnedBSSZeroed() &&
              genuineLibc.CopiedSourceBytes()==
                kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize &&
              genuineLibc.BytesHeld()>=0x1b0000ULL &&
              SourceExecPolicy.sourceShaVerified &&
              SourceExecPolicy.nativeGuestVAIdentityOwned &&
              NativeWXApplied.originalPinnedSourceValidated &&
              NativeWXApplied.nativeNoWritableExecutablePage &&
              NativeWXApplied.nativeNonPTLoadHolesDenied &&
              !NativeWXApplied.androidDeviceTested &&
              Owner.WindowsHeld()==4 && Owner.Module(2) &&
              RightsAt(pageStart)=="r-xp" &&
              c1::GuestRange(pageStart,4096) &&
              genuineLibc.AuthenticatedReadonlyBytes(pageStart,4096);
            if(sourceOwnedRX) {
                ++SourceRXQueries;
                ++SourceLibcRXQueries;
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
                ++SourceLibcStopPageAcceptedRXQueries;
                LastSourceLibcQueryAddress=address;
#endif
                return {pageStart,4096,false};
            }
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
            ++SourceLibcStopPageRejectedRXQueries;
#endif
            return {0,0,false};
        }
#endif
        rx::Range verified{};
        if(!rx::ResolveOriginalSourceExecutableRange(
             Owner,SourceExecPolicy,NativeWXApplied,address,verified)) {
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
            if(libcStopPage)++SourceLibcStopPageRejectedRXQueries;
#endif
            return {0,0,false};
        }
        if(!verified.sourceVerifiedOriginalPTLoadRX ||
           !verified.nativeGuestAddressIsOwned ||
           verified.originalGNUInterpreterStartupCompleted ||
           verified.originalRelocationsExecuted ||
           verified.pageBytes!=4096 ||
           RightsAt(verified.pageStart)!="r-xp") {
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
            if(libcStopPage)++SourceLibcStopPageRejectedRXQueries;
#endif
            return {0,0,false};
        }
        ++SourceRXQueries;
        if(verified.moduleIndex==0)++SourceMainRXQueries;
        if(verified.moduleIndex==1){
            ++SourceInterpreterRXQueries;
            if(address>=OriginalLdsoTarget &&
               address-OriginalLdsoTarget<128)
               ++SourceOriginalCalleeRXQueries;
        }
        if(verified.moduleIndex==2) {
            ++SourceLibcRXQueries;
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
            LastSourceLibcQueryAddress=address;
            if(libcStopPage)++SourceLibcStopPageAcceptedRXQueries;
#endif
        }
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
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
    size_t SourceLibcStopPageAcceptedRXQueries=0;
    size_t SourceLibcStopPageRejectedRXQueries=0;
    uint64_t LastSourceLibcQueryAddress=0;
#endif
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
    [[maybe_unused]] const d::Plan& OriginalDynamicSource;
    [[maybe_unused]] const kernix::g2e::GuestPreflight& OriginalVerifiedSource;
    const c7g::PermissionPlan& SourceExecPolicy;
    const c7g::ApplyWitness& NativeWXApplied;
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
    const kernix::g0::mainpltsource::Witness& MainPLTBeforeFex;
    const kernix::g0::mainrelrotargets::ThreeRelativeSnapshot& ThreeRelativeBeforeFex;
    uint64_t OriginalFixtureRelativeTarget=0;
    const kernix::g0::ldsorelr::Witness& LdsoRelrBeforeFex;
    const kernix::g0::ldsorela::Witness& LdsoRelaBeforeFex;
    // The complete original libc mapping exists at its authentic
    // close(3) boundary, before the loader begins libc relocations.
    // Capture source-backed, read-only baseline values there.
    kernix::g0::libcrelr::Witness LibcRELRAtSourceClose{};
    bool LibcRELRAtSourceCloseCaptured=false;
    kernix::g0::libcrela::Witness LibcRelaAtSourceClose{};
    bool LibcRelaAtSourceCloseCaptured=false;
    kernix::g0::libcrelr::Witness LibcRELRAtLibcBoundary{};
    bool LibcRELRAtLibcBoundaryCaptured=false;
    kernix::g0::libcrela::Witness LibcRelaAtLibcBoundary{};
    bool LibcRelaAtLibcBoundaryCaptured=false;
    kernix::g0::mainrelrotargets::ThreeRelativeSnapshot ThreeRelativeAtLibcRELRO{};
    bool ThreeRelativeAtLibcRELROCaptured=false;
    bool MainPLTAtLibcRELROCaptured=false;
    uint64_t MainPLTAtLibcRELROValue=0;
    kernix::g0::ldsosyscallorigin::Witness LibcMprotectOpcode{};
    bool LibcMprotectOpcodeAuthenticated=false;
    bool MainSymbolicAtLibcRELROCaptured=false;
    kernix::g0::mainrelrotargets::Witness MainSymbolicAtLibcRELRO{};
#endif
    [[maybe_unused]] gbrk::OriginalGuestMainProgramBreak* GuestProgramBreak=nullptr;
    [[maybe_unused]] size_t RealOriginalLdsoBrkCalls=0;
    [[maybe_unused]] size_t RealOriginalLdsoAccessCalls=0;
    [[maybe_unused]] size_t RealOriginalLdsoCacheOpenCalls=0;
    [[maybe_unused]] size_t RealOriginalLdsoLibcOpens=0;
    [[maybe_unused]] size_t RealOriginalLdsoLibcReads=0;
    [[maybe_unused]] size_t RealOriginalLdsoLibcPreads=0;
    [[maybe_unused]] size_t RealOriginalLdsoLibcFstats=0;
    [[maybe_unused]] size_t RealOriginalLdsoLibcMmaps=0;
    [[maybe_unused]] size_t RealOriginalLdsoLibcCloses=0;
    [[maybe_unused]] size_t RealOriginalLdsoPostCloseAnonMaps=0;
    [[maybe_unused]] size_t RealOriginalLdsoPostCloseSetFSCalls=0;
    [[maybe_unused]] size_t RealOriginalLdsoPostCloseSetTidAddressCalls=0;
    [[maybe_unused]] size_t RealOriginalLdsoPostCloseRobustListCalls=0;
    [[maybe_unused]] size_t RealOriginalLdsoPostCloseRseqENOSYSCalls=0;
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_RSEQ_RELRO_MPROTECT_ONLY)
    size_t OriginalLibcRELROMprotectCalls=0;
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_SOURCE_LDSO_SELF_RELRO_8K)
    bool OriginalMainGuestRELRORealSealed=false;
#if defined(KERNIX_G0_EXPERIMENTAL_REAL_ORIGINAL_LIBC_PRLIMIT64_GETSTACK)
    bool OriginalLdsoSelfRELRORealSealed=false;
    size_t OriginalLibcPrlimit64Calls=0;
#endif
#endif
#endif
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
#if defined(KERNIX_G0_DIAGNOSTIC_DISABLE_TSO_ONLY)
    // Differential single-thread diagnostic of native ARM64 unaligned
    // LDAR SIGBUS. This is NEVER a safe final emulator setting:
    // disabling x86 TSO may introduce memory-ordering and concurrency
    // correctness bugs. Do NOT apply to production emulator/phone.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_TSOENABLED,"0");
    if(FEXCore::Config::GetConv<bool>(
         FEXCore::Config::CONFIG_TSOENABLED).value_or(true))return 120;
    stage("DIAGNOSTIC_ONLY_FEX_TSO_DISABLED_NOT_A_PRODUCTION_MEMORY_MODEL");
#endif
#if defined(KERNIX_G0_PROBE_UPSTREAM_SIGBUS_BACKPATCH_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_OPEN_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_READ_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
    // Keep correct original FEX x86 memory ordering: only SIGBUS backpatch
    // is being probed. Unlike the single-process TSO-off differential,
    // this does not turn off TSO even for the fixture.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_TSOENABLED,"1");
    if(!FEXCore::Config::GetConv<bool>(
         FEXCore::Config::CONFIG_TSOENABLED).value_or(false))return 150;
    stage("ORIGINAL_FEX_TSO_ENABLED_UPSTREAM_SIGBUS_FRONTEND_DIAGNOSTIC_ARMED");
#endif
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
    [[maybe_unused]] gbrk::OriginalGuestMainProgramBreak guestBreak{};
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION) && defined(KERNIX_G0_ENABLE_GUEST_BRK12)
    if(!guestBreak.Install(owned,planRights,rights) ||
       !guestBreak.Ready() ||
       guestBreak.Minimum()==0 ||
       RightsAt(guestBreak.Minimum())!="---p")
        return 124; // no native ::brk and no guest source WX changes
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
    // Capture the authentic original main PLT slot while guest has not
    // executed a single translated instruction. This is a detached
    // read-only numeric snapshot, not a future pointer into guest memory.
    const auto& mainSourceBefore=original.snapshots[0];
    kernix::g0::mainpltsource::Witness pltBeforeFex{};
    if(!mainSourceBefore.readOnlySnapshot() ||
       !kernix::g0::mainpltsource::ReadOnlyOriginalMainJumpSlot(
          mainSourceBefore.bytes(),mainSourceBefore.size(),
          original.exactSha256Matched,owned,planRights,
          authenticMainRelroRWPage,pltBeforeFex) ||
       !pltBeforeFex.authenticatedSourceJumpSlot ||
       !pltBeforeFex.originalWritablePageVerified ||
       !pltBeforeFex.targetInMainRELRO ||
       std::strcmp(pltBeforeFex.symbolName,"puts")!=0 ||
       pltBeforeFex.guestTarget==relative.guestTarget ||
       pltBeforeFex.guestTarget==sourceRelr.guestTarget ||
       RightsAt(authenticMainRelroRWPage)!="rw-p")return 186;
    std::fprintf(stderr,
      "KERNIX_G0_MAIN_PLT_PRE_FEX_SOURCE_SNAPSHOT_READONLY"
      " symbol=%s target=%llx pre_live=%llx"
      " fixture_relative_excluded=1 fixture_relr_excluded=1"
      " before_translated_execution=1 original_ldso_writes_unproven=1\n",
      pltBeforeFex.symbolName,
      static_cast<unsigned long long>(pltBeforeFex.guestTarget),
      static_cast<unsigned long long>(pltBeforeFex.guestValue));
    std::fflush(stderr);
    kernix::g0::ldsorelr::Witness ldsoRelrBeforeFex{};
    const auto& sourceLdsoBefore=original.snapshots[1];
    if(!sourceLdsoBefore.readOnlySnapshot() ||
       !sourceLdsoBefore.bytes() ||
       !kernix::g0::ldsorelr::SampleOriginalLdsoRelrReadOnly(
          sourceLdsoBefore.bytes(),sourceLdsoBefore.size(),
          original.exactSha256Matched,owned,planRights,
          ldsoRelrBeforeFex) ||
       !ldsoRelrBeforeFex.attestedOriginalSource ||
       ldsoRelrBeforeFex.count!=11 ||
       ldsoRelrBeforeFex.guestLdsoWriteRIPTraced ||
       ldsoRelrBeforeFex.originalRelocationClosureProven)
       return 220;
    std::fprintf(stderr,
      "KERNIX_G0_ORIGINAL_LDSO_11_RELR_PRE_FEX_SOURCE_READONLY"
      " targets=%zu file_backed=%zu bss=%zu"
      " source_equal=%zu source_different=%zu"
      " expected_equal=%zu expected_different=%zu"
      " no_guest_execution_yet=1 no_guest_write=1\n",
      ldsoRelrBeforeFex.count,
      ldsoRelrBeforeFex.backed,ldsoRelrBeforeFex.unbacked,
      ldsoRelrBeforeFex.sourceMatching,
      ldsoRelrBeforeFex.sourceDifferent,
      ldsoRelrBeforeFex.expectedMatching,
      ldsoRelrBeforeFex.expectedDifferent);
    kernix::g0::ldsorela::Witness ldsoRelaBeforeFex{};
    if(!kernix::g0::ldsorela::SampleOriginalLdsoThreeRelaReadOnly(
          sourceLdsoBefore.bytes(),sourceLdsoBefore.size(),
          original.exactSha256Matched,owned,planRights,
          ldsoRelaBeforeFex) ||
       !ldsoRelaBeforeFex.authenticatedSource ||
       ldsoRelaBeforeFex.count!=3 ||
       ldsoRelaBeforeFex.irelative!=1 ||
       ldsoRelaBeforeFex.symbolic!=2 ||
       ldsoRelaBeforeFex.originalLdsoStoreRIPTraced ||
       ldsoRelaBeforeFex.fullRelocationClosureProven)
       return 224;
    std::fprintf(stderr,
      "KERNIX_G0_ORIGINAL_LDSO_3_RELA_PRE_FEX_READONLY"
      " targets=%zu irelative=%zu symbolic=%zu"
      " file_backed=%zu bss=%zu"
      " source_equal=%zu source_different=%zu"
      " no_guest_execution_yet=1 no_guest_write=1\n",
      ldsoRelaBeforeFex.count,ldsoRelaBeforeFex.irelative,
      ldsoRelaBeforeFex.symbolic,ldsoRelaBeforeFex.backed,
      ldsoRelaBeforeFex.bss,ldsoRelaBeforeFex.sourceEqual,
      ldsoRelaBeforeFex.sourceDifferent);
    kernix::g0::mainrelrotargets::ThreeRelativeSnapshot triplePre{};
    if(!kernix::g0::mainrelrotargets::ReadOnlyOriginalMainThreeRelative(
          mainSourceBefore.bytes(),mainSourceBefore.size(),
          original.exactSha256Matched,owned,planRights,
          authenticMainRelroRWPage,triplePre) ||
       !triplePre.sourceAuthenticated ||
       triplePre.originalLdsoStoreRIPProven ||
       RightsAt(authenticMainRelroRWPage)!="rw-p")
      return 194;
    // The authored real-x86 guest fixture runs before entering original
    // GNU ld-linux and writes ONE source-verified RELATIVE guest slot.
    // Bind that exact guest target/expected value now, without hardcoding
    // the ELF relocation order or attributing other changes to ldso.
    size_t authoredFixtureSlot=3;
    for(size_t k=0;k<triplePre.total;++k) {
      if(triplePre.slots[k].guestTarget!=relative.guestTarget)continue;
      if(authoredFixtureSlot!=3) return 198;
      authoredFixtureSlot=k;
    }
    if(authoredFixtureSlot>=3 ||
       triplePre.exactExpected!=0 || triplePre.notExpected!=3 ||
       triplePre.slots[authoredFixtureSlot].guestValue!=relative.previousValue ||
       triplePre.slots[authoredFixtureSlot].expectedValue!=
           relative.expectedSourceValue ||
       !triplePre.slots[authoredFixtureSlot].targetInRELRO)
       return 199;
    std::fprintf(stderr,
      "KERNIX_G0_MAIN_RELATIVE_AUTHORED_FIXTURE_SOURCE_TARGET"
      " index=%zu target=%llx before=%llx expected=%llx"
      " source_attested=1 fixture_not_yet_executed=1"
      " no_original_ldso_write_proof=1\n",
      authoredFixtureSlot,
      static_cast<unsigned long long>(relative.guestTarget),
      static_cast<unsigned long long>(relative.previousValue),
      static_cast<unsigned long long>(relative.expectedSourceValue));
    std::fprintf(stderr,
      "KERNIX_G0_MAIN_RELATIVE_TRIPLE_PRE_FEX_READONLY"
      " count=%zu matched=%zu not_matched=%zu"
      " guest_execution_not_started=1 no_guest_write=1\n",
      triplePre.total,triplePre.exactExpected,triplePre.notExpected);
#endif
    OneProcessOriginalElfSyscalls handler{
        code.Address(),originalTarget,*plan,*main,first8,
        owned,guestFS,authenticMainRelroRWPage,sourceFileKernel,
        sourceRelr,dynamic,original,planRights,rights
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_POST_LIBC_RELRO_MAIN_PROVENANCE_ONLY)
        ,pltBeforeFex,triplePre,relative.guestTarget,
         ldsoRelrBeforeFex,ldsoRelaBeforeFex
#endif
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
#if defined(KERNIX_G0_PROBE_UPSTREAM_SIGBUS_BACKPATCH_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_OPEN_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_READ_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
    kernix::g0::sigbusdiagnostic::ScopedUpstreamFEXBackpatch
      fexOriginalSIGBUSBackpatch;
    if(!interpreter ||
       interpreter->chosenImageStart>
          UINT64_MAX-c7b::kImageCapacity ||
       !planRights.sourceShaVerified ||
       !planRights.nativeGuestVAIdentityOwned ||
       planRights.modules[1].nativeOwnedStart!=interpreter->chosenImageStart ||
       !fexOriginalSIGBUSBackpatch.Install(
         ctx.get(),thread,interpreter->chosenImageStart,
         interpreter->chosenImageStart+c7b::kImageCapacity,
         planRights.modules[1].rights.data(),
         planRights.modules[1].rights.size()))
      return 151;
    stage("original_FEX_host_SIGBUS_altstack_and_JIT_only_backpatch_installed");
#endif
    stage("original_x86_guest_cpu_state_ready_before_execute");
    std::fputs("KERNIX_G0_ORIGINAL_LDSO_MOV_CALL_AFTER_FEX_HEAP_START\n",stderr);
#if defined(KERNIX_G0_UNPATCHED_ORIGINAL_LDSO_CONTINUATION)
    std::fputs("KERNIX_G0_REAL_ORIGINAL_GNU_LDSO_UNPATCHED_CONTINUATION_BEFORE_FEX_EXECUTE_NOT_RUNTIME_SUCCESS\n",stderr);
#endif
    std::fflush(stderr);
    ctx->ExecuteThread(thread);
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
    // IMPORTANT: a source-authentic return from FEX without another
    // x86 syscall is NOT a loader or rseq-fallback success. Capture the
    // real guest CPU state and guest TLS cpu_id for focused diagnosis.
    // No x86 instruction bytes are patched or executed by this witness.
    const uint64_t diagnosticRIP=cpu.rip;
    const uint64_t diagnosticFS=cpu.fs_cached;
    const uint64_t diagnosticRseq=sourceFileKernel.OriginalLdsoRseqAddress();
    const uint64_t diagnosticLibc=
      sourceFileKernel.OriginalLibcLargeReadonlyMap().Address();
    const uint64_t diagnosticLibcBytes=
      sourceFileKernel.OriginalLibcLargeReadonlyMap().BytesHeld();
    uint32_t diagnosticCpuId=0x55555555U;
    const auto& diagnosticVM=sourceFileKernel.OriginalLdsoPostCloseAnonymousVM();
    const auto cpuSpan=diagnosticVM.AuthenticatedRW(
      diagnosticRseq+4,4);
    if(diagnosticRseq && diagnosticRseq<=UINT64_MAX-4 &&
       cpuSpan.attested && cpuSpan.guestRead && !cpuSpan.guestExecute &&
       RightsAt(diagnosticRseq+4)=="rw-p")
      std::memcpy(&diagnosticCpuId,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(diagnosticRseq+4)),4);
    const bool inLibcRX=diagnosticLibc &&
      diagnosticRIP>=diagnosticLibc &&
      diagnosticRIP-diagnosticLibc<diagnosticLibcBytes &&
      RightsAt(diagnosticRIP)=="r-xp";
    std::fprintf(stderr,
      "KERNIX_G0_ORIGINAL_LDSO_RSEQ334_POST_ENOSYS_GENUINE_FEX_THREAD_RETURN_NOT_NEXT_SYSCALL_DIAGNOSTIC rip=%llx rax=%llx rsp=%llx fs=%llx rseq=%llx cpu_id=%08x libc=%llx libc_offset=%llx rip_rights=%s traps=%u\n",
      static_cast<unsigned long long>(diagnosticRIP),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RAX]),
      static_cast<unsigned long long>(
        cpu.gregs[FEXCore::X86State::REG_RSP]),
      static_cast<unsigned long long>(diagnosticFS),
      static_cast<unsigned long long>(diagnosticRseq),
      static_cast<unsigned>(diagnosticCpuId),
      static_cast<unsigned long long>(diagnosticLibc),
      static_cast<unsigned long long>(
        diagnosticRIP>=diagnosticLibc?diagnosticRIP-diagnosticLibc:UINT64_MAX),
      RightsAt(diagnosticRIP).c_str(),handler.Calls);
    if(inLibcRX && diagnosticRIP>=diagnosticLibc+16 &&
       diagnosticRIP-diagnosticLibc+16<=diagnosticLibcBytes) {
      const auto* bytes=reinterpret_cast<const uint8_t*>(
        static_cast<uintptr_t>(diagnosticRIP-16));
      std::fputs("KERNIX_G0_ORIGINAL_LDSO_RSEQ334_POST_RETURN_REAL_SOURCE_LIBC_CODE_BYTES_MINUS16_PLUS16=",stderr);
      for(size_t i=0;i<32;++i)std::fprintf(stderr,"%02x",unsigned(bytes[i]));
      std::fputc('\n',stderr);
    }
    std::fflush(stderr);
#endif
#if defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_RSEQ_ONE_SOURCE_GLOB_DAT_ONLY)
    // Pinned upstream FEXCore CpuStateFrame synchronous-fault witness.
    // No guest/JIT mutations, no reason for exit inferred solely from RIP.
    const auto& postFault=thread->CurrentFrame->SynchronousFaultData;
    std::fprintf(stderr,
      "KERNIX_G0_POST_RSEQ_FEX_STOP_READONLY_WITNESS"
      " rip=%llx rax=%llx rsp=%llx"
      " libc_rx_queries=%zu stop_page_accepted=%zu stop_page_rejected=%zu"
      " last_libc_rx_query=%llx sync_generated=%d sync_signal=%u"
      " sync_trap=%u sync_si_code=%u sync_err_code=%u"
      " in_syscall_info=%llx signal_refs=%u callret_sp=%llx"
      " NOT_EXECUTION_PROGRESS_NOT_GLIBC_PASS\n",
      static_cast<unsigned long long>(cpu.rip),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RAX]),
      static_cast<unsigned long long>(cpu.gregs[FEXCore::X86State::REG_RSP]),
      handler.SourceLibcRXQueries,
      handler.SourceLibcStopPageAcceptedRXQueries,
      handler.SourceLibcStopPageRejectedRXQueries,
      static_cast<unsigned long long>(handler.LastSourceLibcQueryAddress),
      int(postFault.FaultToTopAndGeneratedException),
      unsigned(postFault.Signal),unsigned(postFault.TrapNo),
      unsigned(postFault.si_code),unsigned(postFault.err_code),
      static_cast<unsigned long long>(thread->CurrentFrame->InSyscallInfo),
      unsigned(thread->CurrentFrame->SignalHandlerRefCounter),
      static_cast<unsigned long long>(cpu.callret_sp));
    std::fflush(stderr);
    // Read-only post-mortem: distinguish an absent source relocation
    // from an FEX stop at the first real libc load after rseq ENOSYS.
    // This never resumes the guest, alters x86 code, changes W^X,
    // rewrites the source GOT, or upgrades an unsuccessful runtime gate.
    // Original x86 source: libc + 0xc8570:
    //   endbr64
    //   mov rax, qword ptr [rip+0x13a935]   -> libc GOT +0x202eb0
    //   mov rdx, qword ptr [rax+0x1e0]     -> ldso global_ro field
    const auto* postLdsoModule=owned.Module(1);
    const uint64_t postLibcBase=
      sourceFileKernel.OriginalLibcLargeReadonlyMap().Address();
    const uint64_t postExpectedRIP=postLibcBase+0xc8570ULL;
    const uint64_t postExpectedGOT=postLibcBase+
      kernix::g0::originalglobdat::kLibcGOTVaddr;
    const uint64_t postExpectedSymbol=postLdsoModule?
      postLdsoModule->loadBias+
        kernix::g0::originalglobdat::kLdsoSymbolVaddr:0;
    const bool postCanReadCode=postLibcBase &&
      postExpectedRIP>=postLibcBase &&
      postExpectedRIP-postLibcBase+18 <=
        sourceFileKernel.OriginalLibcLargeReadonlyMap().BytesHeld() &&
      RightsAt(postExpectedRIP)=="r-xp";
    const bool postCanReadGOT=postCanReadCode &&
      RightsAt(postExpectedGOT)=="rw-p";
    const bool postCanReadSymbol=postLdsoModule &&
      postExpectedSymbol &&
      postExpectedSymbol<=UINT64_MAX-0x1e8ULL &&
      RightsAt(postExpectedSymbol)=="rw-p" &&
      RightsAt(postExpectedSymbol+0x1e0ULL)=="rw-p" &&
      owned.GuestReadOnlyBytes(1,postExpectedSymbol,0x1e8)!=nullptr;
    bool postOpcodesMatch=false;
    bool postRIPTargetsSourceGOT=false;
    uint64_t postActualGOT=0;
    uint64_t postSourceFieldQword=0;
    if(postCanReadCode && postCanReadGOT && postCanReadSymbol) {
      const auto* b=reinterpret_cast<const uint8_t*>(
        static_cast<uintptr_t>(postExpectedRIP));
      int32_t firstDisplacement=0;
      int32_t secondDisplacement=0;
      std::memcpy(&firstDisplacement,b+7,4);
      std::memcpy(&secondDisplacement,b+14,4);
      postOpcodesMatch=
        b[0]==0xf3 && b[1]==0x0f && b[2]==0x1e &&
        b[3]==0xfa && b[4]==0x48 && b[5]==0x8b &&
        b[6]==0x05 && b[11]==0x48 && b[12]==0x8b &&
        b[13]==0x90 && secondDisplacement==0x1e0;
      const uint64_t computedGOT=
        postExpectedRIP+11+static_cast<int64_t>(firstDisplacement);
      postRIPTargetsSourceGOT=postOpcodesMatch &&
        computedGOT==postExpectedGOT;
      std::memcpy(&postActualGOT,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(postExpectedGOT)),8);
      std::memcpy(&postSourceFieldQword,reinterpret_cast<const void*>(
        static_cast<uintptr_t>(postExpectedSymbol+0x1e0ULL)),8);
    }
    std::fprintf(stderr,
      "KERNIX_G0_POST_RSEQ_SOURCE_LIBC_GOT_TWO_LOAD_READONLY_DIAGNOSTIC"
      " rip=%llx expected_rip=%llx got=%llx got_value=%llx"
      " expected_ldso_symbol=%llx ldso_field_plus_1e0=%llx"
      " rx_source_opcode=%d rip_targets_got=%d"
      " got_source_ldso_match=%d source_field_owner=%d"
      " no_guest_mutation=1 NOT_FEX_PROGRESS_NOT_GLIBC_PASS\n",
      static_cast<unsigned long long>(cpu.rip),
      static_cast<unsigned long long>(postExpectedRIP),
      static_cast<unsigned long long>(postExpectedGOT),
      static_cast<unsigned long long>(postActualGOT),
      static_cast<unsigned long long>(postExpectedSymbol),
      static_cast<unsigned long long>(postSourceFieldQword),
      int(postOpcodesMatch),int(postRIPTargetsSourceGOT),
      int(postCanReadGOT && postActualGOT==postExpectedSymbol),
      int(postCanReadSymbol));
    std::fflush(stderr);
#endif
    stage("original_fex_execute_thread_returned");
#if defined(KERNIX_G0_PROBE_UPSTREAM_SIGBUS_BACKPATCH_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_OPEN_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_READ_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_PREAD_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_STACK_FSTAT_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_LARGE_RO_MMAP_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_TEXT_RX_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RO_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_DATA_RW_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_OWNED_ANONYMOUS_BSS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_AFTER_BSS_CLOSE_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ANON8K_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_ARCH_SET_FS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_TID_ADDRESS_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_SET_ROBUST_LIST_ONLY) || \
    defined(KERNIX_G0_PROBE_ORIGINAL_LDSO_LIBC_POST_CLOSE_RSEQ_ENOSYS_ONLY)
    if(fexOriginalSIGBUSBackpatch.HandledCount() == 0)return 152;
    std::fputs("KERNIX_G0_ORIGINAL_FEX_TSO_ENABLED_SIGBUS_BACKPATCH_RETURNED_TO_EXECUTE_THREAD_NOT_FULL_GLIBC\n",stderr);
    fexOriginalSIGBUSBackpatch.Release();
#endif
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
