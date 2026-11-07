// SPDX-License-Identifier: MIT
#pragma once
// G0 opt-in Android/Bionic AArch64 subprocess diagnostic ONLY.
// Port of the pinned upstream FEX Arm64 HalfBarrier SIGBUS backpatch
// operation, isolated from the verified Linux-only implementation.
// No guest-memory writes, no TSO disable, no arbitrary PC recovery,
// and NO production/mobile compatibility proof until on-device tests.
// SIGBUS outside the owned FEX JIT fails closed instead of hiding a
// host application fault. Run this only in a separately sandboxed child.
#if !defined(__aarch64__) || !defined(__ANDROID__)
#error This SIGBUS diagnostic is exclusively for Android Bionic ARM64.
#endif
#include <FEXCore/Core/Context.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

namespace kernix::g0::sigbusdiagnostic {
class ScopedUpstreamFEXBackpatch final {
  FEXCore::Context::Context* context_{};
  FEXCore::Core::InternalThreadState* guestThread_{};
  void* guardAllocation_{MAP_FAILED};
  size_t allocationBytes_{};
  size_t nativePage_{};
  stack_t previousStack_{};
  struct sigaction previousAction_{};
  bool previousStackValid_{};
  bool altstackInstalled_{};
  bool actionInstalled_{};
  volatile sig_atomic_t handledCount_{};
  volatile sig_atomic_t inHandler_{};
  // This is a bounded child diagnostic, not an unrestricted runtime loop.
  static constexpr sig_atomic_t kMaxHandledBusFaults=4096;
  static constexpr size_t kAltStackBytes=256*1024;
  inline static thread_local ScopedUpstreamFEXBackpatch* active_=nullptr;

  static void OnBionicSIGBUS(int signum,siginfo_t* info,
                             void* opaque) noexcept {
    auto* self=active_;
    if(signum!=SIGBUS || !self || !self->context_ ||
       !self->guestThread_ || !info || !opaque ||
       info->si_code!=BUS_ADRALN)
      ::_exit(181); // Other faults must not be treated as JIT recovery.
    auto* uc=static_cast<ucontext_t*>(opaque);
    const uintptr_t pc=static_cast<uintptr_t>(uc->uc_mcontext.pc);
    if(!pc || (pc&3U) ||
       !self->context_->IsAddressInCodeBuffer(self->guestThread_,pc))
      ::_exit(182); // Explicit JIT ownership verification.
    // If an upstream backpatch fails to make forward progress, stop this
    // isolated diagnostic child rather than continually faulting/heating
    // the phone. Never report a recovered fault as a valid gameplay pass.
    if(self->inHandler_ || self->handledCount_>=kMaxHandledBusFaults) {
      static constexpr char rejection[]=
        "KERNIX_G0_ANDROID_BIONIC_FEX_SIGBUS_REENTRANT_OR_BUDGET_REJECT\n";
      (void)::write(STDERR_FILENO,rejection,sizeof(rejection)-1);
      ::_exit(184);
    }
    self->inHandler_=1;
    static_assert(sizeof(uc->uc_mcontext.regs[0])==sizeof(uint64_t));
    const auto recovered=FEXCore::ArchHelpers::Arm64::
       HandleUnalignedAccess(
         self->guestThread_,
         FEXCore::ArchHelpers::Arm64::
           UnalignedHandlerType::HalfBarrier,pc,
         reinterpret_cast<uint64_t*>(uc->uc_mcontext.regs));
    if(!recovered.has_value() || !*recovered ||
       *recovered>128 || ((*recovered)&3U) ||
       pc>std::numeric_limits<uintptr_t>::max()-*recovered)
      ::_exit(183);
    uc->uc_mcontext.pc=pc+*recovered;
    self->handledCount_=self->handledCount_+1;
    self->inHandler_=0;
    if(self->handledCount_==1){
      static constexpr char evidence[]=
        "KERNIX_G0_ANDROID_BIONIC_FEX_JIT_SIGBUS_HALF_BARRIER_BACKPATCH"
        "_DIAGNOSTIC_HANDLED_NOT_FULL_GLIBC_OR_WINE_PASS\n";
      (void)::write(STDERR_FILENO,evidence,sizeof(evidence)-1);
    }
  }

public:
  ScopedUpstreamFEXBackpatch()=default;
  ScopedUpstreamFEXBackpatch(
    const ScopedUpstreamFEXBackpatch&)=delete;
  ScopedUpstreamFEXBackpatch& operator=(
    const ScopedUpstreamFEXBackpatch&)=delete;
  ~ScopedUpstreamFEXBackpatch(){Release();}

  bool Install(FEXCore::Context::Context* ctx,
               FEXCore::Core::InternalThreadState* thread) noexcept {
    if(active_ || !ctx || !thread ||
       guardAllocation_!=MAP_FAILED)return false;
    const long page=::sysconf(_SC_PAGESIZE);
    // Only a bounded, native-page-aligned diagnostic alternate stack.
    // Guest 4K emulation on native 16K pages is still NOT demonstrated.
    if(page<4096 || page>65536 || (page&(page-1)))return false;
    nativePage_=static_cast<size_t>(page);
    if(nativePage_>SIZE_MAX/2 ||
       kAltStackBytes>SIZE_MAX-2*nativePage_)return false;
    allocationBytes_=kAltStackBytes+2*nativePage_;
    guardAllocation_=::mmap(nullptr,allocationBytes_,PROT_NONE,
                      MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(guardAllocation_==MAP_FAILED){
      allocationBytes_=0;return false;
    }
    void* alt=static_cast<void*>(
      static_cast<unsigned char*>(guardAllocation_)+nativePage_);
    if(::mprotect(alt,kAltStackBytes,PROT_READ|PROT_WRITE)!=0 ||
       ::sigaltstack(nullptr,&previousStack_)!=0){
      Release();return false;
    }
    previousStackValid_=true;
    stack_t current{};
    current.ss_sp=alt;
    current.ss_size=kAltStackBytes;
    current.ss_flags=0;
    if(::sigaltstack(&current,nullptr)!=0){
      Release();return false;
    }
    altstackInstalled_=true;
    context_=ctx;
    guestThread_=thread;
    handledCount_=0;
    inHandler_=0;
    active_=this;
    struct sigaction action{};
    action.sa_sigaction=&OnBionicSIGBUS;
    action.sa_flags=SA_SIGINFO|SA_ONSTACK;
    if(::sigemptyset(&action.sa_mask)!=0 ||
       ::sigaction(SIGBUS,&action,&previousAction_)!=0){
      Release();return false;
    }
    actionInstalled_=true;
    return true;
  }
  // Keep the Android build-only diagnostic ABI compatible with the
  // Linux source-locked guest RIP experiment. This overload validates
  // the same immutable 8 MiB / 4 KiB PT_LOAD permission policy before
  // installing the existing bounded Android child SIGBUS handler.
  // It does not claim that Android has executed this probe, nor
  // attest any guest RIP / relocation store on device.
  bool Install(FEXCore::Context::Context* ctx,
               FEXCore::Core::InternalThreadState* thread,
               uint64_t originalGuestSourceWindowStart,
               uint64_t originalGuestSourceWindowEnd,
               const uint8_t* shaPinnedSourcePageRights,
               size_t sourcePageCount) noexcept {
    constexpr size_t kSourceImageBytes=8*1024*1024;
    constexpr size_t kGuestPageBytes=4096;
    if(!ctx || !thread || !originalGuestSourceWindowStart ||
       originalGuestSourceWindowStart%kGuestPageBytes ||
       originalGuestSourceWindowEnd<=originalGuestSourceWindowStart ||
       originalGuestSourceWindowEnd-originalGuestSourceWindowStart!=
         kSourceImageBytes ||
       !shaPinnedSourcePageRights ||
       sourcePageCount!=kSourceImageBytes/kGuestPageBytes)
      return false;
    size_t rxPages=0;
    for(size_t i=0;i<sourcePageCount;++i) {
      const uint8_t rights=shaPinnedSourcePageRights[i];
      if((rights&~uint8_t{7}) ||
         ((rights&uint8_t{2}) && (rights&uint8_t{4})))
        return false; // Never authorize any guest W+X page.
      rxPages+=size_t((rights&uint8_t{7})==uint8_t{5});
    }
    if(!rxPages)return false;
    return Install(ctx,thread); // Current Android diagnostic only.
  }

  sig_atomic_t HandledCount()const noexcept{return handledCount_;}

  void Release()noexcept {
    if(actionInstalled_){
      (void)::sigaction(SIGBUS,&previousAction_,nullptr);
      actionInstalled_=false;
    }
    if(active_==this)active_=nullptr;
    context_=nullptr;guestThread_=nullptr;
    inHandler_=0;
    if(altstackInstalled_ && previousStackValid_){
      (void)::sigaltstack(&previousStack_,nullptr);
      altstackInstalled_=false;
    }
    if(guardAllocation_!=MAP_FAILED){
      (void)::munmap(guardAllocation_,allocationBytes_);
      guardAllocation_=MAP_FAILED;
      allocationBytes_=0;
    }
  }
};
} // namespace kernix::g0::sigbusdiagnostic
