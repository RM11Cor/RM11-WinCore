// SPDX-License-Identifier: MIT
// G0 isolated Linux ARM64 diagnostic: FEXCore's original TSO-preserving
// SIGBUS unaligned JIT backpatch. Never included in Android/production.
#pragma once
#if !defined(__aarch64__) || defined(__ANDROID__)
#error This SIGBUS backpatch experiment is Linux ARM64 diagnostic only.
#endif
#include <FEXCore/Core/Context.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <csignal>
#include <cstdint>
#include <cstddef>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

namespace kernix::g0::sigbusdiagnostic {
class ScopedUpstreamFEXBackpatch final {
  FEXCore::Context::Context* ctx_ {};
  FEXCore::Core::InternalThreadState* thread_ {};
  void* allocation_ {MAP_FAILED};
  stack_t previous_stack_ {};
  struct sigaction previous_action_ {};
  bool previous_stack_known_ {};
  bool alternate_stack_installed_ {};
  bool handler_installed_ {};
  volatile sig_atomic_t handled_count_ {};
  // Numeric address bounds are derived from the already SHA-locked
  // original x86 ELF owner. They must never be supplied by guest code.
  uint64_t sourceGuestWindowStart_ {};
  uint64_t sourceGuestWindowEnd_ {};
  // Immutable copy-free pointer to source-SHA-authenticated PT_LOAD
  // rights kept alive by Run() throughout the FEX execution.
  const uint8_t* sourceGuestPageRights_ {};
  std::size_t sourceGuestPageCount_ {};
  static constexpr std::size_t kPage = 4096;
  static constexpr std::size_t kSourceImageBytes = 8 * 1024 * 1024;
  static constexpr std::size_t kStack = 256 * 1024;
  static constexpr std::size_t kAllocation = kStack + 2 * kPage;
  inline static thread_local ScopedUpstreamFEXBackpatch* active_ = nullptr;

  // No logging allocations, locks, STL containers or app file I/O inside
  // the signal callback. Only FEX's pinned upstream backpatcher can alter JIT.
  static void OnSIGBUS(int signal, siginfo_t* info, void* opaque) noexcept {
    auto* self = active_;
    if(signal != SIGBUS || !self || !self->ctx_ || !self->thread_ ||
       !info || !opaque || info->si_code != BUS_ADRALN) {
      ::_exit(161); // unrelated host faults are NOT swallowed
    }
    auto* uctx = static_cast<ucontext_t*>(opaque);
    const auto pc = static_cast<uintptr_t>(uctx->uc_mcontext.pc);
    if((pc & 3U) != 0U ||
       !self->ctx_->IsAddressInCodeBuffer(self->thread_, pc)) {
      ::_exit(162); // refuse any fault outside the owned FEX JIT
    }
    // This is the same AArch64 ucontext GPR ABI reinterpret cast used by
    // pinned upstream LinuxEmulation/ArchHelpers/MContext.h:GetArmGPRs.
    static_assert(sizeof(uctx->uc_mcontext.regs[0]) == sizeof(uint64_t));
    const auto result =
      FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(
        self->thread_,
        FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier,
        pc, reinterpret_cast<uint64_t*>(uctx->uc_mcontext.regs));
    if(!result.has_value()) {
      ::_exit(163); // no guessed patching or skipping guest instructions
    }
    uctx->uc_mcontext.pc = pc + *result;
    self->handled_count_ = self->handled_count_ + 1;
    if(self->handled_count_ == 1) {
      // FEX's real host-PC -> x86 RIP reconstruction is an upstream
      // diagnostic facility, not a relocation store tracer. The fallback
      // to frame->State.rip may only give block-level accuracy. Record
      // candidate guest RIP ONLY for a known source-owned x86 ELF
      // virtual address window. Never alter guest RIP, memory or rights.
      if(self->sourceGuestWindowStart_ &&
         self->sourceGuestWindowEnd_ > self->sourceGuestWindowStart_) {
        const uint64_t guestRIP=
            self->ctx_->RestoreRIPFromHostPC(self->thread_,pc);
        if(guestRIP>=self->sourceGuestWindowStart_ &&
           guestRIP<self->sourceGuestWindowEnd_) {
          // The reserved ELF allocation also includes guard holes,
          // RELRO and RW data. Never attest a candidate unless the
          // *actual source-pinned page policy* says RX, no W.
          const auto pageIndex=static_cast<std::size_t>(
            (guestRIP-self->sourceGuestWindowStart_)/kPage);
          if(!self->sourceGuestPageRights_ ||
             pageIndex>=self->sourceGuestPageCount_ ||
             (self->sourceGuestPageRights_[pageIndex]&7u)!=5u)
            ::_exit(164);
          static constexpr char kMarker[] =
            "KERNIX_G0_FEX_HOST_JIT_SIGBUS_RESTORED_SOURCE_WINDOW_X86_RIP_CANDIDATE_ONLY"
            " guest_rip=";
          (void)::write(STDERR_FILENO,kMarker,sizeof(kMarker)-1);
          char digits[17] {};
          static constexpr char kHex[]="0123456789abcdef";
          for(unsigned i=0;i<16;++i)
            digits[i]=kHex[(guestRIP >> ((15u-i)*4u))&15u];
          digits[16]=' ';
          (void)::write(STDERR_FILENO,digits,sizeof(digits));
          static constexpr char kRX[] =
            "original_interpreter_source_ELF_RX_page=1"
            " original_sha_locked_permission_plan=1"
            " real_FEX_host_PC_reconstructed_to_guest_RIP=1"
            " relocation_store_guest_RIP_not_traced=1\n";
          (void)::write(STDERR_FILENO,kRX,sizeof(kRX)-1);
        }
      }
      static constexpr char kEvidence[] =
        "KERNIX_G0_ORIGINAL_FEX_ARM64_TSO_ENABLED_SIGBUS_UPSTREAM_BACKPATCH_HANDLER_APPLIED_NOT_GLIBC_PASS\n";
      (void)::write(STDERR_FILENO, kEvidence, sizeof(kEvidence) - 1);
    }
  }

public:
  ScopedUpstreamFEXBackpatch() = default;
  ScopedUpstreamFEXBackpatch(const ScopedUpstreamFEXBackpatch&) = delete;
  ScopedUpstreamFEXBackpatch& operator=(const ScopedUpstreamFEXBackpatch&) = delete;
  ~ScopedUpstreamFEXBackpatch() { Release(); }

  bool Install(FEXCore::Context::Context* ctx,
               FEXCore::Core::InternalThreadState* thread,
               uint64_t originalGuestSourceWindowStart,
               uint64_t originalGuestSourceWindowEnd,
               const uint8_t* shaPinnedSourcePageRights,
               std::size_t sourcePageCount) noexcept {
    if(active_ || !ctx || !thread || allocation_ != MAP_FAILED ||
       !originalGuestSourceWindowStart ||
       originalGuestSourceWindowEnd<=originalGuestSourceWindowStart ||
       originalGuestSourceWindowEnd-originalGuestSourceWindowStart !=
          kSourceImageBytes ||
       !shaPinnedSourcePageRights ||
       sourcePageCount!=kSourceImageBytes/kPage)
      return false;
    allocation_ = ::mmap(nullptr, kAllocation, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(allocation_ == MAP_FAILED) return false;
    void* usable = static_cast<void*>(
      static_cast<unsigned char*>(allocation_) + kPage);
    if(::mprotect(usable, kStack, PROT_READ | PROT_WRITE) != 0 ||
       ::sigaltstack(nullptr, &previous_stack_) != 0) {
      Release();
      return false;
    }
    previous_stack_known_ = true;
    stack_t next {};
    next.ss_sp = usable;
    next.ss_size = kStack;
    next.ss_flags = 0;
    if(::sigaltstack(&next, nullptr) != 0) {
      Release();
      return false;
    }
    alternate_stack_installed_ = true;
    ctx_ = ctx;
    thread_ = thread;
    sourceGuestWindowStart_=originalGuestSourceWindowStart;
    sourceGuestWindowEnd_=originalGuestSourceWindowEnd;
    sourceGuestPageRights_=shaPinnedSourcePageRights;
    sourceGuestPageCount_=sourcePageCount;
    active_ = this;
    struct sigaction action {};
    action.sa_sigaction = &OnSIGBUS;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    if(::sigemptyset(&action.sa_mask) != 0 ||
       ::sigaction(SIGBUS, &action, &previous_action_) != 0) {
      Release();
      return false;
    }
    handler_installed_ = true;
    return true;
  }

  sig_atomic_t HandledCount() const noexcept { return handled_count_; }

  void Release() noexcept {
    if(handler_installed_) {
      (void)::sigaction(SIGBUS, &previous_action_, nullptr);
      handler_installed_ = false;
    }
    if(active_ == this) active_ = nullptr;
    ctx_ = nullptr;
    thread_ = nullptr;
    sourceGuestWindowStart_=0;
    sourceGuestWindowEnd_=0;
    sourceGuestPageRights_=nullptr;
    sourceGuestPageCount_=0;
    if(alternate_stack_installed_ && previous_stack_known_) {
      (void)::sigaltstack(&previous_stack_, nullptr);
      alternate_stack_installed_ = false;
    }
    if(allocation_ != MAP_FAILED) {
      (void)::munmap(allocation_, kAllocation);
      allocation_ = MAP_FAILED;
    }
  }
};
} // namespace kernix::g0::sigbusdiagnostic
