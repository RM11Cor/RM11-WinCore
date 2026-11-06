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
  static constexpr std::size_t kPage = 4096;
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
               FEXCore::Core::InternalThreadState* thread) noexcept {
    if(active_ || !ctx || !thread || allocation_ != MAP_FAILED) return false;
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
