// SPDX-License-Identifier: MIT
// R3D21: single x86 guest-thread ABI bookkeeping inside the SAME 07H Wine
// Linux bootstrap. The guest thread is currently 1:1 with an isolated
// Android native worker. No Linux clone/futex/exit robust-list cleanup is
// claimed; these require a separate real guest thread backend.
//
// set_tid_address(218) returns a *real* worker kernel TID. Its argument
// records the guest clear_child_tid address for later guest lifecycle code.
// Crucially, DO NOT invoke the host set_tid_address on a guest pointer:
// Android's own thread TLS/lifecycle must not be overwritten.
#pragma once
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <unistd.h>
#include <sys/syscall.h>
namespace carx_r3d21 {
constexpr uint64_t kRobustListHead64Size=24;
constexpr uint64_t kRseqGuestStructSize=32;
struct ThreadABI {
  int32_t tid{0};
  int32_t pid{0};
  uint64_t clearChildTid{0};
  uint64_t robustListHead{0};
  bool registeredChildTid{false};
  bool registeredRobustList{false};
  bool rseqUnavailableProbed{false};

  bool initialize_single_native_worker() noexcept {
    if(tid>0 && pid>0)return true;
    const long currentTid=::syscall(SYS_gettid);
    const pid_t currentPid=::getpid();
    if(currentTid<=0 || currentTid>INT32_MAX || currentPid<=0)return false;
    tid=static_cast<int32_t>(currentTid);
    pid=static_cast<int32_t>(currentPid);
    return true;
  }
  template<typename IsOwned>
  int64_t register_guest_clear_child_tid(uint64_t guestAddress,
                                         const IsOwned& owned) noexcept {
    if(!initialize_single_native_worker())return -EIO;
    if(guestAddress!=0 &&
       ((guestAddress&3)!=0 || !owned(guestAddress,4)))return -EFAULT;
    clearChildTid=guestAddress;
    registeredChildTid=true;
    return tid;
  }
  template<typename IsOwned>
  int64_t register_guest_robust_list(uint64_t guestHead,
                                     uint64_t structLength,
                                     const IsOwned& owned) noexcept {
    if(structLength!=kRobustListHead64Size)return -EINVAL;
    if((guestHead&7)!=0 || !owned(guestHead,structLength))
       return -EFAULT;
    robustListHead=guestHead;
    registeredRobustList=true;
    // A successful single-thread address registration, NOT kernel robust
    // futex exit handling or support for guest clone/exit/futex.
    return 0;
  }
  int64_t unsupported_guest_rseq(uint64_t /*guestRseqAddress*/,
                                  uint64_t /*guestLength*/,
                                  uint64_t /*guestFlags*/,
                                  uint64_t /*guestSignature*/) noexcept {
    rseqUnavailableProbed=true;
    // Explicit capability rejection; libc may choose its ENOSYS fallback.
    return -ENOSYS;
  }
  int64_t guest_gettid() noexcept {
    return initialize_single_native_worker()?tid:-EIO;
  }
  int64_t guest_getpid() noexcept {
    return initialize_single_native_worker()?pid:-EIO;
  }
};
} // namespace carx_r3d21
