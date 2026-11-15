// SPDX-License-Identifier: MIT
// R3D20: source-locked x86-64 arch_prctl TLS for the existing integrated Wine
// Linux ABI bootstrap. Modifies FEX's *guest* FS/GS CPU state, not the
// Android ARM64 host's thread pointer. No generic syscall host passthrough.
#pragma once
#include "carxpc/r3d19/native/unified_guest_libc_abi.hpp"
#include <cstdint>
#include <cstring>
#include <cerrno>
namespace carx_r3d20 {
constexpr uint64_t kArchSetGs=0x1001ULL;
constexpr uint64_t kArchSetFs=0x1002ULL;
constexpr uint64_t kArchGetFs=0x1003ULL;
constexpr uint64_t kArchGetGs=0x1004ULL;
// Linux x86-64 userspace canonical address envelope (LA48 conservative).
constexpr uint64_t kMaxCanonicalUser=0x00007FFFFFFFFFFFULL;
struct DispatchResult {
  bool recognized{false};
  int64_t returnValue{-EINVAL};
  bool fsChanged{false};
  bool gsChanged{false};
};
template <typename CpuState, typename OwnedRange>
inline DispatchResult dispatch_arch_prctl(CpuState& state,
                                          uint64_t operation,
                                          uint64_t guestAddress,
                                          const OwnedRange& owned) noexcept {
  if(operation==kArchSetFs || operation==kArchSetGs){
    if(guestAddress<4096 || guestAddress>kMaxCanonicalUser ||
       !owned(guestAddress,1))
      return {true,-EFAULT,false,false};
    // This is the exact FEX CPUState field used for x86 segment overrides.
    // Never call Linux/Android host arch_prctl in an ARM64 process.
    if(operation==kArchSetFs){
      state.fs_cached=guestAddress;
      return {true,0,true,false};
    }
    state.gs_cached=guestAddress;
    return {true,0,false,true};
  }
  if(operation==kArchGetFs || operation==kArchGetGs){
    // Initial bootstrap exposes GET_* only to the owned writable guest ABI
    // stack. Protect adjacent host and readonly guest ELF segments.
    if(!carx_r3d18::owned_stack_write_bounds(guestAddress,8))
      return {true,-EFAULT,false,false};
    const uint64_t value=
       operation==kArchGetFs?state.fs_cached:state.gs_cached;
    std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(guestAddress)),
                &value,sizeof(value));
    return {true,0,false,false};
  }
  return {}; // Unrecognized controls remain explicitly unsupported.
}
} // namespace carx_r3d20
