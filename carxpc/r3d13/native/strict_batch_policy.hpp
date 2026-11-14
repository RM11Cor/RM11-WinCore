// SPDX-License-Identifier: MIT
// CarX R3D13: strict, intentionally tiny syscalls allowed during ld.so batch.
// This is not a Linux syscall implementation. No syscalls are forwarded.
#pragma once
#include <cstdint>
namespace carx_r3d13 {
constexpr uint32_t kMaxWitnesses = 32;
constexpr uint64_t kBrkQuery = 12;
constexpr uint64_t kAccess = 21;
constexpr uint64_t kOpenAt = 257;
constexpr uint64_t kReadOK = 4;
constexpr uint64_t kOpenAtCloexecOnly = 0x80000ULL; // Linux x86-64 O_CLOEXEC
constexpr uint64_t kAtFdcwdZeroExtended = 0x00000000FFFFFF9CULL;
constexpr uint64_t kAtFdcwdSignExtended = 0xFFFFFFFFFFFFFF9CULL;

inline constexpr bool is_safe_missing_guest_cache_openat(
    uint64_t dirfd,uint64_t flags,uint64_t mode) noexcept {
  // Do not accept O_CREAT, O_WRONLY, O_TRUNC, O_DIRECTORY, or unknown flags.
  (void)mode; // openat ignores mode unless O_CREAT or O_TMPFILE.\n  return (dirfd==kAtFdcwdZeroExtended ||
          dirfd==kAtFdcwdSignExtended) &&
         flags==kOpenAtCloexecOnly; // 4th 'mode' arg is unused without O_CREAT
}

inline constexpr bool is_safe_brk_zero_query(
    uint64_t number,uint64_t arg0) noexcept {
  return number==kBrkQuery && arg0==0;
}

inline constexpr bool is_safe_preload_access_query(
    uint64_t number,uint64_t access_flags) noexcept {
  return number==kAccess && access_flags==kReadOK;
}
} // namespace carx_r3d13
