#include "carxpc/r3d13/native/strict_batch_policy.hpp"
#include <cassert>
#include <cstdint>
int main(){
  using namespace carx_r3d13;
  static_assert(kMaxWitnesses==32);
  static_assert(is_safe_brk_zero_query(12,0));
  static_assert(!is_safe_brk_zero_query(12,4096));
  static_assert(!is_safe_brk_zero_query(257,0));
  static_assert(is_safe_preload_access_query(21,4));
  static_assert(!is_safe_preload_access_query(21,0));
  static_assert(!is_safe_preload_access_query(21,2));
  static_assert(!is_safe_preload_access_query(257,4));
  static_assert(is_safe_missing_guest_cache_openat(kAtFdcwdZeroExtended,0x80000,0));
  static_assert(is_safe_missing_guest_cache_openat(kAtFdcwdSignExtended,0x80000,0));
  static_assert(!is_safe_missing_guest_cache_openat(0,0x80000,0));
  static_assert(!is_safe_missing_guest_cache_openat(42,0x80000,0));
  static_assert(!is_safe_missing_guest_cache_openat(kAtFdcwdZeroExtended,0,0));
  static_assert(!is_safe_missing_guest_cache_openat(kAtFdcwdZeroExtended,0x80001,0));
  static_assert(!is_safe_missing_guest_cache_openat(kAtFdcwdZeroExtended,0x80002,0));
  static_assert(!is_safe_missing_guest_cache_openat(kAtFdcwdZeroExtended,0x80200,0));
  static_assert(!is_safe_missing_guest_cache_openat(kAtFdcwdZeroExtended,0x80000,0x1A4));
  static_assert(!is_safe_missing_guest_cache_openat(kAtFdcwdZeroExtended,0x40080000,0));
  return 0;
}
