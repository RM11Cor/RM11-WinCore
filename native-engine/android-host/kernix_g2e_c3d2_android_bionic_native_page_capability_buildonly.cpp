// KERNIX G2-E/C3-D2: Android AArch64/Bionic native-kernel page capability
// source/ABI test ONLY. This shared ELF is unshipped and not device-tested.
// Actual Android 16K runtime protection has NOT been demonstrated.
// Never grant FEX guest memory based on an ABI build-only success.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d1_prot_none_guest_va_lease.h"
#include <cerrno>
#include <cstdint>
#include <unistd.h>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2-E/C3-D2 must compile against Android AArch64/Bionic
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d2_android_native_kernel_page_capability_BUILDONLY(
    uint64_t* out_native_kernel_page_bytes,
    uint32_t* out_16k_runtime_kernel_confirmed,
    uint32_t* out_real_guest_mapping_authorized) noexcept {
    if(out_native_kernel_page_bytes)*out_native_kernel_page_bytes=0;
    if(out_16k_runtime_kernel_confirmed)
        *out_16k_runtime_kernel_confirmed=0;
    if(out_real_guest_mapping_authorized)
        *out_real_guest_mapping_authorized=0; // Never allow guest mapping
    if(!out_native_kernel_page_bytes ||
       !out_16k_runtime_kernel_confirmed ||
       !out_real_guest_mapping_authorized)
        return -EINVAL;
#if !defined(MAP_FIXED_NOREPLACE)
    return -ENOTSUP; // No unsafe MAP_FIXED fallback
#else
    const long page=sysconf(_SC_PAGESIZE);
    if(page!=4096 && page!=16384)
        return -ENOTSUP;
    *out_native_kernel_page_bytes=static_cast<uint64_t>(page);
    *out_16k_runtime_kernel_confirmed=page==16384 ? 1U:0U;
    // Page size alone does not prove actual 4K guest isolation, non-RWX
    // code mapping, upstream FEX VM ownership, or Linux syscalls.
    return 0;
#endif
}
