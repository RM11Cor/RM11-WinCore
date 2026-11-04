// G2-E/C3-C real x86 libc.so.6 source-backed 4KiB shadow memory
// Android AArch64/Bionic *BUILD-ONLY* entry. Not in APK, no FEX, no mmap,
// no guest-visible pointers, no actual 16KiB host mprotect or code execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3c_libc_shadow_subpage_memory.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2-E/C3-C source MUST be compiled for Android Bionic AArch64
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3c_android_pinned_libc_shadow_4k_testonly_BUILDONLY(
    int authenticated_original_guest_private_rootfd,
    const uint8_t* caller_entropy16,
    uint32_t* out_original_libc_guest_4k_pages,
    uint32_t* out_file_backed_copy_bytes,
    uint32_t* out_zero_initialized_bss_bytes,
    uint32_t* out_plan_only_relro_4k_page_count) noexcept {
    if(out_original_libc_guest_4k_pages)
        *out_original_libc_guest_4k_pages=0;
    if(out_file_backed_copy_bytes)*out_file_backed_copy_bytes=0;
    if(out_zero_initialized_bss_bytes)
        *out_zero_initialized_bss_bytes=0;
    if(out_plan_only_relro_4k_page_count)
        *out_plan_only_relro_4k_page_count=0;
    if(authenticated_original_guest_private_rootfd<0 || !caller_entropy16 ||
       !out_original_libc_guest_4k_pages ||
       !out_file_backed_copy_bytes ||
       !out_zero_initialized_bss_bytes ||
       !out_plan_only_relro_4k_page_count)
        return -EINVAL;
    try {
        kernix::g2e::GuestPreflight source;
        std::string why;
        if(!kernix::g2e::Validate(
             authenticated_original_guest_private_rootfd,source,why))
            return -ENOEXEC;
        std::array<uint8_t,16> entropy{};
        std::memcpy(entropy.data(),caller_entropy16,16);
        kernix::g2e::c3b::Result plan;
        if(!kernix::g2e::c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
             source,entropy,plan,why))return -ENOEXEC;
        kernix::g2e::c3c::LibcShadow shadow;
        if(!kernix::g2e::c3c::PreparePinnedLibcShadowDataOnly(
             source,entropy,plan,shadow,why) ||
           !shadow.originalLibcSHA256Proved ||
           !shadow.software4KPermissionsEnforced ||
           shadow.host16KSubpageMprotectImplemented ||
           shadow.actualGuestMemoryMapped ||
           shadow.fexCpuStateUsesShadow ||
           shadow.originalGuestLoaderExecuted ||
           shadow.originalGuestLibcExecuted ||
           shadow.nativeDirectGuestAddressAccessAuthorized)
            return -ENOEXEC;
        *out_original_libc_guest_4k_pages=
            static_cast<uint32_t>(shadow.pages.size());
        *out_file_backed_copy_bytes=
            static_cast<uint32_t>(shadow.originalFileBytesCopied);
        *out_zero_initialized_bss_bytes=
            static_cast<uint32_t>(shadow.bssBytesZeroInitialized);
        *out_plan_only_relro_4k_page_count=
            static_cast<uint32_t>(shadow.relro4KPages);
        return 0; // source-authenticated shadow DATA check only
    }catch(...){return -EFAULT;}
}
