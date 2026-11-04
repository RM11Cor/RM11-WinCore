// C3-D0 AArch64 Android/Bionic build-only. Real signed original x86 Linux
// ELF main/ld-linux/libc/stack bytes become nonexecutable host-owned 16K
// heap backing grouped into 4K guest-permission subpages. NO APK payload,
// NO native guest mapping, NO FEX thread, NO syscalls or ld-linux execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d_unified_guest_va_shadow.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D0 must compile specifically for Android Bionic AArch64
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d0_android_bionic_original_x86_16k_owned_shadow_BUILDONLY(
    int pinned_app_private_original_guest_rootfd,
    const uint8_t* caller_supplied_entropy16,
    uint32_t* out_total_original_guest_4k,
    uint32_t* out_host_owned_16k_groups,
    uint32_t* out_host_16k_wx_subpage_groups,
    uint32_t* out_libc_bytes_from_original_ELF) noexcept {
    if(out_total_original_guest_4k)*out_total_original_guest_4k=0;
    if(out_host_owned_16k_groups)*out_host_owned_16k_groups=0;
    if(out_host_16k_wx_subpage_groups)*out_host_16k_wx_subpage_groups=0;
    if(out_libc_bytes_from_original_ELF)*out_libc_bytes_from_original_ELF=0;
    if(pinned_app_private_original_guest_rootfd<0 ||
       !caller_supplied_entropy16 ||
       !out_total_original_guest_4k ||
       !out_host_owned_16k_groups ||
       !out_host_16k_wx_subpage_groups ||
       !out_libc_bytes_from_original_ELF)
        return -EINVAL;
    try{
        kernix::g2e::GuestPreflight source;
        std::string why;
        if(!kernix::g2e::Validate(
            pinned_app_private_original_guest_rootfd,source,why))
            return -ENOEXEC;
        std::array<uint8_t,16> entropy{};
        std::memcpy(entropy.data(),caller_supplied_entropy16,16);
        kernix::g2e::c3d::UnifiedGuestShadow shadow;
        if(!kernix::g2e::c3d::BuildUnifiedHost16KShadowFromPinnedOriginals(
              source,entropy,shadow,why) ||
           !shadow.pinnedOriginalThreeELFsVerified ||
           !shadow.software4KGuestPermissionsEnforced ||
           !shadow.allOriginalBytesCopiedToHostOwnedBuffers ||
           shadow.realGuestVirtualAddressReservation ||
           shadow.host16KSubpageMprotectImplemented ||
           shadow.fexGuestMemoryAttached ||
           shadow.fexCpuStateExecuted ||
           shadow.originalLdsoEntered ||
           shadow.originalLibcEntered ||
           shadow.directGuestNativePointersExposed)
            return -ENOEXEC;
        *out_total_original_guest_4k=
            static_cast<uint32_t>(shadow.totalRealGuest4KPages);
        *out_host_owned_16k_groups=
            static_cast<uint32_t>(shadow.host16KPageGroups);
        *out_host_16k_wx_subpage_groups=
            static_cast<uint32_t>(shadow.host16KPagesWithWXSubpages);
        *out_libc_bytes_from_original_ELF=
            static_cast<uint32_t>(shadow.libcFileBytesCopied);
        return 0; // only host-owned byte/permission proof; zero guest code
    }catch(...){return -EFAULT;}
}
