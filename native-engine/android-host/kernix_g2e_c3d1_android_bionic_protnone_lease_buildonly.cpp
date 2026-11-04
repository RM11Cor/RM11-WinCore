// G2-E/C3-D1 Android AArch64/Bionic native NO-EXEC source-link gate.
// This shared ELF is not packaged or run on a device. If explicitly
// invoked in a FUTURE isolated process, the only native mappings this
// module can reserve are fixed no-replace PROT_NONE with RAII rollback.
// No guest bytes go into a VA and no guest thread/FEX executes.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d1_prot_none_guest_va_lease.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D1 build-only target must be Android Bionic AArch64
#endif

extern "C" __attribute__((visibility("default")))
int kernix_g2ec3d1_android_noexec_original_x86_va_lease_BUILDONLY(
    int original_verified_app_private_x86_guest_rootfd,
    const uint8_t* test_entropy16,
    uint32_t* out_reserved_and_released_exact_host16k_pages,
    uint32_t* out_no_guest_execution) noexcept {
    if(out_reserved_and_released_exact_host16k_pages)
        *out_reserved_and_released_exact_host16k_pages=0;
    if(out_no_guest_execution)*out_no_guest_execution=1;
    if(original_verified_app_private_x86_guest_rootfd<0 ||
       !test_entropy16 || !out_reserved_and_released_exact_host16k_pages ||
       !out_no_guest_execution)return -EINVAL;
    try {
        kernix::g2e::GuestPreflight original;
        std::string why;
        if(!kernix::g2e::Validate(
             original_verified_app_private_x86_guest_rootfd,
             original,why))return -ENOEXEC;
        std::array<uint8_t,16> entropy{};
        std::memcpy(entropy.data(),test_entropy16,16);
        kernix::g2e::c3d::UnifiedGuestShadow shadow;
        if(!kernix::g2e::c3d::BuildUnifiedHost16KShadowFromPinnedOriginals(
             original,entropy,shadow,why))
            return -ENOEXEC;
        kernix::g2e::c3d1::ProtNoneGuestVALease lease;
        kernix::g2e::c3d1::ReservationWitness result;
        if(!lease.Reserve(shadow,result))
            return -ENOTSUP; // collision/unavailable must NOT replace others
        const bool safe=result.allVAsExact &&
            result.sourceTripleELFAuthenticated &&
            result.originalGuestPagePermissionsChecked &&
            result.hostMappingWasProtNoneOnly &&
            !result.hostPageWXGranted &&
            !result.guestBytesInstalledInNativeVA &&
            !result.fexContextAttached &&
            !result.x86GuestExecuted &&
            !result.linuxLdsoExecuted;
        if(!safe)return -EPERM; // destructor unwinds exactly owned pages
        *out_reserved_and_released_exact_host16k_pages=
            static_cast<uint32_t>(lease.PagesHeld());
        lease.Release();
        return 0;
    }catch(...){return -EFAULT;}
}
