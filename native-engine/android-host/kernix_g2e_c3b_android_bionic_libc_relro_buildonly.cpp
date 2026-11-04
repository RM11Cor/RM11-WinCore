// G2-E/C3-B Android Bionic ARM64 NO-MAP/NO-EXEC symbol and linking proof.
// Revalidates source-authenticated real Linux x86 main, ld-linux, libc snapshots.
// No guest VA installation, FEX thread, Wine, or Android device execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3b_original_glibc_relro_page_plan.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <cerrno>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-B must compile against Android/Bionic AArch64, not Linux host
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3b_original_libc_relro_4k_16k_bionic_BUILDONLY(
    int app_private_pinned_linux_guest_dir_fd,
    const uint8_t* caller_supplied_entropy16,
    uint32_t* out_libc_ptloads,
    uint32_t* out_libc_guest_4k_pages,
    uint32_t* out_relro_full_guest_4k_pages,
    uint32_t* out_before_relro_16k_host_WX,
    uint32_t* out_after_relro_16k_host_WX) noexcept {
    if(out_libc_ptloads)*out_libc_ptloads=0;
    if(out_libc_guest_4k_pages)*out_libc_guest_4k_pages=0;
    if(out_relro_full_guest_4k_pages)*out_relro_full_guest_4k_pages=0;
    if(out_before_relro_16k_host_WX)*out_before_relro_16k_host_WX=0;
    if(out_after_relro_16k_host_WX)*out_after_relro_16k_host_WX=0;
    if(app_private_pinned_linux_guest_dir_fd<0 ||
       !caller_supplied_entropy16 || !out_libc_ptloads ||
       !out_libc_guest_4k_pages || !out_relro_full_guest_4k_pages ||
       !out_before_relro_16k_host_WX || !out_after_relro_16k_host_WX)
        return -EINVAL;
    try {
        kernix::g2e::GuestPreflight proof;
        std::string reason;
        if(!kernix::g2e::Validate(
             app_private_pinned_linux_guest_dir_fd,proof,reason))
            return -ENOEXEC;
        std::array<uint8_t,16> entropy{};
        std::memcpy(entropy.data(),caller_supplied_entropy16,16);
        kernix::g2e::c3b::Result ledger;
        if(!kernix::g2e::c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
               proof,entropy,ledger,reason) ||
           !ledger.originalLibcSHA256Attested ||
           !ledger.relroPlannedNotApplied ||
           !ledger.fullImagePagePlanValidated ||
           ledger.nativeDirectMappingAuthorized ||
           ledger.hostGuestMemoryInstalled ||
           ledger.originalFEXGuestEntered ||
           ledger.originalLdsoExecuted ||
           ledger.originalLibcExecuted)
            return -ENOEXEC;
        *out_libc_ptloads=static_cast<uint32_t>(ledger.libcPTLoadCount);
        *out_libc_guest_4k_pages=
            static_cast<uint32_t>(ledger.libcUnique4KPages);
        *out_relro_full_guest_4k_pages=
            static_cast<uint32_t>(ledger.fullyCoveredRelro4KPages);
        *out_before_relro_16k_host_WX=
            static_cast<uint32_t>(ledger.initialHost16KWxConflicts);
        *out_after_relro_16k_host_WX=
            static_cast<uint32_t>(ledger.afterRelroHost16KWxConflicts);
        return 0; // success of metadata audit only; zero guest instructions
    }catch(...){return -EFAULT;}
}
