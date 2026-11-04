// KERNIX C3-A Android/Bionic ARM64 source ABI gate only.
// Works with previously verified original Linux x86-64 guest rootfd;
// this is NOT packaged in an APK, not linked to FEX/JIT, not device-tested.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3_guest_page_ledger.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <cerrno>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error KERNIX C3-A Android source must compile for Bionic AArch64
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2ec3_bionic_pinned_glibc_4k_16k_ledger_BUILDONLY(
    int app_private_guest_rootfd,
    const uint8_t* attested_entropy16,
    uint32_t* out_guest_4k_page_count,
    uint32_t* out_host_16k_conflict_count,
    uint32_t* out_requires_guest_subpage_emulation) noexcept {
    if(out_guest_4k_page_count)*out_guest_4k_page_count=0;
    if(out_host_16k_conflict_count)*out_host_16k_conflict_count=0;
    if(out_requires_guest_subpage_emulation)
        *out_requires_guest_subpage_emulation=0;
    if(app_private_guest_rootfd<0 || !attested_entropy16 ||
       !out_guest_4k_page_count || !out_host_16k_conflict_count ||
       !out_requires_guest_subpage_emulation)return -EINVAL;
    try {
        kernix::g2e::GuestPreflight source;
        std::string error;
        if(!kernix::g2e::Validate(
               app_private_guest_rootfd,source,error))return -ENOEXEC;
        std::array<uint8_t,16> entropy{};
        std::memcpy(entropy.data(),attested_entropy16,16);
        kernix::g2e::GuestLdsoEntryWitness witness;
        kernix::g2b::X86GuestProcessLaunchPlan launch;
        if(!kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
             source,entropy,witness,error,&launch))
            return -ENOEXEC;
        kernix::g2e::c3::Ledger plan;
        if(!kernix::g2e::c3::BuildPinnedGlibcGuestPageLedger(
            launch,witness,plan,error) ||
           !plan.inputValidated || plan.nativeDirectMapAuthorized ||
           plan.guestMemoryInstalled || plan.fexGuestEntered ||
           plan.linuxLdsoExecuted)
            return -ENOEXEC;
        *out_guest_4k_page_count=
            static_cast<uint32_t>(plan.guestPages.size());
        *out_host_16k_conflict_count=
            static_cast<uint32_t>(plan.hostPagesNeedingSubpageEmulation);
        *out_requires_guest_subpage_emulation=
            plan.anyHost16KPageWriteExecuteConflict ||
            plan.anyGuest4KPageWriteExecuteConflict ? 1U:0U;
        return 0; // means only safe host DATA-PLAN built, no guest executed
    }catch(...){return -EFAULT;}
}
