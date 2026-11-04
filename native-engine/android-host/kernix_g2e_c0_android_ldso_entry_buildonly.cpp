// KERNIX G2-E/C0: future Android Bionic FEX initial-entry contract.
// This translation unit is for Android NDK source/link auditing ONLY.
// It is NOT packaged into the v0.27 APK; no guest VA mapping, JIT or Wine.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_guest_ldso_entry_contract.h"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2-E/C0 source must target Android Bionic ARM64
#endif
extern "C" __attribute__((visibility("default")))
int kernix_g2e_c0_android_verify_guest_pt_interp_entry_data_only(
    int verified_app_private_guest_rootfd,
    const uint8_t* caller_supplied_random16,
    uint32_t* out_verified_auxv_entries) noexcept {
    if(out_verified_auxv_entries)*out_verified_auxv_entries=0;
    if(verified_app_private_guest_rootfd<0 ||
       !caller_supplied_random16 || !out_verified_auxv_entries)
        return -EINVAL;
    try {
        kernix::g2e::GuestPreflight proof;
        std::string reason;
        if(!kernix::g2e::Validate(
             verified_app_private_guest_rootfd,proof,reason))
            return -ENOEXEC;
        std::array<uint8_t,16> random{};
        std::memcpy(random.data(),caller_supplied_random16,random.size());
        kernix::g2e::GuestLdsoEntryWitness witness;
        if(!kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
             proof,random,witness,reason) ||
           !witness.exactOriginalSha256Assets ||
           !witness.guestPtInterpEntryContractVerified ||
           !witness.linuxX86AuxvContractVerified ||
           witness.guestAddressSpaceReserved ||
           witness.fexThreadInitialized ||
           witness.guestLdsoEntered ||
           witness.glibcExecuted || witness.wineExecuted)
            return -ENOEXEC;
        // Do not export the synthetic guest VA RIP/RSP outside the library.
        // Those plan addresses are not installed or valid executable memory.
        *out_verified_auxv_entries=14;
        return 0;
    }catch(...){return -EFAULT;}
}
