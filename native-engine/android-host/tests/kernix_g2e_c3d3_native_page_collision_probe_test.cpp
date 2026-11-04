// KERNIX C3-D3 Linux host test of kernel-chosen PROT_NONE page + exact
// NOREPLACE rejection. Does NOT prove Android runtime until device result.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d3_native_page_collision_probe.h"
#include <cassert>
#include <cstdio>
#include <sys/mman.h>
#include <unistd.h>
int main(int argc,char**) {
    if(argc!=1)return 2;
    kernix::g2e::c3d3::NativePageWitness result{};
    const bool supported=kernix::g2e::c3d3::
        RunOneHostNativePageCollisionProbe(result);
    if(!supported) {
        std::fputs(
           "KERNIX_G2EC3D3_KERNEL_NATIVE_PAGE_NOREPLACE_NOT_PROVEN_FAIL_CLOSED\n",
           stderr);
        return 3;
    }
    assert(result.kernelPageVerified &&
           (result.nativeKernelPageBytes==4096 ||
            result.nativeKernelPageBytes==16384));
    assert(result.native16KObserved==
           (result.nativeKernelPageBytes==16384));
    assert(result.noreplaceFlagCompiled);
    assert(result.singleOwnedHostPageMmapSucceeded);
    assert(result.existingOwnedMappingProtectedFromReplacement);
    assert(!result.unsupportedFlagReturnedDifferentAddress);
    assert(result.exactOriginalMappingStillOwned);
    assert(result.originalOwnedMappingReleased);
    assert(result.hostUsedProtNoneOnly);
    assert(!result.guestX86CodeExecuted &&
           !result.originalGuestVAsReserved &&
           !result.originalGuestPtLoadInstalled &&
           !result.fexCoreAttached &&
           !result.realHostSubpageProtectionImplemented);
    std::printf(
      "KERNIX_G2EC3D3_KERNEL_CHOSEN_ONE_PAGE_NOREPLACE_COLLISION_PASS native_page=%llu collision_preserved=1 released=1 host_PROT_NONE=1 guest_FEX=0 android_device=0\n",
      static_cast<unsigned long long>(result.nativeKernelPageBytes));
    return 0;
}
