// KERNIX G2-E/C3-D3 Android Bionic AArch64 independently signed
// opt-in subprocess source. Never maps original Linux x86 ELF guest VAs.
// No FEX/JIT/Win32. Only OS-chosen, one-page PROT_NONE mmap and a second
// NOREPLACE request to prove a collision; always unmaps test pages.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d3_native_page_collision_probe.h"
#include <cstdio>
#include <cstring>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G2-E/C3-D3 Android child must be Bionic AArch64
#endif
namespace {
constexpr const char* kFixedFlag =
    "--kernix-g2e-c3d3-kernel-native-page-noreplace-v1";
}
int main(int argc,char** argv) {
    if(argc!=2 || !argv[1] || std::strcmp(argv[1],kFixedFlag)!=0) {
        std::fputs("KERNIX_G2EC3D3_FIXED_CLI_REJECTED\n",stderr);
        return 126;
    }
    kernix::g2e::c3d3::NativePageWitness evidence{};
    const bool supported=kernix::g2e::c3d3::
        RunOneHostNativePageCollisionProbe(evidence);
    if(!supported ||
       !evidence.kernelPageVerified ||
       !evidence.noreplaceFlagCompiled ||
       !evidence.singleOwnedHostPageMmapSucceeded ||
       !evidence.existingOwnedMappingProtectedFromReplacement ||
       !evidence.exactOriginalMappingStillOwned ||
       !evidence.originalOwnedMappingReleased ||
       !evidence.hostUsedProtNoneOnly ||
       evidence.guestX86CodeExecuted ||
       evidence.originalGuestVAsReserved ||
       evidence.originalGuestPtLoadInstalled ||
       evidence.fexCoreAttached ||
       evidence.realHostSubpageProtectionImplemented) {
        std::printf(
            "KERNIX_G2EC3D3_DEVICE_KERNEL_PAGE_OR_NOREPLACE_NOT_PROVEN_FAIL_CLOSED native_page=%llu\n",
            static_cast<unsigned long long>(evidence.nativeKernelPageBytes));
        return 23;
    }
    std::printf(
        "KERNIX_G2EC3D3_DEVICE_NATIVE_PAGE_NOREPLACE_COLLISION_NO_GUEST_PASS\n"
        "NATIVE_KERNEL_PAGE_BYTES=%llu\n"
        "NATIVE_KERNEL_16K=%u\n"
        "NOREPLACE_EXISTING_MAPPING_PRESERVED=1\n"
        "ISOLATED_NATIVE_PAGE_RELEASED=1\n"
        "FEX_EXECUTED=0\n"
        "LINUX_LDSO_EXECUTED=0\n"
        "GUEST_NATIVE_VA_RESERVED=0\n",
        static_cast<unsigned long long>(evidence.nativeKernelPageBytes),
        evidence.native16KObserved?1U:0U);
    std::fflush(stdout);
    return 0;
}
