// SPDX-License-Identifier: MIT
// C3-D6: exact original x86 ELF bytes in Android native 4KiB readonly pages.
// Isolated, opt-in Bionic ARM64 PIE; never executes guest x86, FEX or Wine.
#include "kernix_g2e_c3d4_native_4k_original_elf_readonly_lease.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D6 requires Android Bionic AArch64
#endif
int main(int argc,char** argv) {
    constexpr const char* flag=
        "--kernix-g2e-c3d6-original-4k-ro-bionic-probe-v1";
    if(argc!=3 || !argv[1] || !argv[2] ||
       std::strcmp(argv[1],flag)!=0 || argv[2][0]!='/' ||
       std::strlen(argv[2])>4096 ||
       std::string(argv[2]).find("..")!=std::string::npos ||
       !std::string(argv[2]).ends_with("/c3d6-root")) {
        std::puts("KERNIX_C3D6_INVALID_FIXED_CLI_FAIL_CLOSED");
        return 126;
    }
    const int root=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0) {
        std::printf("KERNIX_C3D6_PRIVATE_ROOT_OPEN_FAIL_CLOSED errno=%d\n",errno);
        return 21;
    }
    struct stat st{};
    if(fstat(root,&st)!=0 || !S_ISDIR(st.st_mode) ||
       st.st_uid!=getuid() || (st.st_mode&(S_IWGRP|S_IWOTH))) {
        close(root);
        std::puts("KERNIX_C3D6_PRIVATE_ROOT_OWNER_OR_MODE_REJECTED");
        return 22;
    }
    // Deterministic 16-byte entropy is ONLY for the bounded static
    // stack/AUXV test. No Windows/game runtime is ever started.
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    kernix::g2e::c3d4::OriginalGuestNative4KReadOnlyLease lease;
    kernix::g2e::c3d4::NativeReadOnlyWitness evidence;
    const bool staged=lease.StageFromPinnedOriginals(root,entropy,evidence);
    close(root);
    const size_t held=lease.PagesHeld();
    const bool qualified=
        staged && evidence.actualNativeKernelPageBytes==4096 &&
        evidence.plannedOriginalGuest4KPages==609 &&
        evidence.exactNative4KPagesReserved==609 &&
        evidence.originalNative4KPagesByteCompared==609 &&
        evidence.sourceThreeOriginalELFsSHA256Verified &&
        evidence.exactNoreplaceNative4KGuestVAOwned &&
        evidence.originalGuestBytesInstalledReadOnly &&
        evidence.hostNeverGrantedExecutablePages &&
        evidence.allOwnedMapsFinalReadOnly &&
        !evidence.originalFexGuestMemoryAttached &&
        !evidence.originalLinuxLdsoExecuted &&
        !evidence.wineWindowsPEExecuted && held==609;
    const bool released=lease.Release() && lease.PagesHeld()==0;
    if(!qualified || !released) {
        std::printf(
          "KERNIX_C3D6_ANDROID_ORIGINAL_RO_PAGES_FAIL_CLOSED "
          "kernel_page=%llu reserved=%zu copied=%zu "
          "rollback_remaining=%zu failure_errno=%d\n",
          static_cast<unsigned long long>(
              evidence.actualNativeKernelPageBytes),
          evidence.exactNative4KPagesReserved,
          evidence.originalNative4KPagesByteCompared,
          lease.PagesHeld(),evidence.boundedFailureErrno);
        return 23;
    }
    std::puts(
        "KERNIX_G2EC3D6_DEVICE_ORIGINAL_609_GUEST4K_NATIVE_RO_NO_FEX_PASS\n"
        "NATIVE_KERNEL_PAGE_BYTES=4096\n"
        "ORIGINAL_GUEST_4K_PAGES=609\n"
        "SOURCE_TRIPLE_SHA256_VERIFIED=1\n"
        "ORIGINAL_4096_BYTE_PAGES_COMPARED=609\n"
        "NATIVE_RO_PAGES_RELEASED=1\n"
        "FEX_EXECUTED=0\n"
        "LINUX_LDSO_EXECUTED=0\n"
        "WINDOWS_PE_EXECUTED=0");
    return 0;
}
