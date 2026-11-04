// SPDX-License-Identifier: MIT
// C3-D6-R2. Original signed x86 Linux ELF bytes only. Android kernel-owned
// native memory is relocated; original guest VAs remain metadata only.
#include "kernix_g2e_c3d6r2_kernel_chosen_guest_window.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(__ANDROID__) || !defined(__aarch64__)
#error C3-D6-R2 must run as Android Bionic AArch64
#endif
int main(int argc,char** argv) {
    constexpr const char* flag=
      "--kernix-g2e-c3d6r2-host-chosen-4k-ro-probe-v1";
    if(argc!=3 || !argv[1] || !argv[2] ||
       std::strcmp(argv[1],flag)!=0 || argv[2][0]!='/' ||
       std::strlen(argv[2])>4096 ||
       std::string(argv[2]).find("..")!=std::string::npos ||
       !std::string(argv[2]).ends_with("/c3d6-root")) {
        std::puts("KERNIX_C3D6R2_INVALID_FIXED_CLI_FAIL_CLOSED");
        return 126;
    }
    const int root=::open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0)return 21;
    struct stat st{};
    if(::fstat(root,&st)!=0 || !S_ISDIR(st.st_mode) ||
       st.st_uid!=::getuid() || (st.st_mode&(S_IWGRP|S_IWOTH))) {
        ::close(root);
        std::puts("KERNIX_C3D6R2_PRIVATE_ROOT_OWNER_REJECTED");
        return 22;
    }
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    kernix::g2e::c3d6r2::KernelChosenReadOnlyGuestWindow lease;
    kernix::g2e::c3d6r2::Witness w;
    const bool prepared=lease.StageOriginals(root,entropy,w);
    ::close(root);
    const bool valid=prepared &&
        w.nativeKernelPageBytes==4096 &&
        w.originalGuestPages==609 &&
        w.pagesCopiedAndCompared==609 &&
        w.originalSourceSha256Verified &&
        w.exactGuestToHostMetadataMaintained &&
        w.kernelChoseHostVA &&
        !w.originalNativeGuestVAsMapped &&
        w.noHostExecutablePages &&
        w.allPagesFinallyReadOnly &&
        !w.fexOriginalGuestMemoryAttached &&
        !w.originalLdsoEntered &&
        !w.windowsPEExecuted &&
        lease.PagesHeld()==609;
    const bool released=lease.Release() && lease.PagesHeld()==0;
    if(!valid || !released) {
        std::printf(
            "KERNIX_C3D6R2_ANDROID_HOST_CHOSEN_RO_FAIL_CLOSED "
            "phase=%s kernel_page=%ld guest_pages=%zu copied=%zu "
            "remaining=%zu errno=%d\n",
            kernix::g2e::c3d6r2::PhaseName(w.phase),
            w.nativeKernelPageBytes,w.originalGuestPages,
            w.pagesCopiedAndCompared,lease.PagesHeld(),w.failureErrno);
        return 23;
    }
    std::puts(
        "KERNIX_G2EC3D6R2_DEVICE_609_GUEST4K_HOST_CHOSEN_RO_NO_FEX_PASS\n"
        "NATIVE_KERNEL_PAGE_BYTES=4096\n"
        "ORIGINAL_GUEST_4K_PAGES=609\n"
        "SOURCE_TRIPLE_SHA256_VERIFIED=1\n"
        "ORIGINAL_4096_BYTE_PAGES_COMPARED=609\n"
        "GUEST_VA_TO_HOST_VA_METADATA_MAINTAINED=1\n"
        "HOST_KERNEL_CHOSEN_VA_WINDOW=1\n"
        "ORIGINAL_FIXED_GUEST_VA_MAPPED=0\n"
        "NATIVE_RO_PAGES_RELEASED=1\n"
        "FEX_EXECUTED=0\n"
        "LINUX_LDSO_EXECUTED=0\n"
        "WINDOWS_PE_EXECUTED=0");
    return 0;
}
