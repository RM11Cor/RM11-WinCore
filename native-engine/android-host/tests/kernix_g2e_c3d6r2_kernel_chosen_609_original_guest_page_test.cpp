// SPDX-License-Identifier: MIT
// C3-D6-R2 host-selected native mapping/data-only guest 4K translation.
#include "kernix_g2e_c3d6r2_kernel_chosen_guest_window.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<16;++i)entropy[i]=static_cast<uint8_t>(i+1);
    using namespace kernix::g2e::c3d6r2;
    KernelChosenReadOnlyGuestWindow lease;
    Witness result;
    if(sysconf(_SC_PAGESIZE)!=4096)return 4;
    assert(!lease.StageOriginals(-1,entropy,result));
    assert(lease.PagesHeld()==0);
    assert(!lease.StageOriginals(fd,entropy,result,2));
    assert(result.failureErrno==ECANCELED);
    assert(result.pagesCopiedAndCompared==2);
    assert(result.pagesReleased==609);
    assert(lease.PagesHeld()==0);
    assert(lease.StageOriginals(fd,entropy,result));
    assert(result.phase==Phase::Complete);
    assert(result.originalGuestPages==609);
    assert(result.pagesCopiedAndCompared==609);
    assert(result.originalSourceSha256Verified);
    assert(result.exactGuestToHostMetadataMaintained);
    assert(result.kernelChoseHostVA);
    assert(!result.originalNativeGuestVAsMapped);
    assert(result.allPagesFinallyReadOnly);
    assert(!result.fexOriginalGuestMemoryAttached);
    assert(lease.PagesHeld()==609);
    assert(lease.ReadOnlyNativePageForGuestVA(
        kernix::g2e::kC0MainTestVA,4096)!=nullptr);
    assert(lease.ReadOnlyNativePageForGuestVA(
        kernix::g2e::kC0MainTestVA+4095,2)==nullptr);
    assert(lease.ReadOnlyNativePageForGuestVA(
        0x12345000ULL,4096)==nullptr);
    assert(lease.Release());
    assert(lease.PagesHeld()==0);
    close(fd);
    puts("KERNIX_G2EC3D6R2_HOST_CHOSEN_REAL_609_GUEST4K_RO_TRANSLATION_AND_ROLLBACK_LINUX_PASS no_guest_exec=1 native_guest_fixed_va=0");
    return 0;
}
