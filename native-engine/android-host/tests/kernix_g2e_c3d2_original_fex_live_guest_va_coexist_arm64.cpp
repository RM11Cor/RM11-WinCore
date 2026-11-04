// KERNIX G2-E/C3-D2. Real original, source-pinned FEXCore Linux ARM64
// JIT executes the C2 bounded *41-byte* x86 SYSCALL fixture WHILE all
// SHA256-pinned original Linux main/ld-linux/libc/stack guest virtual
// addresses stay reserved as native PROT_NONE VMA with fixed NOREPLACE.
// The original ELF bytes stay ONLY in safe C++ host-owned heap buffers.
// No FEX thread enters original ld-linux, no 16K host 4K mprotect yet.
// SPDX-License-Identifier: MIT
#define main kernix_g2ec2_original_fixture_embedded_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main
#include "kernix_g2e_c3d1_prot_none_guest_va_lease.h"
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#if !defined(__aarch64__) || !defined(KERNIX_G2EC2_ORIGINAL_FEX_LINUX_ARM64_CI)
#error G2-E/C3-D2 source-pinned original FEX co-residence proof runs only on Linux ARM64
#endif

namespace d2 {
bool MappedNoAccess(uint64_t address) {
    std::ifstream proc("/proc/self/maps");
    std::string line;
    while(std::getline(proc,line)){
        unsigned long long start=0,past=0;
        char permissions[5]{};
        if(std::sscanf(line.c_str(),"%llx-%llx %4s",
                       &start,&past,permissions)!=3)continue;
        if(address>=start && address<past)
            return std::string(permissions)=="---p";
    }
    return false;
}
bool NoCurrentMapping(uint64_t address) {
    std::ifstream proc("/proc/self/maps");
    std::string line;
    while(std::getline(proc,line)){
        unsigned long long start=0,past=0;
        if(std::sscanf(line.c_str(),"%llx-%llx",&start,&past)!=2)
            continue;
        if(address>=start && address<past)return false;
    }
    return true;
}
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const long nativePageBytes=sysconf(_SC_PAGESIZE);
    if(nativePageBytes!=4096 && nativePageBytes!=16384 &&
       nativePageBytes!=65536)return 3;
    const int dirfd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dirfd<0)return 4;
    kernix::g2e::GuestPreflight pinned;
    std::string reason;
    const bool originalVerified=kernix::g2e::Validate(dirfd,pinned,reason);
    close(dirfd);
    if(!originalVerified)return 5;
    std::array<uint8_t,16> fixedEntropy{};
    for(size_t i=0;i<fixedEntropy.size();++i)
        fixedEntropy[i]=static_cast<uint8_t>(i+1);
    kernix::g2e::c3d::UnifiedGuestShadow source;
    if(!kernix::g2e::c3d::BuildUnifiedHost16KShadowFromPinnedOriginals(
           pinned,fixedEntropy,source,reason) ||
       source.host16K.size()!=154 ||
       source.totalRealGuest4KPages!=609 ||
       source.host16KPagesWithWXSubpages!=1 ||
       source.fexGuestMemoryAttached ||
       source.directGuestNativePointersExposed)
        return 6;
    kernix::g2e::c3d1::ProtNoneGuestVALease lease;
    kernix::g2e::c3d1::ReservationWitness witness;
    // On a genuine 64KiB native kernel, 16KiB mmap granularity is invalid.
    // Reject it explicitly: the only native alignment proven here is the
    // actual sysconf host page size, never an assumed Android 16KiB kernel.
    if(nativePageBytes>16384) {
        if(lease.Reserve(source,witness) || lease.PagesHeld()!=0)
            return 7;
        std::puts("KERNIX_G2EC3D2_ORIGINAL_ARM64_KERNEL_PAGE_64K_FAIL_CLOSED_NO_EXECUTION");
        return 0;
    }
    if(!lease.Reserve(source,witness) ||
       lease.PagesHeld()!=154 || !witness.allVAsExact ||
       !witness.hostMappingWasProtNoneOnly ||
       witness.hostPageWXGranted ||
       witness.guestBytesInstalledInNativeVA ||
       witness.fexContextAttached ||
       witness.x86GuestExecuted ||
       witness.linuxLdsoExecuted)
        return 8;
    for(const auto& [address,backing]:source.host16K) {
        (void)backing;
        if(!lease.ContainsExactReservedPage(address) ||
           !d2::MappedNoAccess(address))
            return 9;
    }
    // Bounded actual original FEXCore guest fixture, not any of the pinned
    // original x86 ELF processes. Its code/stack live in separate host VMAs.
    const int fexReturn=run();
    if(fexReturn!=0)return 10+fexReturn;
    if(lease.PagesHeld()!=154)return 70;
    for(const auto& [address,backing]:source.host16K) {
        (void)backing;
        if(!d2::MappedNoAccess(address))return 71;
    }
    lease.Release();
    if(lease.PagesHeld()!=0)return 72;
    for(const auto& [address,backing]:source.host16K) {
        (void)backing;
        if(!d2::NoCurrentMapping(address))return 73;
    }
    std::printf(
      "KERNIX_G2EC3D2_PINNED_FEX_REAL_X86_SYSCALL_WITH_154_ORIGINAL_GUEST_VA_PROT_NONE_ARM64_PASS native_page_bytes=%ld fex_actual_guest_syscall=1 original_guest_ldso_executed=0 direct_guest_mapping=0 rollback=1\n",
      nativePageBytes);
    return 0;
}
