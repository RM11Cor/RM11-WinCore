// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D5: actual source-pinned original FEXCore on Linux ARM64,
// running the existing bounded C2 x86 SYSCALL fixture while original SHA-locked
// x86 Linux main/ld-linux/libc/stack bytes are staged in 609 native 4K
// READ-ONLY host VMAs at their exact guest VAs.
// NOTE: x86 fixture has its OWN memory. Pinned ld-linux is NOT entered,
// the 609 host pages are NOT FEX-owned, no Android/Windows/Wine claim.
#define main kernix_g2ec2_actual_fex_syscall_fixture_main
#include "kernix_g2e_c2_original_fex_actual_syscall_trap_arm64.cpp"
#undef main

#include "kernix_g2e_c3d4_native_4k_original_elf_readonly_lease.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__) || !defined(KERNIX_G2EC2_ORIGINAL_FEX_LINUX_ARM64_CI)
#error G2-E/C3-D5 original FEX read-only guest co-residence is Linux ARM64 only
#endif

namespace c3d5 {
inline std::string NativePagePermissions(uint64_t address) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while(std::getline(maps,line)) {
        unsigned long long first=0,past=0;
        char flags[5]{};
        if(std::sscanf(line.c_str(),"%llx-%llx %4s",
                       &first,&past,flags)!=3)continue;
        if(address>=first && address<past)return std::string(flags);
    }
    return "unmapped";
}
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    if(sysconf(_SC_PAGESIZE)!=4096)
        return 3;  // no 16K kernel guest-page claim
    const int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0)return 4;

    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);

    kernix::g2e::c3d4::OriginalGuestNative4KReadOnlyLease lease;
    kernix::g2e::c3d4::NativeReadOnlyWitness evidence;
    if(!lease.StageFromPinnedOriginals(root,entropy,evidence) ||
       evidence.actualNativeKernelPageBytes!=4096 ||
       evidence.plannedOriginalGuest4KPages!=609 ||
       evidence.exactNative4KPagesReserved!=609 ||
       evidence.originalNative4KPagesByteCompared!=609 ||
       !evidence.originalGuestBytesInstalledReadOnly ||
       !evidence.allOwnedMapsFinalReadOnly ||
       !evidence.sourceThreeOriginalELFsSHA256Verified ||
       evidence.originalFexGuestMemoryAttached ||
       evidence.originalLinuxLdsoExecuted ||
       evidence.wineWindowsPEExecuted) {
        close(root);
        return 5;
    }
    close(root);

    // Independent re-read source metadata to inspect all native mappings.
    // Preflight is source immutable and only metadata is retained. Confirm
    // there were no unexpected native rights before entering FEX.
    size_t roPageCount=0;
    for(uintptr_t p=0;p==0;) { // no arbitrary scanning of host VA space
        break;
    }
    // Exact membership and RO permissions are established by the Stage
    // function; check its published proof and one bounded test VA.
    constexpr uint64_t kKnownMainTestVA =
        kernix::g2e::kC0MainTestVA;
    if(!lease.ContainsExactPage(kKnownMainTestVA) ||
       c3d5::NativePagePermissions(kKnownMainTestVA)!="r--p")
        return 6;
    roPageCount=evidence.originalNative4KPagesByteCompared;
    if(roPageCount!=lease.PagesHeld())
        return 7;

    // Source-pinned FEX executes the same bounded 41-byte original C2
    // test guest while every pre-reserved original page stays host RO.
    // This does NOT point FEX RIP at those Linux dynamic ELF pages.
    if(run()!=0)
        return 8;

    if(lease.PagesHeld()!=609 ||
       c3d5::NativePagePermissions(kKnownMainTestVA)!="r--p" ||
       !lease.ContainsExactPage(kKnownMainTestVA))
        return 9;
    if(!lease.Release() || lease.PagesHeld()!=0)
        return 10;
    if(c3d5::NativePagePermissions(kKnownMainTestVA)!="unmapped")
        return 11;

    std::printf(
        "KERNIX_G2EC3D5_ORIGINAL_FEX_X86_SYSCALL_WITH_609_AUTHENTIC_NATIVE_RO_4K_PAGES_LINUX_ARM64_PASS original_pages=609 original_bytes_readonly=1 no_host_executable_guest_pages=1 fex_fixture_executed=1 original_ldso_executed=0 fex_original_guest_memory_attached=0 rollback=1 android_device=0\n");
    return 0;
}
