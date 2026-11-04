// SPDX-License-Identifier: MIT
// C3-D4 ORIGINAL SHA-pinned Linux x86 guest bytes, native 4KiB Linux VMAs.
// Explicitly NOT an Android device test or a FEX/Wine execution test.
#include "kernix_g2e_c3d4_native_4k_original_elf_readonly_lease.h"
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace g2e=kernix::g2e;
namespace c3d=g2e::c3d;
namespace c3d4=g2e::c3d4;
static std::string NativeMappingRights(uint64_t address) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while(std::getline(maps,line)) {
        unsigned long long first=0,past=0;
        char perms[5]{};
        if(std::sscanf(line.c_str(),"%llx-%llx %4s",
                       &first,&past,perms)!=3)continue;
        if(address>=first && address<past)return std::string(perms);
    }
    return "unmapped";
}
static void NothingMappedAt(
    const std::vector<std::pair<uint64_t,const unsigned char*>>& pages) {
    for(const auto& [address,source]:pages) {
        (void)source;
        assert(NativeMappingRights(address)=="unmapped");
    }
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    if(sysconf(_SC_PAGESIZE)!=4096) {
        std::puts("KERNIX_G2EC3D4_NATIVE_NON4K_REJECTED_NO_GUEST_EXEC");
        return 0;
    }
#if !defined(MAP_FIXED_NOREPLACE)
    return 3;
#endif
    const int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0)return 4;
    g2e::GuestPreflight verified;
    std::string why;
    assert(g2e::Validate(root,verified,why));
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    c3d::UnifiedGuestShadow shadow;
    assert(c3d::BuildUnifiedHost16KShadowFromPinnedOriginals(
        verified,entropy,shadow,why));
    std::vector<std::pair<uint64_t,const unsigned char*>> pages;
    for(const auto& [base,backing]:shadow.host16K)
        for(size_t j=0;j<4;++j)
            if(backing.subpages[j].present)
                pages.emplace_back(base+j*4096,
                                   backing.bytes.data()+j*4096);
    assert(pages.size()==609 && shadow.host16K.size()==154);
    NothingMappedAt(pages);
    {
        c3d4::OriginalGuestNative4KReadOnlyLease lease;
        c3d4::NativeReadOnlyWitness witness;
        assert(!lease.StageFromPinnedOriginals(
            -1,entropy,witness));
        assert(lease.PagesHeld()==0);
        assert(!witness.originalGuestBytesInstalledReadOnly);
        assert(!lease.StageFromPinnedOriginals(
            root,entropy,witness,2));
        assert(witness.boundedFailureErrno==ECANCELED);
        assert(witness.exactNative4KPagesReserved==2);
        assert(witness.native4KPagesReleasedOnFailure==2);
        assert(lease.PagesHeld()==0);
        NothingMappedAt(pages);
    }
    {
        // Another ownership at third page must NEVER be overwritten.
        void* independent=mmap(
            reinterpret_cast<void*>(
                static_cast<uintptr_t>(pages[2].first)),
            4096,PROT_NONE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
        assert(independent!=MAP_FAILED &&
               reinterpret_cast<uintptr_t>(independent)==pages[2].first);
        assert(NativeMappingRights(pages[2].first)=="---p");
        c3d4::OriginalGuestNative4KReadOnlyLease lease;
        c3d4::NativeReadOnlyWitness witness;
        assert(!lease.StageFromPinnedOriginals(root,entropy,witness));
        assert(witness.boundedFailureErrno==EEXIST);
        assert(witness.exactNative4KPagesReserved==2);
        assert(witness.native4KPagesReleasedOnFailure==2);
        assert(NativeMappingRights(pages[2].first)=="---p");
        assert(lease.PagesHeld()==0);
        assert(munmap(independent,4096)==0);
        NothingMappedAt(pages);
    }
    {
        // Two successfully copied pages must also be rolled back atomically
        // in response to a staged failure after reservation of all 609.
        c3d4::OriginalGuestNative4KReadOnlyLease lease;
        c3d4::NativeReadOnlyWitness witness;
        assert(!lease.StageFromPinnedOriginals(
            root,entropy,witness,609,2));
        assert(witness.boundedFailureErrno==ECANCELED);
        assert(witness.exactNative4KPagesReserved==609);
        assert(witness.originalNative4KPagesByteCompared==2);
        assert(witness.native4KPagesReleasedOnFailure==609);
        assert(!witness.originalGuestBytesInstalledReadOnly);
        assert(lease.PagesHeld()==0);
        NothingMappedAt(pages);
    }
    {
        // Exactly the original authenticated 609 x86 guest 4K pages
        // now exist as non-executable, native 4K, read-only host mappings.
        c3d4::OriginalGuestNative4KReadOnlyLease lease;
        c3d4::NativeReadOnlyWitness witness;
        assert(lease.StageFromPinnedOriginals(
            root,entropy,witness));
        assert(witness.actualNativeKernelPageBytes==4096 &&
               witness.plannedOriginalGuest4KPages==609 &&
               witness.exactNative4KPagesReserved==609 &&
               witness.originalNative4KPagesByteCompared==609 &&
               witness.sourceThreeOriginalELFsSHA256Verified &&
               witness.exactNoreplaceNative4KGuestVAOwned &&
               witness.originalGuestBytesInstalledReadOnly &&
               witness.hostNeverGrantedExecutablePages &&
               witness.allOwnedMapsFinalReadOnly &&
               !witness.originalFexGuestMemoryAttached &&
               !witness.originalLinuxLdsoExecuted &&
               !witness.wineWindowsPEExecuted);
        assert(lease.PagesHeld()==609);
        for(const auto& [addr,source]:pages) {
            assert(lease.ContainsExactPage(addr));
            assert(NativeMappingRights(addr)=="r--p");
            const void* actual=reinterpret_cast<const void*>(
                static_cast<uintptr_t>(addr));
            assert(std::memcmp(actual,source,4096)==0);
        }
        c3d4::NativeReadOnlyWitness duplicate;
        assert(!lease.StageFromPinnedOriginals(
            root,entropy,duplicate));
        assert(lease.PagesHeld()==609);
        assert(lease.Release());
        assert(lease.PagesHeld()==0);
        NothingMappedAt(pages);
    }
    close(root);
    std::puts(
      "KERNIX_G2EC3D4_REAL_PINNED_ORIGINAL_609_GUEST4K_NATIVE_READONLY_EXACT_VA_BYTES_PASS pages=609 native_page=4096 collision_preserved=1 atomic_reserve_and_stage_rollback=1 host_exec=0 fex=0 ldso=0 android_device=0");
    return 0;
}
