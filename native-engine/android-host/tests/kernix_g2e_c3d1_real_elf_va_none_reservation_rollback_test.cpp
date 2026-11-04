// KERNIX G2-E/C3-D1. Linux host CI ONLY: reserve authenticated original
// Linux x86 main, interpreter, libc and stack 16K host pages at exact
// test guest VAs, PROT_NONE, MAP_FIXED_NOREPLACE and nothing else.
// Verify /proc/self/maps ---p and collision/rollback safety.
// x86 guest not executed; never dereference reservation addresses.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d1_prot_none_guest_va_lease.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace d=kernix::g2e::c3d;
namespace d1=kernix::g2e::c3d1;
using namespace kernix::g2e;

static bool IsMappedAsNone(uint64_t va) {
    // Only userspace /proc metadata; never read a PROT_NONE guest address.
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while(std::getline(maps,line)){
        unsigned long long first=0,past=0;
        char perms[5]{};
        if(std::sscanf(line.c_str(),"%llx-%llx %4s",
                       &first,&past,perms)!=3)continue;
        if(va<first || va>=past)continue;
        return std::string(perms)=="---p";
    }
    return false;
}
static bool IsNotMapped(uint64_t va) {
    // mincore is only a mapping-presence check, not a guest dereference.
    unsigned char vec[4]{};
    errno=0;
    return ::mincore(reinterpret_cast<void*>(
             static_cast<uintptr_t>(va)),d::HostPageBytes,vec)!=0 &&
           errno==ENOMEM;
}
static void FailedLeaseMustBeEmpty(
    const d::UnifiedGuestShadow& candidate) {
    d1::ProtNoneGuestVALease reserve;
    d1::ReservationWitness witness;
    assert(!reserve.Reserve(candidate,witness));
    assert(reserve.PagesHeld()==0);
    assert(!witness.allVAsExact &&
           !witness.hostPageWXGranted &&
           !witness.guestBytesInstalledInNativeVA &&
           !witness.fexContextAttached &&
           !witness.x86GuestExecuted &&
           !witness.linuxLdsoExecuted);
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
#if !defined(MAP_FIXED_NOREPLACE)
    std::fputs("C3D1_MAP_FIXED_NOREPLACE_UNAVAILABLE_FAIL_CLOSED\n",stderr);
    return 3;
#endif
    const int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 4;
    GuestPreflight pinned;
    std::string error;
    assert(Validate(fd,pinned,error));
    close(fd);
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    d::UnifiedGuestShadow original;
    assert(d::BuildUnifiedHost16KShadowFromPinnedOriginals(
        pinned,entropy,original,error));
    assert(d1::AttestedHost16KLayout(original));
    assert(original.host16K.size()==154 &&
           original.totalRealGuest4KPages==609 &&
           original.host16KPagesWithWXSubpages==1 &&
           !original.fexGuestMemoryAttached &&
           !original.realGuestVirtualAddressReservation);
    const uint64_t first=original.host16K.begin()->first;
    assert(IsNotMapped(first));
    const uint64_t occupied=std::next(original.host16K.begin(),2)->first;
    assert(IsNotMapped(occupied));
    {
        // Inject failure AFTER the first two genuine exact 16K guest VA
        // reservations. Every acquired address MUST be released.
        d1::ProtNoneGuestVALease lease;
        d1::ReservationWitness witness;
        assert(!lease.Reserve(original,witness,2));
        assert(witness.boundedFailureErrno==ECANCELED &&
               witness.successfullyReservedPages==2 &&
               witness.rolledBackPages==2 &&
               lease.PagesHeld()==0 &&
               !witness.allVAsExact);
        assert(IsNotMapped(first));
        assert(IsNotMapped(std::next(original.host16K.begin())->first));
    }
    {
        // Pre-occupy the *third* guest virtual host page with an unrelated
        // PROT_NONE VMA. Reservation must never use MAP_FIXED and therefore
        // cannot overwrite this distinct ownership. First two roll back.
        void* unrelated=::mmap(
            reinterpret_cast<void*>(static_cast<uintptr_t>(occupied)),
            d::HostPageBytes,PROT_NONE,
            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
        assert(unrelated!=MAP_FAILED &&
               reinterpret_cast<uintptr_t>(unrelated)==occupied);
        assert(IsMappedAsNone(occupied));
        d1::ProtNoneGuestVALease lease;
        d1::ReservationWitness witness;
        assert(!lease.Reserve(original,witness));
        assert(witness.boundedFailureErrno==EEXIST &&
               witness.successfullyReservedPages==2 &&
               witness.rolledBackPages==2 &&
               lease.PagesHeld()==0);
        assert(IsNotMapped(first));
        assert(IsMappedAsNone(occupied)); // user mapping survives unchanged
        assert(::munmap(unrelated,d::HostPageBytes)==0);
        assert(IsNotMapped(occupied));
    }
    {
        // Complete original verified guest VA space: all exact addresses
        // reserved as native PROT_NONE, no exec and no RWX escape.
        d1::ProtNoneGuestVALease lease;
        d1::ReservationWitness witness;
        assert(lease.Reserve(original,witness));
        assert(lease.PagesHeld()==154 &&
               witness.requestedPages==154 &&
               witness.successfullyReservedPages==154 &&
               witness.rolledBackPages==0 &&
               witness.allVAsExact &&
               witness.sourceTripleELFAuthenticated &&
               witness.originalGuestPagePermissionsChecked &&
               witness.mmapFixedNoreplaceUsed &&
               witness.hostMappingWasProtNoneOnly &&
               !witness.hostPageWXGranted &&
               !witness.guestBytesInstalledInNativeVA &&
               !witness.fexContextAttached &&
               !witness.x86GuestExecuted &&
               !witness.linuxLdsoExecuted);
        for(const auto& [address,backing]:original.host16K){
            (void)backing;
            assert(lease.ContainsExactReservedPage(address));
            assert(IsMappedAsNone(address));
        }
        assert(IsMappedAsNone(first));
        assert(!IsNotMapped(first));
        d1::ReservationWitness redundant;
        assert(!lease.Reserve(original,redundant));
        assert(lease.PagesHeld()==154);
        lease.Release();
        assert(lease.PagesHeld()==0);
        for(const auto& [address,backing]:original.host16K) {
            (void)backing;
            assert(IsNotMapped(address));
        }
    }
    {
        // A forged directly mapped/executable source cannot borrow valid
        // SHA provenance to reach the native address reservation.
        auto forged=original;
        forged.directGuestNativePointersExposed=true;
        FailedLeaseMustBeEmpty(forged);
        forged=original;
        forged.fexCpuStateExecuted=true;
        FailedLeaseMustBeEmpty(forged);
        forged=original;
        forged.host16K.begin()->second.directHostGuestMappingApproved=true;
        FailedLeaseMustBeEmpty(forged);
        forged=original;
        forged.host16K.begin()->second.subpages[0].currentRights=
            c3::R|c3::W|c3::X;
        FailedLeaseMustBeEmpty(forged);
    }
    assert(IsNotMapped(first));
    std::printf(
      "KERNIX_G2EC3D1_REAL_ORIGINAL_LINUX_X86_ELF_154_HOST16K_EXACT_VA_PROT_NONE_NO_REPLACE_ROLLBACK_PASS reserved=154 owner_collision_preserved=1 atomic_rollback=1 host_prot_none=1 fex_attached=0 ldso_entered=0\n");
    return 0;
}
