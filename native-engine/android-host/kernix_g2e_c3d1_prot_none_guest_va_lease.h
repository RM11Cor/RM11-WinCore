#pragma once
// KERNIX G2-E/C3-D1: OS-backed 16K guest-VA RESERVATION GATE ONLY.
// Authenticated synthetic x86 Linux VAs from C3-D0 are reserved using
// MAP_FIXED_NOREPLACE + PROT_NONE, never MAP_FIXED or host RWX.
// Fail-closed on MAP_FIXED_NOREPLACE absence, collisions, wrong exact
// mapping address, guard errors or incomplete reservations.
// RAII rolls back exact owned ranges, never overwrites existing VMAs.
// The mappings remain PROT_NONE: zero guest bytes, code or executable
// host pages are installed. Does not attach them to FEX or run ld-linux.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d_unified_guest_va_shadow.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <sys/mman.h>
#include <utility>
#include <vector>

namespace kernix::g2e::c3d1 {
inline constexpr size_t kMaxReservation16KPages=2048;
struct ReservationWitness {
    size_t requestedPages=0;
    size_t successfullyReservedPages=0;
    size_t rolledBackPages=0;
    int boundedFailureErrno=0;
    bool allVAsExact=false;
    bool sourceTripleELFAuthenticated=false;
    bool originalGuestPagePermissionsChecked=false;
    bool hostMappingWasProtNoneOnly=true;
    bool mmapFixedNoreplaceUsed=false;
    bool hostPageWXGranted=false;
    bool guestBytesInstalledInNativeVA=false;
    bool fexContextAttached=false;
    bool x86GuestExecuted=false;
    bool linuxLdsoExecuted=false;
};
inline bool AttestedHost16KLayout(
    const c3d::UnifiedGuestShadow& source) noexcept {
    if(!source.pinnedOriginalThreeELFsVerified ||
       !source.allOriginalBytesCopiedToHostOwnedBuffers ||
       !source.software4KGuestPermissionsEnforced ||
       source.realGuestVirtualAddressReservation ||
       source.host16KSubpageMprotectImplemented ||
       source.fexGuestMemoryAttached ||
       source.fexCpuStateExecuted ||
       source.originalLdsoEntered ||
       source.originalLibcEntered ||
       source.directGuestNativePointersExposed ||
       source.host16K.empty() ||
       source.host16K.size()>kMaxReservation16KPages ||
       source.host16KPageGroups!=source.host16K.size() ||
       source.totalRealGuest4KPages==0 ||
       source.host16KPagesWithWXSubpages==0 ||
       source.originalInterpreterGuestRIP==0 ||
       source.initialLinuxGuestRSP==0)
        return false;
    size_t counted=0,wx=0;
    for(const auto& [address,group]:source.host16K) {
        if((address&(c3d::HostPageBytes-1))!=0 ||
           !c1::GuestRange(address,c3d::HostPageBytes) ||
           group.directHostGuestMappingApproved)
            return false;
        uint8_t total=0;
        unsigned occupied=0;
        for(const auto& sub:group.subpages) {
            if(!sub.present)continue;
            if(!(sub.currentRights&c3::R) ||
               (sub.currentRights&(c3::W|c3::X))==(c3::W|c3::X) ||
               (sub.currentRights&~uint8_t(7)) ||
               sub.currentRights!=sub.initialRights)
                return false;
            total|=sub.currentRights;
            ++occupied;
        }
        if(!occupied)return false;
        counted+=occupied;
        const bool mixedWx=(total&(c3::W|c3::X))==(c3::W|c3::X);
        if(mixedWx)++wx;
        if(mixedWx!=group.originalHostWideWXConflict)return false;
    }
    return counted==source.totalRealGuest4KPages &&
           wx==source.host16KPagesWithWXSubpages;
}

// A *reservation* grants NO permissions and never exposes guest-VA
// pointers. This is real Linux host VM ownership, not a FEX mapping.
class ProtNoneGuestVALease final {
public:
    ProtNoneGuestVALease()=default;
    ProtNoneGuestVALease(const ProtNoneGuestVALease&)=delete;
    ProtNoneGuestVALease& operator=(const ProtNoneGuestVALease&)=delete;
    ProtNoneGuestVALease(ProtNoneGuestVALease&&)=delete;
    ProtNoneGuestVALease& operator=(ProtNoneGuestVALease&&)=delete;
    ~ProtNoneGuestVALease(){Release();}

    // If the OS supports MAP_FIXED_NOREPLACE only. failAfter is used by
    // a bounded CI negative test to prove all-or-nothing rollback.
    bool Reserve(const c3d::UnifiedGuestShadow& source,
                 ReservationWitness& result,
                 size_t testOnlyFailAfter=kMaxReservation16KPages) noexcept {
        result={};
        result.requestedPages=source.host16K.size();
        if(!owned_.empty() || !AttestedHost16KLayout(source))
            return false;
#if !defined(MAP_FIXED_NOREPLACE)
        // NEVER fall back to MAP_FIXED (which can destroy an existing VMA).
        return false;
#else
        for(const auto& [page,group]:source.host16K) {
            (void)group;
            if(owned_.size()>=testOnlyFailAfter) {
                result.boundedFailureErrno=ECANCELED;
                const size_t before=owned_.size();
                Release();
                result.rolledBackPages=before;
                return false;
            }
            errno=0;
            void* p=::mmap(reinterpret_cast<void*>(
                               static_cast<uintptr_t>(page)),
                           c3d::HostPageBytes,PROT_NONE,
                           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,
                           -1,0);
            if(p==MAP_FAILED) {
                result.boundedFailureErrno=errno;
                const size_t before=owned_.size();
                Release();
                result.rolledBackPages=before;
                return false;
            }
            if(reinterpret_cast<uintptr_t>(p)!=page) {
                // Old kernels may ignore unknown flags and return an
                // unrelated address. Reject it and unmap only that
                // unexpected mapping which THIS syscall just created.
                ::munmap(p,c3d::HostPageBytes);
                result.boundedFailureErrno=ENOTSUP;
                const size_t before=owned_.size();
                Release();
                result.rolledBackPages=before;
                return false;
            }
            owned_.push_back(static_cast<uintptr_t>(page));
            ++result.successfullyReservedPages;
        }
        result.allVAsExact=true;
        result.sourceTripleELFAuthenticated=true;
        result.originalGuestPagePermissionsChecked=true;
        result.mmapFixedNoreplaceUsed=true;
        return true;
#endif
    }
    void Release() noexcept {
        for(const auto addr:owned_) {
            // Never touch any other process VM region or a borrowed pointer.
            ::munmap(reinterpret_cast<void*>(addr),c3d::HostPageBytes);
        }
        owned_.clear();
    }
    size_t PagesHeld() const noexcept {return owned_.size();}
    bool ContainsExactReservedPage(uint64_t page) const noexcept {
        for(auto p:owned_)if(p==page)return true;
        return false;
    }
private:
    std::vector<uintptr_t> owned_{};
};
} // namespace kernix::g2e::c3d1
