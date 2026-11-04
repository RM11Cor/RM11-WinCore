#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D4: ORIGINAL SHA-locked x86 Linux main/ld-linux/libc
// and guest stack: native 4KiB host READ-ONLY byte-staging gate.
// This is an independent Linux-host / Android-Bionic BUILD-ONLY component.
// NO FEX, no guest CPU, no ld-linux entry, no Wine, no PROT_EXEC, no MAP_FIXED.
// The preflight must have checked the actual pinned original ELF file hashes.
// All guest VAs are untrusted until 4K kernel PAGE_SIZE, exact NOREPLACE,
// bounded page rights, and non-overwrite checks pass. RAII releases ALL maps.
#include "kernix_g2e_c3d1_prot_none_guest_va_lease.h"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace kernix::g2e::c3d4 {
inline constexpr size_t kExpectedPinnedGuest4KPages=609;
inline constexpr size_t kExpectedPinnedHost16KGroups=154;

struct NativeReadOnlyWitness {
    uint64_t actualNativeKernelPageBytes=0;
    size_t plannedOriginalGuest4KPages=0;
    size_t exactNative4KPagesReserved=0;
    size_t originalNative4KPagesByteCompared=0;
    size_t native4KPagesReleasedOnFailure=0;
    int boundedFailureErrno=0;
    bool sourceThreeOriginalELFsSHA256Verified=false;
    bool exactNoreplaceNative4KGuestVAOwned=false;
    bool originalGuestBytesInstalledReadOnly=false;
    bool hostNeverGrantedExecutablePages=true;
    bool allOwnedMapsFinalReadOnly=false;
    bool originalFexGuestMemoryAttached=false;
    bool originalLinuxLdsoExecuted=false;
    bool wineWindowsPEExecuted=false;
};

class OriginalGuestNative4KReadOnlyLease final {
    struct PageSource {
        uint64_t address;
        const unsigned char* sourceBytes; // points into live verified shadow
    };
    std::vector<uintptr_t> owned_{};
public:
    OriginalGuestNative4KReadOnlyLease()=default;
    OriginalGuestNative4KReadOnlyLease(
        const OriginalGuestNative4KReadOnlyLease&)=delete;
    OriginalGuestNative4KReadOnlyLease& operator=(
        const OriginalGuestNative4KReadOnlyLease&)=delete;
    ~OriginalGuestNative4KReadOnlyLease(){ Release(); }

    size_t PagesHeld() const noexcept { return owned_.size(); }
    bool ContainsExactPage(uint64_t va) const noexcept {
        for(uintptr_t p:owned_)if(static_cast<uint64_t>(p)==va)return true;
        return false;
    }
    bool Release() noexcept {
        // Failed munmap pages stay owned instead of being forgotten.
        // An incomplete rollback must never report full cleanup.
        size_t retained=0;
        for(size_t i=0;i<owned_.size();++i) {
            const uintptr_t page=owned_[i];
            if(::munmap(reinterpret_cast<void*>(page),4096)!=0)
                owned_[retained++]=page;
        }
        owned_.resize(retained);
        return retained==0;
    }
    bool StageFromPinnedOriginals(
        int pinnedRootFd,const std::array<uint8_t,16>& entropy,
        NativeReadOnlyWitness& witness,
        size_t failAfterReservations=kExpectedPinnedGuest4KPages,
        size_t failAfterCopies=kExpectedPinnedGuest4KPages) noexcept {
        witness={};
        if(!owned_.empty() || pinnedRootFd<0) {
            witness.boundedFailureErrno=EINVAL;
            return false;
        }
        const long kernelPage=sysconf(_SC_PAGESIZE);
        if(kernelPage>0)
            witness.actualNativeKernelPageBytes=
                static_cast<uint64_t>(kernelPage);
        // Native 16KiB kernels need a different, independently verified
        // subpage policy. Never treat a 16K software grouping as native 4K.
        if(kernelPage!=4096) {
            witness.boundedFailureErrno=ENOTSUP;
            return false;
        }
#if !defined(MAP_FIXED_NOREPLACE)
        witness.boundedFailureErrno=ENOTSUP;
        return false;
#else
        // All potentially allocating operations happen before any mmap.
        try {
            GuestPreflight pinned;
            std::string why;
            if(!Validate(pinnedRootFd,pinned,why)) {
                witness.boundedFailureErrno=ENOEXEC;
                return false;
            }
            c3d::UnifiedGuestShadow shadow;
            if(!c3d::BuildUnifiedHost16KShadowFromPinnedOriginals(
                    pinned,entropy,shadow,why) ||
               !c3d1::AttestedHost16KLayout(shadow) ||
               shadow.totalRealGuest4KPages!=kExpectedPinnedGuest4KPages ||
               shadow.host16K.size()!=kExpectedPinnedHost16KGroups ||
               shadow.fexGuestMemoryAttached ||
               shadow.originalLdsoEntered ||
               shadow.directGuestNativePointersExposed) {
                witness.boundedFailureErrno=ENOEXEC;
                return false;
            }
            std::vector<PageSource> pages;
            pages.reserve(kExpectedPinnedGuest4KPages);
            for(const auto& [base,backing]:shadow.host16K) {
                for(size_t j=0;j<4;++j) {
                    const auto& sub=backing.subpages[j];
                    if(!sub.present)continue;
                    const uint64_t va=base+j*4096;
                    if(!c1::GuestRange(va,4096) ||
                       (va&4095)!=0 ||
                       (sub.currentRights&c3::R)==0 ||
                       (sub.currentRights&(c3::W|c3::X))==
                           (c3::W|c3::X) ||
                       sub.currentRights!=sub.initialRights ||
                       sub.currentRights&~uint8_t(7)) {
                        witness.boundedFailureErrno=EINVAL;
                        return false;
                    }
                    pages.push_back(PageSource{
                        va,backing.bytes.data()+j*4096});
                }
            }
            if(pages.size()!=kExpectedPinnedGuest4KPages) {
                witness.boundedFailureErrno=EINVAL;
                return false;
            }
            owned_.reserve(pages.size());
            witness.plannedOriginalGuest4KPages=pages.size();
            witness.sourceThreeOriginalELFsSHA256Verified=true;
            // Phase 1: take ownership of EVERY requested exact VA before
            // changing ANY guest byte; external collisions fail closed.
            for(const auto& page:pages) {
                if(owned_.size()>=failAfterReservations) {
                    witness.boundedFailureErrno=ECANCELED;
                    const auto n=owned_.size();
                    const bool cleared=Release();
                    witness.native4KPagesReleasedOnFailure=
                        n-owned_.size();
                    if(!cleared)witness.boundedFailureErrno=EBUSY;
                    return false;
                }
                errno=0;
                void* result=::mmap(
                    reinterpret_cast<void*>(
                        static_cast<uintptr_t>(page.address)),
                    4096,PROT_NONE,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
                if(result==MAP_FAILED) {
                    witness.boundedFailureErrno=errno;
                    const auto n=owned_.size();
                    const bool cleared=Release();
                    witness.native4KPagesReleasedOnFailure=
                        n-owned_.size();
                    if(!cleared)witness.boundedFailureErrno=EBUSY;
                    return false;
                }
                if(reinterpret_cast<uintptr_t>(result)!=page.address) {
                    // Unknown old-kernel flag behavior: only unmap the
                    // unrelated VA created by this call, then roll back.
                    if(result!=reinterpret_cast<void*>(
                            static_cast<uintptr_t>(page.address)))
                        ::munmap(result,4096);
                    witness.boundedFailureErrno=ENOTSUP;
                    const auto n=owned_.size();
                    const bool cleared=Release();
                    witness.native4KPagesReleasedOnFailure=
                        n-owned_.size();
                    if(!cleared)witness.boundedFailureErrno=EBUSY;
                    return false;
                }
                owned_.push_back(static_cast<uintptr_t>(page.address));
                ++witness.exactNative4KPagesReserved;
            }
            witness.exactNoreplaceNative4KGuestVAOwned=true;
            // Phase 2: transient W (never X) only on OUR mapped pages.
            // Final pages are ALL PROT_READ regardless of guest W/X flags.
            // This is intentionally NOT guest rights or FEX memory ownership.
            for(const auto& page:pages) {
                if(witness.originalNative4KPagesByteCompared>=
                        failAfterCopies) {
                    witness.boundedFailureErrno=ECANCELED;
                    const auto n=owned_.size();
                    const bool cleared=Release();
                    witness.native4KPagesReleasedOnFailure=
                        n-owned_.size();
                    if(!cleared)witness.boundedFailureErrno=EBUSY;
                    return false;
                }
                void* dest=reinterpret_cast<void*>(
                    static_cast<uintptr_t>(page.address));
                if(::mprotect(dest,4096,PROT_READ|PROT_WRITE)!=0) {
                    witness.boundedFailureErrno=errno;
                    const auto n=owned_.size();
                    const bool cleared=Release();
                    witness.native4KPagesReleasedOnFailure=
                        n-owned_.size();
                    if(!cleared)witness.boundedFailureErrno=EBUSY;
                    return false;
                }
                std::memcpy(dest,page.sourceBytes,4096);
                if(::mprotect(dest,4096,PROT_READ)!=0) {
                    witness.boundedFailureErrno=errno;
                    const auto n=owned_.size();
                    const bool cleared=Release();
                    witness.native4KPagesReleasedOnFailure=
                        n-owned_.size();
                    if(!cleared)witness.boundedFailureErrno=EBUSY;
                    return false;
                }
                if(std::memcmp(dest,page.sourceBytes,4096)!=0) {
                    witness.boundedFailureErrno=EIO;
                    const auto n=owned_.size();
                    const bool cleared=Release();
                    witness.native4KPagesReleasedOnFailure=
                        n-owned_.size();
                    if(!cleared)witness.boundedFailureErrno=EBUSY;
                    return false;
                }
                ++witness.originalNative4KPagesByteCompared;
            }
            witness.originalGuestBytesInstalledReadOnly=true;
            witness.allOwnedMapsFinalReadOnly=true;
            return true;
        } catch(...) {
            const auto n=owned_.size();
            const bool cleared=Release();
            witness.native4KPagesReleasedOnFailure=n-owned_.size();
            witness.boundedFailureErrno=cleared?ENOMEM:EBUSY;
            return false;
        }
#endif
    }
};
} // namespace kernix::g2e::c3d4
