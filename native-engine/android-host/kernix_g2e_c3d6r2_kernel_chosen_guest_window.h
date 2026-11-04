#pragma once
// SPDX-License-Identifier: MIT
// KERNIX G2-E/C3-D6-R2: user-VA independent native 4K read-only staging.
// Authentic SHA-locked original x86 ELF main/ld-linux/libc + initial stack
// are DATA ONLY. Guest logical VAs are keys, never host pointers here.
// Linux/Android kernel selects one contiguous nonexecutable host mapping.
// This does NOT attach to FEX, emulate ld-linux or authorize guest execution.
#include "kernix_g2e_c3d4_native_4k_original_elf_readonly_lease.h"
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace kernix::g2e::c3d6r2 {
inline constexpr size_t kOriginalGuest4KPages=609;
inline constexpr size_t kNativePageSize=4096;
inline constexpr size_t kNativeWindowBytes=kOriginalGuest4KPages*kNativePageSize;
enum class Phase: uint8_t {
    NotStarted, WrongPageSize, OriginalELFVerification,
    BuildOriginalShadow, ValidateOriginalGuestLayout,
    ReserveHostSelectedWindow, CopyAndSeal, Verify,
    Complete, CleanupFailed
};
inline const char* PhaseName(Phase p) noexcept {
    switch(p) {
        case Phase::NotStarted: return "NOT_STARTED";
        case Phase::WrongPageSize: return "WRONG_KERNEL_PAGE";
        case Phase::OriginalELFVerification: return "VERIFY_ORIGINAL_ELFS";
        case Phase::BuildOriginalShadow: return "BUILD_ORIGINAL_SHADOW";
        case Phase::ValidateOriginalGuestLayout: return "VALIDATE_GUEST_LAYOUT";
        case Phase::ReserveHostSelectedWindow: return "RESERVE_KERNEL_CHOSEN_WINDOW";
        case Phase::CopyAndSeal: return "COPY_AND_SEAL_HOST_RO";
        case Phase::Verify: return "VERIFY_609_ORIGINAL_PAGES";
        case Phase::Complete: return "COMPLETE";
        case Phase::CleanupFailed: return "CLEANUP_FAILED";
    }
    return "UNKNOWN";
}
struct Witness {
    Phase phase=Phase::NotStarted;
    long nativeKernelPageBytes=0;
    size_t originalGuestPages=0;
    size_t pagesCopiedAndCompared=0;
    size_t pagesReleased=0;
    int failureErrno=0;
    bool originalSourceSha256Verified=false;
    bool exactGuestToHostMetadataMaintained=false;
    bool kernelChoseHostVA=false;
    bool originalNativeGuestVAsMapped=false;
    bool noHostExecutablePages=true;
    bool allPagesFinallyReadOnly=false;
    bool fexOriginalGuestMemoryAttached=false;
    bool originalLdsoEntered=false;
    bool windowsPEExecuted=false;
};
class KernelChosenReadOnlyGuestWindow final {
    struct Entry {
        uint64_t guestVA;
        uint8_t guestRights;
        uint16_t sourceIndex;
    };
    void* window_=MAP_FAILED;
    std::vector<Entry> mapping_{};
public:
    KernelChosenReadOnlyGuestWindow()=default;
    KernelChosenReadOnlyGuestWindow(const KernelChosenReadOnlyGuestWindow&)=delete;
    KernelChosenReadOnlyGuestWindow& operator=(const KernelChosenReadOnlyGuestWindow&)=delete;
    ~KernelChosenReadOnlyGuestWindow(){Release();}
    bool Release() noexcept {
        if(window_!=MAP_FAILED) {
            if(::munmap(window_,kNativeWindowBytes)!=0)return false;
            window_=MAP_FAILED;
        }
        mapping_.clear();
        return true;
    }
    size_t PagesHeld() const noexcept {
        return window_==MAP_FAILED?0:mapping_.size();
    }
    // A pointer is READ-ONLY evidence, never a FEX native guest VA.
    // Reject cross-page reads; no raw guest pointer used for execution.
    const uint8_t* ReadOnlyNativePageForGuestVA(
        uint64_t guestVA,size_t bytes) const noexcept {
        if(window_==MAP_FAILED || bytes==0 || bytes>kNativePageSize)
            return nullptr;
        const uint64_t page=guestVA&~uint64_t(kNativePageSize-1);
        const size_t offset=static_cast<size_t>(guestVA-page);
        if(bytes>kNativePageSize-offset)return nullptr;
        const auto it=std::lower_bound(
            mapping_.begin(),mapping_.end(),page,
            [](const Entry& e,uint64_t v){return e.guestVA<v;});
        if(it==mapping_.end() || it->guestVA!=page ||
           !(it->guestRights&c3::R))return nullptr;
        const size_t index=static_cast<size_t>(
            it-mapping_.begin());
        return static_cast<const uint8_t*>(window_)+
            index*kNativePageSize+offset;
    }
    bool StageOriginals(
        int privateRootFD,const std::array<uint8_t,16>& entropy,
        Witness& witness,
        size_t testFailAfterCopied=kOriginalGuest4KPages) noexcept {
        witness={};
        if(window_!=MAP_FAILED || privateRootFD<0) {
            witness.failureErrno=EINVAL;
            return false;
        }
        witness.nativeKernelPageBytes=::sysconf(_SC_PAGESIZE);
        if(witness.nativeKernelPageBytes!=4096) {
            witness.phase=Phase::WrongPageSize;
            witness.failureErrno=ENOTSUP;
            return false;
        }
        try {
            witness.phase=Phase::OriginalELFVerification;
            GuestPreflight pinned;
            std::string reason;
            if(!Validate(privateRootFD,pinned,reason)) {
                witness.failureErrno=ENOEXEC;
                return false;
            }
            witness.originalSourceSha256Verified=true;
            witness.phase=Phase::BuildOriginalShadow;
            c3d::UnifiedGuestShadow source;
            if(!c3d::BuildUnifiedHost16KShadowFromPinnedOriginals(
                   pinned,entropy,source,reason)) {
                witness.failureErrno=ENOEXEC;
                return false;
            }
            witness.phase=Phase::ValidateOriginalGuestLayout;
            if(!c3d1::AttestedHost16KLayout(source) ||
               source.totalRealGuest4KPages!=kOriginalGuest4KPages ||
               source.host16K.size()!=154 ||
               source.directGuestNativePointersExposed ||
               source.fexGuestMemoryAttached ||
               source.originalLdsoEntered) {
                witness.failureErrno=ENOEXEC;
                return false;
            }
            mapping_.reserve(kOriginalGuest4KPages);
            std::vector<const uint8_t*> original;
            original.reserve(kOriginalGuest4KPages);
            for(const auto& [base,backing]:source.host16K) {
                for(size_t j=0;j<4;++j) {
                    const auto& sub=backing.subpages[j];
                    if(!sub.present)continue;
                    const uint64_t guestVA=base+j*kNativePageSize;
                    if(!c1::GuestRange(guestVA,kNativePageSize) ||
                       (guestVA&4095)!=0 ||
                       !(sub.currentRights&c3::R) ||
                       (sub.currentRights&(c3::W|c3::X))==
                           (c3::W|c3::X) ||
                       sub.currentRights!=sub.initialRights) {
                        witness.failureErrno=EINVAL;
                        mapping_.clear();
                        return false;
                    }
                    mapping_.push_back(Entry{guestVA,
                        sub.currentRights,
                        static_cast<uint16_t>(mapping_.size())});
                    original.push_back(backing.bytes.data()+j*kNativePageSize);
                }
            }
            if(mapping_.size()!=kOriginalGuest4KPages ||
               original.size()!=mapping_.size()) {
                witness.failureErrno=EINVAL;
                mapping_.clear();
                return false;
            }
            for(size_t i=1;i<mapping_.size();++i)
                if(mapping_[i].guestVA<=mapping_[i-1].guestVA) {
                    witness.failureErrno=EINVAL;
                    mapping_.clear();
                    return false;
                }
            witness.originalGuestPages=mapping_.size();
            witness.phase=Phase::ReserveHostSelectedWindow;
            errno=0;
            // Crucial Android fix: original 0x5555... and 0x7fff...
            // Linux fixture VAs are NOT forced into Android task size.
            window_=::mmap(nullptr,kNativeWindowBytes,PROT_NONE,
                MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            if(window_==MAP_FAILED) {
                witness.failureErrno=errno;
                mapping_.clear();
                return false;
            }
            witness.kernelChoseHostVA=true;
            witness.exactGuestToHostMetadataMaintained=true;
            witness.phase=Phase::CopyAndSeal;
            for(size_t i=0;i<mapping_.size();++i) {
                if(i>=testFailAfterCopied) {
                    witness.failureErrno=ECANCELED;
                    if(!Release())witness.phase=Phase::CleanupFailed;
                    else witness.pagesReleased=kOriginalGuest4KPages;
                    return false;
                }
                void* dest=static_cast<uint8_t*>(window_)+
                    i*kNativePageSize;
                if(::mprotect(dest,kNativePageSize,
                              PROT_READ|PROT_WRITE)!=0) {
                    witness.failureErrno=errno;
                    if(!Release())witness.phase=Phase::CleanupFailed;
                    else witness.pagesReleased=kOriginalGuest4KPages;
                    return false;
                }
                std::memcpy(dest,original[i],kNativePageSize);
                if(::mprotect(dest,kNativePageSize,PROT_READ)!=0) {
                    witness.failureErrno=errno;
                    if(!Release())witness.phase=Phase::CleanupFailed;
                    else witness.pagesReleased=kOriginalGuest4KPages;
                    return false;
                }
                if(std::memcmp(dest,original[i],kNativePageSize)!=0) {
                    witness.failureErrno=EIO;
                    if(!Release())witness.phase=Phase::CleanupFailed;
                    else witness.pagesReleased=kOriginalGuest4KPages;
                    return false;
                }
                ++witness.pagesCopiedAndCompared;
            }
            witness.phase=Phase::Verify;
            for(size_t i=0;i<mapping_.size();++i) {
                const auto& page=mapping_[i];
                const uint8_t* observed=
                    ReadOnlyNativePageForGuestVA(page.guestVA,4096);
                if(observed==nullptr ||
                   observed!=static_cast<uint8_t*>(window_)+
                       i*kNativePageSize ||
                   std::memcmp(observed,original[i],4096)!=0) {
                    witness.failureErrno=EIO;
                    if(!Release())witness.phase=Phase::CleanupFailed;
                    else witness.pagesReleased=kOriginalGuest4KPages;
                    return false;
                }
            }
            witness.allPagesFinallyReadOnly=true;
            witness.phase=Phase::Complete;
            return true;
        } catch(...) {
            witness.failureErrno=ENOMEM;
            if(!Release())witness.phase=Phase::CleanupFailed;
            return false;
        }
    }
};
} // namespace kernix::g2e::c3d6r2
