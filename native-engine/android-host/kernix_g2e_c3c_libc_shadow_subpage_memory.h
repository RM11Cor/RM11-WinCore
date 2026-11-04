#pragma once
// KERNIX G2-E/C3-C: SOURCE-AUTHENTICATED libc.so.6 4KiB guest page shadow.
// All bytes are copied from the 3 pinned original x86 Linux ELF snapshots.
// Provides owner-owned C++ byte arrays with software 4KiB R/W/X permission
// checks. It does NOT give FEX pointers, does NOT mmap/mprotect any guest VA,
// does NOT run guest x86 code, and does NOT implement host 16KiB mprotect.
// RELRO is changed ONLY in a TEST-ONLY synthetic post-relocation transition.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3b_original_glibc_relro_page_plan.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>
namespace kernix::g2e::c3c {
inline constexpr uint64_t kPage=4096;
inline constexpr size_t kMaxShadowPages=2048;
struct ShadowPage {
    std::array<unsigned char,4096> data{};
    uint8_t originalRights=0;
    uint8_t afterRelroRights=0;
    uint8_t currentRights=0;
};
struct LibcShadow {
    std::map<uint64_t,ShadowPage> pages;
    uint64_t libraryLoadBias=0;
    uint64_t libraryBase=0;
    uint64_t libraryEnd=0;
    size_t originalFileBytesCopied=0;
    size_t bssBytesZeroInitialized=0;
    size_t relro4KPages=0;
    bool originalLibcSHA256Proved=false;
    bool sourceBytesCopiedIntoPrivateShadow=false;
    bool postRelroTestOnly=false;
    bool software4KPermissionsEnforced=false;
    bool host16KSubpageMprotectImplemented=false; // ALWAYS FALSE
    bool actualGuestMemoryMapped=false;
    bool fexCpuStateUsesShadow=false;
    bool originalGuestLoaderExecuted=false;
    bool originalGuestLibcExecuted=false;
    bool nativeDirectGuestAddressAccessAuthorized=false; // ALWAYS FALSE
};
inline bool PreparePinnedLibcShadowDataOnly(
    const GuestPreflight& source,
    const std::array<uint8_t,16>& entropy,
    const c3b::Result& expected,
    LibcShadow& output,std::string& reason) {
    output={};
    const auto fail=[&](const char* why){
        output={};reason=why;return false;
    };
    if(!source.exactSha256Matched ||
       !source.readOnlyAnonymousSnapshots ||
       !source.exactInterpreterAndGlibcClosure ||
       source.guestCodeExecuted || source.dynamicLinkerExecuted ||
       source.fexAttached || source.wineExecuted ||
       !source.snapshots[2].readOnlySnapshot() ||
       !source.snapshots[2].bytes() ||
       source.snapshots[2].size()!=kGuest[2].bytes ||
       !expected.originalLibcSHA256Attested ||
       !expected.relroPlannedNotApplied ||
       !expected.fullImagePagePlanValidated ||
       expected.nativeDirectMappingAuthorized ||
       expected.hostGuestMemoryInstalled ||
       expected.originalFEXGuestEntered ||
       expected.originalLibcExecuted ||
       expected.originalLdsoExecuted ||
       expected.initialGuest4KPages.size()!=expected.afterRelroGuest4KPages.size() ||
       expected.libcUnique4KPages==0 ||
       expected.libcUnique4KPages>kMaxShadowPages ||
       expected.fullyCoveredRelro4KPages==0)
        return fail("C3C_UNTRUSTED_SIGNED_SOURCE_OR_PLAN");
    // Rebuild the complete reference plan from immutable SHA-pinned bytes
    // and caller-supplied entropy; never trust a caller-forged "verified"
    // flag or a modified RELRO permission vector.
    c3b::Result independentlyVerified;
    std::string verifyReason;
    if(!c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
           source,entropy,independentlyVerified,verifyReason))
        return fail("C3C_CANONICAL_SOURCE_PLAN_REBUILD_REJECTED");
    const auto& canonical=independentlyVerified;
    if(expected.libcSyntheticLoadBias!=canonical.libcSyntheticLoadBias ||
       expected.libcSyntheticRelroFirst!=canonical.libcSyntheticRelroFirst ||
       expected.libcSyntheticRelroPastLast!=canonical.libcSyntheticRelroPastLast ||
       expected.libcPTLoadCount!=canonical.libcPTLoadCount ||
       expected.libcUnique4KPages!=canonical.libcUnique4KPages ||
       expected.fullyCoveredRelro4KPages!=canonical.fullyCoveredRelro4KPages ||
       expected.initialHost16KWxConflicts!=canonical.initialHost16KWxConflicts ||
       expected.afterRelroHost16KWxConflicts!=canonical.afterRelroHost16KWxConflicts ||
       expected.initialGuest4KPages.size()!=canonical.initialGuest4KPages.size() ||
       expected.afterRelroGuest4KPages.size()!=canonical.afterRelroGuest4KPages.size())
        return fail("C3C_CALLER_SUPPLIED_PAGE_PLAN_NOT_CANONICAL");
    for(size_t i=0;i<canonical.initialGuest4KPages.size();++i){
        const auto& a=expected.initialGuest4KPages[i];
        const auto& b=canonical.initialGuest4KPages[i];
        const auto& c=expected.afterRelroGuest4KPages[i];
        const auto& d=canonical.afterRelroGuest4KPages[i];
        if(a.address!=b.address || a.permissions!=b.permissions ||
           a.isStack!=b.isStack || c.address!=d.address ||
           c.permissions!=d.permissions || c.isStack!=d.isStack)
            return fail("C3C_CALLER_FORGED_4K_RIGHTS_OR_RELRO");
    }
    c3b::ParsedLibc parsed;
    std::string error;
    const auto* original=source.snapshots[2].bytes();
    const size_t originalSize=source.snapshots[2].size();
    if(!c3b::ParseLibcELFHeadersOnly(
        std::span<const unsigned char>(original,originalSize),
        parsed,error) ||
       parsed.ptLoads.size()!=expected.libcPTLoadCount ||
       expected.libcSyntheticLoadBias!=c3b::kLibcTestBase-parsed.lowestLoadPage)
        return fail("C3C_LIBC_PT_LOAD_OR_BIAS_CHANGED");
    uint64_t first=UINT64_MAX,last=0;
    std::map<uint64_t,ShadowPage> shadow;
    for(const auto& seg:parsed.ptLoads) {
        if(seg.first>UINT64_MAX-expected.libcSyntheticLoadBias ||
           seg.pastLast>c1::kGuestUserLimit-expected.libcSyntheticLoadBias ||
           seg.originalFileOffset>originalSize ||
           seg.originalFileBytes>originalSize-seg.originalFileOffset)
            return fail("C3C_SEGMENT_GUEST_ADDRESS_OR_FILE_OVERFLOW");
        const uint64_t start=seg.first+expected.libcSyntheticLoadBias;
        const uint64_t finish=seg.pastLast+expected.libcSyntheticLoadBias;
        first=std::min(first,start);
        last=std::max(last,finish);
        const uint64_t pageFirst=start&~(kPage-1);
        const uint64_t pageLast=(finish-1)&~(kPage-1);
        for(uint64_t page=pageFirst;;page+=kPage){
            shadow.try_emplace(page);
            if(shadow.size()>kMaxShadowPages)
                return fail("C3C_LIBC_GUEST_4K_SHADOW_PAGE_CAP");
            if(page==pageLast)break;
        }
        // Fresh zero-filled 4K pages are the BSS backing. Copy ONLY the
        // bytes in genuine pinned ELF p_filesz to their guest VA offsets;
        // untouched p_memsz-p_filesz bytes remain initialized to zero.
        size_t done=0;
        while(done<seg.originalFileBytes){
            const uint64_t va=start+done;
            auto it=shadow.find(va&~(kPage-1));
            if(it==shadow.end())
                return fail("C3C_ELF_SOURCE_COPY_PAGE_NOT_PRESENT");
            const size_t off=static_cast<size_t>(va&(kPage-1));
            const size_t n=std::min(
                static_cast<size_t>(seg.originalFileBytes-done),4096-off);
            std::memcpy(it->second.data.data()+off,
                original+seg.originalFileOffset+done,n);
            done+=n;
        }
        output.originalFileBytesCopied+=
            static_cast<size_t>(seg.originalFileBytes);
        output.bssBytesZeroInitialized+=
            static_cast<size_t>((seg.pastLast-seg.first)-seg.originalFileBytes);
    }
    if(shadow.size()!=expected.libcUnique4KPages ||
       first==UINT64_MAX || first>=last)
        return fail("C3C_SOURCE_PAGE_COUNT_OR_BOUNDS_MISMATCH");
    size_t transitioned=0;
    for(auto& [address,page]:shadow){
        auto before=std::lower_bound(
            expected.initialGuest4KPages.begin(),
            expected.initialGuest4KPages.end(),address,
            [](const c3::GuestPage& p,uint64_t value) {
                return p.address<value;
            });
        auto after=std::lower_bound(
            expected.afterRelroGuest4KPages.begin(),
            expected.afterRelroGuest4KPages.end(),address,
            [](const c3::GuestPage& p,uint64_t value) {
                return p.address<value;
            });
        if(before==expected.initialGuest4KPages.end() ||
           after==expected.afterRelroGuest4KPages.end() ||
           before->address!=address || after->address!=address ||
           !(before->permissions&c3::R) ||
           ((before->permissions&(c3::W|c3::X))==(c3::W|c3::X)) ||
           (after->permissions & ~before->permissions) ||
           ((after->permissions&(c3::W|c3::X))==(c3::W|c3::X)))
            return fail("C3C_LIBC_SHADOW_OR_RELRO_RIGHTS_REJECTED");
        page.currentRights=page.originalRights=before->permissions;
        page.afterRelroRights=after->permissions;
        if(page.originalRights!=page.afterRelroRights){
            if(!(page.originalRights&c3::W) ||
               (page.afterRelroRights&c3::W) ||
               (page.originalRights&c3::X))
                return fail("C3C_RELRO_TRANSITION_NOT_WRITE_TO_READ");
            ++transitioned;
        }
    }
    if(transitioned!=expected.fullyCoveredRelro4KPages)
        return fail("C3C_FULL_GUEST_PAGE_RELRO_COUNT_MISMATCH");
    output.pages=std::move(shadow);
    output.libraryLoadBias=expected.libcSyntheticLoadBias;
    output.libraryBase=first;
    output.libraryEnd=last;
    output.relro4KPages=transitioned;
    output.originalLibcSHA256Proved=true;
    output.sourceBytesCopiedIntoPrivateShadow=true;
    output.software4KPermissionsEnforced=true;
    reason="none";
    return true;
}
inline bool ValidShadowRange(const LibcShadow& source,
                             uint64_t va,size_t n,uint8_t need) {
    if(!source.originalLibcSHA256Proved ||
       !source.sourceBytesCopiedIntoPrivateShadow ||
       !source.software4KPermissionsEnforced ||
       source.host16KSubpageMprotectImplemented ||
       source.actualGuestMemoryMapped ||
       source.fexCpuStateUsesShadow ||
       source.originalGuestLoaderExecuted ||
       source.originalGuestLibcExecuted ||
       source.nativeDirectGuestAddressAccessAuthorized ||
       n==0 || n>c1::kMaxGuestIoBytes || !c1::GuestRange(va,n))
        return false;
    const uint64_t end=va+n;
    for(uint64_t page=va&~(kPage-1);page<end;page+=kPage){
        auto it=source.pages.find(page);
        if(it==source.pages.end() ||
           !(it->second.currentRights&need))
            return false;
    }
    return true;
}
// Every read validates all touched pages first. "FetchInstructionBytes"
// copies x86 bytes for inspection; it NEVER transfers control to the guest.
inline bool CopyShadowBytesDataOnly(
    const LibcShadow& source,uint64_t va,void* dst,size_t n,
    bool requireExecutablePage=false) {
    if(!dst || !ValidShadowRange(source,va,n,
        requireExecutablePage?c3::X:c3::R))return false;
    auto* out=static_cast<unsigned char*>(dst);
    size_t copied=0;
    while(copied<n){
        const uint64_t cursor=va+copied;
        const auto it=source.pages.find(cursor&~(kPage-1));
        const size_t off=static_cast<size_t>(cursor&(kPage-1));
        const size_t count=std::min(n-copied,4096-off);
        std::memcpy(out+copied,it->second.data.data()+off,count);
        copied+=count;
    }
    return true;
}
// Atomic permission preflight: no byte of a multi-4K write changes when
// even one page is read-only, executable, absent, or RELRO-sealed.
inline bool WriteShadowBytesTestOnly(
    LibcShadow& source,uint64_t va,const void* src,size_t n) {
    if(!src || !ValidShadowRange(source,va,n,c3::W))
        return false;
    const auto* input=static_cast<const unsigned char*>(src);
    size_t copied=0;
    while(copied<n){
        const uint64_t cursor=va+copied;
        auto it=source.pages.find(cursor&~(kPage-1));
        const size_t off=static_cast<size_t>(cursor&(kPage-1));
        const size_t count=std::min(n-copied,4096-off);
        std::memcpy(it->second.data.data()+off,input+copied,count);
        copied+=count;
    }
    return true;
}
// TEST ONLY: simulates a completed dynamic-relocation phase, changing
// selected 4K shadow permission tags. It is not glibc relocation,
// mprotect, 16K host permission isolation or FEX memory mapping.
inline bool ApplyPlannedRelroShadowTransitionTestOnly(
    LibcShadow& shadow,bool testFixtureExplicitlyRequested) {
    if(!testFixtureExplicitlyRequested ||
       !shadow.software4KPermissionsEnforced ||
       !shadow.sourceBytesCopiedIntoPrivateShadow ||
       shadow.postRelroTestOnly ||
       shadow.host16KSubpageMprotectImplemented ||
       shadow.actualGuestMemoryMapped ||
       shadow.fexCpuStateUsesShadow ||
       shadow.originalGuestLoaderExecuted ||
       shadow.originalGuestLibcExecuted)
        return false;
    size_t count=0;
    for(const auto& [address,page]:shadow.pages){
        (void)address;
        if(page.originalRights!=page.afterRelroRights){
            if(!(page.originalRights&c3::W) ||
               (page.afterRelroRights&c3::W) ||
               (page.afterRelroRights&c3::X) ||
               page.currentRights!=page.originalRights)
                return false;
            ++count;
        }
    }
    if(count!=shadow.relro4KPages)return false;
    for(auto& [address,page]:shadow.pages){
        (void)address;
        page.currentRights=page.afterRelroRights;
    }
    shadow.postRelroTestOnly=true;
    return true;
}
} // namespace kernix::g2e::c3c
