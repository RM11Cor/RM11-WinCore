#pragma once
// KERNIX G2-E/C3-A genuine ELF / ld-linux initial-entry PAGE LEDGER.
// Converts the authenticated C0 Linux x86_64 PT_LOAD + startup stack
// into a bounded guest 4KiB-page permission plan, then identifies host
// 16KiB-page W/X conflicts.  This NEVER mmap/mprotect, returns host
// pointers, or installs guest PT_LOAD in FEX. SPDX-License-Identifier: MIT
#include "kernix_g2e_guest_ldso_entry_contract.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <elf.h>

namespace kernix::g2e::c3 {
inline constexpr uint8_t R=1, W=2, X=4;
inline constexpr uint64_t GuestPage=4096, HostPage16K=16384;
inline constexpr size_t MaxGuestPages=8192;
inline constexpr size_t MaxGuestRegions=96;
struct GuestPage {
    uint64_t address=0;
    uint8_t permissions=0;
    bool isStack=false;
};
struct HostPage {
    uint64_t address=0;
    uint8_t observedPermissions=0;
    uint16_t guestSubpageMask=0; // 4 bits used, one per guest 4KiB subpage
    bool needsSubpagePermissionEmulation=false;
};
struct Ledger {
    std::vector<GuestPage> guestPages;
    std::vector<HostPage> hostPages;
    uint64_t authenticatedInterpreterRIP=0;
    uint64_t validatedStackRSP=0;
    size_t hostPagesNeedingSubpageEmulation=0;
    bool anyGuest4KPageWriteExecuteConflict=false;
    bool anyHost16KPageWriteExecuteConflict=false;
    bool inputValidated=false;
    bool nativeDirectMapAuthorized=false; // ALWAYS FALSE pending C3-C
    bool guestMemoryInstalled=false;
    bool fexGuestEntered=false;
    bool linuxLdsoExecuted=false;
};
// This is a plan-only counter. Even an all-RX image MUST NOT produce
// nativeDirectMapAuthorized=true. Real FEX guest mappings require a separate
// 16K-aware isolation/memory ownership and rollback implementation.
inline bool BuildPinnedGlibcGuestPageLedger(
    const g2b::X86GuestProcessLaunchPlan& plan,
    const GuestLdsoEntryWitness& witness,
    Ledger& output,std::string& reason) {
    output={};
    const auto fail=[&](const char* why){
        output={};reason=why;return false;
    };
    if(!witness.exactOriginalSha256Assets ||
       !witness.guestPtInterpEntryContractVerified ||
       !witness.linuxX86AuxvContractVerified ||
       witness.guestAddressSpaceReserved || witness.fexThreadInitialized ||
       witness.guestLdsoEntered || witness.glibcExecuted ||
       witness.wineExecuted ||
       !plan.guestVirtualAddressesValidated ||
       !plan.stackAndAuxvConsistent ||
       plan.dependencyObjectsChecked!=3 ||
       plan.guestAddressSpaceReserved || plan.guestMemoryMapped ||
       plan.guestCodeExecuted || plan.dynamicLinkerExecuted ||
       plan.fexEntryPointAssigned || plan.androidWineTested ||
       plan.stack.guestRSP!=witness.futureFexRSP ||
       plan.guestInterpreterEntry!=witness.futureFexRIP ||
       plan.guestMainEntry!=witness.expectedATEntry ||
       plan.interpreterLoadBias!=witness.expectedATBase ||
       plan.guestMainPHDR!=witness.expectedATPHDR ||
       plan.mainPHNUM!=witness.expectedATPHNUM ||
       plan.regions.empty() || plan.regions.size()>MaxGuestRegions)
        return fail("C3A_PINNED_REAL_GUEST_ENTRY_OR_NO_EXECUTION_GATE");

    std::map<uint64_t,GuestPage> guest;
    bool foundStack=false,foundInterpreterRX=false;
    uint64_t accumulated=0;
    for(const auto& segment:plan.regions) {
        if(segment.first>=segment.pastLast ||
           segment.first<0x10000 ||
           segment.pastLast>c1::kGuestUserLimit)
            return fail("C3A_INVALID_GUEST_REGION");
        const uint64_t bytes=segment.pastLast-segment.first;
        if(bytes>MaxGuestPages*GuestPage ||
           accumulated>MaxGuestPages*GuestPage-bytes)
            return fail("C3A_REGION_BYTES_OVERFLOW_OR_CAP");
        accumulated+=bytes;
        uint8_t rights=0;
        if(segment.isGuestStack) {
            if(foundStack || segment.originalElfFlags!=0 ||
               segment.first!=plan.stack.guestBottom ||
               segment.pastLast!=plan.stack.guestTop ||
               !plan.stack.initialStackLayoutValidated ||
               plan.stack.guestCodeExecuted || plan.stack.guestMemoryMapped ||
               plan.stack.androidWineTested)
                return fail("C3A_STACK_NOT_OWNER_ATTESTED");
            foundStack=true;
            rights=R|W;
        }else{
            if(segment.originalElfFlags & ~(PF_R|PF_W|PF_X))
                return fail("C3A_ELF_INVALID_PERMISSIONS");
            if(!(segment.originalElfFlags&PF_R) ||
               ((segment.originalElfFlags&PF_W) &&
                (segment.originalElfFlags&PF_X)))
                return fail("C3A_ELF_WX_OR_MISSING_READ");
            rights=static_cast<uint8_t>(
                ((segment.originalElfFlags&PF_R)?R:0) |
                ((segment.originalElfFlags&PF_W)?W:0) |
                ((segment.originalElfFlags&PF_X)?X:0));
            if((rights&X) &&
               witness.futureFexRIP>=segment.first &&
               witness.futureFexRIP<segment.pastLast)
                foundInterpreterRX=true;
        }
        const uint64_t first=segment.first&~(GuestPage-1);
        const uint64_t last=(segment.pastLast-1)&~(GuestPage-1);
        for(uint64_t pos=first;;pos+=GuestPage) {
            auto [it,inserted]=guest.try_emplace(pos,GuestPage{pos,0,false});
            (void)inserted;
            it->second.permissions|=rights;
            it->second.isStack|=segment.isGuestStack;
            if(guest.size()>MaxGuestPages)
                return fail("C3A_GUEST_PAGE_COUNT_TOO_LARGE");
            if(pos==last)break;
        }
    }
    if(!foundStack || !foundInterpreterRX)
        return fail("C3A_INTERPRETER_RX_OR_LINUX_STACK_NOT_PRESENT");
    if(guest.empty())
        return fail("C3A_EMPTY_PAGE_MANIFEST");
    // Complete guest-page ledger is aggregated by actual host 16KiB page.
    std::map<uint64_t,HostPage> host;
    bool guest4kWx=false;
    for(const auto& [pos,p]:guest) {
        const uint8_t rights=p.permissions;
        if((rights&(W|X))==(W|X))
            guest4kWx=true;
        const uint64_t hostPos=pos&~(HostPage16K-1);
        auto [it,inserted]=host.try_emplace(
            hostPos,HostPage{hostPos,0,0,false});
        (void)inserted;
        it->second.observedPermissions|=rights;
        it->second.guestSubpageMask|=
            static_cast<uint16_t>(1U<<((pos-hostPos)/GuestPage));
        if(host.size()>MaxGuestPages)
            return fail("C3A_HOST_PAGE_COUNT_OVERFLOW");
    }
    size_t conflicts=0;
    for(auto& [pos,p]:host){
        (void)pos;
        p.needsSubpagePermissionEmulation=
            (p.observedPermissions&(W|X))==(W|X);
        if(p.needsSubpagePermissionEmulation)++conflicts;
    }
    output.guestPages.reserve(guest.size());
    output.hostPages.reserve(host.size());
    for(const auto& [pos,p]:guest){(void)pos;output.guestPages.push_back(p);}
    for(const auto& [pos,p]:host){(void)pos;output.hostPages.push_back(p);}
    output.authenticatedInterpreterRIP=witness.futureFexRIP;
    output.validatedStackRSP=witness.futureFexRSP;
    output.hostPagesNeedingSubpageEmulation=conflicts;
    output.anyGuest4KPageWriteExecuteConflict=guest4kWx;
    output.anyHost16KPageWriteExecuteConflict=conflicts>0;
    output.inputValidated=true;
    reason="none";
    return true;
}
inline bool CheckGuestPageAccess(
    const Ledger& ledger,uint64_t address,uint64_t count,
    c1::GuestDataAccess access) {
    if(!ledger.inputValidated || !c1::GuestRange(address,count) ||
       ledger.guestMemoryInstalled || ledger.fexGuestEntered ||
       ledger.linuxLdsoExecuted || count>c1::kMaxGuestIoBytes)
        return false;
    const uint64_t first=address&~(GuestPage-1);
    const uint64_t last=(address+count-1)&~(GuestPage-1);
    for(uint64_t pos=first;;pos+=GuestPage){
        bool present=false;
        for(const auto& page:ledger.guestPages) {
            if(page.address!=pos)continue;
            const uint8_t bit=access==c1::GuestDataAccess::Read?R:
                (access==c1::GuestDataAccess::Write?W:X);
            present=(page.permissions&bit)!=0;
            break;
        }
        if(!present)return false;
        if(pos==last)break;
    }
    return true;
}
} // namespace kernix::g2e::c3
