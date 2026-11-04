#pragma once
// KERNIX G2-E/C3-B: authenticated, REAL original Linux x86 libc.so.6
// PT_LOAD + PT_GNU_RELRO page-permission planning ONLY.
// 4K guest / 16K host page policy. Never maps or executes guest data.
// Test virtual addresses are not actual Android ASLR / guest reservations.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3_guest_page_ledger.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace kernix::g2e::c3b {
inline constexpr uint64_t kLibcTestBase=0x0000722200000000ULL;
inline constexpr size_t kMaxLibcPTLoads=16;
inline constexpr size_t kMaxCombinedPages=8192;
inline constexpr uint64_t kGuestPage=4096, kHostPage=16384;
struct LibcLoad {
    uint64_t first=0, pastLast=0;
    uint32_t elfFlags=0;
    uint64_t originalFileOffset=0, originalFileBytes=0;
};
struct ParsedLibc {
    std::vector<LibcLoad> ptLoads;
    uint64_t lowestLoadPage=0, highestLoadEnd=0;
    uint64_t relroFirst=0,relroPastLast=0;
    bool relroFound=false;
    bool originalX86ELFParsed=false;
};
struct HostPermissionPage {
    uint64_t address=0;
    std::array<uint8_t,4> guest4kRights{};
    bool subpagePermissionsDiffer=false;
    bool hostWideWxConflict=false;
    bool hostDirectProtectionAuthorized=false; // ALWAYS false
};
struct Result {
    std::vector<c3::GuestPage> initialGuest4KPages;
    std::vector<c3::GuestPage> afterRelroGuest4KPages;
    std::vector<HostPermissionPage> initialHost16KPages;
    std::vector<HostPermissionPage> afterRelroHost16KPages;
    uint64_t libcSyntheticLoadBias=0;
    uint64_t libcSyntheticRelroFirst=0;
    uint64_t libcSyntheticRelroPastLast=0;
    size_t libcPTLoadCount=0;
    size_t libcUnique4KPages=0;
    size_t fullyCoveredRelro4KPages=0;
    size_t initialHost16KWxConflicts=0;
    size_t afterRelroHost16KWxConflicts=0;
    size_t initialHost16KSubpageDifferences=0;
    bool originalLibcSHA256Attested=false;
    bool relroPlannedNotApplied=false;
    bool fullImagePagePlanValidated=false;
    bool hostGuestMemoryInstalled=false;
    bool originalFEXGuestEntered=false;
    bool originalLibcExecuted=false;
    bool originalLdsoExecuted=false;
    bool nativeDirectMappingAuthorized=false;
};
// Raw parser alone NEVER proves SHA-256 or authentic provenance.
// Caller must validate exact original read-only GuestPreflight first.
inline bool ParseLibcELFHeadersOnly(std::span<const unsigned char> raw,
                                    ParsedLibc& output,std::string& why) {
    output={};
    auto fail=[&](const char* reason){output={};why=reason;return false;};
    if(!raw.data() || raw.size()!=kGuest[2].bytes ||
       raw.size()<sizeof(Elf64_Ehdr))return fail("C3B_LIBC_RAW_SIZE");
    Elf64_Ehdr elf{};
    std::memcpy(&elf,raw.data(),sizeof(elf));
    if(!g2b::GuestElfHeader(elf) || elf.e_type!=ET_DYN ||
       elf.e_phentsize!=sizeof(Elf64_Phdr) ||
       elf.e_phnum==0 || elf.e_phnum>128 ||
       !g2b::ElfRange(elf.e_phoff,
         static_cast<uint64_t>(elf.e_phnum)*sizeof(Elf64_Phdr),
         raw.size()))
        return fail("C3B_LIBC_ELF_HEADER");
    uint64_t minimum=UINT64_MAX,maximum=0;
    bool relro=false;
    for(uint16_t i=0;i<elf.e_phnum;i++){
        Elf64_Phdr ph{};
        std::memcpy(&ph,raw.data()+elf.e_phoff+
                    static_cast<size_t>(i)*sizeof(ph),sizeof(ph));
        if(ph.p_type==PT_GNU_STACK && (ph.p_flags&PF_X))
            return fail("C3B_LIBC_EXEC_STACK");
        if(ph.p_type==PT_GNU_RELRO) {
            if(relro || ph.p_memsz==0 ||
               ph.p_vaddr>UINT64_MAX-ph.p_memsz)
                return fail("C3B_DUPLICATE_OR_INVALID_RELRO");
            relro=true;
            output.relroFirst=ph.p_vaddr;
            output.relroPastLast=ph.p_vaddr+ph.p_memsz;
        }
        if(ph.p_type!=PT_LOAD)continue;
        if(ph.p_filesz==0 && ph.p_memsz==0)continue;
        if(ph.p_memsz==0 || ph.p_filesz>ph.p_memsz ||
           !g2b::ElfRange(ph.p_offset,ph.p_filesz,raw.size()) ||
           ph.p_vaddr>UINT64_MAX-ph.p_memsz ||
           ph.p_align<kGuestPage || (ph.p_align&(ph.p_align-1)) ||
           (ph.p_offset%ph.p_align)!=(ph.p_vaddr%ph.p_align) ||
           !(ph.p_flags&PF_R) ||
           (ph.p_flags & ~(PF_R|PF_W|PF_X)) ||
           ((ph.p_flags&PF_W)&&(ph.p_flags&PF_X)))
            return fail("C3B_LIBC_INVALID_PT_LOAD");
        const uint64_t end=ph.p_vaddr+ph.p_memsz;
        for(const auto& past:output.ptLoads)
            if(ph.p_vaddr<past.pastLast && past.first<end)
                return fail("C3B_LIBC_OVERLAPPING_PT_LOAD_BYTES");
        output.ptLoads.push_back({ph.p_vaddr,end,ph.p_flags,
                                  ph.p_offset,ph.p_filesz});
        if(output.ptLoads.size()>kMaxLibcPTLoads)
            return fail("C3B_LIBC_TOO_MANY_LOADS");
        minimum=std::min(minimum,ph.p_vaddr);
        maximum=std::max(maximum,end);
    }
    if(!relro || output.ptLoads.empty() || minimum==UINT64_MAX ||
       maximum<=minimum || maximum>32*1024*1024ULL ||
       output.relroFirst<minimum || output.relroPastLast>maximum)
        return fail("C3B_LIBC_PT_LOAD_OR_RELRO_MISSING");
    bool relroTouchesWritableLoad=false,foundExecutable=false;
    for(const auto& load:output.ptLoads){
        foundExecutable|=(load.elfFlags&PF_X)!=0;
        if((load.elfFlags&PF_W) &&
            output.relroFirst<load.pastLast &&
            load.first<output.relroPastLast)
            relroTouchesWritableLoad=true;
    }
    if(!relroTouchesWritableLoad || !foundExecutable)
        return fail("C3B_RELRO_NOT_IN_WRITABLE_LIBC_IMAGE");
    output.lowestLoadPage=minimum&~(kGuestPage-1);
    output.highestLoadEnd=maximum;
    output.relroFound=true;
    output.originalX86ELFParsed=true;
    why="none";
    return true;
}
inline bool Build16KHostPolicy(const std::vector<c3::GuestPage>& pages,
                               std::vector<HostPermissionPage>& output,
                               size_t& wx,size_t& divergent) {
    output.clear();wx=0;divergent=0;
    std::map<uint64_t,HostPermissionPage> byHost;
    for(const auto& p:pages) {
        if(!c1::GuestRange(p.address,kGuestPage) ||
           p.address%kGuestPage || (p.permissions&~uint8_t(7)) ||
           !(p.permissions&c3::R) ||
           ((p.permissions&(c3::W|c3::X))==(c3::W|c3::X)))
            return false;
        const uint64_t addr=p.address&~(kHostPage-1);
        auto [it,inserted]=byHost.try_emplace(addr);
        (void)inserted;
        auto& target=it->second;
        target.address=addr;
        const size_t index=static_cast<size_t>((p.address-addr)/kGuestPage);
        if(target.guest4kRights[index]!=0)return false;
        target.guest4kRights[index]=p.permissions;
        if(byHost.size()>kMaxCombinedPages)return false;
    }
    for(auto& [addr,h]:byHost){
        (void)addr;
        uint8_t combined=0;
        for(const uint8_t v:h.guest4kRights)combined|=v;
        h.hostWideWxConflict=
            (combined&(c3::W|c3::X))==(c3::W|c3::X);
        if(h.hostWideWxConflict)++wx;
        h.subpagePermissionsDiffer=std::any_of(
            h.guest4kRights.begin()+1,h.guest4kRights.end(),
            [&](uint8_t v){return v!=h.guest4kRights[0];});
        if(h.subpagePermissionsDiffer)++divergent;
        h.hostDirectProtectionAuthorized=false;
        output.push_back(h);
    }
    return !output.empty();
}
inline bool BuildRealGlibcRelroPermissionPlanDataOnly(
    const GuestPreflight& original,
    const std::array<uint8_t,16>& entropy,
    Result& output,std::string& why) {
    output={};
    auto fail=[&](const char* error){output={};why=error;return false;};
    if(!original.exactSha256Matched ||
       !original.readOnlyAnonymousSnapshots ||
       !original.exactInterpreterAndGlibcClosure ||
       original.guestCodeExecuted || original.dynamicLinkerExecuted ||
       original.fexAttached || original.wineExecuted ||
       !original.snapshots[2].readOnlySnapshot() ||
       !original.snapshots[2].bytes() ||
       original.snapshots[2].size()!=kGuest[2].bytes)
        return fail("C3B_SHA_PINNED_LIBC_NOT_PROVEN");
    // Recompute the C0 plan internally from the pinned snapshots. Untrusted
    // callers cannot append fake extra pages to an otherwise valid witness.
    GuestLdsoEntryWitness witness;
    g2b::X86GuestProcessLaunchPlan launch;
    std::string reason;
    if(!PlanPinnedRealGlibcLdsoEntryDataOnly(original,entropy,
                                               witness,reason,&launch))
        return fail("C3B_REAL_MAIN_INTERPRETER_ENTRY_REJECTED");
    c3::Ledger base;
    if(!c3::BuildPinnedGlibcGuestPageLedger(launch,witness,base,reason) ||
       !base.inputValidated || base.nativeDirectMapAuthorized)
        return fail("C3B_ORIGINAL_MAIN_LDSO_STACK_LEDGER_REJECTED");
    ParsedLibc libc;
    if(!ParseLibcELFHeadersOnly(std::span<const unsigned char>(
        original.snapshots[2].bytes(),original.snapshots[2].size()),
        libc,reason))
        return fail("C3B_ORIGINAL_LIBC_PT_LOAD_OR_RELRO_REJECTED");
    if(libc.lowestLoadPage>kLibcTestBase)
        return fail("C3B_LIBC_VIRTUAL_TEST_BIAS_UNDERFLOW");
    const uint64_t bias=kLibcTestBase-libc.lowestLoadPage;
    std::map<uint64_t,c3::GuestPage> guest;
    for(const auto& p:base.guestPages){
        if(!guest.emplace(p.address,p).second)
            return fail("C3B_DUPLICATE_MAIN_LDSO_STACK_GUEST_PAGE");
    }
    std::map<uint64_t,uint8_t> libcOnly;
    for(const auto& segment:libc.ptLoads){
        if(segment.pastLast>c1::kGuestUserLimit-bias)
            return fail("C3B_LIBC_GUEST_ADDRESS_OVERFLOW");
        uint8_t rights=c3::R;
        if(segment.elfFlags&PF_W)rights|=c3::W;
        if(segment.elfFlags&PF_X)rights|=c3::X;
        uint64_t first=(bias+segment.first)&~(kGuestPage-1);
        uint64_t last=(bias+segment.pastLast-1)&~(kGuestPage-1);
        for(uint64_t p=first;;p+=kGuestPage){
            if(guest.count(p))
                return fail("C3B_LIBC_PAGE_COLLIDES_WITH_MAIN_OR_LDSO");
            libcOnly[p]|=rights;
            if(libcOnly.size()+guest.size()>kMaxCombinedPages)
                return fail("C3B_GUEST_PAGE_CAP");
            if((libcOnly[p]&(c3::W|c3::X))==(c3::W|c3::X))
                return fail("C3B_LIBC_GUEST_4K_WX_CONFLICT");
            if(p==last)break;
        }
    }
    if(libcOnly.empty())
        return fail("C3B_NO_LIBC_PT_LOAD_PAGES");
    uint64_t relroBegin=libc.relroFirst+bias;
    uint64_t relroEnd=libc.relroPastLast+bias;
    // RELRO is a *post-dynamic-relocation* page transition, NEVER applied
    // here. Only FULL guest 4K pages are counted; a partial/overlapping
    // last page retains its original write permission until FEX-aware
    // guest mprotect semantics exist.
    const uint64_t fullStart=(relroBegin+kGuestPage-1)&~(kGuestPage-1);
    const uint64_t fullEnd=relroEnd&~(kGuestPage-1);
    std::map<uint64_t,uint8_t> after=libcOnly;
    size_t eligible=0;
    for(uint64_t p=fullStart;p<fullEnd;p+=kGuestPage){
        auto it=after.find(p);
        if(it==after.end() || (it->second&c3::W)==0 ||
           (it->second&c3::X)!=0)
            return fail("C3B_RELRO_FULL_PAGE_NOT_WRITABLE_LIBC");
        it->second=static_cast<uint8_t>(it->second&~c3::W);
        ++eligible;
    }
    if(!eligible)
        return fail("C3B_NO_FULL_RELRO_PAGE");
    for(const auto& [p,rights]:libcOnly)
        guest.emplace(p,c3::GuestPage{p,rights,false});
    output.initialGuest4KPages.reserve(guest.size());
    output.afterRelroGuest4KPages.reserve(guest.size());
    for(const auto& [p,page]:guest){
        output.initialGuest4KPages.push_back(page);
        auto later=page;
        if(const auto it=after.find(p);it!=after.end())
            later.permissions=it->second;
        output.afterRelroGuest4KPages.push_back(later);
    }
    size_t postWx=0,postDivergent=0;
    if(!Build16KHostPolicy(output.initialGuest4KPages,
                            output.initialHost16KPages,
                            output.initialHost16KWxConflicts,
                            output.initialHost16KSubpageDifferences) ||
       !Build16KHostPolicy(output.afterRelroGuest4KPages,
                            output.afterRelroHost16KPages,
                            postWx,postDivergent))
        return fail("C3B_HOST_SUBPAGE_POLICY_FAILED");
    output.afterRelroHost16KWxConflicts=postWx;
    output.libcSyntheticLoadBias=bias;
    output.libcSyntheticRelroFirst=relroBegin;
    output.libcSyntheticRelroPastLast=relroEnd;
    output.libcPTLoadCount=libc.ptLoads.size();
    output.libcUnique4KPages=libcOnly.size();
    output.fullyCoveredRelro4KPages=eligible;
    output.originalLibcSHA256Attested=true;
    output.relroPlannedNotApplied=true;
    output.fullImagePagePlanValidated=true;
    why="none";
    return true;
}
} // namespace kernix::g2e::c3b
