#pragma once
// KERNIX G2-E/C3-D0: all original pinned ELF main/ld-linux/libc + startup
// Linux stack placed in a SOFTWARE VIRTUAL ADDRESS SPACE using 16K host-owned
// heap buffers and per-4K guest R/W/X permission checks. Data-only.
// NO guest VA mmap, NO FEX/JIT address mapping, NO raw pointer exported,
// NO host mprotect, NO guest instruction execution, NO Windows PE/Wine.
// Synthetic C0/C3B virtual addresses are only bounded CI fixtures.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3c_libc_shadow_subpage_memory.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <map>
#include <string>
#include <vector>
namespace kernix::g2e::c3d {
inline constexpr uint64_t GuestPageBytes=4096, HostPageBytes=16384;
inline constexpr size_t MaxUnifiedGuestPages=8192;
enum class GuestOwner : uint8_t { Main, Interpreter, Libc, InitialStack };
struct Subpage {
    uint8_t initialRights=0;
    uint8_t postRelroRights=0;
    uint8_t currentRights=0;
    GuestOwner owner=GuestOwner::Main;
    bool present=false;
};
struct Host16KBacking {
    // Host heap data is never executable. Only APIs below read or modify
    // bytes after checking every affected guest 4K page's rights.
    std::array<unsigned char,16384> bytes{};
    std::array<Subpage,4> subpages{};
    bool originalHostWideWXConflict=false;
    bool directHostGuestMappingApproved=false; // never true
};
struct UnifiedGuestShadow {
    std::map<uint64_t,Host16KBacking> host16K;
    uint64_t originalInterpreterGuestRIP=0;
    uint64_t initialLinuxGuestRSP=0;
    uint64_t mainFileBytesCopied=0;
    uint64_t interpreterFileBytesCopied=0;
    uint64_t libcFileBytesCopied=0;
    uint64_t libcZeroBssBytes=0;
    uint64_t initialLinuxStackBytesCopied=0;
    size_t totalRealGuest4KPages=0;
    size_t host16KPageGroups=0;
    size_t host16KPagesWithWXSubpages=0;
    size_t pagesEligibleForRelro=0;
    bool pinnedOriginalThreeELFsVerified=false;
    bool allOriginalBytesCopiedToHostOwnedBuffers=false;
    bool software4KGuestPermissionsEnforced=false;
    bool testOnlyRelroSealed=false;
    bool realGuestVirtualAddressReservation=false;
    bool host16KSubpageMprotectImplemented=false;
    bool fexGuestMemoryAttached=false;
    bool fexCpuStateExecuted=false;
    bool originalLdsoEntered=false;
    bool originalLibcEntered=false;
    bool directGuestNativePointersExposed=false;
};
inline constexpr uint64_t HostPageOf(uint64_t addr) {
    return addr&~(HostPageBytes-1);
}
inline constexpr size_t SubpageOf(uint64_t addr) {
    return static_cast<size_t>((addr&(HostPageBytes-1))/GuestPageBytes);
}
inline bool OwnerForPage(
    const g2b::X86GuestProcessLaunchPlan& launch,
    const c3c::LibcShadow& libc,uint64_t page,
    GuestOwner& owner) {
    const bool inStack=page>=launch.stack.guestBottom &&
                       page<launch.stack.guestTop;
    const bool inLibc=libc.pages.find(page)!=libc.pages.end();
    bool inMain=false,inLdso=false;
    for(const auto& region:launch.regions){
        if(region.isGuestStack || page>=region.pastLast ||
           page+GuestPageBytes<=region.first)continue;
        if(page>=kC0MainTestVA &&
           page<kC0MainTestVA+16*1024*1024ULL)inMain=true;
        else if(page>=kC0LdsoTestVA &&
                page<kC0LdsoTestVA+16*1024*1024ULL)inLdso=true;
        else return false;
    }
    const unsigned matches=static_cast<unsigned>(inStack)+
        static_cast<unsigned>(inLibc)+static_cast<unsigned>(inMain)+
        static_cast<unsigned>(inLdso);
    if(matches!=1)return false;
    owner=inStack?GuestOwner::InitialStack:
          inLibc?GuestOwner::Libc:
          inMain?GuestOwner::Main:GuestOwner::Interpreter;
    return true;
}
inline bool InternalCopyFileBytes(
    UnifiedGuestShadow& state,uint64_t guestVA,
    const unsigned char* source,size_t count,GuestOwner owner) {
    if(!source || !count || !c1::GuestRange(guestVA,count))return false;
    // Preflight ALL destination subpages before mutating any bytes.
    uint64_t cursor=guestVA,end=guestVA+count;
    while(cursor<end){
        auto it=state.host16K.find(HostPageOf(cursor));
        if(it==state.host16K.end())return false;
        const auto& sub=it->second.subpages[SubpageOf(cursor)];
        if(!sub.present || sub.owner!=owner)return false;
        cursor=std::min<uint64_t>(end,
            (cursor&~(GuestPageBytes-1))+GuestPageBytes);
    }
    size_t done=0;
    while(done<count){
        const uint64_t va=guestVA+done;
        auto& block=state.host16K.at(HostPageOf(va));
        const size_t offset=static_cast<size_t>(va&(HostPageBytes-1));
        const size_t n=std::min(count-done,16384-offset);
        std::memcpy(block.bytes.data()+offset,source+done,n);
        done+=n;
    }
    return true;
}
inline bool CopyFromOriginalELFSegments(
    const GuestPreflight& source,
    size_t elfIndex,uint64_t loadBias,
    GuestOwner owner,UnifiedGuestShadow& target,
    size_t& copiedBytes,std::string& error) {
    copiedBytes=0;
    if(elfIndex>1 || !source.snapshots[elfIndex].readOnlySnapshot() ||
       !source.snapshots[elfIndex].bytes() ||
       source.snapshots[elfIndex].size()!=kGuest[elfIndex].bytes) {
        error="C3D_ORIGINAL_MAIN_OR_LDSO_MISSING";
        return false;
    }
    const unsigned char* raw=source.snapshots[elfIndex].bytes();
    const size_t size=source.snapshots[elfIndex].size();
    Elf64_Ehdr elf{};
    if(size<sizeof(elf))return false;
    std::memcpy(&elf,raw,sizeof(elf));
    if(!g2b::GuestElfHeader(elf) || elf.e_type!=ET_DYN ||
       elf.e_phentsize!=sizeof(Elf64_Phdr) ||
       elf.e_phnum==0 || elf.e_phnum>128 ||
       !g2b::ElfRange(elf.e_phoff,
          static_cast<uint64_t>(elf.e_phnum)*sizeof(Elf64_Phdr),size)){
        error="C3D_ORIGINAL_ELF_HEADER_MISMATCH";return false;
    }
    size_t count=0;
    for(uint16_t i=0;i<elf.e_phnum;++i) {
        Elf64_Phdr ph{};
        std::memcpy(&ph,raw+elf.e_phoff+
                    static_cast<size_t>(i)*sizeof(ph),sizeof(ph));
        if(ph.p_type!=PT_LOAD || ph.p_memsz==0)continue;
        if(ph.p_filesz>ph.p_memsz ||
           !g2b::ElfRange(ph.p_offset,ph.p_filesz,size) ||
           ph.p_vaddr>UINT64_MAX-loadBias ||
           ph.p_memsz>c1::kGuestUserLimit-(ph.p_vaddr+loadBias) ||
           !c1::GuestRange(ph.p_vaddr+loadBias,ph.p_memsz) ||
           (ph.p_flags&PF_W && ph.p_flags&PF_X))
            {error="C3D_ELF_SEGMENT_GUEST_RANGE";return false;}
        if(ph.p_filesz==0)continue;
        if(!InternalCopyFileBytes(target,ph.p_vaddr+loadBias,
                raw+ph.p_offset,static_cast<size_t>(ph.p_filesz),owner)){
            error="C3D_ORIGINAL_SEGMENT_SHADOW_OWNER_MISMATCH";
            return false;
        }
        copiedBytes+=static_cast<size_t>(ph.p_filesz);
        ++count;
    }
    if(!count || copiedBytes==0){
        error="C3D_ORIGINAL_ELF_NO_DATA_SEGMENTS";return false;
    }
    error="none";
    return true;
}
inline bool BuildUnifiedHost16KShadowFromPinnedOriginals(
    const GuestPreflight& source,
    const std::array<uint8_t,16>& entropy,
    UnifiedGuestShadow& output,std::string& reason) {
    output={};
    const auto fail=[&](const char* why){
        output={};reason=why;return false;
    };
    if(!source.exactSha256Matched ||
       !source.readOnlyAnonymousSnapshots ||
       !source.exactInterpreterAndGlibcClosure ||
       source.guestCodeExecuted || source.dynamicLinkerExecuted ||
       source.fexAttached || source.wineExecuted)
        return fail("C3D_THREE_PINNED_REAL_ELF_CLOSURE_NOT_AUTHENTICATED");
    GuestLdsoEntryWitness witness;
    g2b::X86GuestProcessLaunchPlan launch;
    std::string local;
    if(!PlanPinnedRealGlibcLdsoEntryDataOnly(
          source,entropy,witness,local,&launch))
        return fail("C3D_PT_INTERP_LINUX_X86_STACK_ENTRY_REJECTED");
    c3b::Result policy;
    if(!c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
          source,entropy,policy,local) ||
       !policy.fullImagePagePlanValidated ||
       policy.nativeDirectMappingAuthorized ||
       policy.hostGuestMemoryInstalled ||
       policy.originalFEXGuestEntered)
        return fail("C3D_SOURCE_REBUILT_FULL_IMAGE_4K_POLICY_REJECTED");
    c3c::LibcShadow libc;
    if(!c3c::PreparePinnedLibcShadowDataOnly(
          source,entropy,policy,libc,local))
        return fail("C3D_SOURCE_REBUILT_LIBC_SHADOW_REJECTED");
    UnifiedGuestShadow unified;
    if(policy.initialGuest4KPages.empty() ||
       policy.initialGuest4KPages.size()>MaxUnifiedGuestPages ||
       policy.initialGuest4KPages.size()!=
           policy.afterRelroGuest4KPages.size())
        return fail("C3D_UNEXPECTED_GUEST_PAGE_COUNT");
    for(size_t i=0;i<policy.initialGuest4KPages.size();++i) {
        const auto& before=policy.initialGuest4KPages[i];
        const auto& after=policy.afterRelroGuest4KPages[i];
        if(before.address!=after.address ||
           before.address%GuestPageBytes ||
           !c1::GuestRange(before.address,GuestPageBytes) ||
           !(before.permissions&c3::R) ||
           (before.permissions&(c3::W|c3::X))==(c3::W|c3::X) ||
           (after.permissions & ~before.permissions))
            return fail("C3D_UNTRUSTED_REAL_GUEST_PAGE_RIGHTS");
        GuestOwner owner{};
        if(!OwnerForPage(launch,libc,before.address,owner))
            return fail("C3D_GUEST_PAGE_OWNER_NOT_UNIQUE");
        const uint64_t hostVA=HostPageOf(before.address);
        auto [it,inserted]=unified.host16K.try_emplace(hostVA);
        (void)inserted;
        auto& slot=it->second.subpages[SubpageOf(before.address)];
        if(slot.present)return fail("C3D_DUPLICATE_GUEST_4K_PAGE");
        slot={before.permissions,after.permissions,
              before.permissions,owner,true};
        if(unified.host16K.size()>MaxUnifiedGuestPages/4+1)
            return fail("C3D_HOST_PAGE_CAP");
    }
    if(unified.host16K.size()!=policy.initialHost16KPages.size())
        return fail("C3D_ORIGINAL_HOST_PAGE_GROUPS_NOT_MATCHED");
    for(const auto& expected:policy.initialHost16KPages) {
        auto it=unified.host16K.find(expected.address);
        if(it==unified.host16K.end() ||
           expected.hostDirectProtectionAuthorized)
            return fail("C3D_HOST16K_POLICY_NOT_PRESENT");
        uint8_t aggregate=0;
        for(unsigned j=0;j<4;j++){
            const uint8_t rights=it->second.subpages[j].present ?
                it->second.subpages[j].currentRights:0;
            if(rights!=expected.guest4kRights[j])
                return fail("C3D_HOST16K_SUBPAGE_MASK_CHANGED");
            aggregate|=rights;
        }
        it->second.originalHostWideWXConflict=
             (aggregate&(c3::W|c3::X))==(c3::W|c3::X);
        if(it->second.originalHostWideWXConflict)
            ++unified.host16KPagesWithWXSubpages;
    }
    if(unified.host16KPagesWithWXSubpages!=
       policy.initialHost16KWxConflicts)
        return fail("C3D_REAL_16K_HOST_CONFLICT_COUNT_MISMATCH");
    // Libc shadow bytes already SHA-authenticated and BSS zero-initialized.
    for(const auto& [va,page]:libc.pages) {
        if(!InternalCopyFileBytes(unified,va,
                page.data.data(),page.data.size(),GuestOwner::Libc))
            return fail("C3D_LIBC_PRIVATE_BYTES_COPY_REJECTED");
    }
    unified.libcFileBytesCopied=libc.originalFileBytesCopied;
    unified.libcZeroBssBytes=libc.bssBytesZeroInitialized;
    size_t copiedMain=0,copiedInterpreter=0;
    if(!CopyFromOriginalELFSegments(
          source,0,launch.mainLoadBias,GuestOwner::Main,unified,
          copiedMain,local))
        return fail("C3D_MAIN_ELF_SOURCE_COPY_REJECTED");
    if(!CopyFromOriginalELFSegments(
          source,1,launch.interpreterLoadBias,
          GuestOwner::Interpreter,unified,
          copiedInterpreter,local))
        return fail("C3D_INTERPRETER_ELF_SOURCE_COPY_REJECTED");
    unified.mainFileBytesCopied=copiedMain;
    unified.interpreterFileBytesCopied=copiedInterpreter;
    if(!launch.stack.initialStackLayoutValidated ||
       launch.stack.guestBottom!=kC0StackTestVA ||
       launch.stack.guestTop!=kC0StackTestVA+kC0StackBytes ||
       launch.stack.bytes.size()!=kC0StackBytes ||
       !InternalCopyFileBytes(
           unified,launch.stack.guestBottom,
           launch.stack.bytes.data(),launch.stack.bytes.size(),
           GuestOwner::InitialStack))
        return fail("C3D_AUTHENTIC_LINUX_STACK_BYTES_COPY_REJECTED");
    unified.initialLinuxStackBytesCopied=launch.stack.bytes.size();
    unified.originalInterpreterGuestRIP=witness.futureFexRIP;
    unified.initialLinuxGuestRSP=witness.futureFexRSP;
    unified.totalRealGuest4KPages=policy.initialGuest4KPages.size();
    unified.host16KPageGroups=unified.host16K.size();
    unified.pagesEligibleForRelro=policy.fullyCoveredRelro4KPages;
    unified.pinnedOriginalThreeELFsVerified=true;
    unified.allOriginalBytesCopiedToHostOwnedBuffers=true;
    unified.software4KGuestPermissionsEnforced=true;
    output=std::move(unified);
    reason="none";
    return true;
}
inline bool GuestSpanPermitted(
    const UnifiedGuestShadow& space,uint64_t guestVA,size_t bytes,
    uint8_t permission) {
    if(!space.pinnedOriginalThreeELFsVerified ||
       !space.allOriginalBytesCopiedToHostOwnedBuffers ||
       !space.software4KGuestPermissionsEnforced ||
       space.realGuestVirtualAddressReservation ||
       space.host16KSubpageMprotectImplemented ||
       space.fexGuestMemoryAttached || space.fexCpuStateExecuted ||
       space.originalLdsoEntered || space.originalLibcEntered ||
       space.directGuestNativePointersExposed ||
       bytes==0 || bytes>c1::kMaxGuestIoBytes ||
       !c1::GuestRange(guestVA,bytes) ||
       (permission!=c3::R && permission!=c3::W && permission!=c3::X))
        return false;
    const uint64_t last=guestVA+bytes;
    uint64_t page=guestVA&~(GuestPageBytes-1);
    for(;;page+=GuestPageBytes) {
        const auto it=space.host16K.find(HostPageOf(page));
        if(it==space.host16K.end())return false;
        const auto& sub=it->second.subpages[SubpageOf(page)];
        if(!sub.present || !(sub.currentRights&permission))
            return false;
        if(page>=((last-1)&~(GuestPageBytes-1)))break;
    }
    return true;
}
inline bool ReadGuestDataOnly(
    const UnifiedGuestShadow& space,uint64_t guestVA,
    void* output,size_t bytes,bool requireGuestExecute=false) {
    if(!output || !GuestSpanPermitted(
        space,guestVA,bytes,requireGuestExecute?c3::X:c3::R))
        return false;
    size_t done=0;
    while(done<bytes) {
        uint64_t cursor=guestVA+done;
        const auto& backing=space.host16K.at(HostPageOf(cursor));
        const size_t offset=static_cast<size_t>(cursor&(HostPageBytes-1));
        const size_t n=std::min(bytes-done,16384-offset);
        std::memcpy(static_cast<unsigned char*>(output)+done,
                    backing.bytes.data()+offset,n);
        done+=n;
    }
    return true;
}
inline bool WriteGuestTestOnly(
    UnifiedGuestShadow& space,uint64_t guestVA,
    const void* src,size_t bytes) {
    // Atomic full-range permission preflight: no partial writes.
    if(!src || !GuestSpanPermitted(space,guestVA,bytes,c3::W))
        return false;
    size_t done=0;
    while(done<bytes) {
        const uint64_t cursor=guestVA+done;
        auto& backing=space.host16K.at(HostPageOf(cursor));
        const size_t offset=static_cast<size_t>(cursor&(HostPageBytes-1));
        const size_t n=std::min(bytes-done,16384-offset);
        std::memcpy(backing.bytes.data()+offset,
                    static_cast<const unsigned char*>(src)+done,n);
        done+=n;
    }
    return true;
}
inline bool TestOnlySealRelroGuest4K(
    UnifiedGuestShadow& space,bool explicitSyntheticFixture) {
    if(!explicitSyntheticFixture || space.testOnlyRelroSealed ||
       !space.software4KGuestPermissionsEnforced ||
       space.fexGuestMemoryAttached ||
       space.directGuestNativePointersExposed ||
       space.realGuestVirtualAddressReservation ||
       space.host16KSubpageMprotectImplemented ||
       space.fexCpuStateExecuted || space.originalLdsoEntered)
        return false;
    size_t changed=0;
    for(const auto& [address,host]:space.host16K){
        (void)address;
        for(const auto& sub:host.subpages){
            if(!sub.present)continue;
            if(sub.initialRights!=sub.postRelroRights) {
                if(sub.owner!=GuestOwner::Libc ||
                   !(sub.initialRights&c3::W) ||
                   (sub.postRelroRights&c3::W) ||
                   (sub.postRelroRights&c3::X) ||
                   sub.currentRights!=sub.initialRights)return false;
                ++changed;
            }
        }
    }
    if(changed!=space.pagesEligibleForRelro || changed==0)return false;
    for(auto& [address,host]:space.host16K) {
        (void)address;
        for(auto& sub:host.subpages)
            if(sub.present)sub.currentRights=sub.postRelroRights;
    }
    space.testOnlyRelroSealed=true;
    return true;
}
} // namespace kernix::g2e::c3d
