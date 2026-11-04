// C3-D0 genuine pinned original guest ELF main+ld-linux+libc+stack bytes
// copied to 16K nonexecutable host HEAP backing; every R/W/X access goes
// through a 4K guest permission gate. No FEX guest VA map or real mprotect.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3d_unified_guest_va_shadow.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

using namespace kernix::g2e;
namespace d=kernix::g2e::c3d;
namespace b=kernix::g2b;
namespace p=kernix::g2e::c3b;
namespace c=kernix::g2e::c3;
static void CheckOriginalPIEBytes(const GuestPreflight& source,
                                 const d::UnifiedGuestShadow& space,
                                 size_t index,uint64_t bias) {
    assert(index<2);
    const auto* data=source.snapshots[index].bytes();
    assert(data);
    const size_t n=source.snapshots[index].size();
    Elf64_Ehdr e{};
    std::memcpy(&e,data,sizeof(e));
    assert(b::GuestElfHeader(e) && e.e_type==ET_DYN);
    unsigned touched=0;
    for(uint16_t i=0;i<e.e_phnum;i++) {
        Elf64_Phdr ph{};
        std::memcpy(&ph,data+e.e_phoff+i*sizeof(ph),sizeof(ph));
        if(ph.p_type!=PT_LOAD || !ph.p_filesz)continue;
        assert(b::ElfRange(ph.p_offset,ph.p_filesz,n));
        size_t examined=0;
        while(examined<ph.p_filesz) {
            const size_t chunk=std::min(
                size_t(8192),size_t(ph.p_filesz-examined));
            std::array<unsigned char,8192> result{};
            assert(d::ReadGuestDataOnly(
                space,bias+ph.p_vaddr+examined,result.data(),chunk));
            assert(std::memcmp(result.data(),
                data+ph.p_offset+examined,chunk)==0);
            examined+=chunk;
        }
        ++touched;
    }
    assert(touched>=2);
}
static void MustRejectProvenance(const GuestPreflight& input,
                                const std::array<uint8_t,16>& entropy) {
    d::UnifiedGuestShadow denied;
    std::string error;
    assert(!d::BuildUnifiedHost16KShadowFromPinnedOriginals(
        input,entropy,denied,error));
    assert(!error.empty() && error!="none");
    assert(denied.host16K.empty());
    assert(!denied.allOriginalBytesCopiedToHostOwnedBuffers);
    assert(!denied.fexGuestMemoryAttached && !denied.originalLdsoEntered);
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    GuestPreflight original;
    std::string reason;
    assert(Validate(fd,original,reason));
    close(fd);
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    d::UnifiedGuestShadow unified;
    assert(d::BuildUnifiedHost16KShadowFromPinnedOriginals(
        original,entropy,unified,reason));
    assert(reason=="none");
    assert(unified.pinnedOriginalThreeELFsVerified &&
           unified.allOriginalBytesCopiedToHostOwnedBuffers &&
           unified.software4KGuestPermissionsEnforced);
    assert(unified.totalRealGuest4KPages==609);
    assert(unified.host16KPageGroups==154);
    assert(unified.host16KPagesWithWXSubpages==1);
    assert(unified.pagesEligibleForRelro==3);
    assert(unified.libcFileBytesCopied==2103931);
    assert(unified.libcZeroBssBytes==54984);
    assert(unified.initialLinuxStackBytesCopied==65536);
    assert(unified.mainFileBytesCopied>0);
    assert(unified.interpreterFileBytesCopied>0);
    assert(!unified.realGuestVirtualAddressReservation &&
           !unified.host16KSubpageMprotectImplemented &&
           !unified.fexGuestMemoryAttached &&
           !unified.fexCpuStateExecuted &&
           !unified.originalLdsoEntered &&
           !unified.originalLibcEntered &&
           !unified.directGuestNativePointersExposed);
    GuestLdsoEntryWitness entry;
    b::X86GuestProcessLaunchPlan launch;
    assert(PlanPinnedRealGlibcLdsoEntryDataOnly(
        original,entropy,entry,reason,&launch));
    assert(unified.originalInterpreterGuestRIP==
           launch.guestInterpreterEntry &&
           unified.originalInterpreterGuestRIP!=launch.guestMainEntry &&
           unified.initialLinuxGuestRSP==launch.stack.guestRSP);
    CheckOriginalPIEBytes(original,unified,0,launch.mainLoadBias);
    CheckOriginalPIEBytes(original,unified,1,launch.interpreterLoadBias);
    {
        const size_t chunk=8192;
        for(size_t offset=0;offset<launch.stack.bytes.size();offset+=chunk) {
            std::array<unsigned char,chunk> buf{};
            assert(d::ReadGuestDataOnly(
                unified,launch.stack.guestBottom+offset,
                buf.data(),buf.size()));
            assert(std::memcmp(buf.data(),
                launch.stack.bytes.data()+offset,buf.size())==0);
        }
    }
    {
        // Independently compare entire original libc PT_LOAD raw file bytes
        // against host-owned 16K groups, never accessing guest native VA.
        p::ParsedLibc libc;
        assert(p::ParseLibcELFHeadersOnly(
            std::span<const unsigned char>(
                original.snapshots[2].bytes(),
                original.snapshots[2].size()),libc,reason));
        for(const auto& seg:libc.ptLoads) {
            for(uint64_t offset=0;offset<seg.originalFileBytes;) {
                const size_t bytes=static_cast<size_t>(
                    std::min<uint64_t>(8192,seg.originalFileBytes-offset));
                std::array<unsigned char,8192> buf{};
                assert(d::ReadGuestDataOnly(
                    unified,p::kLibcTestBase-libc.lowestLoadPage+
                        seg.first+offset,buf.data(),bytes));
                assert(std::memcmp(buf.data(),
                    original.snapshots[2].bytes()+
                        seg.originalFileOffset+offset,bytes)==0);
                offset+=bytes;
            }
        }
    }
    // The actual interpreter entry is executable in *guest* rights,
    // never a native AArch64 callable pointer.
    std::array<unsigned char,8> originalEntry{};
    assert(d::ReadGuestDataOnly(
        unified,entry.futureFexRIP,
        originalEntry.data(),originalEntry.size(),true));
    const unsigned char marker[8]{
        0xd1,0x7e,0x44,0x41,0x51,0x8d,0xf2,0x0a};
    assert(!d::WriteGuestTestOnly(
        unified,entry.futureFexRIP,marker,sizeof(marker)));
    std::array<unsigned char,8> sameEntry{};
    assert(d::ReadGuestDataOnly(
        unified,entry.futureFexRIP,
        sameEntry.data(),sameEntry.size(),true));
    assert(sameEntry==originalEntry);
    assert(!d::ReadGuestDataOnly(unified,0,
        sameEntry.data(),sameEntry.size()));
    assert(!d::ReadGuestDataOnly(unified,UINT64_MAX-2,
        sameEntry.data(),sameEntry.size()));
    assert(!d::ReadGuestDataOnly(unified,entry.futureFexRIP,
        sameEntry.data(),65537));
    assert(!d::WriteGuestTestOnly(unified,
        unified.initialLinuxGuestRSP,nullptr,8));
    // The real 16K group with 4K RX and RW subpages must have no
    // guest/native shared RWX permission and no direct pointer access.
    bool sawDifferingWX=false;
    bool hadRWSubpage=false;
    for(const auto& [hostVA,host]:unified.host16K) {
        (void)hostVA;
        assert(!host.directHostGuestMappingApproved);
        if(!host.originalHostWideWXConflict)continue;
        bool hasX=false,hasW=false;
        for(const auto& sub:host.subpages) {
            if(!sub.present)continue;
            hasX|=(sub.currentRights&c::X)!=0;
            hasW|=(sub.currentRights&c::W)!=0;
            assert((sub.currentRights&(c::W|c::X))!=(c::W|c::X));
        }
        assert(hasX && hasW);
        sawDifferingWX=true;
    }
    assert(sawDifferingWX);
    // A host-wide page is mutable only in its precisely matching 4K
    // guest RW part, not in its adjacent 4K guest RX part.
    for(const auto& [hostVA,host]:unified.host16K){
        if(!host.originalHostWideWXConflict)continue;
        for(size_t n=0;n<4;n++){
            if(!host.subpages[n].present ||
               !(host.subpages[n].currentRights&c::W))continue;
            const uint64_t address=hostVA+n*4096;
            std::array<unsigned char,8> before{},after{};
            assert(d::ReadGuestDataOnly(
                unified,address,before.data(),before.size()));
            assert(d::WriteGuestTestOnly(
                unified,address,marker,sizeof(marker)));
            assert(d::ReadGuestDataOnly(
                unified,address,after.data(),after.size()));
            assert(std::memcmp(after.data(),marker,sizeof(marker))==0);
            hadRWSubpage=true;
            break;
        }
        break;
    }
    assert(hadRWSubpage);
    // Pre-RELRO real libc page writable only through guarded shadow.
    uint64_t relroVA=0;
    for(const auto& [hostVA,host]:unified.host16K) {
        for(size_t n=0;n<4;n++) {
            const auto& sub=host.subpages[n];
            if(sub.present && sub.owner==d::GuestOwner::Libc &&
               sub.initialRights!=sub.postRelroRights) {
                relroVA=hostVA+n*4096;
                break;
            }
        }
        if(relroVA)break;
    }
    assert(relroVA>0);
    assert(d::WriteGuestTestOnly(unified,relroVA,marker,sizeof(marker)));
    assert(!d::TestOnlySealRelroGuest4K(unified,false));
    assert(d::TestOnlySealRelroGuest4K(unified,true));
    assert(unified.testOnlyRelroSealed);
    assert(!d::TestOnlySealRelroGuest4K(unified,true));
    assert(!d::WriteGuestTestOnly(
        unified,relroVA,marker,sizeof(marker)));
    std::array<unsigned char,8> result{};
    assert(d::ReadGuestDataOnly(
        unified,relroVA,result.data(),result.size()));
    assert(std::memcmp(result.data(),marker,sizeof(marker))==0);
    // Both halves of a cross-4K attempted write remain unchanged if one
    // subpage is read-only, even when sharing a single 16K host buffer.
    bool deniedAtomic=false;
    for(const auto& [hostVA,host]:unified.host16K) {
        for(size_t i=0;i<3;i++){
            const auto& left=host.subpages[i];
            const auto& right=host.subpages[i+1];
            if(!left.present || !right.present ||
               (left.currentRights&c::W) ||
               !(right.currentRights&c::W))continue;
            std::array<unsigned char,8> before{},after{};
            const uint64_t va=hostVA+i*4096+4092;
            assert(d::ReadGuestDataOnly(
                unified,va,before.data(),8));
            assert(!d::WriteGuestTestOnly(unified,va,marker,8));
            assert(d::ReadGuestDataOnly(
                unified,va,after.data(),8));
            assert(after==before);
            deniedAtomic=true;break;
        }
        if(deniedAtomic)break;
    }
    assert(deniedAtomic);
    {
        // A "FEX attached" bit cannot be used to bypass the no-native-
        // mapping boundary: all guest byte copy operations must deny.
        unified.fexGuestMemoryAttached=true;
        assert(!d::ReadGuestDataOnly(
            unified,relroVA,result.data(),result.size()));
        unified.fexGuestMemoryAttached=false;
    }
    {
        original.exactSha256Matched=false;
        MustRejectProvenance(original,entropy);
        original.exactSha256Matched=true;
    }
    {
        original.dynamicLinkerExecuted=true;
        MustRejectProvenance(original,entropy);
        original.dynamicLinkerExecuted=false;
    }
    std::printf(
        "KERNIX_G2EC3D0_REAL_MAIN_LDSO_LIBC_STACK_16K_BACKED_4K_GUEST_SOFTWARE_OWNER_PERMISSIONS_NO_FEX_PASS total_guest_4k=%zu host_16k=%zu host_wx_groups=%zu libc_file_bytes=%llu initial_stack=%llu relro_test_only=%zu no_native_mapping=1\n",
        unified.totalRealGuest4KPages,
        unified.host16KPageGroups,
        unified.host16KPagesWithWXSubpages,
        static_cast<unsigned long long>(unified.libcFileBytesCopied),
        static_cast<unsigned long long>(unified.initialLinuxStackBytesCopied),
        unified.pagesEligibleForRelro);
}
