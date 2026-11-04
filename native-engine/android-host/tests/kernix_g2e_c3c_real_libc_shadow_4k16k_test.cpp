// G2-E/C3-C SHA-pinned Linux x86 libc shadow bytes, 4K guest software
// R/W/X checks and TEST-ONLY RELRO transition. Never FEX/Android executable.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3c_libc_shadow_subpage_memory.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

using namespace kernix::g2e;
namespace c3c=kernix::g2e::c3c;
namespace c3b=kernix::g2e::c3b;
namespace c3=kernix::g2e::c3;

static void Reject(const GuestPreflight& src,
                   const c3b::Result& plan) {
    c3c::LibcShadow denied;
    std::string reason;
    assert(!c3c::PreparePinnedLibcShadowDataOnly(
        src,plan,denied,reason));
    assert(!reason.empty() && reason!="none" &&
           denied.pages.empty() &&
           !denied.originalLibcSHA256Proved &&
           !denied.actualGuestMemoryMapped);
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    GuestPreflight source;
    std::string why;
    assert(Validate(fd,source,why));
    close(fd);
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    c3b::Result plan;
    assert(c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
        source,entropy,plan,why));
    c3c::LibcShadow shadow;
    assert(c3c::PreparePinnedLibcShadowDataOnly(
        source,plan,shadow,why));
    assert(why=="none");
    assert(shadow.pages.size()==plan.libcUnique4KPages &&
           shadow.relro4KPages==plan.fullyCoveredRelro4KPages &&
           shadow.sourceBytesCopiedIntoPrivateShadow &&
           shadow.software4KPermissionsEnforced &&
           shadow.originalLibcSHA256Proved &&
           !shadow.actualGuestMemoryMapped &&
           !shadow.fexCpuStateUsesShadow &&
           !shadow.host16KSubpageMprotectImplemented &&
           !shadow.originalGuestLoaderExecuted &&
           !shadow.nativeDirectGuestAddressAccessAuthorized);
    c3b::ParsedLibc parsed;
    assert(c3b::ParseLibcELFHeadersOnly(
        std::span<const unsigned char>(source.snapshots[2].bytes(),
                                       source.snapshots[2].size()),
        parsed,why));
    size_t validatedSourceBytes=0;
    size_t verifiedBss=0;
    uint64_t writableVA=0,execVA=0,relroVA=0;
    for(const auto& [page,record]:shadow.pages){
        if(!writableVA && (record.currentRights&c3::W))
            writableVA=page;
        if(!execVA && (record.currentRights&c3::X))
            execVA=page;
        if(!relroVA &&
           record.originalRights!=record.afterRelroRights)
            relroVA=page;
    }
    assert(writableVA && execVA && relroVA);
    for(const auto& ph:parsed.ptLoads){
        const uint64_t vaddr=ph.first+shadow.libraryLoadBias;
        const auto* reference=source.snapshots[2].bytes()+
                                ph.originalFileOffset;
        // Verify EACH real PT_LOAD's whole on-disk image, in bounded chunks.
        size_t copied=0;
        while(copied<ph.originalFileBytes){
            const size_t n=std::min(size_t(8192),
                         size_t(ph.originalFileBytes-copied));
            std::array<unsigned char,8192> block{};
            assert(c3c::CopyShadowBytesDataOnly(
                shadow,vaddr+copied,block.data(),n));
            assert(std::memcmp(block.data(),reference+copied,n)==0);
            copied+=n;
            validatedSourceBytes+=n;
        }
        // ELF p_memsz > p_filesz bytes MUST be zero-initialized. No real
        // page faults, relocations or Android native mappings have occurred.
        const uint64_t bss=ph.pastLast-ph.first-ph.originalFileBytes;
        uint64_t tested=0;
        while(tested<bss){
            const size_t n=static_cast<size_t>(
                std::min<uint64_t>(4096,bss-tested));
            std::array<unsigned char,4096> zeros{};
            std::array<unsigned char,4096> actual{};
            assert(c3c::CopyShadowBytesDataOnly(shadow,
                vaddr+ph.originalFileBytes+tested,actual.data(),n));
            assert(std::memcmp(actual.data(),zeros.data(),n)==0);
            tested+=n;
            verifiedBss+=n;
        }
    }
    assert(validatedSourceBytes==shadow.originalFileBytesCopied &&
           verifiedBss==shadow.bssBytesZeroInitialized &&
           validatedSourceBytes>1000000);
    std::array<unsigned char,8> observed{},before{};
    assert(c3c::CopyShadowBytesDataOnly(
        shadow,execVA,before.data(),before.size(),true));
    assert(!c3c::WriteShadowBytesTestOnly(
        shadow,execVA,before.data(),before.size()));
    assert(c3c::CopyShadowBytesDataOnly(
        shadow,execVA,observed.data(),observed.size(),true));
    assert(observed==before);
    const unsigned char marker[8]={0x77,0x64,0x54,0x32,0x37,0x16,0x10,0x99};
    assert(c3c::WriteShadowBytesTestOnly(
        shadow,relroVA,marker,sizeof(marker)));
    std::array<unsigned char,8> result{};
    assert(c3c::CopyShadowBytesDataOnly(
        shadow,relroVA,result.data(),result.size()));
    assert(std::memcmp(marker,result.data(),sizeof(marker))==0);
    assert(!c3c::ApplyPlannedRelroShadowTransitionTestOnly(shadow,false));
    assert(!shadow.postRelroTestOnly);
    assert(c3c::ApplyPlannedRelroShadowTransitionTestOnly(shadow,true));
    assert(shadow.postRelroTestOnly);
    assert(!c3c::ApplyPlannedRelroShadowTransitionTestOnly(shadow,true));
    assert(!c3c::WriteShadowBytesTestOnly(
        shadow,relroVA,marker,sizeof(marker)));
    result={};
    assert(c3c::CopyShadowBytesDataOnly(
        shadow,relroVA,result.data(),result.size()));
    assert(std::memcmp(marker,result.data(),sizeof(marker))==0);

    // Cross-4K transaction: a RELRO read-only page next to a writable
    // 4K page inside a 16K host page must not partially update either.
    bool crossPageRejectionObserved=false;
    for(const auto& [page,record]:shadow.pages) {
        if(record.currentRights&c3::W)continue;
        const auto next=shadow.pages.find(page+4096);
        if(next==shadow.pages.end() ||
           !(next->second.currentRights&c3::W))continue;
        const uint64_t start=page+4092;
        std::array<unsigned char,8> existing{},after{};
        if(!c3c::CopyShadowBytesDataOnly(
             shadow,start,existing.data(),existing.size()))continue;
        assert(!c3c::WriteShadowBytesTestOnly(
            shadow,start,marker,sizeof(marker)));
        assert(c3c::CopyShadowBytesDataOnly(
            shadow,start,after.data(),after.size()));
        assert(existing==after);
        crossPageRejectionObserved=true;
        break;
    }
    assert(crossPageRejectionObserved);
    assert(!c3c::CopyShadowBytesDataOnly(
        shadow,0,observed.data(),observed.size()));
    assert(!c3c::CopyShadowBytesDataOnly(
        shadow,UINT64_MAX-2,observed.data(),observed.size()));
    assert(!c3c::WriteShadowBytesTestOnly(
        shadow,writableVA,marker,0));
    assert(!c3c::WriteShadowBytesTestOnly(
        shadow,writableVA,nullptr,8));
    {
        auto modified=plan;
        modified.libcUnique4KPages+=1;
        Reject(source,modified);
    }
    {
        auto modified=plan;
        modified.afterRelroGuest4KPages.clear();
        Reject(source,modified);
    }
    {
        auto modified=plan;
        modified.nativeDirectMappingAuthorized=true;
        Reject(source,modified);
    }
    {
        // Replay after live guest execution flag is never accepted.
        auto modified=plan;
        modified.originalFEXGuestEntered=true;
        Reject(source,modified);
    }
    {
        // Data-only snapshot checksum provenance is a strict prerequisite.
        source.exactSha256Matched=false;
        Reject(source,plan);
        source.exactSha256Matched=true;
    }
    std::printf(
        "KERNIX_G2EC3C_AUTHENTIC_LIBC_SHADOW_BYTES_4K_PERMISSION_RELRO_TEST_ONLY_PASS_NO_FEX_NO_ANDROID pages=%zu file_bytes=%zu bss_zero=%zu relro_4k=%zu no_partial_write=1\n",
        shadow.pages.size(),validatedSourceBytes,verifiedBss,
        shadow.relro4KPages);
    return 0;
}
