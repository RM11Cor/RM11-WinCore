// C3-B: actual pinned original Ubuntu x86-64 libc GNU_RELRO + main ldso.
// Only metadata/guest permission planning, never a native mmap or FEX guest.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3b_original_glibc_relro_page_plan.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <string>
#include <unistd.h>
#include <vector>

using namespace kernix::g2e;
namespace c3b=kernix::g2e::c3b;
namespace c3=kernix::g2e::c3;

static void RejectLibcELF(std::span<const unsigned char> raw) {
    c3b::ParsedLibc parsed;
    std::string reason;
    assert(!c3b::ParseLibcELFHeadersOnly(raw,parsed,reason));
    assert(!parsed.originalX86ELFParsed);
    assert(!reason.empty() && reason!="none");
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    GuestPreflight pinned;
    std::string why;
    assert(Validate(fd,pinned,why));
    close(fd);
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1);
    c3b::Result plan;
    assert(c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
        pinned,entropy,plan,why));
    assert(why=="none" && plan.fullImagePagePlanValidated &&
           plan.originalLibcSHA256Attested && plan.relroPlannedNotApplied);
    assert(plan.libcPTLoadCount>=2 &&
           plan.libcPTLoadCount<=c3b::kMaxLibcPTLoads &&
           plan.libcUnique4KPages>0 &&
           plan.fullyCoveredRelro4KPages>0 &&
           plan.libcSyntheticLoadBias>0 &&
           plan.initialGuest4KPages.size()>
               plan.libcUnique4KPages &&
           plan.initialHost16KPages.size()>0 &&
           plan.initialGuest4KPages.size()==
               plan.afterRelroGuest4KPages.size() &&
           plan.initialHost16KPages.size()==
               plan.afterRelroHost16KPages.size() &&
           !plan.hostGuestMemoryInstalled &&
           !plan.originalFEXGuestEntered &&
           !plan.originalLibcExecuted &&
           !plan.originalLdsoExecuted &&
           !plan.nativeDirectMappingAuthorized);
    assert(plan.afterRelroHost16KWxConflicts<=
           plan.initialHost16KWxConflicts);
    size_t actuallyChanged=0;
    for(size_t i=0;i<plan.initialGuest4KPages.size();++i) {
        const auto& before=plan.initialGuest4KPages[i];
        const auto& later=plan.afterRelroGuest4KPages[i];
        assert(before.address==later.address);
        assert((before.permissions&(c3::W|c3::X))!=(c3::W|c3::X));
        assert((later.permissions&(c3::W|c3::X))!=(c3::W|c3::X));
        if(before.permissions!=later.permissions){
            assert((before.permissions&c3::W) &&
                   !(later.permissions&c3::W) &&
                   (later.permissions&c3::R) &&
                   !(before.permissions&c3::X));
            assert(before.address>=plan.libcSyntheticRelroFirst &&
                   before.address+c3b::kGuestPage<=
                       plan.libcSyntheticRelroPastLast);
            ++actuallyChanged;
        }
    }
    assert(actuallyChanged==plan.fullyCoveredRelro4KPages);
    // Precise host 16K policy tracks *each* 4K subpage. It never
    // grants direct mapping even if the host page has equal permissions.
    for(const auto& host:plan.initialHost16KPages) {
        assert(!host.hostDirectProtectionAuthorized);
        if(host.hostWideWxConflict)
            assert(host.subpagePermissionsDiffer);
    }
    // The parser is deliberately not a SHA authority. All altered ELF
    // metadata must be rejected, even when supplied with unchanged size.
    auto bytes=std::vector<unsigned char>(
        pinned.snapshots[2].bytes(),
        pinned.snapshots[2].bytes()+pinned.snapshots[2].size());
    c3b::ParsedLibc libc;
    assert(c3b::ParseLibcELFHeadersOnly(bytes,libc,why));
    assert(libc.originalX86ELFParsed && libc.relroFound);
    {
        auto bad=bytes;
        Elf64_Ehdr h{};
        std::memcpy(&h,bad.data(),sizeof(h));
        h.e_machine=EM_AARCH64;
        std::memcpy(bad.data(),&h,sizeof(h));
        RejectLibcELF(bad);
    }
    {
        auto bad=bytes;
        Elf64_Ehdr h{};
        std::memcpy(&h,bad.data(),sizeof(h));
        for(unsigned i=0;i<h.e_phnum;i++){
            Elf64_Phdr ph{};
            auto* location=bad.data()+h.e_phoff+
                static_cast<size_t>(i)*sizeof(ph);
            std::memcpy(&ph,location,sizeof(ph));
            if(ph.p_type!=PT_GNU_RELRO)continue;
            ph.p_memsz=0;
            std::memcpy(location,&ph,sizeof(ph));
            break;
        }
        RejectLibcELF(bad);
    }
    {
        auto bad=bytes;
        Elf64_Ehdr h{};
        std::memcpy(&h,bad.data(),sizeof(h));
        bool forged=false;
        for(unsigned i=0;i<h.e_phnum;i++){
            Elf64_Phdr ph{};
            auto* location=bad.data()+h.e_phoff+
                static_cast<size_t>(i)*sizeof(ph);
            std::memcpy(&ph,location,sizeof(ph));
            if(ph.p_type!=PT_LOAD || !(ph.p_flags&PF_W))continue;
            ph.p_flags|=PF_X;
            std::memcpy(location,&ph,sizeof(ph));
            forged=true;break;
        }
        assert(forged);
        RejectLibcELF(bad);
    }
    {
        pinned.exactSha256Matched=false;
        c3b::Result reject;
        assert(!c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
            pinned,entropy,reject,why));
        assert(!reject.fullImagePagePlanValidated &&
               reject.initialGuest4KPages.empty());
        pinned.exactSha256Matched=true;
    }
    {
        pinned.wineExecuted=true;
        c3b::Result reject;
        assert(!c3b::BuildRealGlibcRelroPermissionPlanDataOnly(
            pinned,entropy,reject,why));
        pinned.wineExecuted=false;
    }
    {
        std::vector<c3::GuestPage> bad{{0x10000,c3::R|c3::W|c3::X,false}};
        std::vector<c3b::HostPermissionPage> out;
        size_t wx=0,diff=0;
        assert(!c3b::Build16KHostPolicy(bad,out,wx,diff));
    }
    {
        std::vector<c3::GuestPage> adjacent{
            {0x30000,c3::R|c3::X,false},
            {0x31000,c3::R|c3::W,false}};
        std::vector<c3b::HostPermissionPage> out;
        size_t wx=0,diff=0;
        assert(c3b::Build16KHostPolicy(adjacent,out,wx,diff));
        assert(wx==1 && diff==1 &&
               out.size()==1 &&
               !out[0].hostDirectProtectionAuthorized);
    }
    std::printf(
      "KERNIX_G2EC3B_REAL_LIBC_PT_LOAD_RELRO_4K_16K_NO_GUEST_EXEC_PASS libc_ptloads=%zu libc_4k=%zu total_4k=%zu host_16k=%zu pre_relro_host_WX=%zu post_relro_host_WX=%zu fully_covered_relro_4k=%zu\n",
      plan.libcPTLoadCount,plan.libcUnique4KPages,
      plan.initialGuest4KPages.size(),plan.initialHost16KPages.size(),
      plan.initialHost16KWxConflicts,
      plan.afterRelroHost16KWxConflicts,
      plan.fullyCoveredRelro4KPages);
    return 0;
}
