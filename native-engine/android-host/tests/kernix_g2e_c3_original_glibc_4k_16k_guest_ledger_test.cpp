// C3-A: genuine SHA-locked Linux x86 PIE/ld-linux/libc -> page ledger.
// Host-only source proof. NEVER direct-map these source pages into FEX.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_c3_guest_page_ledger.h"
#include <cassert>
#include <array>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

using namespace kernix::g2e;
namespace c3=kernix::g2e::c3;

static void Reject(const g2b::X86GuestProcessLaunchPlan& plan,
                   const GuestLdsoEntryWitness& witness) {
    c3::Ledger rejected;
    std::string why;
    assert(!c3::BuildPinnedGlibcGuestPageLedger(plan,witness,rejected,why));
    assert(!why.empty() && why!="none");
    assert(!rejected.inputValidated &&
           !rejected.nativeDirectMapAuthorized &&
           !rejected.guestMemoryInstalled &&
           !rejected.fexGuestEntered &&
           !rejected.linuxLdsoExecuted);
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    GuestPreflight original;
    std::string error;
    assert(Validate(fd,original,error));
    close(fd);
    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();i++)entropy[i]=static_cast<uint8_t>(i+1);
    GuestLdsoEntryWitness witness;
    g2b::X86GuestProcessLaunchPlan real;
    assert(PlanPinnedRealGlibcLdsoEntryDataOnly(original,entropy,
                                                 witness,error,&real));
    c3::Ledger ledger;
    assert(c3::BuildPinnedGlibcGuestPageLedger(real,witness,ledger,error));
    assert(error=="none");
    assert(ledger.inputValidated && !ledger.guestPages.empty());
    assert(!ledger.hostPages.empty() && !ledger.nativeDirectMapAuthorized);
    assert(!ledger.guestMemoryInstalled && !ledger.fexGuestEntered &&
           !ledger.linuxLdsoExecuted);
    assert(ledger.authenticatedInterpreterRIP==real.guestInterpreterEntry &&
           ledger.authenticatedInterpreterRIP!=real.guestMainEntry);
    assert(ledger.validatedStackRSP==real.stack.guestRSP);
    assert(c3::CheckGuestPageAccess(
             ledger,witness.futureFexRIP,1,
             c1::GuestDataAccess::Execute));
    assert(!c3::CheckGuestPageAccess(
             ledger,witness.futureFexRIP,1,
             c1::GuestDataAccess::Write));
    assert(c3::CheckGuestPageAccess(
             ledger,witness.futureFexRSP,8,
             c1::GuestDataAccess::Read));
    assert(c3::CheckGuestPageAccess(
             ledger,witness.futureFexRSP,8,
             c1::GuestDataAccess::Write));
    assert(!c3::CheckGuestPageAccess(
             ledger,witness.futureFexRSP,8,
             c1::GuestDataAccess::Execute));
    assert(!c3::CheckGuestPageAccess(ledger,UINT64_MAX-1,8,
                                    c1::GuestDataAccess::Read));
    assert(!c3::CheckGuestPageAccess(ledger,0,1,
                                    c1::GuestDataAccess::Read));
    assert(!c3::CheckGuestPageAccess(ledger,witness.futureFexRIP,65537,
                                    c1::GuestDataAccess::Read));

    // A valid data-only plan MUST fail closed for forged entry/stack/mapping.
    {
        auto bad=real;bad.guestInterpreterEntry=bad.guestMainEntry;
        Reject(bad,witness);
    }
    {
        auto bad=real;bad.guestMemoryMapped=true;
        Reject(bad,witness);
    }
    {
        auto bad=real;bad.stack.initialStackLayoutValidated=false;
        Reject(bad,witness);
    }
    {
        auto bad=real;bad.regions.clear();
        Reject(bad,witness);
    }
    {
        auto bad=real;
        bad.regions[0].originalElfFlags=PF_R|PF_W|PF_X;
        Reject(bad,witness);
    }
    {
        auto bad=real;
        bad.regions[0].pastLast=UINT64_MAX;
        Reject(bad,witness);
    }
    {
        auto bad=real;
        bad.regions[0].first=bad.regions[0].pastLast;
        Reject(bad,witness);
    }
    {
        auto badWitness=witness;badWitness.fexThreadInitialized=true;
        Reject(real,badWitness);
    }
    {
        auto badWitness=witness;badWitness.futureFexRIP=real.guestMainEntry;
        Reject(real,badWitness);
    }
    // Additional synthetic *policy* case: RX guest page and immediately
    // adjacent RW guest page are separate at 4K but share one 16K host page.
    // The host page MUST be marked as requiring explicit subpage emulation.
    // This policy-only addition is not a source-authenticated guest image,
    // and is NEVER authorized to map or execute.
    {
        auto modified=real;
        const uint64_t base=0x0000666600040000ULL;
        modified.regions.push_back({base,base+4096,PF_R|PF_X,false});
        modified.regions.push_back({base+4096,base+8192,PF_R|PF_W,false});
        c3::Ledger conflict;
        assert(c3::BuildPinnedGlibcGuestPageLedger(
            modified,witness,conflict,error));
        assert(conflict.anyHost16KPageWriteExecuteConflict &&
               conflict.hostPagesNeedingSubpageEmulation>=1);
        assert(!conflict.nativeDirectMapAuthorized);
        assert(!conflict.guestMemoryInstalled);
        // Even forged same-guest-page RX/RW permissions must stay blocked.
        modified.regions.back().first=base+2048;
        assert(c3::BuildPinnedGlibcGuestPageLedger(
            modified,witness,conflict,error));
        assert(conflict.anyGuest4KPageWriteExecuteConflict &&
               !conflict.nativeDirectMapAuthorized);
    }
    std::printf(
      "KERNIX_G2EC3A_ORIGINAL_GLIBC_LDSO_GUEST_4K_HOST_16K_WX_LEDGER_PASS_NO_GUEST_MAP host_pages=%zu guest_pages=%zu host_wx_subpage_conflicts=%zu guest_4k_wx=%u\n",
      ledger.hostPages.size(),ledger.guestPages.size(),
      ledger.hostPagesNeedingSubpageEmulation,
      ledger.anyGuest4KPageWriteExecuteConflict ? 1U:0U);
    return 0;
}
