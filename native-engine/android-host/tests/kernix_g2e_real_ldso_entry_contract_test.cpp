// KERNIX G2-E/C0 original, source-attested real GNU ld-linux and glibc.
// Tests real x86 ELF metadata and Linux AUXV entry-plan only.
// No FEX Core/thread initialization, no guest code, no Android execution.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_guest_ldso_entry_contract.h"
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

static void Reject(const kernix::g2b::X86GuestProcessLaunchPlan& plan,
                   const std::array<uint8_t,16>& random) {
    kernix::g2e::GuestLdsoEntryWitness out;
    std::string failure;
    assert(!kernix::g2e::VerifyLdsoEntryPlanOnly(plan,random,out,failure));
    assert(failure!="none" && !failure.empty());
    assert(!out.exactOriginalSha256Assets &&
           !out.guestPtInterpEntryContractVerified &&
           !out.linuxX86AuxvContractVerified &&
           !out.fexThreadInitialized &&
           !out.guestLdsoEntered);
}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0)return 3;
    kernix::g2e::GuestPreflight original;
    std::string reason;
    assert(kernix::g2e::Validate(root,original,reason));
    close(root);
    assert(original.exactSha256Matched &&
           original.readOnlyAnonymousSnapshots &&
           original.exactInterpreterAndGlibcClosure &&
           !original.guestCodeExecuted &&
           !original.dynamicLinkerExecuted && !original.fexAttached);

    std::array<uint8_t,16> entropy{};
    for(size_t i=0;i<entropy.size();++i)
        entropy[i]=static_cast<uint8_t>(i+1); // only test fixture entropy
    kernix::g2e::GuestLdsoEntryWitness attested{};
    kernix::g2b::X86GuestProcessLaunchPlan plan;
    assert(kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
        original,entropy,attested,reason,&plan));
    assert(reason=="none");
    assert(attested.exactOriginalSha256Assets &&
           attested.guestPtInterpEntryContractVerified &&
           attested.linuxX86AuxvContractVerified);
    assert(attested.futureFexRIP==plan.guestInterpreterEntry);
    assert(attested.futureFexRIP!=plan.guestMainEntry);
    assert(attested.expectedATEntry==plan.guestMainEntry);
    assert(attested.expectedATBase==plan.interpreterLoadBias);
    assert(attested.futureFexRSP%16==0);
    assert(attested.expectedATRandom==plan.stack.guestRandomPointer);
    assert(!attested.guestAddressSpaceReserved &&
           !attested.fexThreadInitialized &&
           !attested.guestLdsoEntered &&
           !attested.glibcExecuted && !attested.wineExecuted);
    // Important: the raw x86-64 PIE entry is NOT a replacement for its
    // genuine PT_INTERP entry. Entry and AUXV mismatches must fail closed.
    {
        auto bad=plan;
        bad.guestInterpreterEntry=bad.guestMainEntry;
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        bad.guestInterpreter="/lib64/not-the-original-ld-linux.so";
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        bad.stack.guestRSP+=8;
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        const size_t off=static_cast<size_t>(
            bad.stack.guestRSP-bad.stack.guestBottom);
        bad.stack.bytes[off+40]^=1; // invalidate first AT_PHDR tag
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        const size_t off=static_cast<size_t>(
            bad.stack.guestRandomPointer-bad.stack.guestBottom);
        bad.stack.bytes[off]^=1;
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        bad.guestCodeExecuted=true;
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        bad.fexEntryPointAssigned=true;
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        bad.guestInterpreterEntry=0;
        Reject(bad,entropy);
    }
    {
        auto bad=plan;
        bad.dependencyObjectsChecked=2;
        Reject(bad,entropy);
    }
    {
        kernix::g2e::GuestLdsoEntryWitness failed{};
        std::array<uint8_t,16> wrongEntropy{};
        assert(!kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
            original,wrongEntropy,failed,reason));
        assert(!failed.guestPtInterpEntryContractVerified);
    }
    {
        original.exactInterpreterAndGlibcClosure=false;
        kernix::g2e::GuestLdsoEntryWitness failed{};
        assert(!kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
            original,entropy,failed,reason));
        assert(reason=="G2EC0_ORIGINAL_GLIBC_SNAPSHOT_NOT_VERIFIED");
        assert(!failed.exactOriginalSha256Assets);
    }
    std::puts("KERNIX_G2EC0_REAL_X86_LDSO_PT_INTERP_RIP_STACK_AUXV_AND_NEGATIVE_GATES_PASS_NO_FEX");
    return 0;
}
