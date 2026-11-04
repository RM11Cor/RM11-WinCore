// KERNIX G2-E/C1: fail-closed host-independent x86-64 syscall ABI fixture.
// The input real ELF root is SHA-attested via C0; this test never traps,
// dispatches to a host syscall, or runs a guest/FEX thread.
// SPDX-License-Identifier: MIT
#include "kernix_g2e_guest_ldso_entry_contract.h"
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <cstdint>
#include <string>

using namespace kernix::g2e::c1;
static_assert(kOpenat==257 && kMmap==9 && kWrite==1 &&
              kExitGroup==231 && kArchPrctl==158 &&
              kNewfstatat==262 && kGetrandom==318);
static_assert(X86LinuxErrno(22)==-22);
static_assert(X86LinuxErrno(0)==-38);
static_assert(IsX86LinuxError(-4095) && !IsX86LinuxError(-4096));

int main(int argc,char** argv) {
    if(argc!=2)return 2;
    int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 3;
    kernix::g2e::GuestPreflight pinned;
    std::string why;
    assert(kernix::g2e::Validate(fd,pinned,why));
    close(fd);
    std::array<uint8_t,16> entropy{};
    for(unsigned i=0;i<16;i++)entropy[i]=static_cast<uint8_t>(i+1);
    kernix::g2e::GuestLdsoEntryWitness entry;
    kernix::g2b::X86GuestProcessLaunchPlan plan;
    assert(kernix::g2e::PlanPinnedRealGlibcLdsoEntryDataOnly(
        pinned,entropy,entry,why,&plan));
    assert(entry.futureFexRIP==plan.guestInterpreterEntry &&
           entry.futureFexRIP!=plan.guestMainEntry);
    assert(!entry.fexThreadInitialized && !entry.guestLdsoEntered);

    X86GuestStackBoundary trusted{
        plan.stack.guestBottom,plan.stack.guestTop,
        plan.stack.initialStackLayoutValidated
    };
    X86LinuxSyscallTrap trap{
        kMmap,
        0,16384,3,0x22,UINT64_MAX,0,
        entry.futureFexRIP,entry.futureFexRIP+2,
        0x246,entry.futureFexRSP
    };
    TrapClassification classification;
    assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(classification.guestNumber==kMmap &&
           classification.args[0]==0 &&
           classification.args[1]==16384 &&
           classification.args[2]==3 &&
           classification.args[3]==0x22 &&
           classification.args[4]==UINT64_MAX &&
           classification.args[5]==0);
    assert(classification.sourceRegisterMappingChecked &&
           classification.trapBoundaryAuthenticated &&
           !classification.hostSyscallDispatched &&
           !classification.guestMemoryDereferenced);
    assert(classification.nextGuestRIP==trap.rip+2);
    assert(BoundedAnonymousMmapIntent(classification));
    const C1DispatchPlan deny=PlanHostlessGuestDispatch(classification);
    assert(deny.safeGuestReturn==-38 && deny.requiresGuestKernel &&
           deny.category==CallCategory::NeedsGuestKernel &&
           !deny.hostSyscallInvoked && !deny.guestMemoryTouched &&
           !deny.hostProcessExited);
    // A Linux x86_64 syscall's arg4 is R10. RCX is the return instruction
    // address and must NEVER replace R10 (amd64 C-call ABI differs).
    assert(trap.rcxNext!=trap.r10);
    trap.r10=0x32; // MAP_FIXED supplied by guest instead of exact 0x22
    assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(classification.args[3]==0x32);
    assert(!BoundedAnonymousMmapIntent(classification));
    trap.r10=0x22;
    trap.r8=0;assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(!BoundedAnonymousMmapIntent(classification));
    trap.r8=UINT32_MAX;assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(BoundedAnonymousMmapIntent(classification));
    trap.rax=kOpenat;
    assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(classification.category==CallCategory::NeedsGuestKernel);
    assert(PlanHostlessGuestDispatch(classification).safeGuestReturn==-38);
    trap.rax=kExitGroup;
    assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(classification.category==CallCategory::ExitIntentOnly);
    assert(!PlanHostlessGuestDispatch(classification).hostProcessExited);
    trap.rax=kGetpid;
    assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(classification.category==CallCategory::HostlessIdentity);
    assert(PlanHostlessGuestDispatch(classification).safeGuestReturn==-38);
    trap.rax=9999999;
    assert(ClassifyVerifiedTrap(trap,trusted,classification));
    assert(classification.category==CallCategory::UnknownDenied);
    assert(!PlanHostlessGuestDispatch(classification).requiresGuestKernel);

    // A wrong FEX boundary, guest stack, or untrusted stack fails closed.
    trap.rax=kMmap;
    trap.rcxNext=trap.rip+3;
    assert(!ClassifyVerifiedTrap(trap,trusted,classification));
    assert(!classification.trapBoundaryAuthenticated);
    assert(PlanHostlessGuestDispatch(classification).safeGuestReturn==-38);
    trap.rcxNext=trap.rip+2;
    trap.rsp=trusted.pastLast+8;
    assert(!ClassifyVerifiedTrap(trap,trusted,classification));
    trap.rsp=entry.futureFexRSP;
    trusted.attestedFromPinnedGuest=false;
    assert(!ClassifyVerifiedTrap(trap,trusted,classification));
    trusted.attestedFromPinnedGuest=true;
    assert(ClassifyVerifiedTrap(trap,trusted,classification));
    classification.fexGuestExecuted=true;
    assert(!PlanHostlessGuestDispatch(classification).requiresGuestKernel);

    // No host or guest dereference: just boundary, permissions and 16K
    // subpage W/X intent matching.
    GuestVmInterval guestRX{
        entry.futureFexRIP&~uint64_t(4095),
        (entry.futureFexRIP&~uint64_t(4095))+4096,
        true,false,true,true};
    GuestVmInterval guestRW{
        guestRX.start+4096,guestRX.pastLast+4096,
        true,true,false,true};
    assert(PinnedGuestSpan(entry.futureFexRIP,2,GuestDataAccess::Execute,guestRX));
    assert(!PinnedGuestSpan(entry.futureFexRIP,2,GuestDataAccess::Write,guestRX));
    assert(!PinnedGuestSpan(guestRX.pastLast-1,2,GuestDataAccess::Read,guestRX));
    assert(HostPageExecuteWriteConflict(guestRX,guestRW,16384) ==
           ((guestRX.start&~uint64_t(16383)) ==
            (guestRW.start&~uint64_t(16383))));
    assert(!HostPageExecuteWriteConflict(guestRX,guestRW,4096));
    assert(HostPageExecuteWriteConflict(guestRX,guestRW,8192));
    guestRW.guestWrite=false;
    assert(!HostPageExecuteWriteConflict(guestRX,guestRW,16384));
    guestRW.guestWrite=true;
    guestRW.attested=false;
    assert(HostPageExecuteWriteConflict(guestRX,guestRW,16384));
    assert(!GuestRange(UINT64_MAX-1,4));
    assert(!GuestRange(0,1));
    assert(GuestRange(guestRX.start,4096));
    assert(IsGuestMmapFdAnonymous(UINT32_MAX) &&
           IsGuestMmapFdAnonymous(UINT64_MAX) &&
           !IsGuestMmapFdAnonymous(0));
    std::puts("KERNIX_G2EC1_ORIGINAL_GLIBC_X86_LINUX_SYSCALL_RAX_R10_R8_R9_ABI_NO_HOST_DISPATCH_AND_16K_NEGATIVES_PASS");
}
