// SPDX-License-Identifier: MIT
// Pure plan: REAL original ELF/guest syscall evidence prerequisites; no syscall.
// The native-x86 loader protects source main RELRO before its own self IFUNC.
// Release requires separate actual kernel mprotect, return & write-denial proof.
#include "../kernix_g0_original_main_relro_stage_mprotect_plan.h"
#include <cassert>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>
#include <utility>
using namespace kernix::g0::originalmainrelro;
struct Fixture {
  SourceStage source{};
  OwnedVMA owner{};
  GuestSyscall syscall{};
};
static Fixture Good() {
  Fixture s;
  s.source.mainSha256Verified=true;
  s.source.originalLdsoSha256Verified=true;
  s.source.originalLibcSha256Verified=true;
  s.source.originalFexShaVerified=true;
  s.source.originalGuestSyscallInstructionFromLdsoRX=true;
  s.source.sourceGuestTrapAndOriginalRegisterMapAuthenticated=true;
  s.source.sourceOriginalMainNineWriterEventsExactGuestRIPs=true;
  s.source.originalMainEightRelroTargetsSourceAuth=true;
  s.source.sourceRELATIVE0FixtureIgnoredAndActualLdsoRewriteProven=true;
  s.source.mainRelocationPhaseDoneBeforeMainGuestMprotect=true;
  s.source.originalLibcRelroPhaseAlreadyReached=true;
  s.source.sourceLibc46IRELATIVEJitStoresObserved=true;
  // Source-original GNU ldso self IFUNC genuinely comes *after* mprotect.
  s.source.originalLdsoSelfIRELATIVEResolverCompleted=false;
  s.source.allOriginalTriad1237RelocationsClosed=false;
  s.owner.ownedExactOriginalMainELF=true;
  s.owner.sourceBackedMainPTGNURELRO=true;
  s.owner.ownerRegistrySourceSHAIdentityChecked=true;
  s.owner.noForeignHostPointerOrOverlappingVMA=true;
  s.owner.noOverlappingLiveExecutableOrWritableGuestAlias=true;
  s.owner.currentlyExactGuestRelroPageReadWriteAndNotExecute=true;
  s.owner.pendingOriginalMainPageWriter=false;
  s.owner.hostNativePageBytes=4096;
  s.owner.guestPageBytes=4096;
  s.owner.exactOwnedNativeSpanBytes=4096;
  s.owner.mappedGuestPageStart=kSourceGuestMainRelroPage;
  s.owner.mappedHostPageStart=0x7f000000;
  s.syscall.x86TrapFromAuthenticFexGuest=true;
  s.syscall.syscallNumber=kLinuxX86SyscallMprotect;
  s.syscall.sourceGuestRIP=kSourceGuestMprotectRIP;
  s.syscall.sourceGuestNextRIP=kSourceGuestMprotectRIP+2;
  s.syscall.address=kSourceGuestMainRelroPage;
  s.syscall.length=kSourceGuestMainRelroBytes;
  s.syscall.protection=kLinuxProtRead;
  return s;
}
struct Bad {
  const char* label;
  Decision expected;
  std::function<void(Fixture&)> corrupt;
};
int main() {
  const auto good=Good();
  const auto planned=PlanOneOriginalMainPage(good.source,good.owner,good.syscall);
  assert(planned.decision==Decision::PlanAllowedOnly_NoSyscallExecuted);
  assert(planned.canAttemptHostMprotectForThisOneSourcePage);
  assert(!planned.nativeKernelProtectionChanged && !planned.guestSyscallSucceeded &&
         !planned.sourceMainRELROSealed && !planned.originalLdsoSelfIFUNCExecuted &&
         !planned.AndroidWineOrGamesProven);
  // Don't deadlock by requiring a self IRELATIVE that is executed later.
  auto later=good;
  later.source.originalLdsoSelfIRELATIVEResolverCompleted=true;
  later.source.allOriginalTriad1237RelocationsClosed=true;
  assert(PlanOneOriginalMainPage(later.source,later.owner,later.syscall).decision==
         Decision::PlanAllowedOnly_NoSyscallExecuted);
  std::vector<Bad> tests;
  auto add=[&](const char* label,Decision code,std::function<void(Fixture&)> fn) {
    tests.push_back({label,code,std::move(fn)});
  };
  const auto source=Decision::DenyMissingOriginalSourceOrGuestProvenance;
  const auto stage=Decision::DenyMainRelocationWriterOrStageIncomplete;
  const auto syscall=Decision::DenyInvalidGuestSyscallOrPTGNURELRO;
  const auto owned=Decision::DenyUnownedOrUnsafeGuestNativeMapping;
  const auto page=Decision::DenyNonEquivalentNativePageOrSubpageAliasing;
  add("source main hash",source,[](Fixture& x){x.source.mainSha256Verified=false;});
  add("original ldso hash",source,[](Fixture& x){x.source.originalLdsoSha256Verified=false;});
  add("original libc hash",source,[](Fixture& x){x.source.originalLibcSha256Verified=false;});
  add("original FEX SHA",source,[](Fixture& x){x.source.originalFexShaVerified=false;});
  add("original syscall byte",source,[](Fixture& x){x.source.originalGuestSyscallInstructionFromLdsoRX=false;});
  add("original guest trap register origin",source,[](Fixture& x){x.source.sourceGuestTrapAndOriginalRegisterMapAuthenticated=false;});
  add("only eight of nine main writer events",stage,[](Fixture& x){x.source.sourceOriginalMainNineWriterEventsExactGuestRIPs=false;});
  add("not all eight main RELRO writes",stage,[](Fixture& x){x.source.originalMainEightRelroTargetsSourceAuth=false;});
  add("authored fixture misattributed",stage,[](Fixture& x){x.source.sourceRELATIVE0FixtureIgnoredAndActualLdsoRewriteProven=false;});
  add("main source dynamic relocation stage still active",stage,[](Fixture& x){x.source.mainRelocationPhaseDoneBeforeMainGuestMprotect=false;});
  add("glibc relro phase not done",stage,[](Fixture& x){x.source.originalLibcRelroPhaseAlreadyReached=false;});
  add("glibc 46 IFUNC native source writer traps not observed",stage,[](Fixture& x){x.source.sourceLibc46IRELATIVEJitStoresObserved=false;});
  add("guest trap forged",syscall,[](Fixture& x){x.syscall.x86TrapFromAuthenticFexGuest=false;});
  add("guest syscall wrong number",syscall,[](Fixture& x){x.syscall.syscallNumber=11;});
  add("x86 guest syscall wrong RIP",syscall,[](Fixture& x){x.syscall.sourceGuestRIP++;});
  add("x86 guest syscall wrong next RIP",syscall,[](Fixture& x){x.syscall.sourceGuestNextRIP++;});
  add("foreign page",syscall,[](Fixture& x){x.syscall.address+=4096;});
  add("base rounded down 16K",syscall,[](Fixture& x){x.syscall.address-=4096;});
  add("host 16K span instead of guest 4K",syscall,[](Fixture& x){x.syscall.length=16384;});
  add("unaligned guest length",syscall,[](Fixture& x){x.syscall.length=4095;});
  add("wrong protection RW",syscall,[](Fixture& x){x.syscall.protection=3;});
  add("wrong protection RX",syscall,[](Fixture& x){x.syscall.protection=5;});
  add("wrong protection RWX",syscall,[](Fixture& x){x.syscall.protection=7;});
  add("no owner ELF",owned,[](Fixture& x){x.owner.ownedExactOriginalMainELF=false;});
  add("unowned PT_GNU_RELRO",owned,[](Fixture& x){x.owner.sourceBackedMainPTGNURELRO=false;});
  add("wrong owner identity",owned,[](Fixture& x){x.owner.ownerRegistrySourceSHAIdentityChecked=false;});
  add("host alias shared VMA",owned,[](Fixture& x){x.owner.noForeignHostPointerOrOverlappingVMA=false;});
  add("guest writable executable alias",owned,[](Fixture& x){x.owner.noOverlappingLiveExecutableOrWritableGuestAlias=false;});
  add("unexpected native RX",owned,[](Fixture& x){x.owner.currentlyExactGuestRelroPageReadWriteAndNotExecute=false;});
  add("pending GNU main relro writer",owned,[](Fixture& x){x.owner.pendingOriginalMainPageWriter=true;});
  add("wrong source guest owner VA",owned,[](Fixture& x){x.owner.mappedGuestPageStart+=4096;});
  add("null host page",owned,[](Fixture& x){x.owner.mappedHostPageStart=0;});
  add("unaligned host map",owned,[](Fixture& x){x.owner.mappedHostPageStart+=1;});
  add("host16k non-isolated native subpage",page,[](Fixture& x){x.owner.hostNativePageBytes=16384;});
  add("host16k even if whole span remapped",page,[](Fixture& x){x.owner.hostNativePageBytes=16384;x.owner.exactOwnedNativeSpanBytes=16384;});
  add("host 64K native page",page,[](Fixture& x){x.owner.hostNativePageBytes=65536;});
  add("guest16k page mismatch",page,[](Fixture& x){x.owner.guestPageBytes=16384;});
  add("native owner slice bigger than guest",page,[](Fixture& x){x.owner.exactOwnedNativeSpanBytes=8192;});
  add("native owner slice zero",page,[](Fixture& x){x.owner.exactOwnedNativeSpanBytes=0;});
  assert(tests.size()==39);
  for(const auto& test:tests){
    auto corrupted=good;test.corrupt(corrupted);
    const auto result=PlanOneOriginalMainPage(corrupted.source,corrupted.owner,corrupted.syscall);
    assert(result.decision==test.expected);
    assert(!result.canAttemptHostMprotectForThisOneSourcePage);
    assert(!result.nativeKernelProtectionChanged && !result.guestSyscallSucceeded &&
           !result.sourceMainRELROSealed && !result.originalLdsoSelfIFUNCExecuted &&
           !result.AndroidWineOrGamesProven);
  }
  // Ordinary FEX G0 source records alone DO NOT prove host ownership.
  auto empty=PlanOneOriginalMainPage(SourceStage{},OwnedVMA{},GuestSyscall{});
  assert(empty.decision==source && !empty.canAttemptHostMprotectForThisOneSourcePage);
  std::printf("KERNIX_G0_GNU_MAIN_RELRO_STAGE_MPROTECT_PLANNING_GATE_39_NEGATIVE_CASES_PASS_NO_REAL_SYSCALL_AND_NO_16K_UNSAFE_ROUNDING\n");
}
