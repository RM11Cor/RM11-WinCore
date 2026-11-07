// SPDX-License-Identifier: MIT
#pragma once
// Negative controls for a verified, AUTHENTIC original GNU x86
// ld-linux mprotect trap at original main PT_GNU_RELRO.
// All alternatives operate on local classification copies or inspect
// unmodified SHA-verified ELF/guest bytes. No syscall forwarding,
// no host/guest writes, no permissions changed, no seal authorization.
#include "kernix_g0_original_ldso_x86_mprotect_syscall_source_witness.h"
#include "kernix_g0_original_main_relro_post_libc_source_audit.h"
#include <cstddef>
#include <cstdint>

namespace kernix::g0::relrospoof {
struct Witness {
  unsigned invalidMainMprotectDenied=0;
  unsigned invalidSourceOpcodeDenied=0;
  bool originalMainPageStillRW=false;
  bool originalLoaderSealOrFullRelocationClaim=false;
  bool testedOnAndroid=false;
};
inline bool RejectThirteenSpoofedOriginalMainRELRORequests(
    const uint8_t* ldsoSource,size_t sourceBytes,bool sourceSHA,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& plan,
    const kernix::g2e::c3d7g::ApplyWitness& applied,
    const kernix::g2e::c1::TrapClassification& realTrap,
    uint64_t realInstructionRIP,uint64_t nextGuestRIP,
    uint64_t originalMainRELROPage,bool mainPageRW,
    Witness& out) noexcept {
  namespace c1=kernix::g2e::c1;
  namespace main=kernix::g0::mainrelroaudit;
  namespace code=kernix::g0::ldsosyscallorigin;
  out={};
  const auto* originalMain=owned.Module(0);
  if(!originalMain || !ldsoSource || !sourceSHA ||
     !mainPageRW || !originalMainRELROPage ||
     originalMainRELROPage>UINT64_MAX-8192 ||
     nextGuestRIP==UINT64_MAX || sourceBytes<sizeof(Elf64_Ehdr) ||
     realTrap.args[0]!=originalMainRELROPage ||
     realTrap.args[1]!=4096 || realTrap.args[2]!=1)
    return false;
  const auto positive=main::ObserveNextOriginalMainRELRO(
      realTrap,owned,plan,applied,originalMainRELROPage,true);
  code::Witness authenticOpcode{};
  if(!positive.authenticatedGuestMprotect10 ||
     !positive.originalSourceELF64PTGNURelroFullPage ||
     !positive.sourceOwnedOriginalMainRWPage ||
     !positive.noGuestVMRightsModified ||
     positive.realDynamicRelocationClosureAttested ||
     !code::AuthenticateOriginalLdsoSyscallInstruction(
       ldsoSource,sourceBytes,sourceSHA,owned,plan,
       realInstructionRIP,nextGuestRIP,authenticOpcode) ||
     !authenticOpcode.originalGNUInterpreterPinnedSource ||
     !authenticOpcode.sourceAndGuestOpcodeIdentical ||
     !authenticOpcode.guestPageOwnedOriginalRX ||
     authenticOpcode.originalDynamicRelocationClosureProven)
    return false;
  // Verify authentic syscall classification with copies of the
  // REAL observed x86 CPUState classification, one mutation each.
  const auto deniesMain=[&](const c1::TrapClassification& req,
                             bool pageRW=true) noexcept {
    const auto result=main::ObserveNextOriginalMainRELRO(
        req,owned,plan,applied,originalMainRELROPage,pageRW);
    return !result.authenticatedGuestMprotect10 &&
           !result.originalSourceELF64PTGNURelroFullPage &&
           !result.sourceOwnedOriginalMainRWPage &&
           result.noGuestVMRightsModified &&
           !result.realDynamicRelocationClosureAttested;
  };
  auto bad=realTrap;
  bad.args[0]=originalMainRELROPage+4096;
  if(!deniesMain(bad))return false;
  ++out.invalidMainMprotectDenied;
  bad=realTrap;bad.args[1]=8192;
  if(!deniesMain(bad))return false;
  ++out.invalidMainMprotectDenied;
  bad=realTrap;bad.args[2]=3; // writable page is never a RELRO seal
  if(!deniesMain(bad))return false;
  ++out.invalidMainMprotectDenied;
  bad=realTrap;bad.guestNumber=c1::kMmap;
  if(!deniesMain(bad))return false;
  ++out.invalidMainMprotectDenied;
  bad=realTrap;bad.trapBoundaryAuthenticated=false;
  if(!deniesMain(bad))return false;
  ++out.invalidMainMprotectDenied;
  bad=realTrap;bad.sourceRegisterMappingChecked=false;
  if(!deniesMain(bad))return false;
  ++out.invalidMainMprotectDenied;
  bad=realTrap;bad.hostSyscallDispatched=true;
  if(!deniesMain(bad))return false;
  ++out.invalidMainMprotectDenied;
  if(!deniesMain(realTrap,false))return false;
  ++out.invalidMainMprotectDenied;
  // Check the original-ELF opcode witness rejects forged provenance
  // even with a real SHA-pinned RX guest page still present.
  const auto deniesOpcode=[&](const uint8_t* candidate,size_t count,
                              bool sha,uint64_t rip,uint64_t next) noexcept {
    code::Witness result{};
    return !code::AuthenticateOriginalLdsoSyscallInstruction(
        candidate,count,sha,owned,plan,rip,next,result) &&
        !result.originalGNUInterpreterPinnedSource &&
        !result.sourceAndGuestOpcodeIdentical &&
        !result.guestPageOwnedOriginalRX &&
        !result.originalDynamicRelocationClosureProven;
  };
  if(!deniesOpcode(ldsoSource,sourceBytes,false,
                   realInstructionRIP,nextGuestRIP))return false;
  ++out.invalidSourceOpcodeDenied;
  if(!deniesOpcode(nullptr,sourceBytes,sourceSHA,
                   realInstructionRIP,nextGuestRIP))return false;
  ++out.invalidSourceOpcodeDenied;
  if(!deniesOpcode(ldsoSource,sizeof(Elf64_Ehdr)-1,sourceSHA,
                   realInstructionRIP,nextGuestRIP))return false;
  ++out.invalidSourceOpcodeDenied;
  if(!deniesOpcode(ldsoSource,sourceBytes,sourceSHA,
                   realInstructionRIP,nextGuestRIP+1))return false;
  ++out.invalidSourceOpcodeDenied;
  if(!deniesOpcode(ldsoSource,sourceBytes,sourceSHA,
                   originalMain->chosenImageStart,
                   originalMain->chosenImageStart+2))return false;
  ++out.invalidSourceOpcodeDenied;
  out.originalMainPageStillRW=mainPageRW &&
      positive.noGuestVMRightsModified;
  return out.invalidMainMprotectDenied==8 &&
         out.invalidSourceOpcodeDenied==5 &&
         out.originalMainPageStillRW &&
         !out.originalLoaderSealOrFullRelocationClaim &&
         !out.testedOnAndroid;
}
} // namespace kernix::g0::relrospoof
