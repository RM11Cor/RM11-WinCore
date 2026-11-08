// SPDX-License-Identifier: MIT
#pragma once
// EXPERIMENTAL Linux AArch64 ONLY: original SHA-pinned FEX guest libc
// exit_group(231), status 0, after the same native source-owned guest
// wrote its 45 stdout bytes successfully. Original x86 syscall never
// forwarded to host: this is an attested request to terminate the
// independent bounded test process, NOT a general exit dispatcher.
//
// Distinguish original guest exit_group(0) request, verified native FEX
// callback and host test process exiting 0; no proof main's return
// instruction, every ELF relocation, Android/Wine/games or 16K subpages.
#include "kernix_g2e_c1_x86_linux_syscall_boundary.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>
#include <unistd.h>

namespace kernix::g0::originalexitgroup {
constexpr uint64_t kSourceOriginalGuestLibcBase=0x804000000ULL;
constexpr uint64_t kOriginalSourceGuestExitGroupRIP=0x8040ee0dbULL;
constexpr uint64_t kOriginalSourceExitFileVA=
  kOriginalSourceGuestExitGroupRIP-kSourceOriginalGuestLibcBase;
constexpr uint64_t kGuestLinuxExitGroupSyscall=231ULL;
struct Witness {
  bool exactOriginalSourceELF64ExitGroupOpcode=false;
  bool liveSourceGuestRXMatchesImmutableOpcode=false;
  bool exactGuestX86ExitGroup0TrapOnly=false;
  bool oneOriginalNativeStdoutWrite45AlreadySucceeded=false;
  bool originalNativeKernelThreeELFRELROAndLibcSyscallsProven=false;
  bool independentSourceFEXOriginalGuestExitGroup0RequestObserved=false;
  bool hostKernelExitGroupSyscallForwarded=false;
  bool originalMainReturnInstructionTraced=false;
  bool originalLdsoResolverGuestEntryReturnTraced=false;
  bool completeOriginalELFDynamicRelocationClosureProven=false;
  bool android16KWineProtonGameExecutionProven=false;
};

inline bool OriginalLibcSourceExitGroupOpcode(
  const uint8_t* source,size_t size) noexcept {
  if(!source || size!=2118168 || size<sizeof(Elf64_Ehdr))return false;
  Elf64_Ehdr h{};
  std::memcpy(&h,source,sizeof(h));
  if(std::memcmp(h.e_ident,ELFMAG,SELFMAG)!=0 ||
     h.e_ident[EI_CLASS]!=ELFCLASS64 ||
     h.e_ident[EI_DATA]!=ELFDATA2LSB ||
     h.e_type!=ET_DYN || h.e_machine!=EM_X86_64 ||
     h.e_phentsize!=sizeof(Elf64_Phdr) ||
     h.e_phnum==0 || h.e_phnum>128 ||
     h.e_phoff>size ||
     h.e_phnum>(size-h.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  size_t matches=0,at=0;
  for(size_t i=0;i<h.e_phnum;++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph,source+h.e_phoff+i*sizeof(ph),sizeof(ph));
    if(ph.p_type!=PT_LOAD || (ph.p_flags&PF_X)==0 ||
       (ph.p_flags&PF_W)!=0)continue;
    if(ph.p_filesz>ph.p_memsz || ph.p_offset>size ||
       ph.p_filesz>size-ph.p_offset ||
       ph.p_vaddr>UINT64_MAX-ph.p_filesz)return false;
    if(kOriginalSourceExitFileVA<ph.p_vaddr ||
       kOriginalSourceExitFileVA-ph.p_vaddr>ph.p_filesz ||
       ph.p_filesz-(kOriginalSourceExitFileVA-ph.p_vaddr)<2)
      continue;
    at=ph.p_offset+kOriginalSourceExitFileVA-ph.p_vaddr;
    ++matches;
  }
  return matches==1 && at<=size-2 &&
         source[at]==0x0f && source[at+1]==0x05;
}

inline Witness AuthenticateOnlyPinnedOriginalGuestExitGroup0(
  const kernix::g2e::c1::TrapClassification& trap,
  uint64_t originalGuestRIP,
  const uint8_t* immutablePinnedOriginalLibcSource,size_t sourceSize,
  bool originalThreeELFSHAAndLiveFEXTrapAuthenticated,
  bool originalLibcMainLdsoActualKernelRELROSealedInThisProcess,
  bool originalPrlimitFstatGetrandomPreviouslySucceededInSameGuestProcess,
  bool originalNativeSourceOwnedGuestWrite45SucceededExactlyOnce,
  std::string(*rightsAt)(uint64_t)) noexcept {
  Witness w{};
  if(!rightsAt || !originalThreeELFSHAAndLiveFEXTrapAuthenticated ||
     !originalLibcMainLdsoActualKernelRELROSealedInThisProcess ||
     !originalPrlimitFstatGetrandomPreviouslySucceededInSameGuestProcess ||
     !originalNativeSourceOwnedGuestWrite45SucceededExactlyOnce ||
     ::sysconf(_SC_PAGESIZE)!=4096 ||
     trap.guestNumber!=kGuestLinuxExitGroupSyscall ||
     trap.category!=kernix::g2e::c1::CallCategory::ExitIntentOnly ||
     !trap.trapBoundaryAuthenticated ||
     !trap.sourceRegisterMappingChecked ||
     trap.hostSyscallDispatched || trap.guestMemoryDereferenced ||
     originalGuestRIP!=kOriginalSourceGuestExitGroupRIP ||
     trap.nextGuestRIP!=originalGuestRIP+2 ||
     trap.args[0]!=0 || // exact Linux x86 0 exit status
     !OriginalLibcSourceExitGroupOpcode(immutablePinnedOriginalLibcSource,
                                        sourceSize) ||
     rightsAt(originalGuestRIP)!="r-xp" ||
     rightsAt(0x800003000ULL)!="r--p" ||
     rightsAt(0x801036000ULL)!="r--p" ||
     rightsAt(0x801037000ULL)!="r--p")
    return w;
  w.exactOriginalSourceELF64ExitGroupOpcode=true;
  const uint8_t* live=reinterpret_cast<const uint8_t*>(
     static_cast<uintptr_t>(originalGuestRIP));
  if(live[0]!=0x0f || live[1]!=0x05)return w;
  w.liveSourceGuestRXMatchesImmutableOpcode=true;
  w.exactGuestX86ExitGroup0TrapOnly=true;
  w.oneOriginalNativeStdoutWrite45AlreadySucceeded=true;
  w.originalNativeKernelThreeELFRELROAndLibcSyscallsProven=true;
  w.independentSourceFEXOriginalGuestExitGroup0RequestObserved=true;
  return w;
}
} // namespace kernix::g0::originalexitgroup
