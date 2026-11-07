// SPDX-License-Identifier: MIT
#pragma once
// KERNIX G0 / Linux ARM64 source-only authenticity of one real x86
// syscall opcode inside the SHA-pinned, unmodified GNU ld-linux PT_LOAD.
// Exact source ELF file-backed opcode, live guest byte identity, trusted
// page ownership and RX policy are mandatory. This is NOT proof of
// instruction-level symbol relocation stores, full ldso completion,
// original main GNU_RELRO seal authority or Android/Wine execution.
#include "kernix_g2e_c3d7i_original_x86_dynamic_tls_relocation_contract.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::ldsosyscallorigin {
struct Witness {
  uint64_t guestRIP=0;
  uint64_t sourceVA=0;
  size_t sourceFileOffset=0;
  bool originalGNUInterpreterPinnedSource=false;
  bool sourceAndGuestOpcodeIdentical=false;
  bool guestPageOwnedOriginalRX=false;
  bool originalDynamicRelocationClosureProven=false;
};
inline bool AuthenticateOriginalLdsoSyscallInstruction(
    const uint8_t* source,size_t bytes,bool pinnedSHA,
    const kernix::g2e::c3d7b::NativeChosenPIEGuestLayout& owned,
    const kernix::g2e::c3d7g::PermissionPlan& policy,
    uint64_t trappedGuestRIP,uint64_t guestNextRIP,
    Witness& out) noexcept {
  out={};
  namespace g=kernix::g2e::c3d7g;
  namespace d=kernix::g2e::c3d7i;
  const auto* interpreter=owned.Module(1);
  if(!source || !pinnedSHA || !interpreter ||
     !policy.sourceShaVerified || !policy.nativeGuestVAIdentityOwned ||
     !owned.LaunchPlan() || owned.WindowsHeld()!=4 ||
     bytes<sizeof(Elf64_Ehdr) ||
     trappedGuestRIP<interpreter->chosenImageStart ||
     trappedGuestRIP<interpreter->loadBias ||
     trappedGuestRIP>UINT64_MAX-2 ||
     trappedGuestRIP+2!=guestNextRIP ||
     trappedGuestRIP-interpreter->chosenImageStart>
       g::kModulePages*4096ULL-2)
    return false;
  const size_t page=static_cast<size_t>(
      (trappedGuestRIP-interpreter->chosenImageStart)/4096);
  const auto policyBits=policy.modules[1].rights[page];
  if((policyBits&(g::kRead|g::kExecute))!=
        (g::kRead|g::kExecute) ||
     (policyBits&g::kWrite)!=0 ||
     (trappedGuestRIP&4095)>4096-2)
    return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,source,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_type!=ET_DYN || elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     elf.e_phoff>bytes ||
     size_t(elf.e_phnum)>(bytes-elf.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  const uint64_t va=trappedGuestRIP-interpreter->loadBias;
  size_t offset=0;
  if(!d::SourceFileVA(source,bytes,elf,va,2,offset) ||
     offset>bytes || bytes-offset<2 ||
     source[offset]!=0x0f || source[offset+1]!=0x05)
    return false;
  const auto* live=owned.GuestReadOnlyBytes(1,trappedGuestRIP,2);
  if(!live || live[0]!=source[offset] || live[1]!=source[offset+1])
    return false;
  out.guestRIP=trappedGuestRIP;
  out.sourceVA=va;
  out.sourceFileOffset=offset;
  out.originalGNUInterpreterPinnedSource=true;
  out.sourceAndGuestOpcodeIdentical=true;
  out.guestPageOwnedOriginalRX=true;
  return true;
}
} // namespace kernix::g0::ldsosyscallorigin
