// SPDX-License-Identifier: MIT
#pragma once
// KERNIX G0: inspect all 46 source-authenticated original libc.so.6
// x86_64 R_X86_64_IRELATIVE resolver entries. Compare original pinned
// PT_LOAD RX bytes against the owned guest RX mapping and inventory the
// two live GOT snapshots. No guest store, IFUNC call, hook, artificial
// memory protection change, symbolic binding or relocation-closure claim.
#include "kernix_g0_original_libc_147_rela_jmprel_two_boundary_readonly.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>

namespace kernix::g0::libcifuncinventory {
struct Entry {
  size_t sourceRelaIndex=0;
  uint64_t sourceResolverVA=0,guestResolver=0;
  uint64_t target=0,valueAtLibc=0,valueAtMain=0;
  bool originalSourceAndGuestRXIdentical=false;
  bool nonzeroResultInsideOriginalLibcRX=false;
};
struct Witness {
  std::array<Entry,46> entries{};
  size_t total=0,sourceRX=0,guestRXEqual=0;
  size_t nonzeroAtLibc=0,nonzeroAtMain=0,unchanged=0;
  size_t zeroBoth=0;
  size_t nonzeroResultInsideLibcRX=0;
  size_t nonzeroResultOutsideLibcRX=0;
  bool originalSourceSHA256Verified=false;
  bool originalResolversExecutedByThisAudit=false;
  bool originalLoaderStoreRIPsTraced=false;
  bool originalIFUNCResultsCorrectlyBoundProven=false;
  bool originalDynamicRelocationClosureProven=false;
};
template<class GuestRX>
inline bool AuditAllOriginalLibc46IRELATIVEResolverSourcesReadonly(
    const uint8_t* source,size_t bytes,bool pinnedSHA,
    const kernix::g0::PinnedLibcLargeReadonlyGuestMap& owned,
    const kernix::g0::libcrela::Witness& libcRelocsAtLibc,
    const kernix::g0::libcrela::Witness& libcRelocsAtMain,
    GuestRX&& authenticatedGuestRX,Witness& result) noexcept {
  result={};
  namespace d=kernix::g2e::c3d7i;
  const uint64_t base=owned.Address();
  if(!pinnedSHA || !source || !base ||
     !libcRelocsAtLibc.originalSourceShaPinned ||
     !libcRelocsAtMain.originalSourceShaPinned ||
     libcRelocsAtLibc.count!=147 || libcRelocsAtMain.count!=147 ||
     libcRelocsAtLibc.irelative!=46 || libcRelocsAtMain.irelative!=46 ||
     libcRelocsAtLibc.ifuncNonzero!=45 ||
     libcRelocsAtMain.ifuncNonzero!=45 ||
     libcRelocsAtLibc.guestStoreInstructionsTraced ||
     libcRelocsAtMain.guestStoreInstructionsTraced ||
     libcRelocsAtLibc.symbolOrIfuncResolutionsProven ||
     libcRelocsAtMain.symbolOrIfuncResolutionsProven ||
     bytes!=kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize ||
     owned.CopiedSourceBytes()!=bytes ||
     owned.BytesHeld()!=0x212000ULL ||
     !owned.OriginalOwnedBSSZeroed() ||
     bytes<sizeof(Elf64_Ehdr))return false;
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
  std::array<Elf64_Phdr,128> phdrs{};
  for(uint16_t ph=0;ph<elf.e_phnum;++ph)
    std::memcpy(&phdrs[ph],source+elf.e_phoff+
                size_t(ph)*sizeof(Elf64_Phdr),sizeof(Elf64_Phdr));
  const auto sourceExecutable=[&](uint64_t va,size_t count) noexcept -> bool {
    for(size_t k=0;k<elf.e_phnum;++k){
      const auto& ph=phdrs[k];
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&(PF_R|PF_X|PF_W))!=(PF_R|PF_X) ||
         va<ph.p_vaddr || va-ph.p_vaddr>ph.p_filesz ||
         count>ph.p_filesz-(va-ph.p_vaddr))continue;
      return true;
    }
    return false;
  };
  for(size_t k=0;k<147;++k) {
    const auto& early=libcRelocsAtLibc.slots[k];
    const auto& late=libcRelocsAtMain.slots[k];
    if(!early.target || early.target!=late.target ||
       early.source!=late.source ||
       early.type!=late.type || early.symbol!=late.symbol ||
       early.addend!=late.addend || early.plt!=late.plt ||
       early.sourceBacked!=late.sourceBacked ||
       early.live!=late.live)
       return false;
    if(early.type!=R_X86_64_IRELATIVE)continue;
    if(early.symbol!=0 || early.addend<=0 ||
       result.total>=result.entries.size() ||
       static_cast<uint64_t>(early.addend)>UINT64_MAX-base)
       return false;
    const uint64_t va=static_cast<uint64_t>(early.addend);
    const uint64_t guest=base+va;
    if(guest<base || owned.BytesHeld()<8 ||
       guest-base>owned.BytesHeld()-8 ||
       !sourceExecutable(va,8) || !authenticatedGuestRX(guest))
       return false;
    size_t fileOffset=0;
    if(!d::SourceFileVA(source,bytes,elf,va,8,fileOffset))
       return false;
    const auto* code=owned.AuthenticatedReadonlyBytes(guest,8);
    if(!code || std::memcmp(code,source+fileOffset,8)!=0)
       return false;
    auto& entry=result.entries[result.total];
    entry.sourceRelaIndex=k;
    entry.sourceResolverVA=va;
    entry.guestResolver=guest;
    entry.target=early.target;
    entry.valueAtLibc=early.live;
    entry.valueAtMain=late.live;
    entry.originalSourceAndGuestRXIdentical=true;
    // A nonzero relocation qword may be a pointer inside this source
    // image, outside it, or even something else. Classify, never infer
    // it was returned by the authentic resolver.
    if(late.live>=base) {
      const uint64_t returnedVA=late.live-base;
      entry.nonzeroResultInsideOriginalLibcRX=
          sourceExecutable(returnedVA,1);
    }
    ++result.total;
    ++result.sourceRX;
    ++result.guestRXEqual;
    result.unchanged+=size_t(early.live==late.live);
    result.nonzeroAtLibc+=size_t(early.live!=0);
    result.nonzeroAtMain+=size_t(late.live!=0);
    result.zeroBoth+=size_t(!early.live && !late.live);
    result.nonzeroResultInsideLibcRX+=
        size_t(entry.nonzeroResultInsideOriginalLibcRX);
    result.nonzeroResultOutsideLibcRX+=
        size_t(late.live!=0 && !entry.nonzeroResultInsideOriginalLibcRX);
  }
  if(result.total!=46 || result.sourceRX!=46 ||
     result.guestRXEqual!=46 || result.unchanged!=46 ||
     result.nonzeroAtLibc!=45 || result.nonzeroAtMain!=45 ||
     result.zeroBoth!=1 ||
     result.nonzeroResultInsideLibcRX+
       result.nonzeroResultOutsideLibcRX!=45)
    return false;
  result.originalSourceSHA256Verified=true;
  return true;
}
} // namespace kernix::g0::libcifuncinventory
