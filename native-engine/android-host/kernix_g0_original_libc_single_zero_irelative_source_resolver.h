// SPDX-License-Identifier: MIT
#pragma once
// KERNIX G0 source-only original glibc x86_64 IRELATIVE zero target.
// Compare two guest snapshots with exact pinned ELF RX resolver bytes;
// NEVER invoke the resolver or infer that its zero result is valid.
// This is not dynamic-linker closure or permission to seal main RELRO.
#include "kernix_g0_original_libc_147_rela_jmprel_two_boundary_readonly.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>

namespace kernix::g0::libcifunczero {
struct Witness {
  size_t totalIRELATIVE=0;
  size_t nonzeroBeforeLibcSeal=0;
  size_t nonzeroAtMainBoundary=0;
  size_t zeroAtBothBoundaries=0;
  size_t zeroIndex=0;
  uint64_t target=0;
  uint64_t resolverSourceVA=0;
  uint64_t resolverGuestVA=0;
  uint64_t valueAtLibcBoundary=0;
  uint64_t valueAtMainBoundary=0;
  bool sourceSHA256Authenticated=false;
  bool zeroResolverInsidePinnedSourceRX=false;
  bool exactOriginalResolverBytesPresentInGuestRX=false;
  bool originalIFUNCInvocationProven=false;
  bool zeroIsAValidResolutionProven=false;
  bool allLoaderRelocationsProven=false;
};
template<class Rights>
inline bool AuditSingleZeroOriginalLibcIRELATIVEResolverReadOnly(
    const uint8_t* original,size_t bytes,bool sha256,
    const kernix::g0::PinnedLibcLargeReadonlyGuestMap& map,
    const kernix::g0::libcrela::Witness& atLibc,
    const kernix::g0::libcrela::Witness& atMain,
    Rights&& rights,Witness& out) noexcept {
  out={};
  namespace d=kernix::g2e::c3d7i;
  const uint64_t base=map.Address();
  if(!original || !sha256 || !base ||
     !atLibc.originalSourceShaPinned || !atMain.originalSourceShaPinned ||
     atLibc.count!=147 || atMain.count!=147 ||
     atLibc.irelative!=46 || atMain.irelative!=46 ||
     atLibc.ifuncNonzero!=45 || atMain.ifuncNonzero!=45 ||
     atLibc.guestStoreInstructionsTraced ||
     atMain.guestStoreInstructionsTraced ||
     atLibc.symbolOrIfuncResolutionsProven ||
     atMain.symbolOrIfuncResolutionsProven ||
     bytes!=kernix::g0::PinnedLibcLargeReadonlyGuestMap::kOriginalLibcSize ||
     map.CopiedSourceBytes()!=bytes ||
     map.BytesHeld()!=0x212000ULL ||
     !map.OriginalOwnedBSSZeroed() ||
     bytes<sizeof(Elf64_Ehdr))
    return false;
  Elf64_Ehdr elf{};
  std::memcpy(&elf,original,sizeof(elf));
  if(std::memcmp(elf.e_ident,ELFMAG,SELFMAG)!=0 ||
     elf.e_ident[EI_CLASS]!=ELFCLASS64 ||
     elf.e_ident[EI_DATA]!=ELFDATA2LSB ||
     elf.e_type!=ET_DYN || elf.e_machine!=EM_X86_64 ||
     elf.e_phentsize!=sizeof(Elf64_Phdr) ||
     !elf.e_phnum || elf.e_phnum>128 ||
     elf.e_phoff>bytes ||
     size_t(elf.e_phnum)>(bytes-elf.e_phoff)/sizeof(Elf64_Phdr))
    return false;
  for(size_t i=0;i<147;++i){
    const auto& before=atLibc.slots[i];
    const auto& after=atMain.slots[i];
    if(!before.target || before.target!=after.target ||
       before.source!=after.source ||
       before.type!=after.type ||
       before.symbol!=after.symbol ||
       before.addend!=after.addend ||
       before.plt!=after.plt ||
       before.sourceBacked!=after.sourceBacked)
       return false;
    if(before.type!=R_X86_64_IRELATIVE)continue;
    if(before.symbol!=0)return false;
    ++out.totalIRELATIVE;
    out.nonzeroBeforeLibcSeal+=size_t(before.live!=0);
    out.nonzeroAtMainBoundary+=size_t(after.live!=0);
    if(before.live || after.live)continue;
    if(++out.zeroAtBothBoundaries!=1 || before.addend<=0)
      return false;
    const uint64_t resolverVA=static_cast<uint64_t>(before.addend);
    if(resolverVA>UINT64_MAX-base)return false;
    const uint64_t guest=base+resolverVA;
    if(guest<base || guest-base>map.BytesHeld()-8)
       return false;
    bool authenticRX=false;
    for(uint16_t j=0;j<elf.e_phnum;++j){
      Elf64_Phdr ph{};
      std::memcpy(&ph,original+elf.e_phoff+
           size_t(j)*sizeof(ph),sizeof(ph));
      if(ph.p_type!=PT_LOAD ||
         (ph.p_flags&(PF_R|PF_X|PF_W))!=(PF_R|PF_X) ||
         resolverVA<ph.p_vaddr ||
         resolverVA-ph.p_vaddr>ph.p_filesz ||
         ph.p_filesz-(resolverVA-ph.p_vaddr)<8)
         continue;
      authenticRX=true;break;
    }
    if(!authenticRX || !rights(guest))return false;
    size_t fileOffset=0;
    if(!d::SourceFileVA(original,bytes,elf,resolverVA,8,fileOffset))
       return false;
    const auto* live=map.AuthenticatedReadonlyBytes(guest,8);
    if(!live || std::memcmp(original+fileOffset,live,8)!=0)
       return false;
    out.zeroIndex=i;
    out.target=before.target;
    out.resolverSourceVA=resolverVA;
    out.resolverGuestVA=guest;
    out.valueAtLibcBoundary=before.live;
    out.valueAtMainBoundary=after.live;
    out.zeroResolverInsidePinnedSourceRX=true;
    out.exactOriginalResolverBytesPresentInGuestRX=true;
  }
  if(out.totalIRELATIVE!=46 ||
     out.nonzeroBeforeLibcSeal!=45 ||
     out.nonzeroAtMainBoundary!=45 ||
     out.zeroAtBothBoundaries!=1 ||
     !out.target || !out.resolverSourceVA ||
     !out.zeroResolverInsidePinnedSourceRX ||
     !out.exactOriginalResolverBytesPresentInGuestRX)
     return false;
  out.sourceSHA256Authenticated=true;
  return true;
}
} // namespace kernix::g0::libcifunczero
